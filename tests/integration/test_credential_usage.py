"""last_used_at tracking against real PostgreSQL 18, as the runtime role (ADR-0005, ADR-0012).

Throttling is decided by database time. The boundary tests move the stored timestamp, never a
clock, so they do not sleep.
"""

import logging
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from shiptrace.api.auth import require
from shiptrace.application.credentials import new_token
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import Action, digest, display_prefix
from shiptrace.persistence.credentials import PostgresCredentialStore

from .conftest import Database

EngineFor = Callable[[str], Engine]
PROBE = "/api/v1/_probe"
Make = Callable[..., tuple[str, str]]


@pytest.fixture
def migrator(migrated_database: Database, engine_for: EngineFor) -> Engine:
    return engine_for(migrated_database.migrator_url)


@pytest.fixture
def make(migrator: Engine) -> Iterator[Make]:
    """Commits an unbound read or admin credential as the migrator; returns (token, id)."""
    created: list[str] = []

    def make_one(
        scope: str = "read",
        expires: str = "NULL",
        revoked: str = "NULL",
        last_used: str = "NULL",
    ) -> tuple[str, str]:
        token = new_token()
        # expires, revoked and last_used are fixed SQL expressions chosen by the tests.
        with migrator.begin() as connection:
            credential_id = connection.execute(
                text(
                    "INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix, "
                    "expires_at, revoked_at, last_used_at) VALUES ('usage', :scope, :digest, "
                    f":prefix, {expires}, {revoked}, {last_used}) RETURNING id"
                ),
                {"scope": scope, "digest": digest(token), "prefix": display_prefix(token)},
            ).scalar_one()
        created.append(str(credential_id))
        return token, str(credential_id)

    yield make_one
    with migrator.begin() as connection:
        for credential_id in created:
            connection.execute(
                text("DELETE FROM api_credentials WHERE id = :i"), {"i": credential_id}
            )


def last_used(migrator: Engine, credential_id: str) -> object:
    with migrator.connect() as connection:
        return connection.execute(
            text("SELECT last_used_at FROM api_credentials WHERE id = :i"), {"i": credential_id}
        ).scalar_one()


def seconds_ago(migrator: Engine, credential_id: str) -> float | None:
    with migrator.connect() as connection:
        value = connection.execute(
            text(
                "SELECT extract(epoch FROM now() - last_used_at)::float8 "
                "FROM api_credentials WHERE id = :i"
            ),
            {"i": credential_id},
        ).scalar_one()
    return None if value is None else float(value)


@pytest.fixture
def app_engine(migrated_database: Database, engine_for: EngineFor) -> Engine:
    return engine_for(migrated_database.app_url)


@pytest.fixture
def store(app_engine: Engine) -> PostgresCredentialStore:
    return PostgresCredentialStore(app_engine)


# --- throttling -----------------------------------------------------------------------------


def test_first_use_records_database_time(
    store: PostgresCredentialStore, migrator: Engine, make: Make
) -> None:
    token, credential_id = make()
    assert last_used(migrator, credential_id) is None
    assert store.find_active(digest(token)) is not None
    age = seconds_ago(migrator, credential_id)
    assert age is not None and 0 <= age < 60


def test_repeat_use_within_the_window_writes_nothing(
    store: PostgresCredentialStore, migrator: Engine, make: Make
) -> None:
    token, credential_id = make()
    store.find_active(digest(token))
    first = last_used(migrator, credential_id)
    for _ in range(3):
        assert store.find_active(digest(token)) is not None
    assert last_used(migrator, credential_id) == first


@pytest.mark.parametrize(
    ("age_seconds", "updated"),
    [(1, False), (299, False), (301, True), (86400, True)],
)
def test_five_minute_boundary(
    store: PostgresCredentialStore,
    migrator: Engine,
    make: Make,
    age_seconds: int,
    updated: bool,
) -> None:
    token, credential_id = make(last_used=f"now() - interval '{age_seconds} seconds'")
    before = last_used(migrator, credential_id)
    assert store.find_active(digest(token)) is not None
    assert (last_used(migrator, credential_id) != before) is updated
    if updated:
        age = seconds_ago(migrator, credential_id)
        assert age is not None and 0 <= age < 60


def test_a_write_is_not_attempted_inside_the_window(
    app_engine: Engine, store: PostgresCredentialStore, make: Make
) -> None:
    """The lookup decides staleness itself, so a fresh credential costs no UPDATE at all."""
    statements: list[str] = []

    def record(_c: Any, _cur: Any, statement: str, *_: Any) -> None:
        statements.append(statement.split()[0])

    token, _ = make(last_used="now() - interval '10 seconds'")
    event.listen(app_engine, "before_cursor_execute", record)
    try:
        store.find_active(digest(token))
    finally:
        event.remove(app_engine, "before_cursor_execute", record)
    assert statements == ["SELECT"]


# --- rejected credentials --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expires", "revoked"),
    [("now() - interval '1 second'", "NULL"), ("NULL", "now()")],
    ids=["expired", "revoked"],
)
def test_dead_credentials_are_never_marked_used(
    store: PostgresCredentialStore, migrator: Engine, make: Make, expires: str, revoked: str
) -> None:
    token, credential_id = make(expires=expires, revoked=revoked)
    assert store.find_active(digest(token)) is None
    assert last_used(migrator, credential_id) is None


def test_unknown_credential_writes_no_usage(
    app_engine: Engine, store: PostgresCredentialStore, migrator: Engine
) -> None:
    with migrator.connect() as connection:
        before = connection.execute(
            text("SELECT count(last_used_at), max(last_used_at) FROM api_credentials")
        ).one()
    assert store.find_active(digest(new_token())) is None
    with migrator.connect() as connection:
        after = connection.execute(
            text("SELECT count(last_used_at), max(last_used_at) FROM api_credentials")
        ).one()
    assert tuple(after) == tuple(before)


def test_a_credential_revoked_between_lookup_and_touch_is_not_marked_used(
    app_engine: Engine, store: PostgresCredentialStore, migrator: Engine, make: Make
) -> None:
    """The lookup succeeded, so authentication stands; the touch's own filter refuses the row."""
    token, credential_id = make()
    fired: list[bool] = []

    def revoke_first(_c: Any, _cur: Any, statement: str, *_: Any) -> None:
        if statement.startswith("UPDATE") and not fired:
            fired.append(True)
            with migrator.begin() as connection:
                connection.execute(
                    text("UPDATE api_credentials SET revoked_at = now() WHERE id = :i"),
                    {"i": credential_id},
                )

    event.listen(app_engine, "before_cursor_execute", revoke_first)
    try:
        assert store.find_active(digest(token)) is not None
    finally:
        event.remove(app_engine, "before_cursor_execute", revoke_first)
    assert fired
    assert last_used(migrator, credential_id) is None


# --- concurrency -----------------------------------------------------------------------------

_BLOCKED = (
    "SELECT count(*) FROM pg_stat_activity "
    "WHERE usename = 'shiptrace_app' AND wait_event_type = 'Lock'"
)


def test_two_simultaneous_first_uses_both_succeed_and_store_the_winners_time(
    migrated_database: Database,
    engine_for: EngineFor,
    migrator: Engine,
    make: Make,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The successful-wait case. Connection one touches and holds its transaction open.
    Connection two's lookup (which cannot see that write) judges the credential stale, and its
    UPDATE blocks on the row lock, seen by an observer without sleeping. One commits well inside
    the 100 ms lock timeout, so two re-checks the filter against the committed row, updates
    nothing, and authenticates normally: no error, no second write, and no timeout (asserted
    through the absence of the timeout's log line). The timeout case is the next test.
    """
    token, credential_id = make()
    first = engine_for(migrated_database.app_url)
    second = PostgresCredentialStore(engine_for(migrated_database.app_url))
    observer = engine_for(migrated_database.admin_url)  # Only a superuser sees others' waits.
    outcome: list[object] = []
    errors: list[BaseException] = []

    def loser() -> None:
        try:
            outcome.append(second.find_active(digest(token)))
        except BaseException as error:  # noqa: BLE001 - asserted below.
            errors.append(error)

    thread = threading.Thread(target=loser)
    waited = False
    with first.connect() as connection:
        transaction = connection.begin()
        connection.execute(
            text("UPDATE api_credentials SET last_used_at = now() WHERE id = :i"),
            {"i": credential_id},
        )
        winner_time = connection.execute(
            text("SELECT last_used_at FROM api_credentials WHERE id = :i"), {"i": credential_id}
        ).scalar_one()
        thread.start()
        try:
            for _ in range(2000):
                with observer.connect() as watcher:
                    waited = bool(watcher.execute(text(_BLOCKED)).scalar_one())
                if waited:
                    break
        finally:
            transaction.commit()  # Always release, so a failure cannot leak into other tests.
            thread.join(timeout=30)
    assert not thread.is_alive()
    assert waited, "the second toucher never waited on the first"
    assert errors == []
    assert outcome[0] is not None
    assert "credential usage not recorded" not in caplog.text, "the wait ended by timeout"
    assert last_used(migrator, credential_id) == winner_time


def test_a_row_lock_held_past_the_timeout_gives_up_and_authentication_still_succeeds(
    migrated_database: Database,
    engine_for: EngineFor,
    migrator: Engine,
    make: Make,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The timeout case. Connection one holds the row lock and does NOT commit until the toucher
    has returned. That the toucher returned at all, with the lock still held, proves the 100 ms
    lock timeout ended the wait (without it the call would block until join's 30 s limit)."""
    token, credential_id = make()
    holder = engine_for(migrated_database.app_url)
    # pool_size=1 makes every later use the same physical connection that ran the touch.
    pooled = create_engine(migrated_database.app_url, pool_size=1, max_overflow=0)
    store = PostgresCredentialStore(pooled)
    observer = engine_for(migrated_database.admin_url)
    outcome: list[object] = []
    errors: list[BaseException] = []
    elapsed: list[float] = []

    def toucher() -> None:
        started = time.monotonic()
        try:
            outcome.append(store.find_active(digest(token)))
        except BaseException as error:  # noqa: BLE001 - asserted below.
            errors.append(error)
        elapsed.append(time.monotonic() - started)

    thread = threading.Thread(target=toucher)
    waited = False
    try:
        with holder.connect() as connection, caplog.at_level(logging.WARNING):
            transaction = connection.begin()
            connection.execute(
                text("UPDATE api_credentials SET last_used_at = now() WHERE id = :i"),
                {"i": credential_id},
            )
            thread.start()
            try:
                for _ in range(2000):
                    with observer.connect() as watcher:
                        waited = bool(watcher.execute(text(_BLOCKED)).scalar_one())
                    if waited:
                        break
                thread.join(timeout=30)  # Returns only because the timeout fired.
                finished_while_locked = not thread.is_alive()
            finally:
                transaction.rollback()  # Releases the lock; the holder's write is discarded.
                thread.join(timeout=30)
        assert waited, "the toucher never waited on the lock"
        assert finished_while_locked, "the lock timeout did not end the wait"
        assert errors == []
        (principal,) = outcome
        assert principal is not None and str(principal.id) == credential_id  # type: ignore[attr-defined]
        assert elapsed[0] >= 0.1  # It did wait the full 100 ms.
        assert last_used(migrator, credential_id) is None  # The use was not recorded.
        assert [r.getMessage() for r in caplog.records] == ["credential usage not recorded"]
        assert all(r.exc_info is None for r in caplog.records)
        for leaked in ("UPDATE", "api_credentials", "lock_timeout", "55P03", credential_id):
            assert leaked not in caplog.text
        # SET LOCAL ended with the rolled-back transaction: the pooled connection is unrestricted.
        with pooled.connect() as connection:
            assert connection.execute(text("SHOW lock_timeout")).scalar_one() == "0"
        # And with the lock gone, the next request records the use.
        assert store.find_active(digest(token)) is not None
        assert last_used(migrator, credential_id) is not None
    finally:
        pooled.dispose()


def test_a_successful_touch_does_not_leave_the_lock_timeout_on_the_connection(
    migrated_database: Database, make: Make
) -> None:
    token, _ = make()
    pooled = create_engine(migrated_database.app_url, pool_size=1, max_overflow=0)
    try:
        assert PostgresCredentialStore(pooled).find_active(digest(token)) is not None
        with pooled.connect() as connection:
            assert connection.execute(text("SHOW lock_timeout")).scalar_one() == "0"
    finally:
        pooled.dispose()


def test_many_parallel_requests_for_one_credential_all_authenticate_and_write_once(
    migrated_database: Database, engine_for: EngineFor, migrator: Engine, make: Make
) -> None:
    token, credential_id = make()
    stores = [PostgresCredentialStore(engine_for(migrated_database.app_url)) for _ in range(8)]
    barrier = threading.Barrier(len(stores), timeout=30)
    results: list[object] = []
    errors: list[BaseException] = []

    def work(target: PostgresCredentialStore) -> None:
        try:
            barrier.wait()
            results.append(target.find_active(digest(token)))
        except BaseException as error:  # noqa: BLE001 - asserted below.
            errors.append(error)

    threads = [threading.Thread(target=work, args=(s,)) for s in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == len(stores) and all(r is not None for r in results)
    age = seconds_ago(migrator, credential_id)
    assert age is not None and 0 <= age < 60


# --- failure ---------------------------------------------------------------------------------


def test_a_failing_usage_write_never_fails_authentication(
    app_engine: Engine, store: PostgresCredentialStore, migrator: Engine, make: Make
) -> None:
    token, credential_id = make()

    def fail_update(_c: Any, _cur: Any, statement: str, *_: Any) -> None:
        if statement.startswith("UPDATE"):
            raise OperationalError("UPDATE secret", {"digest": digest(token)}, Exception("down"))

    event.listen(app_engine, "before_cursor_execute", fail_update)
    try:
        principal = store.find_active(digest(token))
    finally:
        event.remove(app_engine, "before_cursor_execute", fail_update)
    assert principal is not None and str(principal.id) == credential_id
    assert last_used(migrator, credential_id) is None
    # The pool is still healthy and the next request records the use.
    assert store.find_active(digest(token)) is not None
    assert last_used(migrator, credential_id) is not None


# --- HTTP ------------------------------------------------------------------------------------


@pytest.fixture
def client(migrated_database: Database) -> Iterator[TestClient]:
    settings = Settings.model_validate(
        {"environment": "test", "database_url": migrated_database.app_url}
    )
    app = create_app(settings)

    def view() -> dict[str, str]:
        return {"status": "ok"}

    app.add_api_route(
        PROBE, view, methods=["GET"], dependencies=[Depends(require(Action.VIEW_REGISTRY))]
    )
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_http_success_records_usage_once_and_response_is_unchanged(
    client: TestClient, migrator: Engine, make: Make
) -> None:
    token, credential_id = make()
    first = client.get(PROBE, headers=bearer(token))
    stored = last_used(migrator, credential_id)
    second = client.get(PROBE, headers=bearer(token))
    assert (
        (first.status_code, first.json())
        == (second.status_code, second.json())
        == (
            200,
            {"status": "ok"},
        )
    )
    assert stored is not None and last_used(migrator, credential_id) == stored


@pytest.mark.parametrize(
    ("expires", "revoked"),
    [("now() - interval '1 second'", "NULL"), ("NULL", "now()")],
    ids=["expired", "revoked"],
)
def test_http_rejected_credentials_stay_401_and_unused(
    client: TestClient, migrator: Engine, make: Make, expires: str, revoked: str
) -> None:
    token, credential_id = make(expires=expires, revoked=revoked)
    assert client.get(PROBE, headers=bearer(token)).status_code == 401
    assert last_used(migrator, credential_id) is None


def test_http_response_is_unchanged_when_the_usage_write_fails(
    migrated_database: Database, engine_for: EngineFor, migrator: Engine, make: Make
) -> None:
    token, credential_id = make()
    engine = engine_for(migrated_database.app_url)

    def fail_update(_c: Any, _cur: Any, statement: str, *_: Any) -> None:
        if statement.startswith("UPDATE"):
            raise OperationalError("UPDATE", {}, Exception("down"))

    app = create_app(
        Settings.model_validate({"environment": "test", "database_url": migrated_database.app_url})
    )
    app.state.credentials = PostgresCredentialStore(engine)
    app.add_api_route(
        PROBE,
        lambda: {"status": "ok"},
        methods=["GET"],
        dependencies=[Depends(require(Action.VIEW_REGISTRY))],
    )
    event.listen(engine, "before_cursor_execute", fail_update)
    try:
        with TestClient(app, raise_server_exceptions=False) as test_client:
            response = test_client.get(PROBE, headers=bearer(token))
    finally:
        event.remove(engine, "before_cursor_execute", fail_update)
    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    assert last_used(migrator, credential_id) is None
