"""PostgresDeploymentStore against real PostgreSQL 18 (CP16; spec R1-R10, ARCHITECTURE §4).

Committed rows in these tables can never be deleted (the append-only triggers stop the owner too),
so nothing here touches the shared `migrated_database`. A module-scoped disposable container holds
every committed row, and each test uses its own service, environment, credential and keys.

Races are deterministic. A "winner" transaction is held open on its own connection with its rows
uncommitted. The "loser" runs the real store in a thread. The test waits until PostgreSQL itself
reports the loser blocked on a lock (pg_stat_activity), then releases the winner. No sleep stands
in for synchronization, and every wait has a deadline.
"""

import logging
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import cast

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from shiptrace.application.access import InvariantFault, StoreUnavailable
from shiptrace.application.deployments import Accepted, DeploymentTarget, Outcome
from shiptrace.domain.deployments import (
    Duplicate,
    EventType,
    NewEvent,
    Reject,
    RejectReason,
)
from shiptrace.persistence.deployments import PostgresDeploymentStore
from shiptrace.persistence.engine import DatabaseOptions, build_engine
from shiptrace.persistence.migrate import downgrade, upgrade

from .conftest import Database, start_database

DEADLINE = 15.0  # Seconds for any wait on another thread or on PostgreSQL.
VERSION = "1.4.2"
SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
SENTINEL = "SENTINEL-" + uuid.uuid4().hex
INSUFFICIENT_PRIVILEGE = "42501"
CHECK_VIOLATION = "23514"
RESTRICT_VIOLATION = "23001"

S, F, C, R = EventType.STARTED, EventType.FAILED, EventType.CANCELLED, EventType.REVERTED
OK = EventType.SUCCEEDED


# Fixtures and helpers


@pytest.fixture(scope="module")
def disposable() -> Iterator[Database]:
    database = start_database()
    try:
        upgrade(database.migrator_url)
        yield database
    finally:
        database.container.stop()


@pytest.fixture(scope="module")
def admin(disposable: Database) -> Iterator[Engine]:
    engine = create_engine(disposable.admin_url)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def stores(disposable: Database) -> Iterator[Callable[..., PostgresDeploymentStore]]:
    engines: list[Engine] = []

    def build(lock_timeout_ms: int = 8000) -> PostgresDeploymentStore:
        engine = build_engine(
            disposable.app_url,
            DatabaseOptions(
                pool_size=8,
                max_overflow=0,
                pool_timeout_seconds=5,
                statement_timeout_ms=10_000,
                lock_timeout_ms=lock_timeout_ms,
                connect_timeout_seconds=5,
            ),
        )
        engines.append(engine)
        return PostgresDeploymentStore(engine)

    yield build
    for engine in engines:
        engine.dispose()


@pytest.fixture(scope="module")
def app(disposable: Database) -> Iterator[Engine]:
    engine = create_engine(disposable.app_url)
    yield engine
    engine.dispose()


@pytest.fixture
def store(stores: Callable[..., PostgresDeploymentStore]) -> PostgresDeploymentStore:
    return stores()


@dataclass(frozen=True)
class Seed:
    service: uuid.UUID
    environment: uuid.UUID
    credential: uuid.UUID
    key: str

    @property
    def target(self) -> DeploymentTarget:
        return DeploymentTarget(self.service, self.environment, self.key)


@pytest.fixture
def seed(admin: Engine) -> Seed:
    suffix = uuid.uuid4().hex[:10]
    with admin.begin() as connection:
        service = connection.execute(
            text("INSERT INTO services (slug) VALUES (:slug) RETURNING id"), {"slug": "s-" + suffix}
        ).scalar_one()
        environment = connection.execute(
            text("INSERT INTO environments (slug) VALUES (:slug) RETURNING id"),
            {"slug": "e-" + suffix},
        ).scalar_one()
        credential = connection.execute(
            text(
                "INSERT INTO api_credentials "
                "(name, scope, service_id, environment_id, secret_sha256, display_prefix) "
                "VALUES ('ci', 'ingest', :s, :e, :digest, 'st1_AbCd') RETURNING id"
            ),
            {"s": service, "e": environment, "digest": uuid.uuid4().bytes + uuid.uuid4().bytes},
        ).scalar_one()
    return Seed(service, environment, credential, "k-" + suffix)


def event(
    kind: EventType,
    reason: str | None = None,
    url: str | None = None,
    version: str = VERSION,
    sha: str = SHA,
) -> NewEvent:
    return NewEvent(type=kind, version=version, commit_sha=sha, source_url=url, reason=reason)


def record(
    store: PostgresDeploymentStore, seed: Seed, new: NewEvent, credential: uuid.UUID | None = None
) -> Outcome:
    return store.record(seed.target, new, credential or seed.credential)


def stored_types(admin: Engine, seed: Seed) -> list[str]:
    with admin.connect() as connection:
        return list(
            connection.execute(
                text(
                    "SELECT e.type FROM deployment_events e JOIN deployments d "
                    "ON d.id = e.deployment_id WHERE d.deployment_key = :key ORDER BY e.seq"
                ),
                {"key": seed.key},
            ).scalars()
        )


def deployment_count(admin: Engine, seed: Seed) -> int:
    with admin.connect() as connection:
        return int(
            connection.execute(
                text("SELECT count(*) FROM deployments WHERE deployment_key = :key"),
                {"key": seed.key},
            ).scalar_one()
        )


def accepted(outcome: Outcome) -> Accepted:
    assert isinstance(outcome, Accepted), outcome
    return outcome


def rejected(outcome: Outcome, reason: RejectReason) -> None:
    assert outcome == Reject(reason), outcome


def existing_deployment(admin: Engine, seed: Seed) -> uuid.UUID:
    with admin.connect() as connection:
        return cast(
            uuid.UUID,
            connection.execute(
                text("SELECT id FROM deployments WHERE deployment_key = :k"), {"k": seed.key}
            ).scalar_one(),
        )


def insert_deployment(
    connection: Connection, seed: Seed, version: str = VERSION, sha: str = SHA
) -> uuid.UUID:
    return cast(
        uuid.UUID,
        connection.execute(
            text(
                "INSERT INTO deployments "
                "(service_id, environment_id, deployment_key, version, commit_sha) "
                "VALUES (:s, :e, :k, :v, :sha) RETURNING id"
            ),
            {"s": seed.service, "e": seed.environment, "k": seed.key, "v": version, "sha": sha},
        ).scalar_one(),
    )


class Winner:
    """An open transaction, as the app role, whose rows stay uncommitted until released."""

    def __init__(self, app: Engine, seed: Seed) -> None:
        self._seed = seed
        self._closed = False
        self._connection = app.connect()
        self._transaction = self._connection.begin()

    def deployment(self, version: str = VERSION, sha: str = SHA) -> uuid.UUID:
        return insert_deployment(self._connection, self._seed, version, sha)

    def event(self, deployment: uuid.UUID, kind: EventType, reason: str | None = None) -> uuid.UUID:
        return cast(
            uuid.UUID,
            self._connection.execute(
                text(
                    "INSERT INTO deployment_events "
                    "(deployment_id, type, source_url, reason, credential_id) "
                    "VALUES (:d, :t, NULL, :r, :c) RETURNING id"
                ),
                {"d": deployment, "t": kind.value, "r": reason, "c": self._seed.credential},
            ).scalar_one(),
        )

    def commit(self) -> None:
        """Strict: committing a transaction that already ended is a bug in the test."""
        self._transaction.commit()

    def rollback(self) -> None:
        """Idempotent: ends the transaction only if it is still active."""
        if self._transaction.is_active:
            self._transaction.rollback()

    def close(self) -> None:
        """Idempotent: releases any lock still held, then returns the connection exactly once."""
        if self._closed:
            return
        self._closed = True
        try:
            self.rollback()
        finally:
            self._connection.close()


@pytest.fixture
def winner(app: Engine, seed: Seed) -> Iterator[Winner]:
    held = Winner(app, seed)
    try:
        yield held
    finally:
        # After a commit, a rollback or a failure anywhere in the test, the connection is closed
        # once and any lock a failed test left behind is freed.
        held.close()


def wait_until_blocked(admin: Engine) -> None:
    """Returns once PostgreSQL reports an app-role INSERT waiting on a lock."""
    end = time.monotonic() + DEADLINE
    gate = threading.Event()
    while time.monotonic() < end:
        with admin.connect() as connection:
            blocked = connection.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND usename = 'shiptrace_app' AND state = 'active' "
                    "AND wait_event_type = 'Lock' AND query LIKE 'INSERT INTO deployment%'"
                )
            ).scalar_one()
        if blocked:
            return
        gate.wait(0.01)  # A poll interval on an observable condition, bounded by DEADLINE.
    raise AssertionError("the losing transaction never blocked on the winner")


def lose_to(
    admin: Engine,
    store: PostgresDeploymentStore,
    seed: Seed,
    new: NewEvent,
    release: Callable[[], None],
) -> Outcome:
    """Runs the store as the loser, waits until it is blocked, then releases the winner."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(record, store, seed, new)
        wait_until_blocked(admin)
        assert not future.done(), "the loser finished without waiting for the winner"
        release()
        return future.result(timeout=DEADLINE)


# R1-R10 against PostgreSQL, one connection at a time


def test_r1_first_started_creates_the_deployment_and_the_event(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    result = accepted(record(store, seed, event(S, reason="rollout", url="https://ci.example/1")))
    assert result.event_id.version == 7  # Generated by uuidv7() in the database.
    assert result.seq > 0
    assert result.received_at.tzinfo is not None
    assert stored_types(admin, seed) == ["started"]
    assert deployment_count(admin, seed) == 1
    with admin.connect() as connection:
        row = connection.execute(
            text("SELECT credential_id, reason FROM deployment_events WHERE id = :id"),
            {"id": result.event_id},
        ).one()
    assert (row.credential_id, row.reason) == (seed.credential, "rollout")


def test_r2_a_later_type_is_added_to_the_same_deployment(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    first = accepted(record(store, seed, event(S)))
    second = accepted(record(store, seed, event(OK)))
    assert second.seq > first.seq
    assert stored_types(admin, seed) == ["started", "succeeded"]
    assert deployment_count(admin, seed) == 1


def test_r3_a_repeat_is_a_duplicate_that_returns_the_stored_event(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    first = accepted(record(store, seed, event(S, reason="x")))
    again = record(store, seed, event(S, reason="x"))
    assert isinstance(again, Duplicate)
    assert again.original.id == first.event_id
    assert stored_types(admin, seed) == ["started"]


def test_r4_same_type_with_other_content_is_refused_and_writes_nothing(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    accepted(record(store, seed, event(S, reason="one")))
    rejected(record(store, seed, event(S, reason="two")), RejectReason.EVENT_CONFLICT)
    rejected(
        record(store, seed, event(S, reason="one", url="https://ci.example/2")),
        RejectReason.EVENT_CONFLICT,
    )
    assert stored_types(admin, seed) == ["started"]


@pytest.mark.parametrize(
    "changed", [event(S, version="2.0.0"), event(S, sha=OTHER_SHA)], ids=["version", "commit_sha"]
)
def test_r5_changed_deployment_attributes_are_refused(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, changed: NewEvent
) -> None:
    accepted(record(store, seed, event(S)))
    rejected(record(store, seed, changed), RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT)
    assert stored_types(admin, seed) == ["started"]


@pytest.mark.parametrize("second", [F, C])
def test_r6_a_second_terminal_event_is_refused(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, second: EventType
) -> None:
    accepted(record(store, seed, event(OK)))
    rejected(record(store, seed, event(second)), RejectReason.TERMINAL_CONFLICT)
    assert stored_types(admin, seed) == ["succeeded"]


def test_r7_started_may_arrive_after_a_terminal_event(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    accepted(record(store, seed, event(F)))
    accepted(record(store, seed, event(S)))
    assert sorted(stored_types(admin, seed)) == ["failed", "started"]


@pytest.mark.parametrize("kind", [OK, F, C])
def test_r8_a_terminal_event_may_create_the_deployment(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, kind: EventType
) -> None:
    accepted(record(store, seed, event(kind)))
    assert stored_types(admin, seed) == [kind.value]


def test_r9_a_revert_with_no_deployment_creates_nothing(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    rejected(record(store, seed, event(R)), RejectReason.REVERT_REQUIRES_SUCCESS)
    assert deployment_count(admin, seed) == 0
    assert RejectReason.REVERT_REQUIRES_SUCCESS.retryable


def test_r9_a_revert_before_success_is_refused_and_can_be_retried(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    accepted(record(store, seed, event(S)))
    rejected(record(store, seed, event(R)), RejectReason.REVERT_REQUIRES_SUCCESS)
    assert stored_types(admin, seed) == ["started"]
    accepted(record(store, seed, event(OK)))
    accepted(record(store, seed, event(R)))
    assert stored_types(admin, seed) == ["started", "succeeded", "reverted"]


@pytest.mark.parametrize("terminal", [F, C])
def test_r10_a_revert_after_a_non_success_terminal_is_refused(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, terminal: EventType
) -> None:
    accepted(record(store, seed, event(terminal)))
    rejected(record(store, seed, event(R)), RejectReason.REVERT_NOT_APPLICABLE)
    assert stored_types(admin, seed) == [terminal.value]
    assert not RejectReason.REVERT_NOT_APPLICABLE.retryable


def test_a_repeated_revert_is_a_duplicate(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    accepted(record(store, seed, event(OK)))
    first = accepted(record(store, seed, event(R, reason="bad build")))
    again = record(store, seed, event(R, reason="bad build"))
    assert isinstance(again, Duplicate)
    assert again.original.id == first.event_id


def test_the_same_key_in_another_environment_is_another_deployment(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    accepted(record(store, seed, event(S)))
    with admin.begin() as connection:
        other = connection.execute(
            text("INSERT INTO environments (slug) VALUES (:slug) RETURNING id"),
            {"slug": "e2-" + uuid.uuid4().hex[:10]},
        ).scalar_one()
    elsewhere = DeploymentTarget(seed.service, other, seed.key)
    accepted(store.record(elsewhere, event(S, sha=OTHER_SHA), seed.credential))
    assert deployment_count(admin, seed) == 2


# Rollback and sanitized errors


def test_a_new_deployment_is_rolled_back_when_its_first_event_fails(
    store: PostgresDeploymentStore,
    seed: Seed,
    admin: Engine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A control character passes the domain object but not the database CHECK on reason.
    bad = event(S, reason=f"{SENTINEL}\x07")
    with caplog.at_level(logging.DEBUG), pytest.raises(InvariantFault) as caught:
        record(store, seed, bad)
    assert deployment_count(admin, seed) == 0
    assert (caught.value.__cause__, caught.value.__context__) == (None, None)
    assert caught.value.args == ()
    assert SENTINEL not in caplog.text
    assert SENTINEL not in repr(caught.value)
    assert "23514" in caplog.text  # The state and the constraint name are the only detail.
    assert "deployment_events_reason_format" in caplog.text
    accepted(record(store, seed, event(S)))  # The identity is free for a valid first event.


def test_an_unknown_credential_is_a_fault_and_leaves_no_deployment(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG), pytest.raises(InvariantFault):
        record(store, seed, event(S, reason=SENTINEL), credential=uuid.uuid4())
    assert deployment_count(admin, seed) == 0
    assert SENTINEL not in caplog.text
    assert "deployment_events_credential_fkey" in caplog.text


def test_a_refused_event_on_an_existing_deployment_leaves_it_unchanged(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    accepted(record(store, seed, event(S)))
    rejected(record(store, seed, event(S, reason="other")), RejectReason.EVENT_CONFLICT)
    with pytest.raises(InvariantFault):
        record(store, seed, event(OK, reason="bad\x07"))
    assert stored_types(admin, seed) == ["started"]


def test_corrupt_stored_state_is_a_fault_not_a_rejection(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine
) -> None:
    """A deployment with no events cannot be produced by the store. Plant one as the owner."""
    with admin.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO deployments "
                "(service_id, environment_id, deployment_key, version, commit_sha) "
                "VALUES (:s, :e, :k, :v, :sha)"
            ),
            {
                "s": seed.service,
                "e": seed.environment,
                "k": seed.key,
                "v": VERSION,
                "sha": SHA,
            },
        )
    with pytest.raises(InvariantFault):
        record(store, seed, event(S))
    assert stored_types(admin, seed) == []


# Two-connection races. The loser is the real store; the winner is held open and uncommitted.


def test_race_identical_events_the_loser_reads_the_committed_winner(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    deployment = winner.deployment()
    winner_event = winner.event(deployment, S, reason="same")
    outcome = lose_to(admin, store, seed, event(S, reason="same"), winner.commit)
    assert isinstance(outcome, Duplicate)
    assert outcome.original.id == winner_event  # Read from the winner's commit, not its own.
    assert stored_types(admin, seed) == ["started"]
    assert deployment_count(admin, seed) == 1


def test_race_same_type_with_conflicting_content(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    winner.event(winner.deployment(), S, reason="winner")
    outcome = lose_to(admin, store, seed, event(S, reason="loser"), winner.commit)
    rejected(outcome, RejectReason.EVENT_CONFLICT)
    assert stored_types(admin, seed) == ["started"]
    with admin.connect() as connection:
        reasons = connection.execute(
            text(
                "SELECT e.reason FROM deployment_events e JOIN deployments d "
                "ON d.id = e.deployment_id WHERE d.deployment_key = :k"
            ),
            {"k": seed.key},
        ).scalars()
        assert list(reasons) == ["winner"]


def test_race_for_the_identity_with_different_attributes(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    winner.event(winner.deployment(version="1.0.0"), S)
    outcome = lose_to(admin, store, seed, event(S, version="2.0.0"), winner.commit)
    rejected(outcome, RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT)
    assert deployment_count(admin, seed) == 1
    assert stored_types(admin, seed) == ["started"]


def test_race_the_loser_creates_the_deployment_when_the_winner_rolls_back(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    winner.event(winner.deployment(), S)
    outcome = lose_to(admin, store, seed, event(S), winner.rollback)
    accepted(outcome)
    assert stored_types(admin, seed) == ["started"]
    assert deployment_count(admin, seed) == 1


def test_race_on_an_existing_deployment_identical_event(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    accepted(record(store, seed, event(S)))
    existing = existing_deployment(admin, seed)
    winner_event = winner.event(existing, OK, reason="done")
    outcome = lose_to(admin, store, seed, event(OK, reason="done"), winner.commit)
    assert isinstance(outcome, Duplicate)
    assert outcome.original.id == winner_event
    assert stored_types(admin, seed) == ["started", "succeeded"]


def test_race_competing_terminal_events(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    accepted(record(store, seed, event(S)))
    existing = existing_deployment(admin, seed)
    winner.event(existing, F)
    outcome = lose_to(admin, store, seed, event(OK), winner.commit)
    rejected(outcome, RejectReason.TERMINAL_CONFLICT)
    assert stored_types(admin, seed) == ["started", "failed"]


def test_race_a_revert_that_cannot_see_an_uncommitted_success_is_refused_then_accepted(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    accepted(record(store, seed, event(S)))
    existing = existing_deployment(admin, seed)
    winner.event(existing, OK)
    # READ COMMITTED: the success is invisible, so R9 applies and nothing blocks.
    rejected(record(store, seed, event(R)), RejectReason.REVERT_REQUIRES_SUCCESS)
    winner.commit()
    accepted(record(store, seed, event(R)))
    assert stored_types(admin, seed) == ["started", "succeeded", "reverted"]


def test_race_identical_reverts(
    store: PostgresDeploymentStore, seed: Seed, admin: Engine, winner: Winner
) -> None:
    accepted(record(store, seed, event(OK)))
    existing = existing_deployment(admin, seed)
    winner_event = winner.event(existing, R, reason="bad")
    outcome = lose_to(admin, store, seed, event(R, reason="bad"), winner.commit)
    assert isinstance(outcome, Duplicate)
    assert outcome.original.id == winner_event
    assert stored_types(admin, seed) == ["succeeded", "reverted"]


def test_race_eight_identical_submissions_write_exactly_one_event(
    stores: Callable[..., PostgresDeploymentStore], seed: Seed, admin: Engine
) -> None:
    shared = stores()
    barrier = threading.Barrier(8, timeout=DEADLINE)

    def submit() -> Outcome:
        barrier.wait()
        return record(shared, seed, event(S, reason="same"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [f.result(timeout=DEADLINE) for f in [pool.submit(submit) for _ in range(8)]]
    kinds = Counter(type(r) for r in results)
    assert kinds == {Accepted: 1, Duplicate: 7}
    winner_id = next(r for r in results if isinstance(r, Accepted)).event_id
    assert {r.original.id for r in results if isinstance(r, Duplicate)} == {winner_id}
    assert stored_types(admin, seed) == ["started"]
    assert deployment_count(admin, seed) == 1


def test_race_three_terminal_events_leave_exactly_one(
    stores: Callable[..., PostgresDeploymentStore], seed: Seed, admin: Engine
) -> None:
    shared = stores()
    barrier = threading.Barrier(3, timeout=DEADLINE)

    def submit(kind: EventType) -> Outcome:
        barrier.wait()
        return record(shared, seed, event(kind))

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(submit, kind) for kind in (OK, F, C)]
        results = [f.result(timeout=DEADLINE) for f in futures]
    assert Counter(type(r) for r in results) == {Accepted: 1, Reject: 2}
    assert all(
        r == Reject(RejectReason.TERMINAL_CONFLICT) for r in results if isinstance(r, Reject)
    )
    assert len(stored_types(admin, seed)) == 1


# Lock timeout


def test_a_wait_longer_than_lock_timeout_is_retryable_and_leaves_nothing(
    stores: Callable[..., PostgresDeploymentStore], seed: Seed, admin: Engine, winner: Winner
) -> None:
    impatient = stores(lock_timeout_ms=200)
    winner.event(winner.deployment(), S)
    started = time.monotonic()
    with pytest.raises(StoreUnavailable) as caught:
        record(impatient, seed, event(S))
    assert time.monotonic() - started < DEADLINE
    assert (caught.value.__cause__, caught.value.__context__) == (None, None)
    winner.commit()
    assert stored_types(admin, seed) == ["started"]
    assert deployment_count(admin, seed) == 1
    again = record(impatient, seed, event(S))
    assert isinstance(again, Duplicate)  # The pool connection is usable after the timeout.


# Trigger and function privileges for the runtime role (V215 obligation 4)

_NOOP = (
    "CREATE OR REPLACE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql "
    "AS $$ BEGIN RETURN NEW; END $$"
)


@pytest.mark.parametrize(
    "name", ["deployment_records_append_only", "deployment_events_revert_guard"]
)
def test_the_runtime_role_cannot_replace_a_trigger_function(app: Engine, name: str) -> None:
    with app.connect() as connection, pytest.raises(DBAPIError) as caught:
        connection.execute(text(_NOOP.format(name=name)))
    assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE  # type: ignore[union-attr]


def test_the_runtime_role_cannot_disable_triggers_through_the_session(app: Engine) -> None:
    with app.connect() as connection, pytest.raises(DBAPIError) as caught:
        connection.execute(text("SET session_replication_role = replica"))
    assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE  # type: ignore[union-attr]


def test_a_function_shadowed_in_pg_temp_does_not_replace_the_revert_guard(
    app: Engine, seed: Seed
) -> None:
    """The guard pins its search_path and schema-qualifies its table, so a temp object of the
    same name changes nothing. If TEMP is not granted, creating it fails and the guard holds."""
    with app.connect() as connection:
        transaction = connection.begin()
        try:
            savepoint = connection.begin_nested()
            try:
                connection.execute(
                    text(
                        "CREATE FUNCTION pg_temp.deployment_events_revert_guard() "
                        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
                    )
                )
                savepoint.commit()
            except DBAPIError:
                savepoint.rollback()
            deployment = insert_deployment(connection, seed)
            with pytest.raises(DBAPIError) as caught:
                connection.execute(
                    text(
                        "INSERT INTO deployment_events "
                        "(deployment_id, type, credential_id) VALUES (:d, 'reverted', :c)"
                    ),
                    {"d": deployment, "c": seed.credential},
                )
            assert caught.value.orig.sqlstate == CHECK_VIOLATION  # type: ignore[union-attr]
        finally:
            transaction.rollback()


def test_a_trigger_function_cannot_be_called_directly(app: Engine) -> None:
    for name in ("deployment_records_append_only", "deployment_events_revert_guard"):
        with app.connect() as connection, pytest.raises(DBAPIError):
            connection.execute(text(f"SELECT {name}()"))


def test_truncate_cascade_from_the_parent_tables_reaches_the_child_triggers(
    admin: Engine,
) -> None:
    for parent in ("services", "environments", "api_credentials"):
        with admin.connect() as connection:
            transaction = connection.begin()
            try:
                with pytest.raises(DBAPIError) as caught:
                    connection.execute(text(f"TRUNCATE {parent} CASCADE"))
                assert caught.value.orig.sqlstate == RESTRICT_VIOLATION  # type: ignore[union-attr]
            finally:
                transaction.rollback()


# Downgrading with committed rows (F8). Its own container: it destroys the schema.


def test_downgrade_works_with_committed_deployments_and_the_schema_returns() -> None:
    database = start_database()
    try:
        upgrade(database.migrator_url)
        admin_engine = create_engine(database.admin_url)
        app_engine = build_engine(
            database.app_url,
            DatabaseOptions(2, 0, 5, 10_000, 5000, 5),
        )
        try:
            with admin_engine.begin() as connection:
                ids = _seed_ids(connection)
            target = DeploymentTarget(ids[0], ids[1], "k-downgrade")
            PostgresDeploymentStore(app_engine).record(target, event(S), ids[2])
            downgrade(database.migrator_url, "0003")
            with admin_engine.connect() as connection:
                assert connection.execute(
                    text("SELECT to_regclass('public.deployments') IS NULL")
                ).scalar_one()
            upgrade(database.migrator_url)
        finally:
            app_engine.dispose()
            admin_engine.dispose()
    finally:
        database.container.stop()


def _seed_ids(connection: Connection) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    suffix = uuid.uuid4().hex[:10]
    service = connection.execute(
        text("INSERT INTO services (slug) VALUES (:s) RETURNING id"), {"s": "s-" + suffix}
    ).scalar_one()
    environment = connection.execute(
        text("INSERT INTO environments (slug) VALUES (:s) RETURNING id"), {"s": "e-" + suffix}
    ).scalar_one()
    credential = connection.execute(
        text(
            "INSERT INTO api_credentials "
            "(name, scope, service_id, environment_id, secret_sha256, display_prefix) "
            "VALUES ('ci', 'ingest', :s, :e, :d, 'st1_AbCd') RETURNING id"
        ),
        {"s": service, "e": environment, "d": uuid.uuid4().bytes + uuid.uuid4().bytes},
    ).scalar_one()
    return service, environment, credential
