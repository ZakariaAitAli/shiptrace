"""POST /api/v1/deployment-events against real PostgreSQL 18, through the real composition root
(`create_app`), as the runtime role. CP18 (S5).

Committed events can never be deleted, so a module-scoped disposable container holds them and each
test uses its own service, environment and credentials. Race campaigns are CP16's and are not
repeated. A spy around the deployment store counts persistence calls, which is how a request that
must not reach the store is shown not to.
"""

import logging
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import permutations
from typing import Any

import anyio.to_thread
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from shiptrace.application.credentials import create_admin_credential, new_token
from shiptrace.application.deployments import DeploymentStore, DeploymentTarget, Outcome
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import digest, display_prefix
from shiptrace.domain.deployments import TERMINAL, EventType, NewEvent, Status, derive_status
from shiptrace.persistence.credentials import PostgresAdminCredentialWriter

from .conftest import Database, start_database

PATH = "/api/v1/deployment-events"
SHA = "0123456789abcdef0123456789abcdef01234567"
SENTINEL = "sentinel-" + uuid.uuid4().hex
PROBLEM_KEYS = {"type", "title", "status", "detail", "code"}


@pytest.fixture(scope="module")
def disposable() -> Iterator[Database]:
    from shiptrace.persistence.migrate import upgrade

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
def migrator(disposable: Database) -> Iterator[Engine]:
    engine = create_engine(disposable.migrator_url)
    yield engine
    engine.dispose()


@dataclass
class Api:
    app: FastAPI
    client: TestClient


@pytest.fixture(scope="module")
def api(disposable: Database) -> Iterator[Api]:
    settings = Settings.model_validate({"environment": "test", "database_url": disposable.app_url})
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield Api(app, client)


class Spy:
    """Delegates to the real store, counts calls, and can attribute events to another credential."""

    def __init__(self, real: DeploymentStore, credential: uuid.UUID | None = None) -> None:
        self.real = real
        self.credential = credential
        self.calls = 0

    def record(
        self, target: DeploymentTarget, event: NewEvent, credential_id: uuid.UUID
    ) -> Outcome:
        self.calls += 1
        return self.real.record(target, event, self.credential or credential_id)


@pytest.fixture
def spy(api: Api) -> Iterator[Spy]:
    real: DeploymentStore = api.app.state.deployments
    wrapped = Spy(real)
    api.app.state.deployments = wrapped
    yield wrapped
    api.app.state.deployments = real


@dataclass(frozen=True)
class World:
    service: str
    environment: str
    other_service: str
    ingest: str
    read: str
    admin: str
    credential_id: uuid.UUID
    service_id: uuid.UUID
    environment_id: uuid.UUID


def _slug(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def world(admin: Engine, migrator: Engine) -> World:
    service, environment, other = _slug("pay"), _slug("prod"), _slug("bill")
    ingest, read = new_token(), new_token()
    with admin.begin() as connection:
        for table, slug in (
            ("services", service),
            ("services", other),
            ("environments", environment),
        ):
            connection.execute(text(f"INSERT INTO {table} (slug) VALUES (:slug)"), {"slug": slug})
        for token, scope, bound in ((ingest, "ingest", True), (read, "read", False)):
            connection.execute(
                text(
                    "INSERT INTO api_credentials "
                    "(name, scope, service_id, environment_id, secret_sha256, display_prefix) "
                    "VALUES ('ci', :scope, "
                    "(SELECT id FROM services WHERE slug = :service AND :bound), "
                    "(SELECT id FROM environments WHERE slug = :environment AND :bound), "
                    ":digest, :prefix)"
                ),
                {
                    "scope": scope,
                    "service": service,
                    "environment": environment,
                    "bound": bound,
                    "digest": digest(token),
                    "prefix": display_prefix(token),
                },
            )
        ids = connection.execute(
            text(
                "SELECT c.id, c.service_id, c.environment_id FROM api_credentials c "
                "WHERE c.secret_sha256 = :digest"
            ),
            {"digest": digest(ingest)},
        ).one()
    # An admin credential exists only through the bootstrap use case, as the migrator role.
    admin_token = create_admin_credential(
        "api-test admin", PostgresAdminCredentialWriter(migrator, "shiptrace_migrator")
    ).token
    return World(service, environment, other, ingest, read, admin_token, *ids)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def event(world: World, **changes: Any) -> dict[str, Any]:
    return {
        "service": world.service,
        "environment": world.environment,
        "deployment_key": "run-" + uuid.uuid4().hex[:8],
        "type": "started",
        "version": "1.4.2",
        "commit_sha": SHA,
        **changes,
    }


def counts(admin: Engine) -> tuple[int, int]:
    with admin.connect() as connection:
        deployments = connection.execute(text("SELECT count(*) FROM deployments")).scalar_one()
        events = connection.execute(text("SELECT count(*) FROM deployment_events")).scalar_one()
    return int(deployments), int(events)


def assert_problem(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert (body["status"], body["code"]) == (status, code)
    assert set(body) >= PROBLEM_KEYS
    return body


# Accepted events and attribution


def test_a_new_event_is_201_and_stored_for_the_credentials_own_target(
    api: Api, world: World, admin: Engine, spy: Spy
) -> None:
    payload = event(world, reason="canary", source_url="https://ci.example/runs/1")
    response = api.client.post(PATH, json=payload, headers=bearer(world.ingest))
    assert response.status_code == 201
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert set(body) == {"id", "type", "duplicate"}
    assert (body["type"], body["duplicate"]) == ("started", False)
    with admin.connect() as connection:
        row = connection.execute(
            text(
                "SELECT d.service_id, d.environment_id, d.deployment_key, e.credential_id, "
                "e.type, e.reason, e.source_url, e.received_at <= now() AS past "
                "FROM deployment_events e JOIN deployments d ON d.id = e.deployment_id "
                "WHERE e.id = :id"
            ),
            {"id": uuid.UUID(body["id"])},
        ).one()
    assert (row.service_id, row.environment_id) == (world.service_id, world.environment_id)
    assert row.credential_id == world.credential_id
    assert (row.deployment_key, row.type) == (payload["deployment_key"], "started")
    assert (row.reason, row.source_url) == ("canary", "https://ci.example/runs/1")
    assert row.past is True  # The time is the database's; the client cannot send one.
    assert spy.calls == 1


# Idempotency


def test_a_replay_is_200_with_the_original_event_and_writes_nothing(
    api: Api, world: World, admin: Engine
) -> None:
    payload = event(world, type="succeeded", reason="ok")
    first = api.client.post(PATH, json=payload, headers=bearer(world.ingest))
    before = counts(admin)
    again = api.client.post(PATH, json=payload, headers=bearer(world.ingest))
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == {**first.json(), "duplicate": True}
    assert counts(admin) == before


# Conflicts


@pytest.mark.parametrize(
    ("code", "setup", "request_"),
    [
        ("event_conflict", [{"reason": "a"}], {"reason": "b"}),
        ("deployment_attribute_conflict", [{}], {"version": "2.0.0"}),
        ("terminal_conflict", [{"type": "succeeded"}], {"type": "failed"}),
        ("revert_requires_success", [], {"type": "reverted"}),
        ("revert_not_applicable", [{"type": "failed"}], {"type": "reverted"}),
    ],
)
def test_each_domain_conflict_is_a_409_problem_and_writes_nothing(
    api: Api,
    world: World,
    admin: Engine,
    code: str,
    setup: list[dict[str, Any]],
    request_: dict[str, Any],
) -> None:
    key = "run-" + uuid.uuid4().hex[:8]
    for step in setup:
        created = api.client.post(
            PATH, json=event(world, deployment_key=key, **step), headers=bearer(world.ingest)
        )
        assert created.status_code == 201
    before = counts(admin)
    response = api.client.post(
        PATH, json=event(world, deployment_key=key, **request_), headers=bearer(world.ingest)
    )
    assert_problem(response, 409, code)
    assert "retry-after" not in response.headers
    assert counts(admin) == before  # Including no deployment for a revert that came first.


def test_a_revert_refused_for_lack_of_success_succeeds_when_retried(api: Api, world: World) -> None:
    key = "run-" + uuid.uuid4().hex[:8]
    revert = event(world, deployment_key=key, type="reverted")
    assert api.client.post(PATH, json=revert, headers=bearer(world.ingest)).status_code == 409
    succeeded = event(world, deployment_key=key, type="succeeded")
    assert api.client.post(PATH, json=succeeded, headers=bearer(world.ingest)).status_code == 201
    assert api.client.post(PATH, json=revert, headers=bearer(world.ingest)).status_code == 201


# Authentication, scope and R11 reach no persistence


def test_unauthenticated_and_wrong_scope_calls_never_reach_the_store(
    api: Api, world: World, admin: Engine, spy: Spy
) -> None:
    before = counts(admin)
    unknown = api.client.post(PATH, json=event(world), headers=bearer(new_token()))
    missing = api.client.post(PATH, json=event(world))
    hostile = api.client.post(
        PATH,
        content=b"{not json",
        headers={**bearer(new_token()), "Content-Type": "application/json"},
    )
    for response in (unknown, missing, hostile):
        assert_problem(response, 401, "unauthenticated")
    for token in (world.read, world.admin):
        assert_problem(
            api.client.post(PATH, json=event(world), headers=bearer(token)), 403, "forbidden"
        )
    assert spy.calls == 0
    assert counts(admin) == before


@pytest.mark.parametrize(
    ("expired", "revoked"),
    [(True, False), (False, True), (True, True)],
    ids=["expired", "revoked", "expired-and-revoked"],
)
def test_an_expired_or_revoked_ingest_credential_is_401_and_never_reaches_the_store(
    api: Api, world: World, admin: Engine, migrator: Engine, spy: Spy, expired: bool, revoked: bool
) -> None:
    """AC6 for this route: a credential bound to a real target and otherwise valid, but dead."""
    dead = new_token()
    with migrator.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO api_credentials (name, scope, service_id, environment_id, "
                "secret_sha256, display_prefix, expires_at, revoked_at) VALUES "
                "('dead', 'ingest', :service, :environment, :digest, :prefix, "
                "CASE WHEN :expired THEN now() - interval '1 second' END, "
                "CASE WHEN :revoked THEN now() END)"
            ),
            {
                "service": world.service_id,
                "environment": world.environment_id,
                "digest": digest(dead),
                "prefix": display_prefix(dead),
                "expired": expired,
                "revoked": revoked,
            },
        )
    before = counts(admin)
    refused = api.client.post(PATH, json=event(world), headers=bearer(dead))
    assert_problem(refused, 401, "unauthenticated")
    assert refused.headers["www-authenticate"] == "Bearer"
    assert spy.calls == 0
    assert counts(admin) == before
    # The same body, with a live credential for the same target, is accepted: the 401 was the
    # credential's, not the payload's, and this one call is the only one the store ever saw.
    assert api.client.post(PATH, json=event(world), headers=bearer(world.ingest)).status_code == 201
    assert spy.calls == 1


def test_a_credential_revoked_after_use_is_refused_on_the_next_request(
    api: Api, world: World, admin: Engine, migrator: Engine, spy: Spy
) -> None:
    """AC11 on this route: revocation takes effect on the next request, with no cache."""
    assert api.client.post(PATH, json=event(world), headers=bearer(world.ingest)).status_code == 201
    assert spy.calls == 1
    with migrator.begin() as connection:
        connection.execute(
            text("UPDATE api_credentials SET revoked_at = now() WHERE secret_sha256 = :digest"),
            {"digest": digest(world.ingest)},
        )
    before = counts(admin)
    response = api.client.post(PATH, json=event(world), headers=bearer(world.ingest))
    assert_problem(response, 401, "unauthenticated")
    assert spy.calls == 1  # Unchanged: the revoked credential reached no persistence.
    assert counts(admin) == before


def test_a_foreign_target_is_the_same_403_whether_or_not_it_exists(
    api: Api, world: World, admin: Engine, spy: Spy
) -> None:
    before = counts(admin)
    registered = api.client.post(
        PATH, json=event(world, service=world.other_service), headers=bearer(world.ingest)
    )
    unregistered = api.client.post(
        PATH, json=event(world, service=_slug("ghost")), headers=bearer(world.ingest)
    )
    wrong_scope = api.client.post(PATH, json=event(world), headers=bearer(world.read))
    assert registered.status_code == unregistered.status_code == wrong_scope.status_code == 403
    assert registered.json() == unregistered.json() == wrong_scope.json()
    assert spy.calls == 0
    assert counts(admin) == before


def test_an_invalid_body_is_422_without_values_and_never_reaches_the_store(
    api: Api, world: World, admin: Engine, spy: Spy
) -> None:
    before = counts(admin)
    response = api.client.post(
        PATH,
        json=event(world, version=SENTINEL + "!", reason=SENTINEL, stowaway=SENTINEL),
        headers=bearer(world.ingest),
    )
    body = assert_problem(response, 422, "validation_failed")
    assert body["errors"] == [
        {"location": "body", "rule": "unknown_field"},
        {"location": "body.version", "rule": "format"},
    ]
    assert SENTINEL not in response.text
    assert spy.calls == 0
    assert counts(admin) == before


# A real database failure leaks nothing


def test_a_database_fault_is_a_sanitized_500_with_no_sql_or_input_in_it(
    api: Api, world: World, admin: Engine, spy: Spy, caplog: pytest.LogCaptureFixture
) -> None:
    """Attribute the event to a credential that does not exist, so PostgreSQL raises a foreign-key
    violation whose DETAIL names the offending key. Neither that nor the statement may leave."""
    spy.credential = uuid.uuid4()
    before = counts(admin)
    payload = event(world, reason=SENTINEL, source_url=f"https://ci.example/{SENTINEL}")
    with caplog.at_level(logging.DEBUG):
        response = api.client.post(PATH, json=payload, headers=bearer(world.ingest))
    assert_problem(response, 500, "internal_error")
    assert "retry-after" not in response.headers
    for fragment in (
        SENTINEL,
        str(spy.credential),
        "INSERT",
        "violates",
        "Key (",
        "deployment_events",
    ):
        assert fragment not in response.text, fragment
    assert SENTINEL not in caplog.text
    assert str(spy.credential) not in caplog.text
    assert "INSERT INTO" not in caplog.text
    assert counts(admin) == before  # The new deployment was rolled back with the failed event.


# P1 S6, AC2: 50 concurrent identical submissions through HTTP and PostgreSQL

CONCURRENCY = 50
DEADLINE = 60.0  # Seconds for any wait on another thread or on PostgreSQL.


async def _raise_thread_limit() -> None:
    """Starlette runs a sync route in a 40-thread pool, so 50 requests could not overlap. Production
    keeps that limit and sheds load with a 503 by design (ARCHITECTURE §5); AC2 measures
    idempotency, so this test lifts the limit, as the spec has it lift the rate limits."""
    anyio.to_thread.current_default_thread_limiter().total_tokens = 4 * CONCURRENCY


@pytest.fixture(scope="module")
def wide_api(disposable: Database) -> Iterator[Api]:
    """The real composition root, with a pool and timeouts that cannot shed or expire 50 callers."""
    settings = Settings.model_validate(
        {
            "environment": "test",
            "database_url": disposable.app_url,
            "db_pool_size": CONCURRENCY,
            "db_max_overflow": 10,
            "db_pool_timeout_seconds": 30,
            "db_statement_timeout_ms": 50_000,
            "db_lock_timeout_ms": 40_000,
        }
    )
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.portal is not None
        client.portal.call(_raise_thread_limit)
        yield Api(app, client)


@pytest.fixture(scope="module")
def runtime(disposable: Database) -> Iterator[Engine]:
    engine = create_engine(disposable.app_url)
    yield engine
    engine.dispose()


def wait_until_blocked(admin: Engine, expected: int) -> int:
    """Returns once PostgreSQL itself reports exactly `expected` runtime-role deployment inserts
    waiting on a lock. A poll of an observable condition, bounded by DEADLINE; never a sleep that
    stands in for synchronization."""
    end = time.monotonic() + DEADLINE
    gate = threading.Event()
    blocked = 0
    while time.monotonic() < end:
        with admin.connect() as connection:
            blocked = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        "AND usename = 'shiptrace_app' AND state = 'active' "
                        "AND wait_event_type = 'Lock' AND query LIKE 'INSERT INTO deployments%'"
                    )
                ).scalar_one()
            )
        if blocked == expected:
            return blocked
        gate.wait(0.01)
    raise AssertionError(f"{blocked} of {expected} requests were blocked inside PostgreSQL")


def stored_event_ids(admin: Engine, world: World, key: str) -> list[uuid.UUID]:
    with admin.connect() as connection:
        return list(
            connection.execute(
                text(
                    "SELECT e.id FROM deployment_events e JOIN deployments d "
                    "ON d.id = e.deployment_id WHERE d.service_id = :s AND d.environment_id = :e "
                    "AND d.deployment_key = :k ORDER BY e.seq"
                ),
                {"s": world.service_id, "e": world.environment_id, "k": key},
            ).scalars()
        )


def test_ac2_fifty_concurrent_identical_submissions_write_exactly_one_event(
    wide_api: Api, world: World, admin: Engine, runtime: Engine
) -> None:
    """The overlap is forced and observed, not hoped for. A separate transaction holds an
    uncommitted deployment on the very identity the requests use, so every request blocks inside
    PostgreSQL on its first write. The test waits until PostgreSQL reports all 50 blocked, then
    rolls the holder back: the 50 then race for the freed identity, one wins, and the other 49 wait
    on the winner's commit and read it."""
    key = "ac2-" + uuid.uuid4().hex[:8]
    payload = event(world, deployment_key=key, type="succeeded", reason="ok")
    headers = bearer(world.ingest)
    with runtime.connect() as holder, ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        transaction = holder.begin()
        try:
            holder.execute(
                text(
                    "INSERT INTO deployments "
                    "(service_id, environment_id, deployment_key, version, commit_sha) "
                    "VALUES (:s, :e, :k, :v, :sha)"
                ),
                {
                    "s": world.service_id,
                    "e": world.environment_id,
                    "k": key,
                    "v": payload["version"],
                    "sha": SHA,
                },
            )
            futures = [
                pool.submit(wide_api.client.post, PATH, json=payload, headers=headers)
                for _ in range(CONCURRENCY)
            ]
            assert wait_until_blocked(admin, CONCURRENCY) == CONCURRENCY
            assert not any(future.done() for future in futures), "a request finished unblocked"
        finally:
            transaction.rollback()  # Frees the identity; also the cleanup if the wait failed.
        responses = [future.result(timeout=DEADLINE) for future in futures]

    assert Counter(r.status_code for r in responses) == {201: 1, 200: CONCURRENCY - 1}
    assert {r.headers["content-type"] for r in responses} == {"application/json"}
    committed = stored_event_ids(admin, world, key)
    assert len(committed) == 1  # Exactly one event is committed.
    assert {r.json()["id"] for r in responses} == {str(committed[0])}  # All name the original.
    created = [r for r in responses if r.status_code == 201]
    assert created[0].json() == {"id": str(committed[0]), "type": "succeeded", "duplicate": False}
    assert all(r.json()["duplicate"] is True for r in responses if r.status_code == 200)
    with admin.connect() as connection:
        deployments = connection.execute(
            text("SELECT count(*) FROM deployments WHERE deployment_key = :k"), {"k": key}
        ).scalar_one()
    assert deployments == 1


# P1 S6, AC4: permutations of an event set through HTTP and PostgreSQL

ST, S, F, C, R = (
    EventType.STARTED,
    EventType.SUCCEEDED,
    EventType.FAILED,
    EventType.CANCELLED,
    EventType.REVERTED,
)
# The valid event sets of spec §3, as in tests/unit/test_deployment_histories.py.
VALID_SETS: list[tuple[EventType, ...]] = [
    (ST,),
    (S,),
    (F,),
    (C,),
    (ST, S),
    (ST, F),
    (ST, C),
    (S, R),
    (ST, S, R),
]
RETRYABLE = (409, "revert_requires_success")
Outcomes = dict[EventType, list[tuple[int, str | None]]]


def send(api: Api, world: World, key: str, kind: EventType) -> tuple[int, str | None]:
    response = api.client.post(
        PATH,
        json=event(world, deployment_key=key, type=kind.value),
        headers=bearer(world.ingest),
    )
    return response.status_code, response.json()["code"] if response.status_code >= 400 else None


def deployment_counts(admin: Engine, world: World, key: str) -> tuple[int, int]:
    """(deployments, events) committed for one deployment key."""
    with admin.connect() as connection:
        row = connection.execute(
            text(
                "SELECT count(DISTINCT d.id), count(e.id) FROM deployments d "
                "LEFT JOIN deployment_events e ON e.deployment_id = d.id "
                "WHERE d.service_id = :s AND d.environment_id = :e AND d.deployment_key = :k"
            ),
            {"s": world.service_id, "e": world.environment_id, "k": key},
        ).one()
    return int(row[0]), int(row[1])


def send_and_check(
    api: Api, world: World, admin: Engine, key: str, kind: EventType, events_before: int
) -> tuple[tuple[int, str | None], int]:
    """Sends one request, then checks what that single transaction left behind.

    A deployment exists exactly when it has events, so a refused first event (an R9 revert, or
    any rejection) leaves no deployment row; a 201 added exactly one event; anything else added
    none; and no deployment anywhere in this test's world is left without events. Checked after
    every request, so a transient orphan that a later event would fill is still caught."""
    outcome = send(api, world, key, kind)
    deployments, events = deployment_counts(admin, world, key)
    assert deployments <= 1, (kind, outcome)
    assert (deployments == 1) == (events > 0), ("deployment and events disagree", kind, outcome)
    assert events - events_before == (1 if outcome[0] == 201 else 0), (kind, outcome)
    assert deployments_without_events(admin, world) == 0, (kind, outcome)
    return outcome, events


def deliver(
    api: Api, world: World, admin: Engine, order: Sequence[EventType]
) -> tuple[str, Outcomes, list[Any]]:
    """Sends each event once, in order, then retries R9 rejections until nothing changes."""
    key = "ac4-" + uuid.uuid4().hex[:10]
    log: Outcomes = {}
    pending: list[EventType] = []
    events = 0
    for kind in order:
        outcome, events = send_and_check(api, world, admin, key, kind, events)
        log.setdefault(kind, []).append(outcome)
        if outcome == RETRYABLE:
            pending.append(kind)
    progress = True
    while pending and progress:
        progress = False
        for kind in list(pending):
            outcome, events = send_and_check(api, world, admin, key, kind, events)
            log[kind].append(outcome)
            if outcome != RETRYABLE:
                pending.remove(kind)
                progress = True
    return key, log, pending


def stored_types(admin: Engine, world: World, key: str) -> list[EventType]:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT e.type FROM deployment_events e JOIN deployments d "
                "ON d.id = e.deployment_id WHERE d.service_id = :s AND d.environment_id = :e "
                "AND d.deployment_key = :k ORDER BY e.seq"
            ),
            {"s": world.service_id, "e": world.environment_id, "k": key},
        ).scalars()
        return [EventType(value) for value in rows]


def deployments_without_events(admin: Engine, world: World) -> int:
    with admin.connect() as connection:
        return int(
            connection.execute(
                text(
                    "SELECT count(*) FROM deployments d WHERE d.service_id = :s "
                    "AND d.environment_id = :e AND NOT EXISTS "
                    "(SELECT 1 FROM deployment_events x WHERE x.deployment_id = d.id)"
                ),
                {"s": world.service_id, "e": world.environment_id},
            ).scalar_one()
        )


def first_terminal(order: Sequence[EventType]) -> EventType:
    return next(kind for kind in order if kind in TERMINAL)


@pytest.mark.parametrize("valid_set", VALID_SETS, ids=lambda s: "+".join(k.value for k in s))
def test_ac4_every_order_of_a_valid_set_converges_with_every_event_stored_once(
    api: Api, world: World, admin: Engine, valid_set: tuple[EventType, ...]
) -> None:
    expected = derive_status(valid_set)
    for order in permutations(valid_set):
        key, log, pending = deliver(api, world, admin, order)
        stored = stored_types(admin, world, key)
        assert pending == [], order
        assert sorted(stored) == sorted(valid_set), order
        assert derive_status(stored) is expected, order
        for kind in valid_set:
            # One 201 per type, and anything before it only the retryable R9 refusal.
            assert [o for o in log[kind] if o[0] == 201] == [(201, None)], (order, kind)
            assert [o for o in log[kind] if o[0] != 201] == [RETRYABLE] * (len(log[kind]) - 1)
    assert deployments_without_events(admin, world) == 0


# Two 24-order sets, not the 120 orders of the in-memory test. `started` cannot change a terminal or
# a revert outcome (R7; decide never consults it for them), and the in-memory test already covers
# every order with it, so the first set checks it beside the terminals and the second checks R.
COMPETING_SETS = [(ST, S, F, C), (S, F, C, R)]


@pytest.mark.parametrize("events", COMPETING_SETS, ids=lambda s: "+".join(k.value for k in s))
def test_ac4_competing_terminals_follow_first_committed_and_do_not_converge(
    api: Api, world: World, admin: Engine, events: tuple[EventType, ...]
) -> None:
    """Competing terminals legitimately differ by arrival order (R6), and a revert follows the
    first terminal: accepted after `succeeded` (R9 retried), refused for good after `failed` or
    `cancelled` (R10). The oracle names the winner from the order, as the in-memory test does."""
    finals: set[Status] = set()
    for order in permutations(events):
        winner = first_terminal(order)
        key, log, pending = deliver(api, world, admin, order)
        stored = stored_types(admin, world, key)
        assert pending == [], order
        assert [t for t in stored if t in TERMINAL] == [winner], order
        for loser in TERMINAL - {winner}:
            assert log[loser] == [(409, "terminal_conflict")], (order, loser)
        if ST in order:
            assert log[ST] == [(201, None)], order
        if R in order:
            if winner is S:
                assert derive_status(stored) is Status.REVERTED, order
                assert log[R][-1] == (201, None), order
            else:
                assert R not in stored, order
                assert derive_status(stored) is Status(winner.value), order
                assert log[R][-1] == (409, "revert_not_applicable"), order
        else:
            assert derive_status(stored) is Status(winner.value), order
        finals.add(derive_status(stored))
    # Arrival order alone yields all three outcomes; with a revert, a success ends as `reverted`.
    won = Status.REVERTED if R in events else Status.SUCCEEDED
    assert finals == {won, Status.FAILED, Status.CANCELLED}
    assert deployments_without_events(admin, world) == 0
