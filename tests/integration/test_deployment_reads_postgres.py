"""Deployment history and detail against real PostgreSQL 18 (P2 S1 CP19), as the runtime role.

Histories are built through the real store, so every set of events here is one the application can
produce. Committed rows can never be deleted (the append-only triggers stop the owner too), so a
module-scoped disposable container holds them and every test uses its own services and
environments. Tests filter by their own service or environment and never list the whole table.

The status filter is a SQL predicate and `derive_status` is the domain rule. Event sets that break
the rules cannot be stored at all (the unique terminal index and the revert guard refuse them, for
every role: tests/integration/test_deployment_schema.py), so the sets below are every set the
database can hold, and checking the predicate against `derive_status` on them is exhaustive.
"""

import logging
import math
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from shiptrace.application.access import InvariantFault, Principal, StoreUnavailable
from shiptrace.application.deployment_reads import (
    DeploymentFilter,
    DeploymentNotFound,
    DeploymentSummary,
    get_deployment,
    list_deployments,
)
from shiptrace.application.deployments import DeploymentTarget, Outcome
from shiptrace.domain.credentials import Scope
from shiptrace.domain.deployments import (
    EventType,
    NewEvent,
    Reject,
    RejectReason,
    Status,
    derive_status,
)
from shiptrace.persistence.deployment_reads import PostgresDeploymentReads
from shiptrace.persistence.deployments import PostgresDeploymentStore
from shiptrace.persistence.engine import DatabaseOptions, build_engine
from shiptrace.persistence.migrate import upgrade

from .conftest import Database, start_database

VERSION = "1.4.2"
SHA = "0123456789abcdef0123456789abcdef01234567"
ST, S, F, C, R = (
    EventType.STARTED,
    EventType.SUCCEEDED,
    EventType.FAILED,
    EventType.CANCELLED,
    EventType.REVERTED,
)
# The valid event sets of spec §3: what a deployment can hold.
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
READER = Principal(id=uuid.uuid4(), scope=Scope.READ, service_id=None, environment_id=None)
OPTIONS = DatabaseOptions(
    pool_size=3,
    max_overflow=0,
    pool_timeout_seconds=5,
    statement_timeout_ms=10_000,
    lock_timeout_ms=5000,
    connect_timeout_seconds=5,
)


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
def creator(disposable: Database) -> Iterator[PostgresDeploymentStore]:
    """One connection only, so every deployment is created by the same PostgreSQL session. uuidv7()
    is monotonic within a session, which makes the creation order deterministic here."""
    engine = build_engine(disposable.app_url, DatabaseOptions(1, 0, 5, 10_000, 5000, 5))
    yield PostgresDeploymentStore(engine)
    engine.dispose()


@pytest.fixture(scope="module")
def reads(disposable: Database) -> Iterator[PostgresDeploymentReads]:
    engine = build_engine(disposable.app_url, OPTIONS)
    yield PostgresDeploymentReads(engine)
    engine.dispose()


def slug(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def new_service(admin: Engine, name: str | None = None) -> tuple[uuid.UUID, str]:
    value = name or slug("svc")
    with admin.begin() as connection:
        found = connection.execute(
            text("INSERT INTO services (slug) VALUES (:slug) RETURNING id"), {"slug": value}
        ).scalar_one()
    return found, value


def new_environment(admin: Engine) -> tuple[uuid.UUID, str]:
    value = slug("env")
    with admin.begin() as connection:
        found = connection.execute(
            text("INSERT INTO environments (slug) VALUES (:slug) RETURNING id"), {"slug": value}
        ).scalar_one()
    return found, value


def new_credential(admin: Engine, service_id: uuid.UUID, environment_id: uuid.UUID) -> uuid.UUID:
    with admin.begin() as connection:
        return connection.execute(  # type: ignore[no-any-return]
            text(
                "INSERT INTO api_credentials (name, scope, service_id, environment_id, "
                "secret_sha256, display_prefix) VALUES ('ci', 'ingest', :s, :e, :d, 'st1_AbCd') "
                "RETURNING id"
            ),
            {"s": service_id, "e": environment_id, "d": uuid.uuid4().bytes + uuid.uuid4().bytes},
        ).scalar_one()


@dataclass(frozen=True)
class Pair:
    """One service and one environment, and a credential to attribute events to."""

    service_id: uuid.UUID
    service: str
    environment_id: uuid.UUID
    environment: str
    credential_id: uuid.UUID

    def target(self, key: str) -> DeploymentTarget:
        return DeploymentTarget(self.service_id, self.environment_id, key)

    @property
    def filters(self) -> DeploymentFilter:
        return DeploymentFilter(service=self.service, environment=self.environment)


def new_pair(admin: Engine) -> Pair:
    service_id, service = new_service(admin)
    environment_id, environment = new_environment(admin)
    credential = new_credential(admin, service_id, environment_id)
    return Pair(service_id, service, environment_id, environment, credential)


def send(
    store: PostgresDeploymentStore,
    pair: Pair,
    key: str,
    kind: EventType,
    reason: str | None = None,
    url: str | None = None,
    target: DeploymentTarget | None = None,
) -> Outcome:
    event = NewEvent(type=kind, version=VERSION, commit_sha=SHA, source_url=url, reason=reason)
    return store.record(target or pair.target(key), event, pair.credential_id)


def build(
    store: PostgresDeploymentStore, pair: Pair, key: str, order: tuple[EventType, ...]
) -> None:
    """Sends each event once in this order, then retries a revert refused for lack of a success."""
    retry = []
    for kind in order:
        if send(store, pair, key, kind) == Reject(RejectReason.REVERT_REQUIRES_SUCCESS):
            retry.append(kind)
    for kind in retry:
        assert not isinstance(send(store, pair, key, kind), Reject), (order, kind)


def deployment_id(admin: Engine, target: DeploymentTarget) -> uuid.UUID:
    with admin.connect() as connection:
        return connection.execute(  # type: ignore[no-any-return]
            text(
                "SELECT id FROM deployments WHERE service_id = :s AND environment_id = :e "
                "AND deployment_key = :k"
            ),
            {"s": target.service_id, "e": target.environment_id, "k": target.deployment_key},
        ).scalar_one()


def walk(
    reads: PostgresDeploymentReads, filters: DeploymentFilter, limit: int
) -> list[list[DeploymentSummary]]:
    pages: list[list[DeploymentSummary]] = []
    after = None
    while True:
        page = list_deployments(READER, filters, after, limit, reads)
        pages.append(page.items)
        if page.next_after is None:
            return pages
        after = page.next_after
        assert len(pages) < 500, "the walk never ended"


def everything(
    reads: PostgresDeploymentReads, filters: DeploymentFilter
) -> list[DeploymentSummary]:
    return [item for page in walk(reads, filters, 100) for item in page]


# Ids are time-ordered, so "newest first" is not random UUID order


def test_ids_are_uuidv7_so_newest_first_is_creation_order(
    admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    pair = new_pair(admin)
    with admin.connect() as connection:
        before = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
    targets = [pair.target(f"k-{n:02d}") for n in range(12)]
    for target in targets:
        send(creator, pair, target.deployment_key, ST)
    with admin.connect() as connection:
        after = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
    ids = [deployment_id(admin, target) for target in targets]

    assert len(set(ids)) == 12
    assert ids == sorted(ids), "ids do not sort in the order the deployments were created"
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id, uuid_extract_version(id) AS version, uuid_extract_timestamp(id) AS ts "
                "FROM deployments WHERE id = ANY(:ids)"
            ),
            {"ids": ids},
        ).all()
    by_id = {row.id: row for row in rows}
    assert {row.version for row in rows} == {7}
    stamps = [by_id[i].ts for i in ids]
    assert stamps == sorted(stamps)  # The id encodes when the row was created.
    slack = timedelta(milliseconds=5)  # The embedded time is truncated to the millisecond.
    assert all(before - slack <= ts <= after + slack for ts in stamps)

    listed = [item.id for item in everything(reads, pair.filters)]
    assert listed == list(reversed(ids))


# Paging


@pytest.mark.parametrize("limit", [1, 2, 3, 5, 6, 11, 12, 13, 100])
def test_a_walk_returns_every_deployment_once_newest_first(
    limit: int, admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    pair = new_pair(admin)
    targets = [pair.target(f"k-{n:02d}") for n in range(12)]
    for target in targets:
        send(creator, pair, target.deployment_key, ST)
    expected = list(reversed([deployment_id(admin, target) for target in targets]))

    pages = walk(reads, pair.filters, limit)
    assert [item.id for page in pages for item in page] == expected
    assert len(pages) == math.ceil(12 / limit)  # An exact multiple adds no empty page.
    assert all(len(page) == limit for page in pages[:-1])


# Filters


def test_filters_match_exact_slugs_and_scope_the_deployment_key(
    admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    service_a_id, service_a = new_service(admin)
    service_b_id, service_b = new_service(admin, service_a + "-b")  # service_a is its prefix.
    env_x_id, env_x = new_environment(admin)
    env_y_id, env_y = new_environment(admin)
    credential = new_credential(admin, service_a_id, env_x_id)

    def pair(service: tuple[uuid.UUID, str], env: tuple[uuid.UUID, str]) -> Pair:
        return Pair(service[0], service[1], env[0], env[1], credential)

    ax = pair((service_a_id, service_a), (env_x_id, env_x))
    ay = pair((service_a_id, service_a), (env_y_id, env_y))
    bx = pair((service_b_id, service_b), (env_x_id, env_x))
    created: dict[str, list[uuid.UUID]] = {"ax": [], "ay": [], "bx": []}
    for name, group, count in (("ax", ax, 3), ("ay", ay, 2), ("bx", bx, 2)):
        for n in range(count):
            # The same key in two pairs is two deployments: the key is scoped to its pair.
            send(creator, group, f"k-{n}", ST)
            created[name].append(deployment_id(admin, group.target(f"k-{n}")))

    def ids(**filters: Any) -> set[uuid.UUID]:
        return {item.id for item in everything(reads, DeploymentFilter(**filters))}

    assert ids(service=service_a) == set(created["ax"] + created["ay"])  # B is not a match.
    assert ids(service=service_b) == set(created["bx"])
    assert ids(environment=env_x) == set(created["ax"] + created["bx"])
    assert ids(service=service_a, environment=env_x) == set(created["ax"])
    assert ids(service=service_b, environment=env_y) == set()  # A real pair with no deployments.
    assert ids(service="no-such-service-registered") == set()
    assert ids(environment="no-such-environment-registered") == set()

    first = everything(reads, DeploymentFilter(service=service_b))[0]
    assert (first.service, first.service_id) == (service_b, service_b_id)
    assert (first.environment, first.environment_id) == (env_x, env_x_id)
    assert (first.version, first.commit_sha, first.status) == (VERSION, SHA, Status.IN_PROGRESS)
    assert first.created_at.tzinfo is not None


# The SQL status filter against domain derive_status


def test_the_status_filter_agrees_with_derive_status_for_every_storable_event_set(
    admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    pair = new_pair(admin)
    expected: dict[uuid.UUID, Status] = {}
    for valid_set in VALID_SETS:
        # As listed, and reversed: the reverse sends a revert first, so R9 and its retry are used.
        orders = list(dict.fromkeys([valid_set, valid_set[::-1]]))
        for number, order in enumerate(orders):
            key = f"{'-'.join(k.value for k in valid_set)}-{number}"
            build(creator, pair, key, order)
            expected[deployment_id(admin, pair.target(key))] = derive_status(valid_set)

    shown = {item.id: item.status for item in everything(reads, pair.filters)}
    assert shown == expected  # The status shown is the domain's, for every set and order.

    seen: set[uuid.UUID] = set()
    for status in Status:
        want = {i for i, value in expected.items() if value is status}
        assert want, f"no test deployment has status {status}, so its filter proves nothing"
        got = {
            item.id
            for item in everything(reads, DeploymentFilter(pair.service, pair.environment, status))
        }
        assert got == want, status
        assert not (got & seen), status  # Every deployment has exactly one status.
        seen |= got
    assert seen == set(expected)


def test_a_status_filter_pages_newest_first(
    admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    pair = new_pair(admin)
    kinds = [S, F, S, ST, S, C, S]  # Four succeeded deployments among the others.
    ids = []
    for number, kind in enumerate(kinds):
        send(creator, pair, f"k-{number}", kind)
        ids.append((deployment_id(admin, pair.target(f"k-{number}")), kind))
    want = [i for i, kind in reversed(ids) if kind is S]
    filters = DeploymentFilter(pair.service, pair.environment, Status.SUCCEEDED)
    pages = walk(reads, filters, 3)
    assert [len(page) for page in pages] == [3, 1]
    assert [item.id for page in pages for item in page] == want


# Detail


def test_detail_has_every_event_in_seq_order_with_its_stored_values(
    admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    pair = new_pair(admin)
    reason = "line one\nline two\ttab é <script>alert(1)</script>"  # Stored and returned as sent.
    url = "https://ci.example/runs/1?a=%41#frag"
    send(creator, pair, "k", ST)
    send(creator, pair, "k", S, reason=reason, url=url)
    send(creator, pair, "k", R, reason="bad build")
    found = deployment_id(admin, pair.target("k"))

    detail = get_deployment(READER, found, reads)
    assert detail.deployment.id == found
    assert detail.deployment.status is Status.REVERTED
    assert (detail.deployment.service, detail.deployment.environment) == (
        pair.service,
        pair.environment,
    )
    assert [e.type for e in detail.events] == [ST, S, R]
    assert [e.seq for e in detail.events] == sorted({e.seq for e in detail.events})
    assert (detail.events[1].reason, detail.events[1].source_url) == (reason, url)
    assert (detail.events[0].reason, detail.events[0].source_url) == (None, None)
    assert {e.credential_id for e in detail.events} == {pair.credential_id}
    stamps = [e.received_at for e in detail.events]
    assert all(stamp.tzinfo is not None for stamp in stamps) and stamps == sorted(stamps)
    with admin.connect() as connection:
        stored = list(
            connection.execute(
                text("SELECT id FROM deployment_events WHERE deployment_id = :d ORDER BY seq"),
                {"d": found},
            ).scalars()
        )
    assert [e.id for e in detail.events] == stored


@pytest.mark.parametrize("valid_set", VALID_SETS, ids=lambda s: "+".join(k.value for k in s))
def test_detail_shows_the_domain_status_of_every_event_set(
    valid_set: tuple[EventType, ...],
    admin: Engine,
    creator: PostgresDeploymentStore,
    reads: PostgresDeploymentReads,
) -> None:
    pair = new_pair(admin)
    build(creator, pair, "k", valid_set)
    detail = get_deployment(READER, deployment_id(admin, pair.target("k")), reads)
    assert detail.deployment.status is derive_status(valid_set)
    assert sorted(e.type for e in detail.events) == sorted(valid_set)


def test_an_unknown_deployment_is_none_at_the_port_and_not_found_to_the_caller(
    reads: PostgresDeploymentReads,
) -> None:
    unknown = uuid.uuid4()
    assert reads.get(unknown) is None
    with pytest.raises(DeploymentNotFound):
        get_deployment(READER, unknown, reads)


# Reads write nothing


def test_reading_changes_no_row(
    admin: Engine, creator: PostgresDeploymentStore, reads: PostgresDeploymentReads
) -> None:
    pair = new_pair(admin)
    build(creator, pair, "k", (ST, S))

    def counts() -> tuple[int, int]:
        with admin.connect() as connection:
            deployments = connection.execute(text("SELECT count(*) FROM deployments")).scalar_one()
            events = connection.execute(text("SELECT count(*) FROM deployment_events")).scalar_one()
        return int(deployments), int(events)

    before = counts()
    everything(reads, pair.filters)
    get_deployment(READER, deployment_id(admin, pair.target("k")), reads)
    assert counts() == before


# Corrupt data is a fault, not a guess


def test_a_deployment_with_no_events_is_an_invariant_fault_with_nothing_in_it(
    admin: Engine, reads: PostgresDeploymentReads, caplog: pytest.LogCaptureFixture
) -> None:
    """The store never leaves one (its transaction commits the deployment with its first event),
    so this plants one as the owner. Showing it with some status would hide the corruption."""
    pair = new_pair(admin)
    with admin.begin() as connection:
        orphan = connection.execute(
            text(
                "INSERT INTO deployments (service_id, environment_id, deployment_key, version, "
                "commit_sha) VALUES (:s, :e, 'orphan-key', :v, :sha) RETURNING id"
            ),
            {"s": pair.service_id, "e": pair.environment_id, "v": VERSION, "sha": SHA},
        ).scalar_one()
    with caplog.at_level(logging.DEBUG), pytest.raises(InvariantFault) as listing:
        reads.list_after(pair.filters, None, 10)
    with caplog.at_level(logging.DEBUG), pytest.raises(InvariantFault) as detail:
        reads.get(orphan)
    for caught in (listing, detail):
        assert (caught.value.__cause__, caught.value.__context__) == (None, None)
        assert caught.value.args == ()
    assert "orphan-key" not in caplog.text and pair.service not in caplog.text
    assert "invariant fault" in caplog.text


# Faults reach the caller sanitized


def test_an_unreachable_database_is_unavailable_with_no_cause() -> None:
    engine = build_engine(
        "postgresql+psycopg://shiptrace_app@127.0.0.1:1/shiptrace",
        DatabaseOptions(1, 0, 2, 5000, 2000, 2),
    )
    unreachable = PostgresDeploymentReads(engine)
    try:
        for attempt in (
            lambda: unreachable.list_after(DeploymentFilter(), None, 10),
            lambda: unreachable.get(uuid.uuid4()),
        ):
            with pytest.raises(StoreUnavailable) as caught:
                attempt()
            assert (caught.value.__cause__, caught.value.__context__) == (None, None)
    finally:
        engine.dispose()
