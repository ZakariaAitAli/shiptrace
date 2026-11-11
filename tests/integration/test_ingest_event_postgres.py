"""The ingest use case through the real credential store and the real deployment store, without
HTTP (CP17). The Principal comes from a credential row and `PostgresCredentialStore`, so the bound
ids and slugs are the database's own.

Committed events can never be deleted, so a module-scoped disposable container holds them and each
test uses its own service, environment and credential. CP16's race campaigns are not repeated.

Zero-query evidence: every refusal before the store must open no pooled connection and execute no
statement on the engine the deployment store uses.
"""

import logging
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine

from shiptrace.application.access import Forbidden, Principal
from shiptrace.application.credentials import create_admin_credential, new_token
from shiptrace.application.deployments import Accepted
from shiptrace.application.ingest import EventRejected, ingest_event
from shiptrace.domain.credentials import Scope, digest, display_prefix
from shiptrace.domain.deployments import Duplicate, Reject, RejectReason
from shiptrace.persistence.credentials import (
    PostgresAdminCredentialWriter,
    PostgresCredentialStore,
)
from shiptrace.persistence.deployments import PostgresDeploymentStore
from shiptrace.persistence.engine import DatabaseOptions, build_engine
from shiptrace.persistence.migrate import upgrade

from .conftest import Database, start_database

SHA = "0123456789abcdef0123456789abcdef01234567"
SENTINEL = "sentinel-" + uuid.uuid4().hex


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
def migrator(disposable: Database) -> Iterator[Engine]:
    engine = create_engine(disposable.migrator_url)
    yield engine
    engine.dispose()


@dataclass
class Traffic:
    """What the deployment store's engine was asked to do."""

    statements: list[str] = field(default_factory=list)
    checkouts: int = 0

    def reset(self) -> None:
        self.statements.clear()
        self.checkouts = 0


@dataclass(frozen=True)
class Wiring:
    credentials: PostgresCredentialStore
    deployments: PostgresDeploymentStore
    traffic: Traffic


@pytest.fixture(scope="module")
def wiring(disposable: Database) -> Iterator[Wiring]:
    options = DatabaseOptions(
        pool_size=3,
        max_overflow=0,
        pool_timeout_seconds=5,
        statement_timeout_ms=10_000,
        lock_timeout_ms=5000,
        connect_timeout_seconds=5,
    )
    # Two engines, so the credential lookup is never counted as deployment-store traffic.
    credential_engine = build_engine(disposable.app_url, options)
    deployment_engine = build_engine(disposable.app_url, options)
    traffic = Traffic()

    def on_statement(*_: Any) -> None:
        traffic.statements.append("statement")  # Count only: never keep text or parameters.

    def on_checkout(*_: Any) -> None:
        traffic.checkouts += 1

    event.listen(deployment_engine, "before_cursor_execute", on_statement)
    event.listen(deployment_engine, "checkout", on_checkout)
    yield Wiring(
        PostgresCredentialStore(credential_engine),
        PostgresDeploymentStore(deployment_engine),
        traffic,
    )
    credential_engine.dispose()
    deployment_engine.dispose()


@dataclass(frozen=True)
class World:
    """One registered service and environment, an ingest credential bound to them, and a second
    registered pair that the credential is not bound to."""

    service: str
    environment: str
    other_service: str
    other_environment: str
    ingest_token: str
    read_token: str
    admin_token: str


def _slug(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _add_credential(
    connection: Any,
    scope: str,
    service: str | None = None,
    environment: str | None = None,
) -> str:
    token = new_token()
    connection.execute(
        text(
            "INSERT INTO api_credentials "
            "(name, scope, service_id, environment_id, secret_sha256, display_prefix) "
            "VALUES ('ci', :scope, "
            "(SELECT id FROM services WHERE slug = :service), "
            "(SELECT id FROM environments WHERE slug = :environment), :digest, :prefix)"
        ),
        {
            "scope": scope,
            "service": service,
            "environment": environment,
            "digest": digest(token),
            "prefix": display_prefix(token),
        },
    )
    return token


@pytest.fixture
def world(admin: Engine, migrator: Engine) -> World:
    service, environment = _slug("pay"), _slug("prod")
    other_service, other_environment = _slug("bill"), _slug("stage")
    with admin.begin() as connection:
        for table, slug in (
            ("services", service),
            ("services", other_service),
            ("environments", environment),
            ("environments", other_environment),
        ):
            connection.execute(text(f"INSERT INTO {table} (slug) VALUES (:slug)"), {"slug": slug})
        ingest_token = _add_credential(connection, "ingest", service, environment)
        read_token = _add_credential(connection, "read")
    # An admin credential is created only the supported way: the bootstrap use case and its writer,
    # which run as the migrator role. The database refuses one issued through ordinary SQL.
    admin_token = create_admin_credential(
        "ingest-test admin", PostgresAdminCredentialWriter(migrator, "shiptrace_migrator")
    ).token
    return World(
        service,
        environment,
        other_service,
        other_environment,
        ingest_token=ingest_token,
        read_token=read_token,
        admin_token=admin_token,
    )


def principal_for(wiring: Wiring, token: str) -> Principal:
    found = wiring.credentials.find_active(digest(token))
    assert found is not None
    return found


def body(world: World, **changes: object) -> dict[str, object]:
    merged: dict[str, object] = {
        "service": world.service,
        "environment": world.environment,
        "deployment_key": "run-" + uuid.uuid4().hex[:8],
        "type": "started",
        "version": "1.4.2",
        "commit_sha": SHA,
        **changes,
    }
    return merged


def row_counts(admin: Engine) -> tuple[int, int]:
    with admin.connect() as connection:
        deployments = connection.execute(text("SELECT count(*) FROM deployments")).scalar_one()
        events = connection.execute(text("SELECT count(*) FROM deployment_events")).scalar_one()
    return int(deployments), int(events)


# The complete path


def test_an_event_flows_from_credential_to_database_and_is_attributed_to_it(
    wiring: Wiring, world: World, admin: Engine
) -> None:
    caller = principal_for(wiring, world.ingest_token)
    payload = body(world, reason="canary", source_url="https://ci.example/runs/1")
    result = ingest_event(caller, payload, wiring.deployments)
    assert isinstance(result, Accepted)
    with admin.connect() as connection:
        row = connection.execute(
            text(
                "SELECT d.service_id, d.environment_id, d.deployment_key, e.credential_id, "
                "e.type, e.reason, e.source_url FROM deployment_events e "
                "JOIN deployments d ON d.id = e.deployment_id WHERE e.id = :id"
            ),
            {"id": result.event_id},
        ).one()
    assert (row.service_id, row.environment_id) == (caller.service_id, caller.environment_id)
    assert row.credential_id == caller.id
    assert (row.deployment_key, row.type) == (payload["deployment_key"], "started")
    assert (row.reason, row.source_url) == ("canary", "https://ci.example/runs/1")


def test_the_rules_of_the_domain_come_through_the_whole_path(
    wiring: Wiring, world: World, admin: Engine
) -> None:
    caller = principal_for(wiring, world.ingest_token)
    first = body(world, type="succeeded", reason="ok")
    accepted = ingest_event(caller, first, wiring.deployments)
    assert isinstance(accepted, Accepted)

    again = ingest_event(caller, first, wiring.deployments)  # R3
    assert isinstance(again, Duplicate)
    assert again.original.id == accepted.event_id

    conflict = ingest_event(caller, {**first, "reason": "other"}, wiring.deployments)  # R4
    assert conflict == Reject(RejectReason.EVENT_CONFLICT)

    changed = ingest_event(caller, {**first, "version": "2.0.0"}, wiring.deployments)  # R5
    assert changed == Reject(RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT)

    failed = ingest_event(caller, {**first, "type": "failed"}, wiring.deployments)  # R6
    assert failed == Reject(RejectReason.TERMINAL_CONFLICT)

    reverted = ingest_event(caller, {**first, "type": "reverted"}, wiring.deployments)  # R9 ok
    assert isinstance(reverted, Accepted)


def test_a_revert_for_a_deployment_that_does_not_exist_creates_nothing(
    wiring: Wiring, world: World, admin: Engine
) -> None:
    caller = principal_for(wiring, world.ingest_token)
    before = row_counts(admin)
    result = ingest_event(caller, body(world, type="reverted"), wiring.deployments)  # R9
    assert result == Reject(RejectReason.REVERT_REQUIRES_SUCCESS)
    assert row_counts(admin) == before


def test_the_same_key_for_another_bound_pair_is_another_deployment(
    wiring: Wiring, world: World, admin: Engine
) -> None:
    """Two credentials bound to different targets never collide on a deployment key."""
    with admin.begin() as connection:
        other_token = _add_credential(
            connection, "ingest", world.other_service, world.other_environment
        )
    mine = principal_for(wiring, world.ingest_token)
    theirs = principal_for(wiring, other_token)
    key = "shared-key"
    first = ingest_event(mine, body(world, deployment_key=key), wiring.deployments)
    second = ingest_event(
        theirs,
        body(world, service=world.other_service, environment=world.other_environment)
        | {"deployment_key": key, "commit_sha": "f" * 40},
        wiring.deployments,
    )
    assert isinstance(first, Accepted)
    assert isinstance(second, Accepted)  # Not a conflict: it is a different deployment.


# Authorization before any query


def test_a_foreign_target_is_forbidden_whether_or_not_it_exists_and_nothing_is_queried(
    wiring: Wiring, world: World, admin: Engine
) -> None:
    caller = principal_for(wiring, world.ingest_token)
    # Give the registered foreign target a deployment, so "exists" is true in every sense.
    with admin.begin() as connection:
        other_token = _add_credential(
            connection, "ingest", world.other_service, world.other_environment
        )
    owner = principal_for(wiring, other_token)
    ingest_event(
        owner,
        body(world, service=world.other_service, environment=world.other_environment),
        wiring.deployments,
    )
    before = row_counts(admin)
    wiring.traffic.reset()

    answers = []
    for service, environment in [
        (world.other_service, world.environment),  # registered, has deployments
        (world.service, world.other_environment),  # registered environment
        (world.other_service, world.other_environment),  # both registered, deployment exists
        (_slug("ghost"), world.environment),  # not registered at all
        (world.service, _slug("ghost")),
        (_slug("ghost"), _slug("void")),
    ]:
        with pytest.raises(Forbidden) as caught:
            ingest_event(
                caller, body(world, service=service, environment=environment), wiring.deployments
            )
        answers.append((type(caught.value), caught.value.args, caught.value.__cause__))

    assert len(set(map(repr, answers))) == 1  # Registered or not, the answer is the same.
    assert wiring.traffic.statements == []
    assert wiring.traffic.checkouts == 0
    assert row_counts(admin) == before


@pytest.mark.parametrize("token_of", ["read_token", "admin_token"])
def test_a_read_or_admin_credential_is_forbidden_before_any_query(
    wiring: Wiring, world: World, admin: Engine, token_of: str
) -> None:
    caller = principal_for(wiring, getattr(world, token_of))
    before = row_counts(admin)
    wiring.traffic.reset()
    with pytest.raises(Forbidden):
        ingest_event(caller, body(world), wiring.deployments)
    assert wiring.traffic.statements == []
    assert wiring.traffic.checkouts == 0
    assert row_counts(admin) == before


def test_an_invalid_body_is_refused_before_any_query_and_leaks_nothing(
    wiring: Wiring, world: World, admin: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    caller = principal_for(wiring, world.ingest_token)
    before = row_counts(admin)
    wiring.traffic.reset()
    bad = body(world, version=SENTINEL + "!", reason=SENTINEL, extra=SENTINEL)
    with caplog.at_level(logging.DEBUG), pytest.raises(EventRejected) as caught:
        ingest_event(caller, bad, wiring.deployments)
    assert wiring.traffic.statements == []
    assert wiring.traffic.checkouts == 0
    assert row_counts(admin) == before
    assert SENTINEL not in caplog.text + repr(caught.value.problems)


def test_a_stored_reason_is_not_logged_on_the_success_path(
    wiring: Wiring, world: World, caplog: pytest.LogCaptureFixture
) -> None:
    caller = principal_for(wiring, world.ingest_token)
    with caplog.at_level(logging.DEBUG):
        result = ingest_event(
            caller,
            body(world, reason=SENTINEL, source_url=f"https://ci.example/{SENTINEL}"),
            wiring.deployments,
        )
    assert isinstance(result, Accepted)
    assert SENTINEL not in caplog.text


def test_the_principal_scope_comes_from_the_database_row(wiring: Wiring, world: World) -> None:
    assert principal_for(wiring, world.ingest_token).scope is Scope.INGEST
    assert principal_for(wiring, world.read_token).scope is Scope.READ
