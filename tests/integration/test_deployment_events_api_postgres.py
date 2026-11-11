"""POST /api/v1/deployment-events against real PostgreSQL 18, through the real composition root
(`create_app`), as the runtime role. CP18 (S5).

Committed events can never be deleted, so a module-scoped disposable container holds them and each
test uses its own service, environment and credentials. Race campaigns are CP16's and are not
repeated. A spy around the deployment store counts persistence calls, which is how a request that
must not reach the store is shown not to.
"""

import logging
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

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
from shiptrace.domain.deployments import NewEvent
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
