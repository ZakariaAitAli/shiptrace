"""Credential issuance against real PostgreSQL 18, as the runtime role with its 0003 grants.

The HTTP tests go through the real app; the issuer tests call the persistence adapter directly,
as code that skipped the use case's checks would, so the database's own refusals are visible.
"""

import uuid
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from shiptrace.application.access import StoreUnavailable
from shiptrace.application.credentials import NewCredential, UnregisteredBinding, new_token
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import Scope, digest, display_prefix
from shiptrace.persistence.issuance import PostgresCredentialIssuer

from .conftest import Database
from .test_admin_cli import token_forms
from .test_registry_api_postgres import bearer, insert_credential, unique_slug

EngineFor = Callable[[str], Engine]
PATH = "/api/v1/credentials"
DAY = 86400


@pytest.fixture
def migrator(migrated_database: Database, engine_for: EngineFor) -> Iterator[Engine]:
    """Removes the credentials and registry rows a test commits, credentials first."""
    engine = engine_for(migrated_database.migrator_url)
    tables = ("api_credentials", "services", "environments")
    with engine.connect() as connection:
        before = {t: set(connection.execute(text(f"SELECT id FROM {t}")).scalars()) for t in tables}
    yield engine
    with engine.begin() as connection:
        for table in tables:
            for row_id in connection.execute(text(f"SELECT id FROM {table}")).scalars():
                if row_id not in before[table]:
                    connection.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": row_id})


@pytest.fixture
def client(migrated_database: Database, migrator: Engine) -> Iterator[TestClient]:
    settings = Settings.model_validate(
        {"environment": "test", "database_url": migrated_database.app_url}
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def admin(migrator: Engine) -> dict[str, str]:
    return bearer(insert_credential(migrator, "admin"))


def register(migrator: Engine) -> tuple[str, str]:
    service, environment = unique_slug(), unique_slug()
    with migrator.begin() as connection:
        connection.execute(text("INSERT INTO services (slug) VALUES (:s)"), {"s": service})
        connection.execute(text("INSERT INTO environments (slug) VALUES (:s)"), {"s": environment})
    return service, environment


def credential_count(migrator: Engine) -> int:
    with migrator.connect() as connection:
        return int(connection.execute(text("SELECT count(*) FROM api_credentials")).scalar_one())


def stored_row(migrator: Engine, credential_id: str) -> dict[str, object]:
    with migrator.connect() as connection:
        row = connection.execute(
            text(
                "SELECT c.name, c.scope, s.slug AS service, e.slug AS environment, "
                "c.secret_sha256, c.display_prefix, c.created_at, c.expires_at, c.revoked_at, "
                "c.last_used_at, extract(epoch FROM c.expires_at - c.created_at) AS lifetime, "
                "c.created_at <= now() AS past "
                "FROM api_credentials c LEFT JOIN services s ON s.id = c.service_id "
                "LEFT JOIN environments e ON e.id = c.environment_id WHERE c.id = :id"
            ),
            {"id": credential_id},
        ).one()
    return dict(row._mapping)


def test_ingest_credential_is_stored_as_digest_and_works_for_its_binding_only(
    client: TestClient, migrator: Engine, admin: dict[str, str]
) -> None:
    service, environment = register(migrator)
    body = {"name": "ci", "scope": "ingest", "service": service, "environment": environment}
    response = client.post(PATH, headers=admin, json=body)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    issued = response.json()
    token = issued["token"]
    row = stored_row(migrator, issued["id"])
    assert row["secret_sha256"] == digest(token)
    assert row["display_prefix"] == issued["display_prefix"] == display_prefix(token)
    assert (row["name"], row["scope"]) == ("ci", "ingest")
    assert (row["service"], row["environment"]) == (service, environment)
    assert (issued["service"], issued["environment"]) == (service, environment)
    assert row["expires_at"] is None and issued["expires_at"] is None
    assert row["revoked_at"] is None and row["last_used_at"] is None
    assert row["past"] is True
    assert issued["created_at"] == row["created_at"].isoformat().replace(  # type: ignore[attr-defined]
        "+00:00", "Z"
    )
    # CP3 authenticates it, and its scope holds: ingest may neither list nor issue.
    assert client.get("/api/v1/services", headers=bearer(token)).status_code == 403
    assert client.post(PATH, headers=bearer(token), json=body).status_code == 403


def test_read_credential_reads_and_cannot_issue(
    client: TestClient, migrator: Engine, admin: dict[str, str]
) -> None:
    response = client.post(PATH, headers=admin, json={"name": "reader", "scope": "read"})
    assert response.status_code == 201
    issued = response.json()
    row = stored_row(migrator, issued["id"])
    assert (row["scope"], row["service"], row["environment"]) == ("read", None, None)
    assert (issued["service"], issued["environment"]) == (None, None)
    token = bearer(issued["token"])
    assert client.get("/api/v1/services", headers=token).status_code == 200
    before = credential_count(migrator)
    assert client.post(PATH, headers=token, json={"name": "x", "scope": "read"}).status_code == 403
    assert credential_count(migrator) == before


@pytest.mark.parametrize("days", [1, 30, 365])
def test_expiry_is_whole_24_hour_days_of_database_time(
    client: TestClient, migrator: Engine, admin: dict[str, str], days: int
) -> None:
    body = {"name": "expiring", "scope": "read", "expires_in_days": days}
    response = client.post(PATH, headers=admin, json=body)
    assert response.status_code == 201
    issued = response.json()
    row = stored_row(migrator, issued["id"])
    assert row["lifetime"] == days * DAY
    assert issued["expires_at"] == row["expires_at"].isoformat().replace(  # type: ignore[attr-defined]
        "+00:00", "Z"
    )


@pytest.mark.parametrize("zone", ["UTC", "Europe/Paris", "America/Santiago"])
def test_issuer_expiry_ignores_the_session_time_zone(
    migrated_database: Database, migrator: Engine, zone: str
) -> None:
    """Calendar days in a daylight-saving zone would be 23 or 25 hours across a change, which the
    guard refuses. Whether a window crosses one depends on today's date, so zones from both
    hemispheres are tried: from any date, the 182-day window crosses a change in Paris or in
    Santiago, so a calendar-day expiry fails at least one case whenever this runs."""
    engine = create_engine(
        migrated_database.app_url, connect_args={"options": f"-c TimeZone={zone}"}
    )
    try:
        issuer = PostgresCredentialIssuer(engine)
        for days in (1, 182, 365):
            token = new_token()
            stored = issuer.add(
                NewCredential("zone", Scope.READ, None, None, days),
                digest(token),
                display_prefix(token),
            )
            assert stored.expires_at is not None
            # Timestamps, not subtraction: Python subtracts datetimes that share a tzinfo as wall
            # clock time, ignoring the offset change, which is the very error under test.
            assert stored.expires_at.timestamp() - stored.created_at.timestamp() == days * DAY
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("service", "environment", "fields"),
    [
        (False, True, ["service"]),
        (True, False, ["environment"]),
        (False, False, ["service", "environment"]),
    ],
)
def test_unregistered_bindings_are_field_specific_422_and_write_nothing(
    client: TestClient,
    migrator: Engine,
    admin: dict[str, str],
    service: bool,
    environment: bool,
    fields: list[str],
) -> None:
    known_service, known_environment = register(migrator)
    missing = "zz-" + uuid.uuid4().hex[:12]
    body = {
        "name": "ci",
        "scope": "ingest",
        "service": known_service if service else missing,
        "environment": known_environment if environment else missing,
    }
    before = credential_count(migrator)
    response = client.post(PATH, headers=admin, json=body)
    assert response.status_code == 422
    assert response.json()["errors"] == [
        {"location": f"body.{field}", "rule": "not_registered"} for field in fields
    ]
    assert missing not in response.text
    assert credential_count(migrator) == before


@pytest.mark.parametrize(
    "body",
    [
        {"name": "root", "scope": "admin"},
        {"name": "ci", "scope": "read", "service": "payments-api"},
        {"name": "ci", "scope": "ingest", "service": "payments-api"},
        {"name": "ci", "scope": "read", "expires_in_days": 366},
        {"name": "ci", "scope": "read", "created_at": "2020-01-01T00:00:00Z"},
    ],
    ids=["admin", "read-bound", "ingest-half-bound", "expiry", "client-time"],
)
def test_refused_requests_write_nothing(
    client: TestClient, migrator: Engine, admin: dict[str, str], body: dict[str, object]
) -> None:
    before = credential_count(migrator)
    response = client.post(PATH, headers=admin, json=body)
    assert response.status_code == 422
    assert "st1_" not in response.text
    assert credential_count(migrator) == before


@pytest.mark.parametrize(
    ("expires", "revoked"),
    [("now() - interval '1 second'", "NULL"), ("NULL", "now()")],
    ids=["expired", "revoked"],
)
def test_dead_admin_credentials_cannot_issue(
    client: TestClient, migrator: Engine, expires: str, revoked: str
) -> None:
    token = insert_credential(migrator, "admin", expires, revoked)
    before = credential_count(migrator)
    response = client.post(PATH, headers=bearer(token), json={"name": "x", "scope": "read"})
    assert response.status_code == 401
    assert credential_count(migrator) == before


def test_duplicate_names_issue_distinct_working_credentials(
    client: TestClient, migrator: Engine, admin: dict[str, str]
) -> None:
    body = {"name": "same name", "scope": "read"}
    first, second = (client.post(PATH, headers=admin, json=body).json() for _ in range(2))
    assert first["id"] != second["id"]
    assert first["token"] != second["token"]
    for issued in (first, second):
        assert stored_row(migrator, issued["id"])["name"] == "same name"
        assert client.get("/api/v1/services", headers=bearer(issued["token"])).status_code == 200


def test_no_column_in_any_table_holds_the_issued_token(
    client: TestClient, migrator: Engine, admin: dict[str, str]
) -> None:
    service, environment = register(migrator)
    body = {"name": "ci", "scope": "ingest", "service": service, "environment": environment}
    token = client.post(PATH, headers=admin, json=body).json()["token"]
    with migrator.connect() as connection:
        tables = (
            connection.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
            .scalars()
            .all()
        )
        for table in tables:
            # Table names come from pg_tables, not input; strpos is exact, unlike LIKE.
            for form in token_forms(token):
                found = connection.execute(
                    text(
                        f"SELECT count(*) FROM {table} t "
                        "WHERE strpos(lower(row_to_json(t)::text), lower(:form)) > 0"
                    ),
                    {"form": form},
                ).scalar_one()
                assert found == 0, table


def test_runtime_issuer_cannot_store_an_admin_credential(
    migrated_database: Database, migrator: Engine, engine_for: EngineFor
) -> None:
    """The use case never passes admin; if code ever did, the database refuses it (ADR-0012).
    Direct SQL as the runtime role is covered by test_credential_writes."""
    issuer = PostgresCredentialIssuer(engine_for(migrated_database.app_url))
    token = new_token()
    before = credential_count(migrator)
    with pytest.raises(StoreUnavailable) as caught:
        issuer.add(NewCredential("root", Scope.ADMIN, None, None, None), digest(token), "st1_test")
    assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True
    assert credential_count(migrator) == before


def test_issuer_reports_unregistered_slugs_and_writes_nothing(
    migrated_database: Database, migrator: Engine, engine_for: EngineFor
) -> None:
    service, _ = register(migrator)
    issuer = PostgresCredentialIssuer(engine_for(migrated_database.app_url))
    before = credential_count(migrator)
    with pytest.raises(UnregisteredBinding) as caught:
        issuer.add(
            NewCredential("ci", Scope.INGEST, service, "zz-none", None),
            digest(new_token()),
            "st1_test",
        )
    assert caught.value.fields == ("environment",)
    assert credential_count(migrator) == before


def test_unreachable_database_is_unavailable_without_detail() -> None:
    engine = create_engine(
        "postgresql+psycopg://shiptrace_app@127.0.0.1:1/shiptrace",
        connect_args={"connect_timeout": 2},
    )
    try:
        with pytest.raises(StoreUnavailable) as caught:
            PostgresCredentialIssuer(engine).add(
                NewCredential("ci", Scope.READ, None, None, None), digest(new_token()), "st1_x"
            )
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__ is True
    finally:
        engine.dispose()
