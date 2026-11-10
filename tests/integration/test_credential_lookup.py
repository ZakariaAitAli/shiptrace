"""Credential lookup and bearer protection against real PostgreSQL 18, as the runtime role.

Expiry and revocation are decided by database time: rows are written relative to the database's
now(), and the application never supplies a clock.
"""

import uuid
from collections.abc import Callable, Iterator

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine

from shiptrace.api.auth import require
from shiptrace.application.access import StoreUnavailable
from shiptrace.application.credentials import new_token
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import Action, Scope, digest, display_prefix
from shiptrace.persistence.credentials import PostgresCredentialStore

from .conftest import Database

EngineFor = Callable[[str], Engine]
PROBE = "/api/v1/_probe"
Insert = Callable[..., str]
UNREACHABLE = "postgresql+psycopg://shiptrace_app@127.0.0.1:1/shiptrace"


@pytest.fixture
def insert_credential(migrated_database: Database, engine_for: EngineFor) -> Iterator[Insert]:
    """Commits credentials as the migrator, as the bootstrap CLI will, and removes them after."""
    migrator = engine_for(migrated_database.migrator_url)
    created: list[bytes] = []
    registry: list[tuple[str, uuid.UUID]] = []

    def insert(scope: str = "read", expires: str = "NULL", revoked: str = "NULL") -> str:
        token = new_token()
        service_id = environment_id = None
        with migrator.begin() as connection:
            if scope == "ingest":
                service_id = connection.execute(
                    text("INSERT INTO services (slug) VALUES (:s) RETURNING id"),
                    {"s": "lookup-" + uuid.uuid4().hex[:8]},
                ).scalar_one()
                environment_id = connection.execute(
                    text("INSERT INTO environments (slug) VALUES (:s) RETURNING id"),
                    {"s": "lookup-" + uuid.uuid4().hex[:8]},
                ).scalar_one()
                registry.extend([("services", service_id), ("environments", environment_id)])
            # expires and revoked are fixed SQL expressions chosen by the tests, never input.
            connection.execute(
                text(
                    "INSERT INTO api_credentials (name, scope, service_id, environment_id, "
                    "secret_sha256, display_prefix, expires_at, revoked_at) VALUES "
                    "('lookup', :scope, :service, :environment, :digest, :prefix, "
                    f"{expires}, {revoked})"
                ),
                {
                    "scope": scope,
                    "service": service_id,
                    "environment": environment_id,
                    "digest": digest(token),
                    "prefix": display_prefix(token),
                },
            )
        created.append(digest(token))
        return token

    yield insert
    with migrator.begin() as connection:
        for secret_digest in created:
            connection.execute(
                text("DELETE FROM api_credentials WHERE secret_sha256 = :d"), {"d": secret_digest}
            )
        for table, row_id in registry:
            connection.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": row_id})


@pytest.fixture
def store(migrated_database: Database, engine_for: EngineFor) -> PostgresCredentialStore:
    return PostgresCredentialStore(engine_for(migrated_database.app_url))


def test_active_credential_is_found_by_digest(
    store: PostgresCredentialStore, insert_credential: Insert
) -> None:
    token = insert_credential(scope="admin")
    principal = store.find_active(digest(token))
    assert principal is not None
    assert principal.scope is Scope.ADMIN
    assert (principal.service_id, principal.environment_id) == (None, None)
    assert (principal.service_slug, principal.environment_slug) == (None, None)


def test_read_credential_has_no_binding(
    store: PostgresCredentialStore, insert_credential: Insert
) -> None:
    principal = store.find_active(digest(insert_credential(scope="read")))
    assert principal is not None
    assert principal.scope is Scope.READ
    assert (principal.service_id, principal.environment_id) == (None, None)
    assert (principal.service_slug, principal.environment_slug) == (None, None)


def test_ingest_binding_is_returned(
    store: PostgresCredentialStore, insert_credential: Insert
) -> None:
    principal = store.find_active(digest(insert_credential(scope="ingest")))
    assert principal is not None
    assert principal.scope is Scope.INGEST
    assert principal.service_id is not None and principal.environment_id is not None
    assert principal.service_slug is not None and principal.environment_slug is not None


def slug_of(engine: Engine, kind: str, row_id: uuid.UUID) -> object:
    statements = {
        "services": text("SELECT slug FROM services WHERE id = :id"),
        "environments": text("SELECT slug FROM environments WHERE id = :id"),
    }
    with engine.connect() as connection:
        return connection.execute(statements[kind], {"id": row_id}).scalar_one()


def test_ingest_principal_carries_the_canonical_slugs_of_its_own_binding(
    store: PostgresCredentialStore,
    insert_credential: Insert,
    migrated_database: Database,
    engine_for: EngineFor,
) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    first = store.find_active(digest(insert_credential(scope="ingest")))
    second = store.find_active(digest(insert_credential(scope="ingest")))
    assert first is not None and second is not None
    for principal in (first, second):
        assert principal.service_id is not None and principal.environment_id is not None
        assert principal.service_slug == slug_of(migrator, "services", principal.service_id)
        assert principal.environment_slug == slug_of(
            migrator, "environments", principal.environment_id
        )
    # Each credential gets its own pair, and a service is never reported as an environment.
    assert first.service_slug != second.service_slug
    assert first.environment_slug != second.environment_slug
    assert first.service_slug != first.environment_slug


@pytest.mark.parametrize(
    ("expires", "revoked"),
    [
        ("now() - interval '1 second'", "NULL"),
        ("now()", "NULL"),
        ("NULL", "now()"),
        ("now() + interval '1 hour'", "now()"),
    ],
    ids=["expired", "expires-now", "revoked", "revoked-and-unexpired"],
)
def test_dead_ingest_credentials_are_not_found_and_leak_no_binding(
    store: PostgresCredentialStore, insert_credential: Insert, expires: str, revoked: str
) -> None:
    token = insert_credential(scope="ingest", expires=expires, revoked=revoked)
    assert store.find_active(digest(token)) is None


def test_an_ingest_credential_with_an_expiry_in_the_future_is_found_with_its_binding(
    store: PostgresCredentialStore, insert_credential: Insert
) -> None:
    token = insert_credential(scope="ingest", expires="now() + interval '1 hour'")
    principal = store.find_active(digest(token))
    assert principal is not None
    assert principal.service_slug is not None and principal.environment_slug is not None


@pytest.mark.parametrize("table", ["services", "environments"])
def test_runtime_role_may_select_the_registry_tables_the_lookup_joins(
    migrated_database: Database, engine_for: EngineFor, table: str
) -> None:
    runtime = engine_for(migrated_database.app_url)
    with runtime.connect() as connection:
        allowed = connection.execute(
            text("SELECT has_table_privilege(current_user, :table, 'SELECT')"), {"table": table}
        ).scalar_one()
    assert allowed is True


def test_lookup_stays_one_statement_and_returns_the_same_principal(
    migrated_database: Database, insert_credential: Insert, engine_for: EngineFor
) -> None:
    engine = engine_for(migrated_database.app_url)
    store = PostgresCredentialStore(engine)
    secret_digest = digest(insert_credential(scope="ingest"))
    first = store.find_active(secret_digest)  # Also records the first use, outside the count.
    assert first is not None
    statements: list[str] = []
    event.listen(
        engine,
        "before_cursor_execute",
        lambda connection, cursor, statement, parameters, context, many: statements.append(
            statement
        ),
    )
    assert store.find_active(secret_digest) == first
    assert len(statements) == 1
    assert statements[0].lstrip().upper().startswith("SELECT")
    assert "JOIN" in statements[0].upper()


def test_first_use_of_an_ingest_credential_is_still_recorded(
    migrated_database: Database,
    store: PostgresCredentialStore,
    insert_credential: Insert,
    engine_for: EngineFor,
) -> None:
    secret_digest = digest(insert_credential(scope="ingest"))
    migrator = engine_for(migrated_database.migrator_url)
    read_last_used = text("SELECT last_used_at FROM api_credentials WHERE secret_sha256 = :d")
    with migrator.connect() as connection:
        assert connection.execute(read_last_used, {"d": secret_digest}).scalar_one() is None
    assert store.find_active(secret_digest) is not None
    with migrator.connect() as connection:
        assert connection.execute(read_last_used, {"d": secret_digest}).scalar_one() is not None


def test_unknown_digest_is_not_found(store: PostgresCredentialStore) -> None:
    assert store.find_active(digest(new_token())) is None


@pytest.mark.parametrize(
    ("expires", "revoked", "active"),
    [
        ("now() + interval '1 hour'", "NULL", True),
        ("now() - interval '1 second'", "NULL", False),
        # Expired at the writing transaction's now(), already past at lookup. This cannot tell
        # > from >= at the same microsecond; that boundary is accepted untested (V118).
        ("now()", "NULL", False),
        ("NULL", "now()", False),
        ("NULL", "now() + interval '1 hour'", False),  # any revocation counts, whatever its time
        ("now() + interval '1 hour'", "now()", False),
    ],
)
def test_expiry_and_revocation_use_database_time(
    store: PostgresCredentialStore,
    insert_credential: Insert,
    expires: str,
    revoked: str,
    active: bool,
) -> None:
    token = insert_credential(expires=expires, revoked=revoked)
    assert (store.find_active(digest(token)) is not None) is active


def test_unreachable_database_is_unavailable_and_carries_no_detail() -> None:
    engine = create_engine(UNREACHABLE, connect_args={"connect_timeout": 2})
    try:
        with pytest.raises(StoreUnavailable) as caught:
            PostgresCredentialStore(engine).find_active(digest(new_token()))
    finally:
        engine.dispose()
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


def test_exhausted_pool_is_unavailable(migrated_database: Database) -> None:
    """Spec §5: pool exhaustion is 503. SQLAlchemy raises TimeoutError, not OperationalError."""
    engine = create_engine(migrated_database.app_url, pool_size=1, max_overflow=0, pool_timeout=0.5)
    try:
        # The first context holds the only connection.
        with engine.connect(), pytest.raises(StoreUnavailable):
            PostgresCredentialStore(engine).find_active(digest(new_token()))
    finally:
        engine.dispose()


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


def test_end_to_end_active_read_credential_passes(
    client: TestClient, insert_credential: Insert
) -> None:
    assert client.get(PROBE, headers=bearer(insert_credential(scope="read"))).status_code == 200


@pytest.mark.parametrize(
    ("expires", "revoked"),
    [("now() - interval '1 second'", "NULL"), ("NULL", "now()")],
    ids=["expired", "revoked"],
)
def test_end_to_end_dead_credentials_are_401(
    client: TestClient, insert_credential: Insert, expires: str, revoked: str
) -> None:
    token = insert_credential(expires=expires, revoked=revoked)
    response = client.get(PROBE, headers=bearer(token))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["code"] == "unauthenticated"


def test_end_to_end_unknown_credential_is_401(client: TestClient) -> None:
    assert client.get(PROBE, headers=bearer(new_token())).status_code == 401


def test_end_to_end_wrong_scope_is_403(client: TestClient, insert_credential: Insert) -> None:
    response = client.get(PROBE, headers=bearer(insert_credential(scope="ingest")))
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
