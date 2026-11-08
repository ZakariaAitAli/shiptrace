"""Registry API against real PostgreSQL 18, as the runtime role with its existing grants."""

import os
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from shiptrace.application.access import StoreUnavailable
from shiptrace.application.credentials import new_token
from shiptrace.application.registry import Kind, RegistryEntry
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import digest, display_prefix
from shiptrace.persistence.registry import PostgresRegistry

from .conftest import Database

EngineFor = Callable[[str], Engine]
TABLES = {Kind.SERVICES: "services", Kind.ENVIRONMENTS: "environments"}
PATHS = {Kind.SERVICES: "/api/v1/services", Kind.ENVIRONMENTS: "/api/v1/environments"}
RACERS = 8


def unique_slug() -> str:
    return "reg-" + uuid.uuid4().hex[:12]


@pytest.fixture
def migrator(migrated_database: Database, engine_for: EngineFor) -> Iterator[Engine]:
    """Deletes the registry rows and credentials a test adds, keeping the session database."""
    engine = engine_for(migrated_database.migrator_url)
    tables = ("api_credentials", "services", "environments")  # Credentials first: foreign keys.
    with engine.connect() as connection:
        before = {t: set(connection.execute(text(f"SELECT id FROM {t}")).scalars()) for t in tables}
    yield engine
    with engine.begin() as connection:
        for table in tables:
            for row_id in connection.execute(text(f"SELECT id FROM {table}")).scalars():
                if row_id not in before[table]:
                    connection.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": row_id})


@pytest.fixture
def registry(
    migrated_database: Database, migrator: Engine, engine_for: EngineFor
) -> PostgresRegistry:
    return PostgresRegistry(engine_for(migrated_database.app_url))


@pytest.mark.parametrize("kind", list(Kind))
def test_add_uses_database_id_and_time(
    registry: PostgresRegistry, migrator: Engine, kind: Kind
) -> None:
    entry = registry.add(kind, unique_slug())
    assert entry is not None
    with migrator.connect() as connection:
        row = connection.execute(
            text(
                "SELECT uuid_extract_version(id) AS version, created_at, "
                f"created_at <= now() AS past FROM {TABLES[kind]} WHERE id = :id"
            ),
            {"id": entry.id},
        ).one()
    assert row.version == 7
    assert row.created_at == entry.created_at
    assert row.past is True


@pytest.mark.parametrize("kind", list(Kind))
def test_duplicate_add_returns_none_and_keeps_the_original(
    registry: PostgresRegistry, migrator: Engine, kind: Kind
) -> None:
    slug = unique_slug()
    first = registry.add(kind, slug)
    assert registry.add(kind, slug) is None
    with migrator.connect() as connection:
        ids = (
            connection.execute(
                text(f"SELECT id FROM {TABLES[kind]} WHERE slug = :slug"), {"slug": slug}
            )
            .scalars()
            .all()
        )
    assert first is not None and ids == [first.id]


@pytest.mark.parametrize("kind", list(Kind))
def test_unreachable_database_is_unavailable_without_detail(kind: Kind) -> None:
    engine = create_engine(
        "postgresql+psycopg://shiptrace_app@127.0.0.1:1/shiptrace",
        connect_args={"connect_timeout": 2},
    )
    registry = PostgresRegistry(engine)
    try:
        for attempt in (
            lambda: registry.add(kind, "api"),
            lambda: registry.list_after(kind, None, 1),
        ):
            with pytest.raises(StoreUnavailable) as caught:
                attempt()
            assert caught.value.__cause__ is None
            assert caught.value.__suppress_context__ is True
    finally:
        engine.dispose()


def all_slugs(engine: Engine, kind: Kind) -> list[str]:
    with engine.connect() as connection:
        return list(
            connection.execute(text(f"SELECT slug FROM {TABLES[kind]} ORDER BY slug")).scalars()
        )


@pytest.mark.parametrize("kind", list(Kind))
def test_keyset_pages_match_a_direct_ordered_read(
    registry: PostgresRegistry, migrator: Engine, kind: Kind
) -> None:
    """Other tests may share the table, so the walk is compared with the table, not a fixture."""
    for slug in ("pg-b", "pg-a-z", "pg-a0", "pg-c", "pg-a"):  # '-' sorts before '0' in "C".
        registry.add(kind, slug + "-" + uuid.uuid4().hex[:4])
    expected = all_slugs(migrator, kind)
    walked: list[str] = []
    after: str | None = None
    for _ in range(len(expected) + 2):  # A position that is ignored would loop forever.
        rows = registry.list_after(kind, after, 2)
        assert len(rows) <= 2  # The database applies the limit; a missing LIMIT reads everything.
        walked += [row.slug for row in rows]
        if len(rows) < 2:
            break
        after = rows[-1].slug
    else:
        raise AssertionError("pagination never reached the end")
    assert walked == expected
    assert walked == sorted(walked)  # Byte order, as Python sorts ASCII.


@pytest.mark.parametrize("kind", list(Kind))
def test_concurrent_registration_has_exactly_one_winner(
    migrated_database: Database, migrator: Engine, kind: Kind
) -> None:
    """Real connections released together; the unique index, not the code, picks the winner."""
    engine = create_engine(migrated_database.app_url, pool_size=RACERS, max_overflow=0)
    # Open every connection first, so the barrier releases statements, not connection setups.
    warm = [engine.connect() for _ in range(RACERS)]
    for connection in warm:
        connection.close()
    assert engine.pool.checkedin() == RACERS  # type: ignore[attr-defined]
    registry = PostgresRegistry(engine)
    slug = unique_slug()
    barrier = threading.Barrier(RACERS, timeout=10)
    results: list[RegistryEntry | None] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def race() -> None:
        try:
            barrier.wait()
            outcome = registry.add(kind, slug)
            with lock:
                results.append(outcome)
        except BaseException as error:  # noqa: BLE001 - reported by the assertion below.
            with lock:
                errors.append(error)

    threads = [threading.Thread(target=race) for _ in range(RACERS)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
    finally:
        engine.dispose()
    assert errors == []
    assert len(results) == RACERS
    winners = [entry for entry in results if entry is not None]
    assert len(winners) == 1
    with migrator.connect() as connection:
        ids = (
            connection.execute(
                text(f"SELECT id FROM {TABLES[kind]} WHERE slug = :slug"), {"slug": slug}
            )
            .scalars()
            .all()
        )
    assert ids == [winners[0].id]


@pytest.mark.parametrize("kind", list(Kind))
def test_add_waits_for_an_uncommitted_winner_and_concedes(
    migrated_database: Database, migrator: Engine, engine_for: EngineFor, kind: Kind
) -> None:
    """Deterministic overlap: a check-then-insert would see nothing, insert, and then fail on the
    unique index once the first writer commits. ON CONFLICT waits and concedes."""
    app = engine_for(migrated_database.app_url)
    registry = PostgresRegistry(app)
    slug = unique_slug()
    outcome: list[RegistryEntry | None] = []
    errors: list[BaseException] = []

    def second_writer() -> None:
        try:
            outcome.append(registry.add(kind, slug))
        except BaseException as error:  # noqa: BLE001 - reported by the assertion below.
            errors.append(error)

    # PostgreSQL shows another role's wait state only to a superuser, so the observer is the
    # test container's admin role; as the migrator, every wait would look like no wait.
    observer = engine_for(migrated_database.admin_url)
    thread = threading.Thread(target=second_writer)
    waited = False
    with app.connect() as first:
        transaction = first.begin()
        first.execute(text(f"INSERT INTO {TABLES[kind]} (slug) VALUES (:slug)"), {"slug": slug})
        thread.start()
        try:
            # Wait, without sleeping, until the second writer is blocked on the first one's row.
            for _ in range(500):
                with observer.connect() as connection:
                    waited = bool(
                        connection.execute(
                            text(
                                "SELECT count(*) FROM pg_stat_activity "
                                "WHERE usename = 'shiptrace_app' AND wait_event_type = 'Lock'"
                            )
                        ).scalar_one()
                    )
                if waited:
                    break
        finally:
            # Always release and join the second writer, so a failure cannot leak into other tests.
            transaction.commit()
            thread.join(timeout=30)
    assert waited, "the second writer never waited on the first"
    assert not thread.is_alive()
    assert errors == []
    assert outcome == [None]


def insert_credential(
    migrator: Engine, scope: str, expires: str = "NULL", revoked: str = "NULL"
) -> str:
    token = new_token()
    service = environment = None
    with migrator.begin() as connection:
        if scope == "ingest":
            service = connection.execute(
                text("INSERT INTO services (slug) VALUES (:s) RETURNING id"), {"s": unique_slug()}
            ).scalar_one()
            environment = connection.execute(
                text("INSERT INTO environments (slug) VALUES (:s) RETURNING id"),
                {"s": unique_slug()},
            ).scalar_one()
        # expires and revoked are fixed SQL expressions chosen by these tests, never input.
        connection.execute(
            text(
                "INSERT INTO api_credentials (name, scope, service_id, environment_id, "
                "secret_sha256, display_prefix, expires_at, revoked_at) VALUES "
                "('registry', :scope, :service, :environment, :digest, :prefix, "
                f"{expires}, {revoked})"
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
def client(migrated_database: Database, migrator: Engine) -> Iterator[TestClient]:
    settings = Settings.model_validate(
        {"environment": "test", "database_url": migrated_database.app_url}
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as test_client:
        yield test_client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


ROUTES = [(method, PATHS[kind]) for kind in Kind for method in ("GET", "POST")]


def call(client: TestClient, method: str, path: str, token: str) -> int:
    body = {"slug": unique_slug()} if method == "POST" else None
    return client.request(method, path, headers=bearer(token), json=body).status_code


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize(
    ("expires", "revoked"),
    [("now() - interval '1 second'", "NULL"), ("NULL", "now()")],
    ids=["expired", "revoked"],
)
def test_dead_admin_credentials_are_401_on_every_route(
    client: TestClient, migrator: Engine, method: str, path: str, expires: str, revoked: str
) -> None:
    token = insert_credential(migrator, "admin", expires, revoked)
    assert call(client, method, path, token) == 401


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_scopes_against_real_credentials(
    client: TestClient, migrator: Engine, method: str, path: str
) -> None:
    expected = {
        "admin": 201 if method == "POST" else 200,
        "read": 403 if method == "POST" else 200,
        "ingest": 403,
    }
    for scope, status in expected.items():
        assert call(client, method, path, insert_credential(migrator, scope)) == status, scope


def run_cli(url: str) -> str:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "shiptrace.bootstrap.cli",
            "create-admin-credential",
            "--name",
            "e2e",
        ],
        env={
            "PATH": os.environ["PATH"],
            "SHIPTRACE_ENVIRONMENT": "test",
            "SHIPTRACE_MIGRATOR_DATABASE_URL": url,
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_cp4_admin_credential_registers_and_lists(
    migrated_database: Database, migrator: Engine, client: TestClient
) -> None:
    token = run_cli(migrated_database.migrator_url)
    for kind in Kind:
        slug = unique_slug()
        created = client.post(PATHS[kind], headers=bearer(token), json={"slug": slug})
        assert created.status_code == 201
        assert created.json()["slug"] == slug
        duplicate = client.post(PATHS[kind], headers=bearer(token), json={"slug": slug})
        assert duplicate.status_code == 409
        assert duplicate.json()["code"] == "already_exists"
        listed: list[str] = []
        params: dict[str, str | int] = {"limit": 100}
        for _ in range(len(all_slugs(migrator, kind)) + 2):  # Bounded: never hangs.
            page = client.get(PATHS[kind], headers=bearer(token), params=params).json()
            listed += [item["slug"] for item in page["items"]]
            if page["next_cursor"] is None:
                break
            params["cursor"] = page["next_cursor"]
        else:
            raise AssertionError("pagination never reached the end")
        assert slug in listed
        assert listed == all_slugs(migrator, kind)
