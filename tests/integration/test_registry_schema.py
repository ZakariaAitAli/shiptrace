"""Migration 0002: services, environments and api_credentials, against real PostgreSQL 18.

Every refusal is checked by SQLSTATE, so a test cannot pass because of an unrelated error, and every
write is rolled back, so the session database stays clean for other tests.
"""

import secrets
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from shiptrace.domain.names import is_valid_credential_name, is_valid_slug
from shiptrace.persistence.migrate import downgrade, upgrade

from .conftest import Database, scalar

EngineFor = Callable[[str], Engine]

INSUFFICIENT_PRIVILEGE = "42501"
CHECK_VIOLATION = "23514"
UNIQUE_VIOLATION = "23505"
FOREIGN_KEY_VIOLATION = "23503"

REGISTRY_TABLES = ("services", "environments")
NEW_TABLES = (*REGISTRY_TABLES, "api_credentials")
PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
    "MAINTAIN",
)
# Exactly what the runtime role holds at table level: reading only. Registration inserts are
# granted on the slug column alone, so ids and timestamps always come from the database.
RUNTIME_TABLE_PRIVILEGES = {table: {"SELECT"} for table in NEW_TABLES}

VALID_SLUGS = ["a", "0", "qa", "payments-api", "eu-west-1", "x" * 63, "a" + "-b" * 31]
INVALID_SLUGS = [
    "",
    "x" * 64,
    "Payments",
    "-api",
    "api-",
    "pay--ments",
    "pay_ments",
    "pay ments",
    "api\n",
    "p" + chr(0x0430) + "yments",  # Cyrillic a
    "api" + chr(0xFF11),  # full-width 1
    "caf" + chr(0x00E9),
]

CREDENTIAL_COLUMNS = {
    "id": "uuid",
    "name": "text",
    "scope": "text",
    "service_id": "uuid",
    "environment_id": "uuid",
    "secret_sha256": "bytea",
    "display_prefix": "text",
    "expires_at": "timestamp with time zone",
    "revoked_at": "timestamp with time zone",
    "last_used_at": "timestamp with time zone",
    "created_at": "timestamp with time zone",
}


@contextmanager
def rolled_back(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()


def refused(engine: Engine, statement: str, sqlstate: str, **params: object) -> None:
    with rolled_back(engine) as connection, pytest.raises(DBAPIError) as caught:
        connection.execute(text(statement), params)
    assert caught.value.orig.sqlstate == sqlstate  # type: ignore[union-attr]


def unique_slug() -> str:
    return "t-" + secrets.token_hex(6)


def credential(**overrides: object) -> Mapping[str, object]:
    row: dict[str, object] = {
        "name": "ci",
        "scope": "admin",
        "service_id": None,
        "environment_id": None,
        "secret_sha256": secrets.token_bytes(32),
        "display_prefix": "st1_AbC-",
    }
    row.update(overrides)
    return row


INSERT_CREDENTIAL = (
    "INSERT INTO api_credentials "
    "(name, scope, service_id, environment_id, secret_sha256, display_prefix) "
    "VALUES (:name, :scope, :service_id, :environment_id, :secret_sha256, :display_prefix)"
)


def test_tables_are_owned_by_the_migrator(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    admin = engine_for(migrated_database.admin_url)
    for table in NEW_TABLES:
        owner = scalar(admin, f"SELECT tableowner FROM pg_tables WHERE tablename = '{table}'")
        assert owner == "shiptrace_migrator", table


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_registration_gets_uuidv7_and_database_time(
    migrated_database: Database, engine_for: EngineFor, table: str
) -> None:
    app = engine_for(migrated_database.app_url)
    with rolled_back(app) as connection:
        row = connection.execute(
            text(
                f"INSERT INTO {table} (slug) VALUES (:slug) "
                "RETURNING uuid_extract_version(id) AS version, created_at = now() AS now"
            ),
            {"slug": unique_slug()},
        ).one()
    assert row.version == 7
    assert row.now is True


@pytest.mark.parametrize("table", REGISTRY_TABLES)
@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO {table} (id, slug) VALUES (uuidv7(), :slug)",
        "INSERT INTO {table} (slug, created_at) VALUES (:slug, now() - interval '1 day')",
    ],
)
def test_runtime_cannot_choose_ids_or_timestamps(
    migrated_database: Database, engine_for: EngineFor, table: str, statement: str
) -> None:
    app = engine_for(migrated_database.app_url)
    refused(app, statement.format(table=table), INSUFFICIENT_PRIVILEGE, slug=unique_slug())


@pytest.mark.parametrize("table", REGISTRY_TABLES)
@pytest.mark.parametrize("slug", VALID_SLUGS)
def test_valid_slugs_are_stored(
    migrated_database: Database, engine_for: EngineFor, table: str, slug: str
) -> None:
    assert is_valid_slug(slug)  # The database and the domain rule must agree.
    app = engine_for(migrated_database.app_url)
    with rolled_back(app) as connection:
        stored = connection.execute(
            text(f"INSERT INTO {table} (slug) VALUES (:slug) RETURNING slug"), {"slug": slug}
        ).scalar_one()
    assert stored == slug


@pytest.mark.parametrize("table", REGISTRY_TABLES)
@pytest.mark.parametrize("slug", INVALID_SLUGS)
def test_invalid_slugs_are_refused_by_the_database(
    migrated_database: Database, engine_for: EngineFor, table: str, slug: str
) -> None:
    assert not is_valid_slug(slug)
    app = engine_for(migrated_database.app_url)
    refused(app, f"INSERT INTO {table} (slug) VALUES (:slug)", CHECK_VIOLATION, slug=slug)


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_duplicate_slug_is_refused(
    migrated_database: Database, engine_for: EngineFor, table: str
) -> None:
    app = engine_for(migrated_database.app_url)
    slug = unique_slug()
    with rolled_back(app) as connection:
        connection.execute(text(f"INSERT INTO {table} (slug) VALUES (:slug)"), {"slug": slug})
        with pytest.raises(DBAPIError) as caught:
            connection.execute(text(f"INSERT INTO {table} (slug) VALUES (:slug)"), {"slug": slug})
    assert caught.value.orig.sqlstate == UNIQUE_VIOLATION  # type: ignore[union-attr]


def test_runtime_privileges_are_exactly_the_approved_ones(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    admin = engine_for(migrated_database.admin_url)
    for table in NEW_TABLES:
        held = {
            privilege
            for privilege in PRIVILEGES
            if scalar(
                admin, f"SELECT has_table_privilege('shiptrace_app', '{table}', '{privilege}')"
            )
        }
        assert held == RUNTIME_TABLE_PRIVILEGES[table], table
    for table in REGISTRY_TABLES:
        for column, insertable in (("slug", True), ("id", False), ("created_at", False)):
            query = f"SELECT has_column_privilege('shiptrace_app', '{table}', '{column}', 'INSERT')"
            assert scalar(admin, query) is insertable, f"{table}.{column}"
    # The credential column grants added by migration 0003 are pinned in test_credential_writes.


@pytest.mark.parametrize("table", REGISTRY_TABLES)
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE {table} SET slug = 'renamed'",
        "DELETE FROM {table}",
        "TRUNCATE {table}",
        "ALTER TABLE {table} ADD COLUMN intruder int",
        "ALTER TABLE {table} DROP CONSTRAINT {table}_slug_format",
    ],
)
def test_runtime_cannot_change_or_reshape_registry_tables(
    migrated_database: Database, engine_for: EngineFor, table: str, statement: str
) -> None:
    app = engine_for(migrated_database.app_url)
    refused(app, statement.format(table=table), INSUFFICIENT_PRIVILEGE)


@pytest.mark.parametrize(
    "statement",
    [
        INSERT_CREDENTIAL,  # An admin credential: refused by the 0003 guard, never by grants alone.
        "DELETE FROM api_credentials",
        "TRUNCATE api_credentials",
        "ALTER TABLE api_credentials DROP CONSTRAINT api_credentials_binding",
    ],
)
def test_runtime_cannot_issue_admin_or_remove_credentials(
    migrated_database: Database, engine_for: EngineFor, statement: str
) -> None:
    app = engine_for(migrated_database.app_url)
    refused(app, statement, INSUFFICIENT_PRIVILEGE, **credential())


def test_runtime_cannot_escalate(migrated_database: Database, engine_for: EngineFor) -> None:
    app = engine_for(migrated_database.app_url)
    refused(app, "SET ROLE shiptrace_migrator", INSUFFICIENT_PRIVILEGE)
    # Without grant option, PostgreSQL only warns and grants nothing; check the outcome.
    with app.begin() as connection:
        connection.execute(text("GRANT INSERT, UPDATE ON api_credentials TO shiptrace_app"))
        connection.execute(text("GRANT UPDATE ON services, environments TO shiptrace_app"))
    admin = engine_for(migrated_database.admin_url)
    for table, privilege in (
        ("api_credentials", "INSERT"),
        ("api_credentials", "UPDATE"),
        ("services", "UPDATE"),
        ("environments", "UPDATE"),
    ):
        query = f"SELECT has_table_privilege('shiptrace_app', '{table}', '{privilege}')"
        assert scalar(admin, query) is False, f"{table} {privilege}"


def test_credential_columns_hold_no_raw_token(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    """A new column would have to be added here on purpose, and reviewed."""
    admin = engine_for(migrated_database.admin_url)
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_name = 'api_credentials'"
            )
        ).all()
    columns: dict[str, str] = {name: data_type for name, data_type in rows}
    assert columns == CREDENTIAL_COLUMNS


@pytest.mark.parametrize("scope", ["admin", "read"])
def test_unbound_scopes_are_stored(
    migrated_database: Database, engine_for: EngineFor, scope: str
) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    with rolled_back(migrator) as connection:
        row = connection.execute(
            text(INSERT_CREDENTIAL + " RETURNING uuid_extract_version(id), created_at = now()"),
            credential(scope=scope),
        ).one()
    assert tuple(row) == (7, True)


def test_ingest_credential_bound_to_both_is_stored(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    with rolled_back(migrator) as connection:
        service = connection.execute(
            text("INSERT INTO services (slug) VALUES (:slug) RETURNING id"), {"slug": unique_slug()}
        ).scalar_one()
        environment = connection.execute(
            text("INSERT INTO environments (slug) VALUES (:slug) RETURNING id"),
            {"slug": unique_slug()},
        ).scalar_one()
        connection.execute(
            text(INSERT_CREDENTIAL),
            credential(scope="ingest", service_id=service, environment_id=environment),
        )


@contextmanager
def registry_ids(engine: Engine) -> Iterator[tuple[Connection, object, object]]:
    with rolled_back(engine) as connection:
        service = connection.execute(
            text("INSERT INTO services (slug) VALUES (:slug) RETURNING id"), {"slug": unique_slug()}
        ).scalar_one()
        environment = connection.execute(
            text("INSERT INTO environments (slug) VALUES (:slug) RETURNING id"),
            {"slug": unique_slug()},
        ).scalar_one()
        yield connection, service, environment


@pytest.mark.parametrize(
    ("scope", "bind_service", "bind_environment"),
    [
        ("ingest", False, False),
        ("ingest", True, False),
        ("ingest", False, True),
        ("admin", True, False),
        ("admin", False, True),
        ("admin", True, True),
        ("read", True, True),
    ],
)
def test_binding_must_match_the_scope(
    migrated_database: Database,
    engine_for: EngineFor,
    scope: str,
    bind_service: bool,
    bind_environment: bool,
) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    with registry_ids(migrator) as (connection, service, environment):
        row = credential(
            scope=scope,
            service_id=service if bind_service else None,
            environment_id=environment if bind_environment else None,
        )
        with pytest.raises(DBAPIError) as caught:
            connection.execute(text(INSERT_CREDENTIAL), row)
    assert caught.value.orig.sqlstate == CHECK_VIOLATION  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": "superuser"},
        {"scope": "Admin"},
        {"secret_sha256": bytes(31)},
        {"secret_sha256": bytes(33)},
        {"secret_sha256": b""},
        {"display_prefix": "st1_AbC"},
        {"display_prefix": "st1_AbC-D"},
        {"display_prefix": "st1_AbC-" + "A" * 39},  # a whole token in the prefix column
        {"display_prefix": "st2_AbC-"},
        {"name": ""},
        {"name": " ci"},
        {"name": "ci\n"},
        {"name": "X" * 65},
        {"name": "ci/prod"},  # forbidden characters in the middle, not only at the ends
        {"name": "ci\nprod"},
        {"name": "c" + chr(0x0430) + "i"},  # Cyrillic a
        {"name": "ci;prod"},
    ],
    ids=lambda overrides: "-".join(f"{key}={len(str(value))}" for key, value in overrides.items()),
)
def test_credential_values_are_checked_by_the_database(
    migrated_database: Database, engine_for: EngineFor, overrides: dict[str, object]
) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    refused(migrator, INSERT_CREDENTIAL, CHECK_VIOLATION, **credential(**overrides))


@pytest.mark.parametrize("name", ["a", "1st deploy", "GitHub Actions prod.v2_x-1", "X" * 64])
def test_valid_credential_names_are_stored(
    migrated_database: Database, engine_for: EngineFor, name: str
) -> None:
    assert is_valid_credential_name(name)  # The database and the domain rule must agree.
    migrator = engine_for(migrated_database.migrator_url)
    with rolled_back(migrator) as connection:
        stored = connection.execute(
            text(INSERT_CREDENTIAL + " RETURNING name"), credential(name=name)
        ).scalar_one()
    assert stored == name


def test_digests_are_unique(migrated_database: Database, engine_for: EngineFor) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    row = credential()
    with rolled_back(migrator) as connection:
        connection.execute(text(INSERT_CREDENTIAL), row)
        with pytest.raises(DBAPIError) as caught:
            connection.execute(text(INSERT_CREDENTIAL), {**row, "name": "other"})
    assert caught.value.orig.sqlstate == UNIQUE_VIOLATION  # type: ignore[union-attr]


def test_binding_must_reference_registered_rows(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    migrator = engine_for(migrated_database.migrator_url)
    with registry_ids(migrator) as (connection, _, environment):
        row = credential(
            scope="ingest",
            service_id="00000000-0000-7000-8000-000000000000",
            environment_id=environment,
        )
        with pytest.raises(DBAPIError) as caught:
            connection.execute(text(INSERT_CREDENTIAL), row)
    assert caught.value.orig.sqlstate == FOREIGN_KEY_VIOLATION  # type: ignore[union-attr]


def table_exists(engine: Engine, table: str) -> bool:
    return scalar(engine, f"SELECT to_regclass('public.{table}') IS NOT NULL") is True


def test_0002_downgrades_and_upgrades_again(
    empty_database: Database, engine_for: EngineFor
) -> None:
    """Leaves the database empty, as the empty_database fixture requires."""
    migrator = engine_for(empty_database.migrator_url)
    upgrade(empty_database.migrator_url, "0002")
    upgrade(empty_database.migrator_url, "0002")  # Repeating it is a no-op.
    assert all(table_exists(migrator, table) for table in NEW_TABLES)

    downgrade(empty_database.migrator_url, "0001")
    assert scalar(migrator, "SELECT version_num FROM alembic_version") == "0001"
    assert not any(table_exists(migrator, table) for table in NEW_TABLES)
    readable = "SELECT has_table_privilege('shiptrace_app', 'alembic_version', 'SELECT')"
    assert scalar(migrator, readable) is True  # 0001 is untouched.

    upgrade(empty_database.migrator_url, "0002")
    assert all(table_exists(migrator, table) for table in NEW_TABLES)
    app = engine_for(empty_database.app_url)
    with rolled_back(app) as connection:  # Grants come back with the tables.
        connection.execute(text("INSERT INTO services (slug) VALUES ('again')"))

    downgrade(empty_database.migrator_url, "base")
    with migrator.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
