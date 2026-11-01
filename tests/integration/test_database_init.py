"""Roles, privileges, session limits and migrations against real PostgreSQL."""

from collections.abc import Callable

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, ProgrammingError

from shiptrace.persistence.engine import DatabaseOptions, build_engine
from shiptrace.persistence.migrate import downgrade, upgrade
from shiptrace.persistence.schema import expected_schema

from .conftest import Database, scalar

EngineFor = Callable[[str], Engine]


@pytest.mark.parametrize("role", ["shiptrace_app", "shiptrace_migrator"])
def test_runtime_roles_are_unprivileged(
    empty_database: Database, engine_for: EngineFor, role: str
) -> None:
    admin = engine_for(empty_database.admin_url)
    query = (
        "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls "
        f"FROM pg_roles WHERE rolname = '{role}'"
    )
    assert scalar(admin, query) is False


def test_wrong_password_is_refused(empty_database: Database, engine_for: EngineFor) -> None:
    engine = engine_for(empty_database.url("shiptrace_app", "wrong"))
    with pytest.raises(OperationalError):
        engine.connect()


def test_app_role_cannot_create_objects(empty_database: Database, engine_for: EngineFor) -> None:
    engine = engine_for(empty_database.app_url)
    with engine.connect() as connection, pytest.raises(ProgrammingError):
        connection.execute(text("CREATE TABLE intruder (id int)"))


def test_public_has_no_database_or_schema_privileges(
    empty_database: Database, engine_for: EngineFor
) -> None:
    admin = engine_for(empty_database.admin_url)
    with admin.begin() as connection:
        connection.execute(text("CREATE ROLE probe_public LOGIN PASSWORD 'probe'"))
    try:
        for privilege, target in (
            ("has_database_privilege('probe_public', 'shiptrace', 'CONNECT')", "database"),
            ("has_schema_privilege('probe_public', 'public', 'CREATE')", "schema"),
            ("has_schema_privilege('probe_public', 'public', 'USAGE')", "usage"),
        ):
            assert scalar(admin, f"SELECT {privilege}") is False, target
    finally:
        with admin.begin() as connection:
            connection.execute(text("DROP ROLE probe_public"))


def test_upgrade_downgrade_round_trip(empty_database: Database, engine_for: EngineFor) -> None:
    migrator = engine_for(empty_database.migrator_url)
    upgrade(empty_database.migrator_url)
    upgrade(empty_database.migrator_url)  # Running twice is a no-op.
    head = expected_schema().head
    assert scalar(migrator, "SELECT version_num FROM alembic_version") == head
    assert (
        scalar(
            migrator,
            "SELECT has_table_privilege('shiptrace_app', 'alembic_version', 'SELECT')",
        )
        is True
    )

    downgrade(empty_database.migrator_url, "base")
    assert scalar(migrator, "SELECT count(*) FROM alembic_version") == 0
    assert (
        scalar(
            migrator,
            "SELECT has_table_privilege('shiptrace_app', 'alembic_version', 'SELECT')",
        )
        is False
    )


def test_app_role_cannot_write_version_table(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    engine = engine_for(migrated_database.app_url)
    with engine.begin() as connection, pytest.raises(ProgrammingError):
        connection.execute(text("UPDATE alembic_version SET version_num = 'forged'"))


def test_built_engine_applies_session_limits(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    engine = build_engine(
        migrated_database.app_url,
        DatabaseOptions(
            pool_size=2,
            max_overflow=1,
            pool_timeout_seconds=3,
            statement_timeout_ms=4321,
            lock_timeout_ms=1234,
            connect_timeout_seconds=3,
        ),
    )
    try:
        assert scalar(engine, "SHOW statement_timeout") == "4321ms"
        assert scalar(engine, "SHOW lock_timeout") == "1234ms"
        assert scalar(engine, "SHOW idle_in_transaction_session_timeout") == "10s"
        assert engine.pool.size() == 2  # type: ignore[attr-defined]
    finally:
        engine.dispose()


def test_statement_timeout_actually_cancels_work(migrated_database: Database) -> None:
    engine = build_engine(
        migrated_database.app_url,
        DatabaseOptions(
            pool_size=1,
            max_overflow=0,
            pool_timeout_seconds=3,
            statement_timeout_ms=100,
            lock_timeout_ms=50,
            connect_timeout_seconds=3,
        ),
    )
    try:
        with engine.connect() as connection, pytest.raises(OperationalError):
            connection.execute(text("SELECT pg_sleep(5)"))
    finally:
        engine.dispose()
