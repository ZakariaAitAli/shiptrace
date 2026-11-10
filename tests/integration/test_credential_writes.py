"""Migration 0003 (ADR-0012): the runtime role's credential writes, against real PostgreSQL 18.

Every attempt is direct SQL as shiptrace_app, as a compromised runtime credential could send, and
every refusal is checked by SQLSTATE. Writes run in rolled-back transactions unless they must be
committed to be seen; committed rows are removed by the fixture.
"""

import secrets
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from shiptrace.persistence.migrate import downgrade, upgrade

from .conftest import Database, scalar

EngineFor = Callable[[str], Engine]
INSUFFICIENT_PRIVILEGE = "42501"
CHECK_VIOLATION = "23514"
GUARD_FUNCTION = "api_credentials_guard"

# The runtime role's column privileges on api_credentials after 0003; anything else is refused.
INSERTABLE = {
    "name",
    "scope",
    "service_id",
    "environment_id",
    "secret_sha256",
    "display_prefix",
    "expires_at",
}
UPDATABLE = {"revoked_at", "last_used_at"}
COLUMNS = INSERTABLE | {"id", "created_at", "revoked_at", "last_used_at"}

ADMIN = "admin credentials are issued only"
EXPIRY = "expiry must be a whole number of days"
REVOCATION = "revocation is recorded once"
USAGE = "usage is recorded at database time"

INSERT = (
    "INSERT INTO api_credentials "
    "(name, scope, service_id, environment_id, secret_sha256, display_prefix, expires_at) "
    "VALUES ('ci', :scope, :service, :environment, :digest, 'st1_AbCd', {expires}) RETURNING id"
)


@contextmanager
def rolled_back(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()


def sqlstate(error: DBAPIError) -> str:
    return error.orig.sqlstate  # type: ignore[union-attr,no-any-return]


@pytest.fixture
def app(migrated_database: Database, engine_for: EngineFor) -> Engine:
    return engine_for(migrated_database.app_url)


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


def binding(connection: Connection) -> tuple[object, object]:
    service = connection.execute(
        text("INSERT INTO services (slug) VALUES (:s) RETURNING id"),
        {"s": "w-" + uuid.uuid4().hex[:10]},
    ).scalar_one()
    environment = connection.execute(
        text("INSERT INTO environments (slug) VALUES (:s) RETURNING id"),
        {"s": "w-" + uuid.uuid4().hex[:10]},
    ).scalar_one()
    return service, environment


def insert(
    connection: Connection,
    scope: str = "read",
    expires: str = "NULL",
    bound: tuple[object, object] = (None, None),
) -> object:
    # expires is one of the fixed SQL expressions these tests choose, never input.
    params = {
        "scope": scope,
        "service": bound[0],
        "environment": bound[1],
        "digest": secrets.token_bytes(32),
    }
    return connection.execute(text(INSERT.format(expires=expires)), params).scalar_one()


# reason, when given, is the start of the guard's fixed message: the refusal must come from that
# rule, not from another constraint or privilege error with the same SQLSTATE.
def refused(
    connection: Connection, statement: str, state: str, reason: str = "", **params: object
) -> None:
    savepoint = connection.begin_nested()
    with pytest.raises(DBAPIError) as caught:
        connection.execute(text(statement), params)
    savepoint.rollback()
    assert sqlstate(caught.value) == state, statement
    message = caught.value.orig.diag.message_primary  # type: ignore[union-attr]
    assert message is not None and message.startswith(reason), message


# Inserts


@pytest.mark.parametrize("scope", ["read", "ingest"])
def test_runtime_issues_read_and_ingest(app: Engine, migrator: Engine, scope: str) -> None:
    with rolled_back(app) as connection:
        bound = binding(connection) if scope == "ingest" else (None, None)
        credential = insert(connection, scope, bound=bound)
        row = connection.execute(
            text(
                "SELECT created_at = now() AS now, revoked_at, last_used_at, expires_at "
                "FROM api_credentials WHERE id = :id"
            ),
            {"id": credential},
        ).one()
    assert row.now is True
    assert (row.revoked_at, row.last_used_at, row.expires_at) == (None, None, None)


def test_runtime_cannot_issue_admin(app: Engine) -> None:
    with rolled_back(app) as connection:
        refused(
            connection,
            INSERT.format(expires="NULL"),
            INSUFFICIENT_PRIVILEGE,
            ADMIN,
            scope="admin",
            service=None,
            environment=None,
            digest=secrets.token_bytes(32),
        )


def test_migrator_still_issues_admin(migrator: Engine) -> None:
    """The bootstrap CLI path (CP4) is unchanged."""
    with rolled_back(migrator) as connection:
        insert(connection, "admin")


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("id", "uuidv7()"),
        ("created_at", "now() - interval '1 day'"),
        ("revoked_at", "now()"),
        ("last_used_at", "now()"),
    ],
)
def test_runtime_cannot_choose_server_columns(app: Engine, column: str, value: str) -> None:
    statement = (
        f"INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix, {column}) "
        f"VALUES ('ci', 'read', :digest, 'st1_AbCd', {value})"
    )
    with rolled_back(app) as connection:
        refused(connection, statement, INSUFFICIENT_PRIVILEGE, digest=secrets.token_bytes(32))


@pytest.mark.parametrize("days", [1, 30, 365])
@pytest.mark.parametrize("zone", ["UTC", "Europe/Paris"])  # Paris has daylight-saving changes.
def test_expiry_in_whole_days_from_now_is_accepted(app: Engine, days: int, zone: str) -> None:
    """The contract is absolute: 24-hour days, so the session time zone cannot matter."""
    with rolled_back(app) as connection:
        connection.execute(text(f"SET LOCAL TIME ZONE '{zone}'"))  # Fixed values, not input.
        credential = insert(connection, expires=f"now() + make_interval(hours => 24 * {days})")
        stored = connection.execute(
            text(
                "SELECT expires_at = now() + make_interval(hours => 24 * :days) "
                "FROM api_credentials WHERE id = :id"
            ),
            {"id": credential, "days": days},
        ).scalar_one()
    assert stored is True


@pytest.mark.parametrize(
    "expires",
    [
        "now()",
        "now() - interval '1 day'",
        "now() + interval '366 days'",
        "now() + interval '10 years'",
        "now() + interval '1 day 1 second'",
        "now() + interval '12 hours'",
        "now() + interval '1 day' - interval '1 microsecond'",
        "'2030-01-01T00:00:00Z'::timestamptz",
        "'infinity'::timestamptz",
        "'-infinity'::timestamptz",
    ],
)
def test_arbitrary_expiry_is_refused(app: Engine, expires: str) -> None:
    with rolled_back(app) as connection:
        refused(
            connection,
            INSERT.format(expires=expires),
            CHECK_VIOLATION,
            EXPIRY,
            scope="read",
            service=None,
            environment=None,
            digest=secrets.token_bytes(32),
        )


# Updates


def committed_credential(app: Engine) -> object:
    with app.begin() as connection:
        return insert(connection)


def test_revocation_takes_database_time_once(app: Engine, migrator: Engine) -> None:
    credential = committed_credential(app)
    with app.begin() as connection:
        connection.execute(
            text("UPDATE api_credentials SET revoked_at = now() WHERE id = :id"), {"id": credential}
        )
        assert connection.execute(
            text("SELECT revoked_at = now() FROM api_credentials WHERE id = :id"),
            {"id": credential},
        ).scalar_one()
    with rolled_back(app) as connection:
        for value in ("now()", "NULL", "now() - interval '1 day'"):
            refused(
                connection,
                f"UPDATE api_credentials SET revoked_at = {value} WHERE id = :id",
                CHECK_VIOLATION,
                REVOCATION,
                id=credential,
            )


@pytest.mark.parametrize(
    "value", ["now() - interval '1 second'", "now() + interval '1 day'", "'2030-01-01'"]
)
def test_revocation_time_cannot_be_chosen(app: Engine, migrator: Engine, value: str) -> None:
    credential = committed_credential(app)
    with rolled_back(app) as connection:
        refused(
            connection,
            f"UPDATE api_credentials SET revoked_at = {value} WHERE id = :id",
            CHECK_VIOLATION,
            REVOCATION,
            id=credential,
        )


def test_usage_time_is_database_time(app: Engine, migrator: Engine) -> None:
    credential = committed_credential(app)
    with rolled_back(app) as connection:
        connection.execute(
            text("UPDATE api_credentials SET last_used_at = now() WHERE id = :id"),
            {"id": credential},
        )
        for value in ("now() - interval '1 second'", "now() + interval '1 day'", "NULL"):
            refused(
                connection,
                f"UPDATE api_credentials SET last_used_at = {value} WHERE id = :id",
                CHECK_VIOLATION,
                USAGE,
                id=credential,
            )


def test_usage_time_never_goes_back(app: Engine, migrator: Engine) -> None:
    """A later value already stored cannot be replaced by an earlier now()."""
    credential = committed_credential(app)
    with migrator.begin() as connection:
        connection.execute(
            text(
                "UPDATE api_credentials SET last_used_at = now() + interval '1 hour' WHERE id = :id"
            ),
            {"id": credential},
        )
    with rolled_back(app) as connection:
        refused(
            connection,
            "UPDATE api_credentials SET last_used_at = now() WHERE id = :id",
            CHECK_VIOLATION,
            USAGE,
            id=credential,
        )


@pytest.mark.parametrize(
    "assignment",
    [
        "scope = 'admin'",
        "scope = 'ingest'",
        "service_id = NULL",
        "environment_id = NULL",
        "name = 'renamed'",
        "secret_sha256 = :digest",
        "display_prefix = 'st1_XXXX'",
        "expires_at = NULL",
        "created_at = now()",
        "id = uuidv7()",
    ],
)
def test_runtime_cannot_change_identity_scope_or_binding(
    app: Engine, migrator: Engine, assignment: str
) -> None:
    with app.begin() as connection:
        credential = insert(connection, "ingest", bound=binding(connection))
    with rolled_back(app) as connection:
        refused(
            connection,
            f"UPDATE api_credentials SET {assignment} WHERE id = :id",
            INSUFFICIENT_PRIVILEGE,
            id=credential,
            digest=secrets.token_bytes(32),
        )


# Bypass attempts


# Upserts, MERGE and a combined update fire the same row trigger as a plain write. :existing is the
# committed credential's digest, so the upserts conflict; :fresh is new, so MERGE inserts.
OTHER_WRITE_PATHS = {
    "upsert revoked_at": (
        "INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix) "
        "VALUES ('ci', 'read', :existing, 'st1_AbCd') "
        "ON CONFLICT (secret_sha256) DO UPDATE SET revoked_at = '2000-01-01'",
        CHECK_VIOLATION,
        REVOCATION,
    ),
    "upsert last_used_at": (
        "INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix) "
        "VALUES ('ci', 'read', :existing, 'st1_AbCd') "
        "ON CONFLICT (secret_sha256) DO UPDATE SET last_used_at = '2000-01-01'",
        CHECK_VIOLATION,
        USAGE,
    ),
    "merge update": (
        "MERGE INTO api_credentials c USING (SELECT CAST(:id AS uuid) AS id) s "
        "ON c.id = s.id WHEN MATCHED THEN UPDATE SET revoked_at = '2000-01-01'",
        CHECK_VIOLATION,
        REVOCATION,
    ),
    "merge insert": (
        "MERGE INTO api_credentials c USING (SELECT uuidv7() AS id) s ON c.id = s.id "
        "WHEN NOT MATCHED THEN INSERT (name, scope, secret_sha256, display_prefix) "
        "VALUES ('ci', 'admin', :fresh, 'st1_AbCd')",
        INSUFFICIENT_PRIVILEGE,
        ADMIN,
    ),
    "both": (
        "UPDATE api_credentials SET revoked_at = now(), last_used_at = '2000-01-01' WHERE id = :id",
        CHECK_VIOLATION,
        USAGE,
    ),
}


@pytest.mark.parametrize("path", OTHER_WRITE_PATHS)
def test_other_write_paths_meet_the_same_guard(app: Engine, migrator: Engine, path: str) -> None:
    statement, state, reason = OTHER_WRITE_PATHS[path]
    credential = committed_credential(app)
    with app.connect() as connection:
        existing = connection.execute(
            text("SELECT secret_sha256 FROM api_credentials WHERE id = :id"), {"id": credential}
        ).scalar_one()
    params = {"id": credential, "existing": existing, "fresh": secrets.token_bytes(32)}
    with rolled_back(app) as connection:
        refused(connection, statement, state, reason, **params)


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM api_credentials",
        "TRUNCATE api_credentials",
        f"ALTER TABLE api_credentials DISABLE TRIGGER {GUARD_FUNCTION}",
        "ALTER TABLE api_credentials DISABLE TRIGGER ALL",
        f"DROP TRIGGER {GUARD_FUNCTION} ON api_credentials",
        f"DROP FUNCTION {GUARD_FUNCTION}()",
        f"CREATE OR REPLACE FUNCTION {GUARD_FUNCTION}() RETURNS trigger "
        "LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
        "SET session_replication_role = replica",  # would skip ordinary triggers
        "CREATE FUNCTION pg_temp.now() RETURNS timestamptz LANGUAGE sql AS 'SELECT now()'",
    ],
)
def test_runtime_cannot_disable_or_replace_the_guard(app: Engine, statement: str) -> None:
    with rolled_back(app) as connection:
        refused(connection, statement, INSUFFICIENT_PRIVILEGE)


def test_guard_function_is_pinned_and_runs_with_the_callers_rights(migrator: Engine) -> None:
    with migrator.connect() as connection:
        row = connection.execute(
            text(
                "SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) AS owner "
                "FROM pg_proc p WHERE p.proname = :name"
            ),
            {"name": GUARD_FUNCTION},
        ).one()
        executable = connection.execute(
            text(f"SELECT has_function_privilege('shiptrace_app', '{GUARD_FUNCTION}()', 'EXECUTE')")
        ).scalar_one()
    assert row.prosecdef is False  # not SECURITY DEFINER
    assert row.owner == "shiptrace_migrator"
    assert row.proconfig == ["search_path=pg_catalog, pg_temp"]
    assert executable is False


def test_runtime_privilege_matrix_is_exact(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    admin = engine_for(migrated_database.admin_url)
    for column in COLUMNS:
        for privilege, allowed in (("INSERT", INSERTABLE), ("UPDATE", UPDATABLE)):
            query = (
                "SELECT has_column_privilege('shiptrace_app', 'api_credentials', "
                f"'{column}', '{privilege}')"
            )
            assert scalar(admin, query) is (column in allowed), f"{column} {privilege}"
    for privilege, expected in (
        ("SELECT", True),
        ("INSERT", False),
        ("UPDATE", False),
        ("DELETE", False),
        ("TRUNCATE", False),
        ("REFERENCES", False),
        ("TRIGGER", False),
        ("MAINTAIN", False),
    ):
        query = f"SELECT has_table_privilege('shiptrace_app', 'api_credentials', '{privilege}')"
        assert scalar(admin, query) is expected, privilege


# Migration


def test_0003_round_trip(empty_database: Database, engine_for: EngineFor) -> None:
    """Leaves the database empty, as the empty_database fixture requires."""
    migrator = engine_for(empty_database.migrator_url)
    insertable = (
        "SELECT has_column_privilege('shiptrace_app', 'api_credentials', 'scope', 'INSERT')"
    )
    guard = f"SELECT count(*) FROM pg_proc WHERE proname = '{GUARD_FUNCTION}'"
    upgrade(empty_database.migrator_url, "0003")
    upgrade(empty_database.migrator_url, "0003")  # Repeating it is a no-op.
    assert scalar(migrator, insertable) is True
    assert scalar(migrator, guard) == 1

    downgrade(empty_database.migrator_url, "0002")
    assert scalar(migrator, "SELECT version_num FROM alembic_version") == "0002"
    assert scalar(migrator, insertable) is False
    for column in UPDATABLE:
        updatable = (
            f"SELECT has_column_privilege('shiptrace_app', 'api_credentials', '{column}', 'UPDATE')"
        )
        assert scalar(migrator, updatable) is False, column
    assert scalar(migrator, guard) == 0
    assert (
        scalar(migrator, "SELECT has_table_privilege('shiptrace_app', 'api_credentials', 'SELECT')")
        is True
    )  # 0002's grant is untouched.

    upgrade(empty_database.migrator_url, "0003")
    assert scalar(migrator, guard) == 1
    downgrade(empty_database.migrator_url, "base")
    with migrator.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
