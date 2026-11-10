"""Migration 0004: deployments and deployment_events, against real PostgreSQL 18 (ADR-0003).

Every attempt is direct SQL, as a compromised runtime credential could send it, and every refusal is
checked by SQLSTATE and, where a trigger decides, by its fixed message. Writes run in rolled-back
transactions: the tables are append-only, so a committed row could never be removed again.

The database enforces a documented subset of the field formats. Where the Python validators are
stricter, a test says so; none of them claims the two are identical.
"""

import secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from shiptrace.domain.deployments import (
    Accept,
    DeploymentFacts,
    EventType,
    NewEvent,
    Reject,
    RejectReason,
    StoredEvent,
    decide,
)
from shiptrace.domain.event_fields import (
    is_valid_commit_sha,
    is_valid_deployment_key,
    is_valid_reason,
    is_valid_source_url,
    is_valid_version,
)
from shiptrace.persistence.migrate import downgrade, upgrade

from .conftest import Database, scalar

EngineFor = Callable[[str], Engine]

INSUFFICIENT_PRIVILEGE = "42501"
CHECK_VIOLATION = "23514"
UNIQUE_VIOLATION = "23505"
FOREIGN_KEY_VIOLATION = "23503"
RESTRICT_VIOLATION = "23001"
APPEND_ONLY = "deployment records are append-only"
REVERT_RULE = "a revert requires a succeeded event"

TABLES = ("deployments", "deployment_events")
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
VERSION = "1.4.2"
SHA = "0123456789abcdef0123456789abcdef01234567"

DEPLOYMENT_COLUMNS = {
    "id": ("uuid", "NO"),
    "service_id": ("uuid", "NO"),
    "environment_id": ("uuid", "NO"),
    "deployment_key": ("text", "NO"),
    "version": ("text", "NO"),
    "commit_sha": ("text", "NO"),
    "created_at": ("timestamp with time zone", "NO"),
}
EVENT_COLUMNS = {
    "seq": ("bigint", "NO"),
    "id": ("uuid", "NO"),
    "deployment_id": ("uuid", "NO"),
    "type": ("text", "NO"),
    "source_url": ("text", "YES"),
    "reason": ("text", "YES"),
    "credential_id": ("uuid", "NO"),
    "received_at": ("timestamp with time zone", "NO"),
}
COLUMNS = {"deployments": DEPLOYMENT_COLUMNS, "deployment_events": EVENT_COLUMNS}
# What the runtime role may insert; ids, seq and both timestamps always come from the database.
INSERTABLE = {
    "deployments": {"service_id", "environment_id", "deployment_key", "version", "commit_sha"},
    "deployment_events": {"deployment_id", "type", "source_url", "reason", "credential_id"},
}

CONSTRAINTS = {
    ("deployments", "deployments_pkey", "p"),
    ("deployments", "deployments_identity_key", "u"),
    ("deployments", "deployments_service_fkey", "f"),
    ("deployments", "deployments_environment_fkey", "f"),
    ("deployments", "deployments_deployment_key_format", "c"),
    ("deployments", "deployments_version_format", "c"),
    ("deployments", "deployments_commit_sha_format", "c"),
    ("deployment_events", "deployment_events_pkey", "p"),
    ("deployment_events", "deployment_events_id_key", "u"),
    ("deployment_events", "deployment_events_one_per_type", "u"),
    ("deployment_events", "deployment_events_deployment_fkey", "f"),
    ("deployment_events", "deployment_events_credential_fkey", "f"),
    ("deployment_events", "deployment_events_type", "c"),
    ("deployment_events", "deployment_events_source_url_format", "c"),
    ("deployment_events", "deployment_events_reason_format", "c"),
}
FOREIGN_KEYS = {
    "deployments_service_fkey": "services",
    "deployments_environment_fkey": "environments",
    "deployment_events_deployment_fkey": "deployments",
    "deployment_events_credential_fkey": "api_credentials",
}
# No history or metrics index yet (P2 adds them after measurement): only what constraints need.
INDEXES = {
    "deployments_pkey",
    "deployments_identity_key",
    "deployment_events_pkey",
    "deployment_events_id_key",
    "deployment_events_one_per_type",
    "deployment_events_one_terminal",
}
TRIGGERS = {
    "deployments_append_only",
    "deployments_no_truncate",
    "deployment_events_append_only",
    "deployment_events_no_truncate",
    "deployment_events_revert_guard",
}
FUNCTIONS = ("deployment_records_append_only", "deployment_events_revert_guard")


# Helpers


@contextmanager
def rolled_back(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()


def attempt(connection: Connection, statement: str, /, **params: object) -> tuple[str | None, str]:
    """Runs one statement in a savepoint: (None, "") on success, else (SQLSTATE, message)."""
    savepoint = connection.begin_nested()
    try:
        connection.execute(text(statement), params)
    except DBAPIError as error:
        savepoint.rollback()
        orig = error.orig
        message = orig.diag.message_primary or ""  # type: ignore[union-attr]
        return orig.sqlstate, message  # type: ignore[union-attr]
    savepoint.commit()
    return None, ""


def refused(
    connection: Connection, statement: str, state: str, message: str = "", /, **params: object
) -> None:
    got_state, got_message = attempt(connection, statement, **params)
    assert got_state == state, (statement, got_state, got_message)
    assert got_message.startswith(message), got_message


def token(prefix: str) -> str:
    return prefix + "-" + secrets.token_hex(6)


@dataclass(frozen=True)
class Target:
    service: object
    environment: object
    credential: object


def make_target(connection: Connection) -> Target:
    service = connection.execute(
        text("INSERT INTO services (slug) VALUES (:slug) RETURNING id"), {"slug": token("s")}
    ).scalar_one()
    environment = connection.execute(
        text("INSERT INTO environments (slug) VALUES (:slug) RETURNING id"), {"slug": token("e")}
    ).scalar_one()
    credential = connection.execute(
        text(
            "INSERT INTO api_credentials "
            "(name, scope, service_id, environment_id, secret_sha256, display_prefix) "
            "VALUES ('ci', 'ingest', :service, :environment, :digest, 'st1_AbCd') RETURNING id"
        ),
        {"service": service, "environment": environment, "digest": secrets.token_bytes(32)},
    ).scalar_one()
    return Target(service, environment, credential)


NEW_DEPLOYMENT = (
    "INSERT INTO deployments (service_id, environment_id, deployment_key, version, commit_sha) "
    "VALUES (:service, :environment, :key, :version, :sha)"
)
NEW_EVENT = (
    "INSERT INTO deployment_events (deployment_id, type, source_url, reason, credential_id) "
    "VALUES (:deployment, :type, :url, :reason, :credential)"
)


def add_deployment(
    connection: Connection,
    target: Target,
    key: str | None = None,
    version: str = VERSION,
    sha: str = SHA,
) -> object:
    return connection.execute(
        text(NEW_DEPLOYMENT + " RETURNING id"),
        {
            "service": target.service,
            "environment": target.environment,
            "key": key or token("k"),
            "version": version,
            "sha": sha,
        },
    ).scalar_one()


def event_params(
    target: Target,
    deployment: object,
    kind: str,
    url: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return {
        "deployment": deployment,
        "type": kind,
        "url": url,
        "reason": reason,
        "credential": target.credential,
    }


def add_event(
    connection: Connection,
    target: Target,
    deployment: object,
    kind: str,
    url: str | None = None,
    reason: str | None = None,
) -> object:
    return connection.execute(
        text(NEW_EVENT + " RETURNING id"), event_params(target, deployment, kind, url, reason)
    ).scalar_one()


@pytest.fixture
def app(migrated_database: Database, engine_for: EngineFor) -> Engine:
    return engine_for(migrated_database.app_url)


@pytest.fixture
def migrator(migrated_database: Database, engine_for: EngineFor) -> Engine:
    return engine_for(migrated_database.migrator_url)


@pytest.fixture
def admin(migrated_database: Database, engine_for: EngineFor) -> Engine:
    return engine_for(migrated_database.admin_url)


# Structure


def test_tables_are_owned_by_the_migrator(admin: Engine) -> None:
    for table in TABLES:
        owner = scalar(admin, f"SELECT tableowner FROM pg_tables WHERE tablename = '{table}'")
        assert owner == "shiptrace_migrator", table


@pytest.mark.parametrize("table", TABLES)
def test_columns_types_and_nullability_are_exactly_these(admin: Engine, table: str) -> None:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = :table"
            ),
            {"table": table},
        ).all()
    assert {name: (kind, nullable) for name, kind, nullable in rows} == COLUMNS[table]


def test_server_owned_columns_have_database_defaults(admin: Engine) -> None:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT table_name, column_name, column_default, is_identity, identity_generation "
                "FROM information_schema.columns WHERE table_schema = 'public' "
                "AND table_name IN ('deployments', 'deployment_events')"
            )
        ).all()
    found = {
        (table, column): (default, identity, mode)
        for table, column, default, identity, mode in rows
    }
    assert found[("deployments", "id")][0] == "uuidv7()"
    assert found[("deployments", "created_at")][0] == "now()"
    assert found[("deployment_events", "id")][0] == "uuidv7()"
    assert found[("deployment_events", "received_at")][0] == "clock_timestamp()"
    assert found[("deployment_events", "seq")] == (None, "YES", "ALWAYS")


def test_format_columns_use_the_c_collation(admin: Engine) -> None:
    """So ranges such as a-z mean ASCII code points, as in migration 0002."""
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT column_name, collation_name FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND table_name IN ('deployments', 'deployment_events') "
                "AND column_name IN ('deployment_key', 'version', 'commit_sha', 'source_url')"
            )
        ).all()
    assert {name: collation for name, collation in rows} == {
        "deployment_key": "C",
        "version": "C",
        "commit_sha": "C",
        "source_url": "C",
    }


def test_constraints_are_exactly_these(admin: Engine) -> None:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT conrelid::regclass::text, conname, contype::text FROM pg_constraint "
                "WHERE conrelid IN ('public.deployments'::regclass, "
                "'public.deployment_events'::regclass) AND contype IN ('p', 'u', 'f', 'c')"
            )
        ).all()
    assert {tuple(row) for row in rows} == CONSTRAINTS


def test_every_foreign_key_restricts_deletion(admin: Engine) -> None:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT conname, confrelid::regclass::text, confdeltype::text FROM pg_constraint "
                "WHERE contype = 'f' AND conrelid IN ('public.deployments'::regclass, "
                "'public.deployment_events'::regclass)"
            )
        ).all()
    assert {name: (target, action) for name, target, action in rows} == {
        name: (target, "r") for name, target in FOREIGN_KEYS.items()
    }


def test_indexes_are_only_those_the_constraints_need(admin: Engine) -> None:
    with admin.connect() as connection:
        names = set(
            connection.execute(
                text(
                    "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' "
                    "AND tablename IN ('deployments', 'deployment_events')"
                )
            ).scalars()
        )
    assert names == INDEXES


def test_the_terminal_slot_index_is_unique_and_partial(admin: Engine) -> None:
    with admin.connect() as connection:
        row = connection.execute(
            text(
                "SELECT indisunique, indpred IS NOT NULL FROM pg_index "
                "WHERE indexrelid = 'public.deployment_events_one_terminal'::regclass"
            )
        ).one()
    assert tuple(row) == (True, True)


def test_triggers_are_exactly_these_and_enabled(admin: Engine) -> None:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT tgname, tgenabled::text FROM pg_trigger WHERE NOT tgisinternal "
                "AND tgrelid IN ('public.deployments'::regclass, "
                "'public.deployment_events'::regclass)"
            )
        ).all()
    assert {name: state for name, state in rows} == {name: "O" for name in TRIGGERS}


def test_trigger_functions_run_with_caller_rights_and_a_pinned_search_path(admin: Engine) -> None:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT proname, prosecdef, proconfig, pg_get_userbyid(proowner) FROM pg_proc "
                "WHERE proname IN "
                "('deployment_records_append_only', 'deployment_events_revert_guard')"
            )
        ).all()
    assert {name for name, *_ in rows} == set(FUNCTIONS)
    for name, security_definer, config, owner in rows:
        assert security_definer is False, name
        assert config == ["search_path=pg_catalog, pg_temp"], name
        assert owner == "shiptrace_migrator", name


@pytest.mark.parametrize("column", ["seq", "received_at"])
def test_timestamps_and_seq_are_documented_as_not_a_commit_order(
    admin: Engine, column: str
) -> None:
    comment = scalar(
        admin,
        "SELECT col_description('public.deployment_events'::regclass, a.attnum) "
        "FROM pg_attribute a "
        f"WHERE a.attrelid = 'public.deployment_events'::regclass AND a.attname = '{column}'",
    )
    assert isinstance(comment, str) and "commit order" in comment.lower()


# Privileges


def test_runtime_table_privileges_are_select_only(admin: Engine) -> None:
    for table in TABLES:
        held = {
            privilege
            for privilege in PRIVILEGES
            if scalar(
                admin, f"SELECT has_table_privilege('shiptrace_app', '{table}', '{privilege}')"
            )
        }
        assert held == {"SELECT"}, table


@pytest.mark.parametrize("table", TABLES)
def test_runtime_column_privileges_are_exactly_the_approved_ones(admin: Engine, table: str) -> None:
    for column in COLUMNS[table]:
        for privilege, expected in (
            ("SELECT", True),
            ("INSERT", column in INSERTABLE[table]),
            ("UPDATE", False),
            ("REFERENCES", False),
        ):
            query = (
                "SELECT has_column_privilege("
                f"'shiptrace_app', '{table}', '{column}', '{privilege}')"
            )
            assert scalar(admin, query) is expected, f"{table}.{column} {privilege}"


def test_runtime_has_no_sequence_privilege_so_identity_needs_none(admin: Engine) -> None:
    sequence = scalar(admin, "SELECT pg_get_serial_sequence('deployment_events', 'seq')")
    assert isinstance(sequence, str)
    for privilege in ("USAGE", "SELECT", "UPDATE"):
        query = f"SELECT has_sequence_privilege('shiptrace_app', '{sequence}', '{privilege}')"
        assert scalar(admin, query) is False, privilege


def test_runtime_inserts_get_identity_ids_and_database_time(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = connection.execute(
            text(NEW_DEPLOYMENT + " RETURNING uuid_extract_version(id), created_at = now()"),
            {
                "service": target.service,
                "environment": target.environment,
                "key": token("k"),
                "version": VERSION,
                "sha": SHA,
            },
        ).one()
        assert tuple(deployment) == (7, True)
        deployment_id = add_deployment(connection, target)
        first = connection.execute(
            text(
                NEW_EVENT + " RETURNING seq, uuid_extract_version(id), "
                "received_at >= now(), received_at <= clock_timestamp()"
            ),
            event_params(target, deployment_id, "started"),
        ).one()
        second_seq = connection.execute(
            text(NEW_EVENT + " RETURNING seq"),
            event_params(target, deployment_id, "succeeded"),
        ).scalar_one()
    seq, version, not_before_start, not_after_now = first
    assert isinstance(seq, int) and version == 7
    assert not_before_start is True and not_after_now is True
    # Within one connection the identity advances; no claim is made about commit order.
    assert second_seq > seq


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO deployments (id, service_id, environment_id, deployment_key, version, "
        "commit_sha) VALUES (uuidv7(), :service, :environment, 'k', :version, :sha)",
        "INSERT INTO deployments (created_at, service_id, environment_id, deployment_key, version, "
        "commit_sha) VALUES (now() - interval '1 day', :service, :environment, 'k', "
        ":version, :sha)",
        "INSERT INTO deployment_events (id, deployment_id, type, credential_id) "
        "VALUES (uuidv7(), :deployment, 'started', :credential)",
        "INSERT INTO deployment_events (received_at, deployment_id, type, credential_id) "
        "VALUES (now() - interval '1 day', :deployment, 'started', :credential)",
        "INSERT INTO deployment_events (seq, deployment_id, type, credential_id) "
        "OVERRIDING SYSTEM VALUE VALUES (1, :deployment, 'started', :credential)",
    ],
    ids=["deployment-id", "created-at", "event-id", "received-at", "seq"],
)
def test_runtime_cannot_supply_server_owned_values(app: Engine, statement: str) -> None:
    unknown = "00000000-0000-7000-8000-000000000000"  # Privileges are checked before any row is.
    with rolled_back(app) as connection:
        refused(
            connection,
            statement,
            INSUFFICIENT_PRIVILEGE,
            service=unknown,
            environment=unknown,
            deployment=unknown,
            credential=unknown,
            version=VERSION,
            sha=SHA,
        )


@pytest.mark.parametrize("table", TABLES)
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE {table} SET id = id",
        "DELETE FROM {table}",
        "TRUNCATE {table}",
        "ALTER TABLE {table} ADD COLUMN intruder int",
        "ALTER TABLE {table} DISABLE TRIGGER ALL",
        "ALTER TABLE {table} DROP CONSTRAINT {table}_pkey CASCADE",
    ],
)
def test_runtime_cannot_change_remove_or_reshape_rows(
    app: Engine, table: str, statement: str
) -> None:
    with rolled_back(app) as connection:
        refused(connection, statement.format(table=table), INSUFFICIENT_PRIVILEGE)


def test_runtime_cannot_drop_the_guards(app: Engine) -> None:
    with rolled_back(app) as connection:
        refused(
            connection,
            "DROP TRIGGER deployment_events_revert_guard ON deployment_events",
            INSUFFICIENT_PRIVILEGE,
        )
        refused(
            connection,
            "DROP FUNCTION deployment_records_append_only() CASCADE",
            INSUFFICIENT_PRIVILEGE,
        )


# Append-only, for the owner as well


def test_the_owner_cannot_update_delete_or_truncate_either(migrator: Engine) -> None:
    with rolled_back(migrator) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        event = add_event(connection, target, deployment, "started")
        for statement in (
            "UPDATE deployments SET version = '9.9.9' WHERE id = :deployment",
            "DELETE FROM deployments WHERE id = :deployment",
            "UPDATE deployment_events SET reason = 'edited' WHERE id = :event",
            "DELETE FROM deployment_events WHERE id = :event",
            "TRUNCATE deployment_events",
            "TRUNCATE deployments CASCADE",
        ):
            refused(
                connection,
                statement,
                RESTRICT_VIOLATION,
                APPEND_ONLY,
                deployment=deployment,
                event=event,
            )
        stored = connection.execute(
            text(
                "SELECT version, count(*) FROM deployments d "
                "JOIN deployment_events e ON e.deployment_id = d.id "
                "WHERE d.id = :deployment GROUP BY version"
            ),
            {"deployment": deployment},
        ).one()
        assert tuple(stored) == (VERSION, 1)


@pytest.mark.parametrize(
    ("table", "column"),
    [("services", "service"), ("environments", "environment"), ("api_credentials", "credential")],
)
def test_referenced_registry_and_credential_rows_cannot_be_deleted(
    migrator: Engine, table: str, column: str
) -> None:
    with rolled_back(migrator) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        add_event(connection, target, deployment, "started")
        state, _ = attempt(
            connection,
            f"DELETE FROM {table} WHERE id = :id",
            id=getattr(target, column),
        )
    # RESTRICT reports a foreign key violation; the exact code is not what matters here.
    assert state in {FOREIGN_KEY_VIOLATION, RESTRICT_VIOLATION}, state


# Uniqueness: deployment identity, one event per type, one terminal event


def test_deployment_identity_is_unique_per_service_environment_and_key(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        other = make_target(connection)
        add_deployment(connection, target, key="run-1")
        params = {
            "service": target.service,
            "environment": target.environment,
            "key": "run-1",
            "version": VERSION,
            "sha": SHA,
        }
        refused(connection, NEW_DEPLOYMENT, UNIQUE_VIOLATION, **params)
        # The same key under another service or another environment is another deployment.
        add_deployment(
            connection, Target(other.service, target.environment, target.credential), "run-1"
        )
        add_deployment(
            connection, Target(target.service, other.environment, target.credential), "run-1"
        )
        add_deployment(connection, target, key="run-2")


def test_a_deployment_holds_at_most_one_event_of_each_type(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        other = add_deployment(connection, target)
        add_event(connection, target, deployment, "started")
        refused(
            connection, NEW_EVENT, UNIQUE_VIOLATION, **event_params(target, deployment, "started")
        )
        add_event(connection, target, other, "started")  # Another deployment, same type.
        add_event(connection, target, deployment, "succeeded")


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("succeeded", "failed"),
        ("succeeded", "cancelled"),
        ("failed", "succeeded"),
        ("cancelled", "failed"),
    ],
)
def test_a_deployment_holds_at_most_one_terminal_event(
    app: Engine, first: str, second: str
) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        add_event(connection, target, deployment, first)
        refused(connection, NEW_EVENT, UNIQUE_VIOLATION, **event_params(target, deployment, second))


def test_started_and_a_terminal_event_coexist_and_reverted_is_not_terminal(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        for kind in ("started", "succeeded", "reverted"):
            add_event(connection, target, deployment, kind)


def test_target_less_do_nothing_lets_both_unique_indexes_decide(app: Engine) -> None:
    """The shape ARCHITECTURE §4 relies on: no row, and no error, for either kind of loser."""
    statement = NEW_EVENT + " ON CONFLICT DO NOTHING RETURNING id"
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        first = connection.execute(
            text(statement), event_params(target, deployment, "succeeded")
        ).all()
        assert len(first) == 1
        same_type = connection.execute(
            text(statement), event_params(target, deployment, "succeeded", reason="again")
        ).all()
        other_terminal = connection.execute(
            text(statement), event_params(target, deployment, "failed")
        ).all()
        compatible = connection.execute(
            text(statement), event_params(target, deployment, "started")
        ).all()
        assert same_type == [] and other_terminal == []
        assert len(compatible) == 1
        count = connection.execute(
            text("SELECT count(*) FROM deployment_events WHERE deployment_id = :d"),
            {"d": deployment},
        ).scalar_one()
        assert count == 2


# The revert precondition


def test_a_revert_needs_a_succeeded_event_on_the_same_deployment(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        elsewhere = add_deployment(connection, target)
        add_event(connection, target, elsewhere, "succeeded")
        revert = event_params(target, deployment, "reverted")
        refused(connection, NEW_EVENT, CHECK_VIOLATION, REVERT_RULE, **revert)  # No events at all.
        add_event(connection, target, deployment, "started")
        refused(connection, NEW_EVENT, CHECK_VIOLATION, REVERT_RULE, **revert)  # Started only.
        add_event(connection, target, deployment, "succeeded")
        add_event(connection, target, deployment, "reverted")


@pytest.mark.parametrize("terminal", ["failed", "cancelled"])
def test_a_revert_after_failed_or_cancelled_is_refused(app: Engine, terminal: str) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        add_event(connection, target, deployment, terminal)
        refused(
            connection,
            NEW_EVENT,
            CHECK_VIOLATION,
            REVERT_RULE,
            **event_params(target, deployment, "reverted"),
        )


def test_the_revert_trigger_still_fires_with_do_nothing(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        refused(
            connection,
            NEW_EVENT + " ON CONFLICT DO NOTHING",
            CHECK_VIOLATION,
            REVERT_RULE,
            **event_params(target, deployment, "reverted"),
        )


STORED_WITHOUT_REVERT = [
    (EventType.STARTED,),
    (EventType.SUCCEEDED,),
    (EventType.FAILED,),
    (EventType.CANCELLED,),
    (EventType.STARTED, EventType.SUCCEEDED),
    (EventType.STARTED, EventType.FAILED),
    (EventType.STARTED, EventType.CANCELLED),
]


@pytest.mark.parametrize(
    "stored", STORED_WITHOUT_REVERT, ids=lambda s: "+".join(k.value for k in s)
)
def test_the_database_accepts_a_revert_exactly_when_the_domain_does(
    app: Engine, stored: tuple[EventType, ...]
) -> None:
    """Defense in depth must not disagree with R9 and R10 of the domain decision."""
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        events = []
        for kind in stored:
            events.append(
                StoredEvent(
                    id=add_event(connection, target, deployment, kind.value),
                    type=kind,
                    source_url=None,
                    reason=None,
                )
            )
        state, _ = attempt(connection, NEW_EVENT, **event_params(target, deployment, "reverted"))
    facts = DeploymentFacts(version=VERSION, commit_sha=SHA, events=tuple(events))
    decision = decide(NewEvent(EventType.REVERTED, VERSION, SHA, None, None), facts)
    if isinstance(decision, Accept):
        assert state is None
    else:
        assert isinstance(decision, Reject)
        assert decision.reason in {
            RejectReason.REVERT_REQUIRES_SUCCESS,
            RejectReason.REVERT_NOT_APPLICABLE,
        }
        assert state == CHECK_VIOLATION


# Format checks: a documented subset of the Python validators

DNS_CHARS = "k" * 128


def vectors(valid: list[str], invalid: list[str]) -> list[str]:
    return [*valid, *invalid]


KEY_VECTORS = vectors(
    ["gha-12345678-1", "a", "0", "Key", "A.b_c-d", DNS_CHARS, "9" + "-" * 127],
    [
        "",
        "k" * 129,
        "-a",
        ".a",
        "_a",
        "a b",
        "a/b",
        "a+b",
        "a\n",
        chr(0xE9),
        chr(0x430),
        chr(0xFF11),
    ],
)
VERSION_VECTORS = vectors(
    ["1.4.2", "v1.4.2", "1.4.2-rc.1", "1.4.2+build.5", "a", "v" * 128],
    ["", "v" * 129, "+1", "-1", ".1", "1 2", "1/2", "1:2", "1@2", "1\n", chr(0xE9), chr(0x430)],
)
SHA_VECTORS = vectors(
    [SHA, "0123456789abcdef" * 4, "f" * 40],
    ["", "0123abc", SHA[:39], SHA + "0", "A" + SHA[1:], "g" * 40, SHA + "\n", chr(0xFF11) * 40],
)


def deployment_row(**overrides: object) -> dict[str, object]:
    return {"key": token("k"), "version": VERSION, "sha": SHA} | overrides


@pytest.mark.parametrize(
    ("field", "vectors_", "valid"),
    [
        ("key", KEY_VECTORS, is_valid_deployment_key),
        ("version", VERSION_VECTORS, is_valid_version),
        ("sha", SHA_VECTORS, is_valid_commit_sha),
    ],
)
def test_deployment_fields_are_checked_exactly_like_the_domain_validators(
    app: Engine, field: str, vectors_: list[str], valid: Callable[[object], bool]
) -> None:
    """These three formats are enforced in full: both layers agree on every vector below."""
    with rolled_back(app) as connection:
        target = make_target(connection)
        for vector in vectors_:
            row = deployment_row(**{field: vector})
            if field != "key":
                row["key"] = token("k")
            state, message = attempt(
                connection,
                NEW_DEPLOYMENT,
                service=target.service,
                environment=target.environment,
                **row,
            )
            expected = None if valid(vector) else CHECK_VIOLATION
            assert state == expected, (field, vector, state, message)


URL_ACCEPTED = [
    None,
    "https://github.com/acme/payments/actions/runs/12345678",
    "https://ci.example.com:8443/job/pay/42?tab=log#step:3",
    "https://xn--bcher-kva.example/run/1",
    "https://[::1]:8443/x",
    "https://example.com/" + "a" * (2048 - len("https://example.com/")),
]
URL_REFUSED_BY_BOTH = [
    "",
    "http://example.com/",
    "HTTPS://example.com/",
    "https://",
    "https://example.com/a b",
    "https://example.com/a\\b",
    'https://example.com/a"b',
    "https://example.com/a<b",
    "https://example.com/" + chr(0xE9),
    "https://" + chr(0xFC) + ".example/",
    "https://example.com/" + "a" * (2049 - len("https://example.com/")),
]
# Within the database's character set and length, so it stores them; the domain refuses them.
URL_ONLY_THE_DOMAIN_REFUSES = [
    "https://user@example.com/",
    "https://example.com:99999/",
    "https://example.com/%zz",
    "https://example.com/%00",
    "https://999.1.1.1/",
    "https://exa_mple.com/",
    "https://example.com/#a#b",
]


def url_state(app: Engine, url: str | None) -> str | None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        state, _ = attempt(
            connection, NEW_EVENT, **event_params(target, deployment, "started", url=url)
        )
        return state


@pytest.mark.parametrize("url", URL_ACCEPTED)
def test_source_urls_both_layers_accept(app: Engine, url: str | None) -> None:
    assert is_valid_source_url(url)
    assert url_state(app, url) is None


@pytest.mark.parametrize("url", URL_REFUSED_BY_BOTH)
def test_source_urls_both_layers_refuse(app: Engine, url: str) -> None:
    assert not is_valid_source_url(url)
    assert url_state(app, url) == CHECK_VIOLATION


@pytest.mark.parametrize("url", URL_ONLY_THE_DOMAIN_REFUSES)
def test_the_database_source_url_check_is_deliberately_weaker_than_the_domain(
    app: Engine, url: str
) -> None:
    """Userinfo, ports, hosts, percent escapes and a second '#' are the domain's to refuse."""
    assert not is_valid_source_url(url)
    assert url_state(app, url) is None


CR = "\r"
DEL = chr(0x7F)
C1 = chr(0x85)
BIDI_OVERRIDE = chr(0x202E)
BIDI_ISOLATE = chr(0x2067)
LINE_SEPARATOR = chr(0x2028)
REASON_ACCEPTED = [
    None,
    "health check timed out after 300s",
    "line one\nline two",
    "col1\tcol2",
    "a",
    "a" * 500,
    "\U0001f600" * 500,
    chr(0x200E) + chr(0x200F) + LINE_SEPARATOR,
    "Zeit" + chr(0xFC) + "berschreitung",
]
REASON_REFUSED_BY_BOTH = [
    "",
    "a" * 501,
    "\U0001f600" * 501,
    "a" + CR + "b",
    "\x1b[31m",
    "\x0b",
    "\x01",
    DEL,
    C1,
    chr(0x9F),
    BIDI_OVERRIDE,
    chr(0x202A),
    BIDI_ISOLATE,
    chr(0x2069),
]


def reason_state(app: Engine, reason: str | None) -> str | None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        state, _ = attempt(
            connection, NEW_EVENT, **event_params(target, deployment, "started", reason=reason)
        )
        return state


@pytest.mark.parametrize("reason", REASON_ACCEPTED)
def test_reasons_both_layers_accept(app: Engine, reason: str | None) -> None:
    assert is_valid_reason(reason)
    assert reason_state(app, reason) is None


@pytest.mark.parametrize("reason", REASON_REFUSED_BY_BOTH)
def test_reasons_both_layers_refuse(app: Engine, reason: str) -> None:
    assert not is_valid_reason(reason)
    assert reason_state(app, reason) == CHECK_VIOLATION


BIDI_CODE_POINTS = [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]
NEXT_TO_THE_BIDI_RANGES = [0x2029, 0x202F, 0x2065, 0x206A]


@pytest.mark.parametrize("code_point", BIDI_CODE_POINTS, ids=lambda c: f"U+{c:04X}")
def test_every_bidirectional_override_and_isolate_is_refused(app: Engine, code_point: int) -> None:
    """The constraint's bracket expression is built with chr() in the migration source."""
    reason = "a" + chr(code_point) + "b"
    assert not is_valid_reason(reason)
    assert reason_state(app, reason) == CHECK_VIOLATION


@pytest.mark.parametrize("code_point", NEXT_TO_THE_BIDI_RANGES, ids=lambda c: f"U+{c:04X}")
def test_the_characters_next_to_the_bidirectional_ranges_are_accepted(
    app: Engine, code_point: int
) -> None:
    reason = "a" + chr(code_point) + "b"
    assert is_valid_reason(reason)
    assert reason_state(app, reason) is None


def test_event_type_is_checked(app: Engine) -> None:
    with rolled_back(app) as connection:
        target = make_target(connection)
        deployment = add_deployment(connection, target)
        for kind in ("", "Started", "progress", "succeeded ", "reverted\n"):
            state, _ = attempt(connection, NEW_EVENT, **event_params(target, deployment, kind))
            assert state == CHECK_VIOLATION, kind


# Migration


def table_exists(engine: Engine, table: str) -> bool:
    return scalar(engine, f"SELECT to_regclass('public.{table}') IS NOT NULL") is True


def function_count(engine: Engine) -> object:
    names = ", ".join(f"'{name}'" for name in FUNCTIONS)
    return scalar(engine, f"SELECT count(*) FROM pg_proc WHERE proname IN ({names})")


def test_0004_round_trip(empty_database: Database, engine_for: EngineFor) -> None:
    """Leaves the database empty, as the empty_database fixture requires."""
    migrator = engine_for(empty_database.migrator_url)
    upgrade(empty_database.migrator_url, "0004")
    upgrade(empty_database.migrator_url, "0004")  # Repeating it is a no-op.
    assert scalar(migrator, "SELECT version_num FROM alembic_version") == "0004"
    assert all(table_exists(migrator, table) for table in TABLES)
    assert function_count(migrator) == 2

    downgrade(empty_database.migrator_url, "0003")
    assert scalar(migrator, "SELECT version_num FROM alembic_version") == "0003"
    assert not any(table_exists(migrator, table) for table in TABLES)
    assert function_count(migrator) == 0
    # 0001 to 0003 are untouched: the registry, the credentials and their guard.
    assert all(
        table_exists(migrator, table) for table in ("services", "environments", "api_credentials")
    )
    assert (
        scalar(migrator, "SELECT count(*) FROM pg_proc WHERE proname = 'api_credentials_guard'")
        == 1
    )
    assert (
        scalar(migrator, "SELECT has_table_privilege('shiptrace_app', 'api_credentials', 'SELECT')")
        is True
    )

    upgrade(empty_database.migrator_url, "0004")
    assert all(table_exists(migrator, table) for table in TABLES)
    assert function_count(migrator) == 2
    app = engine_for(empty_database.app_url)
    with rolled_back(app) as connection:  # The grants come back with the tables.
        target = make_target(connection)
        add_event(connection, target, add_deployment(connection, target), "started")

    downgrade(empty_database.migrator_url, "base")
    with migrator.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
