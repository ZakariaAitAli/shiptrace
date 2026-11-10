"""Deployments and their append-only events (P1 S4; ADR-0003 and ADR-0004).

An expand migration: two new tables, two trigger functions and their triggers. Nothing that exists
is altered, so the previous release keeps working on this schema. The tables are new and empty, so
no `lock_timeout` is needed beyond the one the Alembic environment already sets.

- `deployments` is an immutable identity row. `deployment_events` holds one row per event type per
  deployment, and at most one of the three terminal types (`succeeded`, `failed`, `cancelled`).
  The unique constraints and the partial unique index decide every race (ARCHITECTURE §4).
- Ids, `seq` and both timestamps come from the database. The runtime role may insert only the
  columns a client reports, so it cannot choose any of them; it has no UPDATE, DELETE or TRUNCATE.
- A second layer refuses UPDATE, DELETE and TRUNCATE for every role, the owner included, with fixed
  messages that carry no value (the ADR-0012 pattern: caller's rights, pinned search_path).
- `reverted` is refused unless the same deployment already holds a `succeeded` event. This is
  defense in depth for R9 and R10: events never change, so a bad one could never be corrected.
- CHECK constraints enforce a documented subset of the field formats in docs/PROJECT_SPEC.md §5.
  `deployment_key`, `version` and `commit_sha` follow their patterns exactly. For `source_url` the
  database checks only the length and the RFC 3986 character set, and for `reason` only the length
  and the absence of control and bidirectional override characters. Userinfo, ports, hosts, percent
  escapes and a second `#` are checked by the Python validators alone, which stay the authority.
- `received_at` is the database clock when the row was inserted (`clock_timestamp()`). Neither it
  nor `seq` is a commit order: a transaction can commit after another that inserted later.
- No history or metrics index is created here; P2 adds them once they can be measured.

The downgrade drops the tables and so loses their data: it undoes a fresh migration only, never a
release (ADR-0011).

Revision ID: 0004
Revises: 0003
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

DEPLOYMENT_KEY = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
VERSION = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"
COMMIT_SHA = r"^([0-9a-f]{40}|[0-9a-f]{64})$"
# RFC 3986 characters after https://; ']' first and '-' last are literals in a bracket expression,
# and the doubled quote is one quote inside the SQL literal.
SOURCE_URL = r"^https://[]A-Za-z0-9._~:/?#[@!$&''()*+,;=%-]+$"
# C0 controls except TAB and LF, DEL, C1 controls, and the bidirectional overrides and isolates.
REASON_UNSAFE = r"[\u0001-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]"

DEPLOYMENTS = f"""
CREATE TABLE deployments (
    id uuid NOT NULL DEFAULT uuidv7(),
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    deployment_key text COLLATE "C" NOT NULL,
    version text COLLATE "C" NOT NULL,
    commit_sha text COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT deployments_pkey PRIMARY KEY (id),
    CONSTRAINT deployments_identity_key
        UNIQUE (service_id, environment_id, deployment_key),
    CONSTRAINT deployments_service_fkey
        FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE RESTRICT,
    CONSTRAINT deployments_environment_fkey
        FOREIGN KEY (environment_id) REFERENCES environments (id) ON DELETE RESTRICT,
    CONSTRAINT deployments_deployment_key_format CHECK (deployment_key ~ '{DEPLOYMENT_KEY}'),
    CONSTRAINT deployments_version_format CHECK (version ~ '{VERSION}'),
    CONSTRAINT deployments_commit_sha_format CHECK (commit_sha ~ '{COMMIT_SHA}')
)
"""

EVENTS = f"""
CREATE TABLE deployment_events (
    seq bigint GENERATED ALWAYS AS IDENTITY,
    id uuid NOT NULL DEFAULT uuidv7(),
    deployment_id uuid NOT NULL,
    type text NOT NULL,
    source_url text COLLATE "C",
    reason text,
    credential_id uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT deployment_events_pkey PRIMARY KEY (seq),
    CONSTRAINT deployment_events_id_key UNIQUE (id),
    CONSTRAINT deployment_events_one_per_type UNIQUE (deployment_id, type),
    CONSTRAINT deployment_events_deployment_fkey
        FOREIGN KEY (deployment_id) REFERENCES deployments (id) ON DELETE RESTRICT,
    CONSTRAINT deployment_events_credential_fkey
        FOREIGN KEY (credential_id) REFERENCES api_credentials (id) ON DELETE RESTRICT,
    CONSTRAINT deployment_events_type
        CHECK (type IN ('started', 'succeeded', 'failed', 'cancelled', 'reverted')),
    CONSTRAINT deployment_events_source_url_format
        CHECK (source_url IS NULL
               OR (length(source_url) <= 2048 AND source_url ~ '{SOURCE_URL}')),
    CONSTRAINT deployment_events_reason_format
        CHECK (reason IS NULL
               OR (length(reason) BETWEEN 1 AND 500 AND reason !~ '{REASON_UNSAFE}'))
)
"""

TERMINAL_SLOT = """
CREATE UNIQUE INDEX deployment_events_one_terminal ON deployment_events (deployment_id)
WHERE type IN ('succeeded', 'failed', 'cancelled')
"""

# Runs with the caller's rights and a pinned search_path, and raises a fixed message, never a value.
APPEND_ONLY = """
CREATE FUNCTION deployment_records_append_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'deployment records are append-only'
        USING ERRCODE = 'restrict_violation';
END
$$
"""

# The table is schema-qualified because the pinned search_path excludes public. The caller needs
# SELECT on it, which the runtime role has. Under READ COMMITTED the subquery sees only committed
# rows and the caller's own, which is the visibility R9 relies on.
REVERT_GUARD = """
CREATE FUNCTION deployment_events_revert_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.type = 'reverted' AND NOT EXISTS (
        SELECT 1 FROM public.deployment_events e
        WHERE e.deployment_id = NEW.deployment_id AND e.type = 'succeeded'
    ) THEN
        RAISE EXCEPTION 'a revert requires a succeeded event on the same deployment'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$
"""


def upgrade() -> None:
    op.execute(DEPLOYMENTS)
    op.execute(EVENTS)
    op.execute(TERMINAL_SLOT)
    op.execute(
        "COMMENT ON COLUMN deployment_events.seq IS "
        "'Assigned when the row is inserted, not when it commits, so it is not the commit order'"
    )
    op.execute(
        "COMMENT ON COLUMN deployment_events.received_at IS "
        "'Database clock when the row was inserted. Not a commit order, and not unique'"
    )
    op.execute(APPEND_ONLY)
    op.execute(REVERT_GUARD)
    for table in ("deployments", "deployment_events"):
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION deployment_records_append_only()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION deployment_records_append_only()"
        )
    op.execute(
        "CREATE TRIGGER deployment_events_revert_guard BEFORE INSERT ON deployment_events "
        "FOR EACH ROW EXECUTE FUNCTION deployment_events_revert_guard()"
    )
    op.execute("GRANT SELECT ON deployments, deployment_events TO shiptrace_app")
    op.execute(
        "GRANT INSERT (service_id, environment_id, deployment_key, version, commit_sha) "
        "ON deployments TO shiptrace_app"
    )
    op.execute(
        "GRANT INSERT (deployment_id, type, source_url, reason, credential_id) "
        "ON deployment_events TO shiptrace_app"
    )


def downgrade() -> None:
    # Dropping a table drops its triggers and grants. Drops data: only for undoing a fresh
    # migration, never for rolling back a release (ADR-0011).
    op.execute("DROP TABLE deployment_events")
    op.execute("DROP TABLE deployments")
    op.execute("DROP FUNCTION deployment_events_revert_guard()")
    op.execute("DROP FUNCTION deployment_records_append_only()")
