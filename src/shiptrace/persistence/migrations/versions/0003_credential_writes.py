"""Credential writes by the runtime role: restricted column grants and a guard trigger (ADR-0012).

An expand migration: grants, one trigger function and one trigger on an existing table, no table
rewrite. The S1 build never writes these columns, so it keeps working on this schema.

The runtime role may insert only the columns an issued credential needs, and may update only
revoked_at and last_used_at; id, created_at, scope and binding are never writable by it. Those
column grants decide which columns it may write; the guard decides which values, for every role
except the migrator, which owns the table and runs the bootstrap CLI:

- no admin credentials (admin comes only from the CLI);
- expires_at is NULL or now() plus 1 to 365 whole days of 24 hours (absolute time);
- revoked_at changes only from NULL to exactly now(), and never again;
- last_used_at becomes exactly now(), never earlier than its current value.

The function runs with the caller's rights (not SECURITY DEFINER) and pins its search_path, so no
object the caller can create is consulted. Refusals carry fixed messages, never values.

Revision ID: 0003
Revises: 0002
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

GUARD = """
CREATE FUNCTION api_credentials_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    lifetime numeric;
BEGIN
    IF current_user = 'shiptrace_migrator' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.scope = 'admin' THEN
            RAISE EXCEPTION 'admin credentials are issued only by the bootstrap command'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.expires_at IS NOT NULL THEN
            -- Absolute seconds, so a daylight-saving change in the session time zone cannot
            -- turn a whole number of days into 23 or 25 hours.
            lifetime := extract(epoch FROM NEW.expires_at - now());
            IF lifetime % 86400 <> 0 OR lifetime / 86400 NOT BETWEEN 1 AND 365 THEN
                RAISE EXCEPTION 'expiry must be a whole number of days from 1 to 365'
                    USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
        AND (OLD.revoked_at IS NOT NULL OR NEW.revoked_at <> now()) THEN
        RAISE EXCEPTION 'revocation is recorded once, at database time'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.last_used_at IS DISTINCT FROM OLD.last_used_at
        AND (NEW.last_used_at IS NULL OR NEW.last_used_at <> now()
             OR NEW.last_used_at < OLD.last_used_at) THEN
        RAISE EXCEPTION 'usage is recorded at database time and never moves back'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$
"""


def upgrade() -> None:
    op.execute(GUARD)
    op.execute(
        "CREATE TRIGGER api_credentials_guard BEFORE INSERT OR UPDATE ON api_credentials "
        "FOR EACH ROW EXECUTE FUNCTION api_credentials_guard()"
    )
    op.execute(
        "GRANT INSERT (name, scope, service_id, environment_id, secret_sha256, display_prefix, "
        "expires_at) ON api_credentials TO shiptrace_app"
    )
    op.execute("GRANT UPDATE (revoked_at, last_used_at) ON api_credentials TO shiptrace_app")


def downgrade() -> None:
    # Revoking table-level privileges also revokes the column privileges granted above.
    op.execute("REVOKE INSERT, UPDATE ON api_credentials FROM shiptrace_app")
    op.execute("DROP TRIGGER api_credentials_guard ON api_credentials")
    op.execute("DROP FUNCTION api_credentials_guard()")
