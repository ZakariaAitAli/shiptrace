"""Services, environments and API credentials, with least-privilege grants (P1 S1).

An expand migration: it only adds objects. Rules mirror docs/PROJECT_SPEC.md §5 and ADR-0005 in
the database, so a defect in the application cannot store what the spec forbids.

- Ids are UUIDv7 and timestamps are database time; the runtime role may insert only `slug`, so it
  cannot choose either.
- Text checks use the "C" collation, so ranges such as a-z are plain ASCII code points.
- Only a 32-byte SHA-256 digest of each token is stored, plus an 8-character display prefix.
- The runtime role reads api_credentials and writes nothing there. Admin credentials come from the
  bootstrap CLI under the migrator role; the runtime write model is decided before S2.

Revision ID: 0002
Revises: 0001
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

SLUG = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
CREDENTIAL_NAME = r"^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,62}[A-Za-z0-9])?$"
DISPLAY_PREFIX = r"^st1_[A-Za-z0-9_-]{4}$"


def registry_table(name: str) -> str:
    return f"""
        CREATE TABLE {name} (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            slug text COLLATE "C" NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT {name}_slug_key UNIQUE (slug),
            CONSTRAINT {name}_slug_format CHECK (slug ~ '{SLUG}' AND strpos(slug, '--') = 0)
        )
    """


def upgrade() -> None:
    op.execute(registry_table("services"))
    op.execute(registry_table("environments"))
    op.execute(
        f"""
        CREATE TABLE api_credentials (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            name text COLLATE "C" NOT NULL,
            scope text NOT NULL,
            service_id uuid REFERENCES services (id) ON DELETE RESTRICT,
            environment_id uuid REFERENCES environments (id) ON DELETE RESTRICT,
            secret_sha256 bytea NOT NULL,
            display_prefix text COLLATE "C" NOT NULL,
            expires_at timestamptz,
            revoked_at timestamptz,
            last_used_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT api_credentials_secret_sha256_key UNIQUE (secret_sha256),
            CONSTRAINT api_credentials_secret_sha256_length
                CHECK (octet_length(secret_sha256) = 32),
            CONSTRAINT api_credentials_scope CHECK (scope IN ('admin', 'read', 'ingest')),
            CONSTRAINT api_credentials_binding CHECK (
                CASE WHEN scope = 'ingest'
                    THEN service_id IS NOT NULL AND environment_id IS NOT NULL
                    ELSE service_id IS NULL AND environment_id IS NULL
                END
            ),
            CONSTRAINT api_credentials_name_format CHECK (name ~ '{CREDENTIAL_NAME}'),
            CONSTRAINT api_credentials_display_prefix_format
                CHECK (display_prefix ~ '{DISPLAY_PREFIX}')
        )
        """
    )
    op.execute("GRANT SELECT, INSERT (slug) ON services, environments TO shiptrace_app")
    op.execute("GRANT SELECT ON api_credentials TO shiptrace_app")


def downgrade() -> None:
    # Drops data: only for undoing a fresh migration, never for rolling back a release (ADR-0011).
    op.execute("DROP TABLE api_credentials")
    op.execute("DROP TABLE environments")
    op.execute("DROP TABLE services")
