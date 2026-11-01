"""Let the runtime role read the schema revision, which /readyz needs.

Revision ID: 0001
Revises:
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("GRANT SELECT ON alembic_version TO shiptrace_app")


def downgrade() -> None:
    op.execute("REVOKE SELECT ON alembic_version FROM shiptrace_app")
