"""Alembic environment. Online mode only, with a bounded wait for locks."""

import os

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

LOCK_TIMEOUT_MS = 5000
CONNECT_TIMEOUT_SECONDS = 5


def run_migrations() -> None:
    if context.is_offline_mode():
        raise RuntimeError("offline migrations are not supported")
    url = context.config.attributes.get("url") or os.environ["SHIPTRACE_MIGRATOR_DATABASE_URL"]
    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={
            "connect_timeout": CONNECT_TIMEOUT_SECONDS,
            "options": f"-c lock_timeout={LOCK_TIMEOUT_MS}",
        },
    )
    with engine.connect() as connection:
        # Separate transactions, so an early lock is not held through later migrations.
        context.configure(
            connection=connection, target_metadata=None, transaction_per_migration=True
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


run_migrations()
