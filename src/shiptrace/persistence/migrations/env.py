"""Alembic environment. Online mode only, with a bounded wait for locks."""

import os

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

LOCK_TIMEOUT_MS = 5000


def run_migrations() -> None:
    if context.is_offline_mode():
        raise RuntimeError("offline migrations are not supported")
    url = context.config.attributes.get("url") or os.environ["SHIPTRACE_MIGRATOR_DATABASE_URL"]
    engine = create_engine(
        url,
        poolclass=NullPool,
        connect_args={"options": f"-c lock_timeout={LOCK_TIMEOUT_MS}"},
    )
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


run_migrations()
