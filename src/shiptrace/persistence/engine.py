"""Database engine with every wait bounded."""

from dataclasses import dataclass

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

IDLE_IN_TRANSACTION_TIMEOUT_MS = 10_000
POOL_RECYCLE_SECONDS = 1800
TCP_USER_TIMEOUT_MS = 5000  # statement_timeout is server-side; this bounds a silent network.


@dataclass(frozen=True)
class DatabaseOptions:
    pool_size: int
    max_overflow: int
    pool_timeout_seconds: int
    statement_timeout_ms: int
    lock_timeout_ms: int
    connect_timeout_seconds: int


def build_engine(url: str, options: DatabaseOptions) -> Engine:
    """Creates the engine lazily: the process starts even while the database is down."""
    session_options = (
        f"-c statement_timeout={options.statement_timeout_ms} "
        f"-c lock_timeout={options.lock_timeout_ms} "
        f"-c idle_in_transaction_session_timeout={IDLE_IN_TRANSACTION_TIMEOUT_MS}"
    )
    return create_engine(
        url,
        pool_size=options.pool_size,
        max_overflow=options.max_overflow,
        pool_timeout=options.pool_timeout_seconds,
        pool_recycle=POOL_RECYCLE_SECONDS,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": options.connect_timeout_seconds,
            "tcp_user_timeout": TCP_USER_TIMEOUT_MS,
            "options": session_options,
        },
    )
