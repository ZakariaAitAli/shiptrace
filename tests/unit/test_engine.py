"""The database engine's own settings (P1 gate F6). No database is needed: the engine is lazy."""

from shiptrace.persistence.engine import DatabaseOptions, build_engine

OPTIONS = DatabaseOptions(
    pool_size=2,
    max_overflow=0,
    pool_timeout_seconds=1,
    statement_timeout_ms=5000,
    lock_timeout_ms=2000,
    connect_timeout_seconds=2,
)
URL = "postgresql+psycopg://shiptrace_app@127.0.0.1:1/shiptrace"


def test_the_engine_hides_bind_parameters() -> None:
    """Defense in depth: SQLAlchemy then leaves the values out of its SQL log lines and out of the
    text of the errors it raises. The stores still drop the error itself; this covers any other
    path, such as a log level raised on the `sqlalchemy.engine` logger."""
    assert build_engine(URL, OPTIONS).hide_parameters is True


def test_every_wait_is_still_bounded() -> None:
    engine = build_engine(URL, OPTIONS)
    assert engine.pool.size() == OPTIONS.pool_size  # type: ignore[attr-defined]
    assert engine.pool.timeout() == OPTIONS.pool_timeout_seconds  # type: ignore[attr-defined]
