"""`hide_parameters` on the production engine, against real PostgreSQL 18 (P1 gate F6).

Defense in depth, with its limit shown. SQLAlchemy can write bound values into two places: its SQL
log lines (when the `sqlalchemy.engine` logger is raised to INFO) and the text of the errors it
raises. `build_engine` turns that off. The stores do not depend on it, since they drop the error and
classify by SQLSTATE; this covers a path that does not go through them.

It is not a general guarantee. PostgreSQL and the driver can put a value in their own message, and
the statement text is still logged. The last test pins that boundary so nobody reads more into it.
Every statement is a read-only SELECT, so the shared database stays clean.
"""

import logging
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from shiptrace.persistence.engine import DatabaseOptions, build_engine

from .conftest import Database

SENTINEL = "sentinel-" + uuid.uuid4().hex
OPTIONS = DatabaseOptions(
    pool_size=2,
    max_overflow=0,
    pool_timeout_seconds=5,
    statement_timeout_ms=5000,
    lock_timeout_ms=2000,
    connect_timeout_seconds=5,
)
ECHO = text("SELECT CAST(:v AS text)")
FAILS_WITHOUT_ECHOING = text("SELECT length(CAST(:v AS text)) / 0")  # SQLSTATE 22012
FAILS_ECHOING = text("SELECT CAST(:v AS integer)")  # PostgreSQL names the value in its message


@pytest.fixture
def production(migrated_database: Database) -> Iterator[Engine]:
    engine = build_engine(migrated_database.app_url, OPTIONS)
    yield engine
    engine.dispose()


@pytest.fixture
def control(migrated_database: Database) -> Iterator[Engine]:
    """The same database with SQLAlchemy's default, which shows parameters."""
    engine = create_engine(migrated_database.app_url)
    yield engine
    engine.dispose()


def logged(engine: Engine, caplog: pytest.LogCaptureFixture) -> str:
    caplog.clear()
    # The level goes on the logger SQLAlchemy actually uses; caplog's default root level would
    # leave statement logging off and make this test see nothing.
    with caplog.at_level(logging.INFO, logger="sqlalchemy.engine"), engine.connect() as connection:
        connection.execute(ECHO, {"v": SENTINEL})
    return caplog.text


def test_the_control_engine_logs_the_value_so_the_test_can_see_it(
    control: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    output = logged(control, caplog)
    assert "SELECT CAST" in output  # Statement logging is on.
    assert SENTINEL in output  # And without the setting, the bound value is in it.


def test_the_production_engine_logs_the_statement_but_not_the_bound_value(
    production: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    output = logged(production, caplog)
    assert "SELECT CAST" in output  # Not vacuous: the same logging is on.
    assert SENTINEL not in output


def raised(engine: Engine, statement: object) -> str:
    with pytest.raises(DBAPIError) as caught, engine.connect() as connection:
        connection.execute(statement, {"v": SENTINEL})  # type: ignore[call-overload]
    return str(caught.value)


def test_an_error_names_the_parameters_only_on_the_control_engine(
    production: Engine, control: Engine
) -> None:
    shown = raised(control, FAILS_WITHOUT_ECHOING)
    assert "division by zero" in shown.lower()
    assert SENTINEL in shown and "[parameters:" in shown  # The control leaks, so the test can fail.
    hidden = raised(production, FAILS_WITHOUT_ECHOING)
    assert "division by zero" in hidden.lower()
    assert SENTINEL not in hidden and "[parameters:" not in hidden


def test_it_does_not_hide_a_value_that_postgresql_puts_in_its_own_message(
    production: Engine,
) -> None:
    """The limit. The driver's message carries the offending value, so `hide_parameters` cannot
    keep it out, and this is why the stores drop the SQLAlchemy error and classify by SQLSTATE."""
    message = raised(production, FAILS_ECHOING)
    assert "[parameters:" not in message  # SQLAlchemy's own listing is still hidden.
    assert SENTINEL in message  # PostgreSQL's is not.
