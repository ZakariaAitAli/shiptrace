"""How the deployment store turns a database failure into one of two sanitized exceptions.

Classification uses the SQLSTATE, never the message text. Whatever the driver says, including the
statement, bound values and DETAIL, must not reach an exception chain or a log record.
"""

import logging
from dataclasses import dataclass

import pytest
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout

from shiptrace.application.access import InvariantFault, StoreUnavailable
from shiptrace.persistence.deployments import classify_database_error

SENTINEL = "SENTINEL-do-not-leak"


@dataclass
class Diag:
    constraint_name: str | None = None
    message_primary: str = SENTINEL
    message_detail: str = f"Key (reason)=({SENTINEL}) already exists."


class FakeDriverError(Exception):
    def __init__(self, sqlstate: str | None, constraint: str | None = None) -> None:
        super().__init__(SENTINEL)
        self.sqlstate = sqlstate
        self.diag = Diag(constraint_name=constraint)


def database_error(
    sqlstate: str | None, constraint: str | None = None, cls: type[DBAPIError] = DBAPIError
) -> DBAPIError:
    return cls(
        f"INSERT ... {SENTINEL}", {"reason": SENTINEL}, FakeDriverError(sqlstate, constraint)
    )


RETRYABLE = [
    "55P03",  # lock_timeout while waiting for a concurrent writer
    "57014",  # statement_timeout
    "57P01",  # admin shutdown
    "08006",  # connection failure
    "53300",  # too many connections
    "40001",  # serialization failure
    "40P01",  # deadlock detected
]
FAULTS = [
    ("23505", "deployment_events_one_per_type"),  # a conflict ON CONFLICT should have absorbed
    ("23505", "deployment_events_one_terminal"),
    ("23514", "deployment_events_reason_format"),  # a CHECK the validators should have caught
    ("23514", None),  # the revert guard: a trigger error carries no constraint name
    ("23001", None),  # the append-only trigger
    ("23503", "deployments_service_fkey"),
    ("42501", None),  # privilege
    ("22021", None),  # a character the encoding rejects
    ("XX000", None),
]


@pytest.mark.parametrize("sqlstate", RETRYABLE)
def test_waits_outages_and_overload_are_retryable(sqlstate: str) -> None:
    assert isinstance(classify_database_error(database_error(sqlstate)), StoreUnavailable)


@pytest.mark.parametrize(("sqlstate", "constraint"), FAULTS)
def test_constraint_trigger_and_other_failures_are_invariant_faults(
    sqlstate: str, constraint: str | None
) -> None:
    assert isinstance(classify_database_error(database_error(sqlstate, constraint)), InvariantFault)


@pytest.mark.parametrize("cls", [OperationalError, InterfaceError])
def test_a_driver_error_without_a_sqlstate_is_an_outage(cls: type[DBAPIError]) -> None:
    assert isinstance(classify_database_error(database_error(None, cls=cls)), StoreUnavailable)


def test_an_exhausted_pool_is_an_outage() -> None:
    assert isinstance(classify_database_error(PoolTimeout()), StoreUnavailable)


def test_a_non_driver_sqlalchemy_error_fails_closed() -> None:
    from sqlalchemy.exc import SQLAlchemyError

    assert isinstance(classify_database_error(SQLAlchemyError(SENTINEL)), InvariantFault)


def test_the_message_text_never_decides() -> None:
    """A fault whose message looks like a lock wait is still a fault, and the reverse."""
    fault = database_error("23514")
    fault.orig.diag.message_primary = "canceling statement due to lock timeout"  # type: ignore[union-attr]
    assert isinstance(classify_database_error(fault), InvariantFault)
    wait = database_error("55P03")
    wait.orig.diag.message_primary = "a revert requires a succeeded event"  # type: ignore[union-attr]
    assert isinstance(classify_database_error(wait), StoreUnavailable)


@pytest.mark.parametrize("sqlstate", [*RETRYABLE, "23505", "23514", "42501"])
def test_nothing_from_the_driver_travels_in_the_exception(
    sqlstate: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        result = classify_database_error(
            database_error(sqlstate, "deployment_events_reason_format")
        )
    assert result.__cause__ is None
    assert result.__context__ is None
    assert result.args == ()
    assert SENTINEL not in caplog.text
    assert SENTINEL not in repr(result)


def test_a_fault_leaves_a_trace_with_state_and_constraint_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        classify_database_error(database_error("23514", "deployment_events_reason_format"))
    assert caplog.records, "an invariant fault must leave a trace"
    assert "23514" in caplog.text
    assert "deployment_events_reason_format" in caplog.text
    assert SENTINEL not in caplog.text
