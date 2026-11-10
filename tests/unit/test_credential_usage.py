"""Usage tracking in the credential store, with a scripted engine (no database).

What the database does with these statements is proved against PostgreSQL in
tests/integration/test_credential_usage.py. Here: which statements run, in what order, and that
a failed usage write never changes the outcome of authentication.
"""

import logging
import uuid
from types import TracebackType

import pytest
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from shiptrace.application.access import StoreUnavailable
from shiptrace.domain.credentials import Scope
from shiptrace.persistence.credentials import PostgresCredentialStore

CREDENTIAL = uuid.uuid4()


class Row:
    def __init__(self, stale: bool) -> None:
        self.id = CREDENTIAL
        self.scope = "read"
        self.service_id = None
        self.environment_id = None
        self.usage_stale = stale


class Result:
    def __init__(self, row: Row | None) -> None:
        self._row = row

    def one_or_none(self) -> Row | None:
        return self._row


class ScriptedConnection:
    def __init__(self, row: Row | None, fail_on: str | None, fail_rollback: bool) -> None:
        self._row, self._fail_on, self._fail_rollback = row, fail_on, fail_rollback
        self.calls: list[str] = []
        self.texts: list[str] = []

    def __enter__(self) -> ScriptedConnection:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, _: BaseException | None, __: TracebackType | None
    ) -> None:
        return None

    def execute(self, statement: object, _: object = None) -> Result:
        verb = str(statement).split()[0]
        self.calls.append(verb)
        self.texts.append(str(statement))
        if verb == self._fail_on:
            raise OperationalError("secret statement text", {"digest": b"secret"}, Exception("x"))
        return Result(self._row)

    def commit(self) -> None:
        self.calls.append("COMMIT")
        if self._fail_on == "COMMIT":
            raise OperationalError("commit", {}, Exception("x"))

    def rollback(self) -> None:
        self.calls.append("ROLLBACK")
        if self._fail_rollback:
            raise OperationalError("rollback", {}, Exception("x"))


class ScriptedEngine:
    def __init__(
        self, row: Row | None, fail_on: str | None = None, fail_rollback: bool = False
    ) -> None:
        self.connection = ScriptedConnection(row, fail_on, fail_rollback)

    def connect(self) -> ScriptedConnection:
        return self.connection


def store(engine: ScriptedEngine) -> PostgresCredentialStore:
    return PostgresCredentialStore(engine)  # type: ignore[arg-type]


def test_a_fresh_credential_is_looked_up_without_any_write() -> None:
    engine = ScriptedEngine(Row(stale=False))
    assert store(engine).find_active(b"d") is not None
    assert engine.connection.calls == ["SELECT", "COMMIT"]


def test_a_stale_credential_is_touched_in_a_new_transaction_after_the_lookup() -> None:
    engine = ScriptedEngine(Row(stale=True))
    principal = store(engine).find_active(b"d")
    assert principal is not None and principal.scope is Scope.READ
    # SET LOCAL sits inside the usage transaction, before the write and after the lookup's commit.
    assert engine.connection.calls == ["SELECT", "COMMIT", "SET", "UPDATE", "COMMIT"]


def test_the_lock_timeout_is_local_short_and_absent_from_the_lookup() -> None:
    engine = ScriptedEngine(Row(stale=True))
    store(engine).find_active(b"d")
    texts = engine.connection.texts
    assert texts[1] == "SET LOCAL lock_timeout = '100ms'"
    assert "lock_timeout" not in texts[0]


def test_a_fresh_credential_sets_no_lock_timeout() -> None:
    engine = ScriptedEngine(Row(stale=False))
    store(engine).find_active(b"d")
    assert not any("lock_timeout" in text for text in engine.connection.texts)


def test_a_lock_timeout_leaves_authentication_intact_and_logs_no_detail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine = ScriptedEngine(Row(stale=True), fail_on="UPDATE")
    with caplog.at_level(logging.WARNING):
        principal = store(engine).find_active(b"d")
    assert principal is not None and principal.id == CREDENTIAL
    assert engine.connection.calls == ["SELECT", "COMMIT", "SET", "UPDATE", "ROLLBACK"]
    assert "secret" not in caplog.text and "lock_timeout" not in caplog.text


def test_a_failed_set_skips_the_write_and_leaves_authentication_intact() -> None:
    engine = ScriptedEngine(Row(stale=True), fail_on="SET")
    assert store(engine).find_active(b"d") is not None
    assert engine.connection.calls == ["SELECT", "COMMIT", "SET", "ROLLBACK"]


def test_an_unknown_credential_is_never_touched() -> None:
    engine = ScriptedEngine(None)
    assert store(engine).find_active(b"d") is None
    assert "UPDATE" not in engine.connection.calls


@pytest.mark.parametrize("fail_rollback", [False, True])
def test_a_failed_touch_leaves_authentication_intact_and_logs_no_detail(
    caplog: pytest.LogCaptureFixture, fail_rollback: bool
) -> None:
    engine = ScriptedEngine(Row(stale=True), fail_on="UPDATE", fail_rollback=fail_rollback)
    with caplog.at_level(logging.WARNING):
        principal = store(engine).find_active(b"d")
    assert principal is not None and principal.id == CREDENTIAL
    assert engine.connection.calls[-2:] == ["UPDATE", "ROLLBACK"]
    assert [record.getMessage() for record in caplog.records] == ["credential usage not recorded"]
    assert all(record.exc_info is None for record in caplog.records)
    assert "secret" not in caplog.text


def test_a_failed_touch_commit_leaves_authentication_intact() -> None:
    """The commit whose acknowledgement is lost may or may not have stored the time."""
    engine = ScriptedEngine(Row(stale=True))
    connection = engine.connection
    original = connection.commit
    commits = []

    def commit() -> None:
        commits.append(1)
        original()
        if len(commits) == 2:
            raise OperationalError("lost", {}, Exception("x"))

    connection.commit = commit  # type: ignore[method-assign]
    assert store(engine).find_active(b"d") is not None


def test_a_failed_lookup_is_still_unavailable_and_carries_no_detail() -> None:
    engine = ScriptedEngine(Row(stale=True), fail_on="SELECT")
    with pytest.raises(StoreUnavailable) as caught:
        store(engine).find_active(b"d")
    assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True
    assert "UPDATE" not in engine.connection.calls


def test_the_scripted_errors_are_sqlalchemy_errors() -> None:
    """Guards the doubles above: a failure that is not a SQLAlchemyError would prove nothing."""
    assert issubclass(OperationalError, SQLAlchemyError)
