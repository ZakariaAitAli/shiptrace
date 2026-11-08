"""Creating the first admin credential: the use case with a fake writer, and the CLI's refusals.

Nothing here reaches a database. Real PostgreSQL is in tests/integration/test_admin_cli.py.
"""

import sys
import uuid
from dataclasses import dataclass, field
from importlib.metadata import entry_points

import pytest

from shiptrace.application.credentials import (
    CredentialNotStored,
    InvalidCredentialName,
    WrongDatabaseRole,
    create_admin_credential,
)
from shiptrace.bootstrap import cli
from shiptrace.domain.credentials import digest, display_prefix, is_well_formed

MIGRATOR_URL = "postgresql+psycopg://shiptrace_migrator@127.0.0.1:1/shiptrace"
RUNTIME_URL = "postgresql+psycopg://shiptrace_app@127.0.0.1:1/shiptrace"


@dataclass
class FakeWriter:
    stored: list[tuple[str, bytes, str]] = field(default_factory=list)
    ids: list[uuid.UUID] = field(default_factory=list)
    fail: bool = False

    def add_admin(self, name: str, secret_digest: bytes, prefix: str) -> uuid.UUID:
        if self.fail:
            raise CredentialNotStored
        self.stored.append((name, secret_digest, prefix))
        self.ids.append(uuid.uuid4())
        return self.ids[-1]


def test_issues_a_well_formed_token_and_stores_only_its_digest() -> None:
    writer = FakeWriter()
    # Mixed case, a space and a dot: the name is stored exactly, never lowercased or trimmed.
    issued = create_admin_credential("Ops Team.1", writer)
    assert is_well_formed(issued.token)
    assert writer.stored == [("Ops Team.1", digest(issued.token), display_prefix(issued.token))]
    assert all(issued.token not in str(value) for value in writer.stored[0])
    assert issued.id == writer.ids[0]  # The id the database returned, not a new one.


def test_every_call_issues_a_new_token() -> None:
    writer = FakeWriter()
    tokens = {create_admin_credential("ops", writer).token for _ in range(20)}
    assert len(tokens) == 20


@pytest.mark.parametrize("name", ["", " ops", "ops\n", "a/b", "X" * 65])
def test_invalid_names_are_refused_before_anything_is_written(name: str) -> None:
    writer = FakeWriter()
    with pytest.raises(InvalidCredentialName):
        create_admin_credential(name, writer)
    assert writer.stored == []


def test_no_token_is_returned_when_the_write_fails() -> None:
    with pytest.raises(CredentialNotStored):
        create_admin_credential("ops", FakeWriter(fail=True))


def test_the_issued_credential_never_shows_its_token_in_repr() -> None:
    issued = create_admin_credential("ops", FakeWriter())
    assert issued.token not in repr(issued)
    assert issued.token not in str(issued)


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv("SHIPTRACE_ENVIRONMENT", "test")
    monkeypatch.setenv("SHIPTRACE_MIGRATOR_DATABASE_URL", MIGRATOR_URL)
    return monkeypatch


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["create-admin-credential"],
        ["create-admin-credential", "--name"],
        ["create-admin-credential", "--name", "ops", "--token", "chosen"],
        ["create-admin-credential", "--name", "ops", "--scope", "read"],
        ["create-admin-credential", "--name", "ops", "--service", "payments"],
        ["revoke-credential", "--name", "ops"],
    ],
)
def test_usage_errors_exit_2_and_write_nothing(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    """There is no way to choose a token or a scope, or to touch another credential."""
    environment.setattr(cli, "create_admin_credential", _must_not_run)
    with pytest.raises(SystemExit) as caught:
        cli.main(argv)
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""


def test_invalid_name_exits_2(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    environment.setattr(cli, "create_admin_credential", _must_not_run)
    assert cli.main(["create-admin-credential", "--name", " ops"]) == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("url", [RUNTIME_URL, None])
def test_runtime_role_or_missing_url_is_refused(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], url: str | None
) -> None:
    if url is None:
        environment.delenv("SHIPTRACE_MIGRATOR_DATABASE_URL")
    else:
        environment.setenv("SHIPTRACE_MIGRATOR_DATABASE_URL", url)
    environment.setattr(cli, "create_admin_credential", _must_not_run)
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert "refused" in output.err
    assert "st1_" not in output.err


def test_wrong_database_role_exits_3_without_a_traceback(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def wrong_role(name: str, writer: object) -> object:
        raise WrongDatabaseRole

    environment.setattr(cli, "create_admin_credential", wrong_role)
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 3
    output = capsys.readouterr()
    assert output.out == ""
    assert "refused" in output.err
    assert "Traceback" not in output.err


def test_uncertain_write_names_the_prefix_and_says_may(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A commit whose acknowledgement was lost may have stored an unusable credential."""

    def uncertain(name: str, writer: object) -> object:
        raise CredentialNotStored("st1_AbCd")

    environment.setattr(cli, "create_admin_credential", uncertain)
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 4
    output = capsys.readouterr()
    assert output.out == ""
    assert "may not have been stored" in output.err
    assert "st1_AbCd" in output.err


def test_application_attaches_the_prefix_to_a_failed_write() -> None:
    with pytest.raises(CredentialNotStored) as caught:
        create_admin_credential("ops", FakeWriter(fail=True))
    prefix = caught.value.display_prefix
    assert prefix is not None and len(prefix) == 8 and prefix.startswith("st1_")


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_missing_output_stream_is_refused_before_anything_is_written(
    environment: pytest.MonkeyPatch, stream: str
) -> None:
    """With fd 1 or 2 closed, Python sets the stream to None and print silently does nothing."""
    environment.setattr(cli, "create_admin_credential", _must_not_run)
    environment.setattr(sys, stream, None)
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 3


def test_token_that_cannot_be_written_is_reported_by_id(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    issued: list[object] = []

    def succeed(name: str, writer: object) -> object:
        result = create_admin_credential(name, FakeWriter())
        issued.append(result)
        return result

    class BrokenStdout:
        def write(self, text: str) -> int:
            raise BrokenPipeError

        def flush(self) -> None:
            raise BrokenPipeError

    environment.setattr(cli, "create_admin_credential", succeed)
    environment.setattr(sys, "stdout", BrokenStdout())
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 5
    error = capsys.readouterr().err
    assert str(issued[0].id) in error  # type: ignore[attr-defined]
    assert "could not be written" in error
    assert issued[0].token not in error  # type: ignore[attr-defined]
    assert "Traceback" not in error


def test_failed_write_prints_no_token(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(name: str, writer: object) -> object:
        raise CredentialNotStored

    environment.setattr(cli, "create_admin_credential", fail)
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 4
    output = capsys.readouterr()
    assert output.out == ""
    assert "st1_" not in output.err


def test_success_prints_the_token_once_on_stdout_only(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    issued: list[str] = []

    def succeed(name: str, writer: object) -> object:
        result = create_admin_credential(name, FakeWriter())
        issued.append(result.token)
        return result

    environment.setattr(cli, "create_admin_credential", succeed)
    assert cli.main(["create-admin-credential", "--name", "ops"]) == 0
    output = capsys.readouterr()
    assert output.out == issued[0] + "\n"
    assert issued[0] not in output.err


def test_console_command_is_installed() -> None:
    """`shiptrace create-admin-credential` needs this entry in pyproject.toml, then `uv sync`."""
    scripts = {entry.name: entry.value for entry in entry_points(group="console_scripts")}
    assert scripts.get("shiptrace") == "shiptrace.bootstrap.cli:main"


def _must_not_run(name: str, writer: object) -> object:
    raise AssertionError("nothing may be written")
