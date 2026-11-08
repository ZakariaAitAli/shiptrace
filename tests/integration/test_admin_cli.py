"""`shiptrace create-admin-credential` against real PostgreSQL 18: a real process, the migrator
role, digest-only storage, and the new token authenticating through the CP3 path."""

import base64
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterator

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine

from shiptrace.api.auth import require
from shiptrace.application.credentials import CredentialNotStored, WrongDatabaseRole
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import (
    TOKEN_PREFIX,
    Action,
    digest,
    display_prefix,
    is_well_formed,
)
from shiptrace.persistence.credentials import PostgresAdminCredentialWriter

from .conftest import Database

EngineFor = Callable[[str], Engine]
UNREACHABLE = "postgresql+psycopg://shiptrace_migrator@127.0.0.1:1/shiptrace"
# Never in stderr. The 8-character display prefix may be, by design; a whole token may not.
LEAK_MARKERS = ("psycopg", "SELECT", "INSERT", "sqlalchemy", "Traceback")
WHOLE_TOKEN = re.compile(r"st1_[A-Za-z0-9_-]{43}")
NAME = "Ops Team.1"  # Mixed case, a space and a dot: stored exactly, never normalized.


def run_cli(url: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "SHIPTRACE_ENVIRONMENT": "test",
        "SHIPTRACE_MIGRATOR_DATABASE_URL": url,
    }
    return subprocess.run(
        [sys.executable, "-m", "shiptrace.bootstrap.cli", *arguments],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def create(database: Database, name: str = NAME) -> subprocess.CompletedProcess[str]:
    return run_cli(database.migrator_url, "create-admin-credential", "--name", name)


@pytest.fixture
def migrator(migrated_database: Database, engine_for: EngineFor) -> Iterator[Engine]:
    """Removes every credential the test adds, so the session database stays as it was."""
    engine = engine_for(migrated_database.migrator_url)
    with engine.connect() as connection:
        before = set(connection.execute(text("SELECT id FROM api_credentials")).scalars())
    yield engine
    with engine.begin() as connection:
        for row_id in connection.execute(text("SELECT id FROM api_credentials")).scalars():
            if row_id not in before:
                connection.execute(
                    text("DELETE FROM api_credentials WHERE id = :id"), {"id": row_id}
                )


def credential_rows(engine: Engine) -> list[dict[str, object]]:
    with engine.connect() as connection:
        rows = connection.execute(text("SELECT * FROM api_credentials ORDER BY id")).mappings()
        return [dict(row) for row in rows]


def created_token(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 1, "exactly one line, the token, on stdout"
    assert is_well_formed(lines[0])
    assert lines[0] not in result.stderr
    return lines[0]


def authenticates_as_admin(database: Database, token: str) -> bool:
    settings = Settings.model_validate({"environment": "test", "database_url": database.app_url})
    app = create_app(settings)

    def register() -> dict[str, str]:
        return {"status": "ok"}

    app.add_api_route(
        "/api/v1/_probe",
        register,
        methods=["POST"],
        dependencies=[Depends(require(Action.REGISTER))],
    )
    with TestClient(app) as client:
        response = client.post("/api/v1/_probe", headers={"Authorization": f"Bearer {token}"})
    return response.status_code == 200


def test_creates_one_admin_credential_storing_only_its_digest(
    migrated_database: Database, migrator: Engine
) -> None:
    before = credential_rows(migrator)
    result = create(migrated_database)
    token = created_token(result)
    new = [row for row in credential_rows(migrator) if row not in before]
    assert len(new) == 1
    row = new[0]
    assert row["name"] == NAME
    assert row["scope"] == "admin"
    assert (row["service_id"], row["environment_id"]) == (None, None)
    stored = row["secret_sha256"]
    assert isinstance(stored, bytes) and stored == digest(token)
    assert row["display_prefix"] == display_prefix(token)
    assert (row["expires_at"], row["revoked_at"], row["last_used_at"]) == (None, None, None)
    assert str(row["id"]) in result.stderr  # The operator is told the real id, for revocation.


def token_forms(token: str) -> list[str]:
    """The token and its secret in every encoding a careless change might store."""
    secret = base64.urlsafe_b64decode(token.removeprefix(TOKEN_PREFIX) + "=")
    return [
        token.removeprefix(TOKEN_PREFIX),
        token.encode().hex(),
        secret.hex(),
        base64.b64encode(secret).decode().rstrip("="),
        base64.urlsafe_b64encode(secret).decode().rstrip("="),
    ]


def test_no_column_in_any_table_holds_the_raw_token(
    migrated_database: Database, migrator: Engine
) -> None:
    token = created_token(create(migrated_database))
    with migrator.connect() as connection:
        tables = (
            connection.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
            .scalars()
            .all()
        )
        assert "api_credentials" in tables
        for table in tables:
            # Every column of every row, as text (bytea renders as hex); the table name comes
            # from pg_tables, not input. strpos is exact: LIKE treats underscores as wildcards.
            for form in token_forms(token):
                found = connection.execute(
                    text(
                        f"SELECT count(*) FROM {table} t "
                        "WHERE strpos(lower(row_to_json(t)::text), lower(:form)) > 0"
                    ),
                    {"form": form},
                ).scalar_one()
                assert found == 0, table


def test_a_second_credential_with_the_same_name_leaves_the_first_intact(
    migrated_database: Database, migrator: Engine
) -> None:
    """Names are not unique, and creating one must never revoke, delete or rotate another."""
    first = created_token(create(migrated_database))
    before = credential_rows(migrator)
    second = created_token(create(migrated_database))
    after = credential_rows(migrator)
    assert first != second
    assert [row for row in after if row in before] == before
    assert len(after) == len(before) + 1
    assert authenticates_as_admin(migrated_database, first)
    assert authenticates_as_admin(migrated_database, second)


def test_runtime_role_url_is_refused_and_writes_nothing(
    migrated_database: Database, migrator: Engine
) -> None:
    before = credential_rows(migrator)
    result = run_cli(migrated_database.app_url, "create-admin-credential", "--name", NAME)
    assert result.returncode == 3
    assert result.stdout == ""
    assert not any(marker in result.stderr for marker in LEAK_MARKERS)
    assert not WHOLE_TOKEN.search(result.stderr)
    assert migrated_database.app_password not in result.stderr
    assert credential_rows(migrator) == before


def test_writer_checks_the_connected_role(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    """Even past the URL check, a runtime-role connection is refused before any insert."""
    writer = PostgresAdminCredentialWriter(
        engine_for(migrated_database.app_url), "shiptrace_migrator"
    )
    with pytest.raises(WrongDatabaseRole):
        writer.add_admin(NAME, bytes(32), "st1_AAAA")


def test_database_refuses_the_runtime_role_too(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    """The third layer: the runtime role has no INSERT on api_credentials (migration 0002)."""
    writer = PostgresAdminCredentialWriter(engine_for(migrated_database.app_url), "shiptrace_app")
    with pytest.raises(CredentialNotStored) as caught:
        writer.add_admin(NAME, bytes(32), "st1_AAAA")
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


def test_duplicate_digest_is_refused_without_detail(
    migrated_database: Database, migrator: Engine
) -> None:
    """An integrity error, not only a connection or privilege error, is cut off too."""
    writer = PostgresAdminCredentialWriter(migrator, "shiptrace_migrator")
    before = len(credential_rows(migrator))
    writer.add_admin(NAME, b"\x01" * 32, "st1_AAAA")
    with pytest.raises(CredentialNotStored) as caught:
        writer.add_admin(NAME, b"\x01" * 32, "st1_AAAA")
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert len(credential_rows(migrator)) == before + 1


def test_unreachable_database_exits_4_without_detail() -> None:
    result = run_cli(UNREACHABLE, "create-admin-credential", "--name", NAME)
    assert result.returncode == 4
    assert result.stdout == ""
    assert not any(marker in result.stderr for marker in LEAK_MARKERS)
    assert not WHOLE_TOKEN.search(result.stderr)
    assert "may not have been stored" in result.stderr
