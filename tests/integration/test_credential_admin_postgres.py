"""GET /credentials and POST /credentials/{id}/revoke against real PostgreSQL 18, as the runtime
role with its 0003 grants (ADR-0012). Fixture rows are inserted by the migrator and removed after.
"""

import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError

from shiptrace.application.credential_admin import CredentialRecord
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.domain.credentials import digest
from shiptrace.persistence.lifecycle import PostgresCredentialAdmin

from .conftest import Database
from .test_registry_api_postgres import bearer, insert_credential, unique_slug

EngineFor = Callable[[str], Engine]
PATH = "/api/v1/credentials"
CHECK_VIOLATION = "23514"
FIELDS = {
    "id",
    "name",
    "scope",
    "service",
    "environment",
    "display_prefix",
    "created_at",
    "expires_at",
    "revoked_at",
    "last_used_at",
}


@pytest.fixture
def migrator(migrated_database: Database, engine_for: EngineFor) -> Iterator[Engine]:
    """Removes the credentials and registry rows a test adds, credentials first."""
    engine = engine_for(migrated_database.migrator_url)
    tables = ("api_credentials", "services", "environments")
    with engine.connect() as connection:
        before = {t: set(connection.execute(text(f"SELECT id FROM {t}")).scalars()) for t in tables}
    yield engine
    with engine.begin() as connection:
        for table in tables:
            for row_id in connection.execute(text(f"SELECT id FROM {table}")).scalars():
                if row_id not in before[table]:
                    connection.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": row_id})


@pytest.fixture
def client(migrated_database: Database, migrator: Engine) -> Iterator[TestClient]:
    settings = Settings.model_validate(
        {"environment": "test", "database_url": migrated_database.app_url}
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as test_client:
        yield test_client


def make(
    migrator: Engine, scope: str, expires: str = "NULL", revoked: str = "NULL"
) -> tuple[str, str]:
    """A stored credential as (id, token); the id is found by the digest."""
    token = insert_credential(migrator, scope, expires, revoked)
    with migrator.connect() as connection:
        found = connection.execute(
            text("SELECT id FROM api_credentials WHERE secret_sha256 = :d"), {"d": digest(token)}
        ).scalar_one()
    return str(found), token


def row_state(migrator: Engine, credential_id: str) -> tuple[datetime | None, str]:
    """revoked_at and xmin: xmin changes whenever the row is written, even to the same value."""
    with migrator.connect() as connection:
        row = connection.execute(
            text("SELECT revoked_at, xmin::text FROM api_credentials WHERE id = :id"),
            {"id": credential_id},
        ).one()
    return row[0], row[1]


def revoke_url(credential_id: str) -> str:
    return f"{PATH}/{credential_id}/revoke"


def rfc3339(value: datetime | None) -> str:
    assert value is not None
    return value.isoformat().replace("+00:00", "Z")


# --- listing ---------------------------------------------------------------------------------


def test_list_is_admin_only_and_secret_free(client: TestClient, migrator: Engine) -> None:
    admin_id, admin_token = make(migrator, "admin")
    ingest_id, ingest_token = make(migrator, "ingest")
    _, read_token = make(migrator, "read")
    for token in (read_token, ingest_token):
        assert client.get(PATH, headers=bearer(token)).status_code == 403
    response = client.get(PATH, params={"limit": 100}, headers=bearer(admin_token))
    assert response.status_code == 200
    items = {item["id"]: item for item in response.json()["items"]}
    assert {admin_id, ingest_id} <= set(items)
    assert all(set(item) == FIELDS for item in items.values())
    assert items[ingest_id]["service"] is not None and items[ingest_id]["environment"] is not None
    assert items[admin_id]["scope"] == "admin" and items[admin_id]["service"] is None
    with migrator.connect() as connection:
        digests = connection.execute(text("SELECT secret_sha256 FROM api_credentials")).scalars()
        stored = {bytes(d).hex() for d in digests}
    body = response.text.lower()
    for token in (admin_token, ingest_token, read_token):
        assert token.lower() not in body
        assert token.removeprefix("st1_").lower() not in body
    assert not any(h in body for h in stored)
    assert "sha256" not in body and "digest" not in body


def test_list_shows_revoked_and_expired_credentials(client: TestClient, migrator: Engine) -> None:
    _, admin_token = make(migrator, "admin")
    revoked_id, _ = make(migrator, "read", revoked="now()")
    expired_id, _ = make(migrator, "read", expires="now() - interval '1 second'")
    listed = client.get(PATH, params={"limit": 100}, headers=bearer(admin_token)).json()["items"]
    items = {item["id"]: item for item in listed}
    assert items[revoked_id]["revoked_at"] is not None
    assert items[expired_id]["expires_at"] is not None and items[expired_id]["revoked_at"] is None


def test_pages_are_in_id_order_without_gaps_or_repeats(
    client: TestClient, migrator: Engine
) -> None:
    _, admin_token = make(migrator, "admin")
    created = {make(migrator, "read")[0] for _ in range(5)}
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, str | int] = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        body = client.get(PATH, params=params, headers=bearer(admin_token)).json()
        assert len(body["items"]) <= 2
        seen += [item["id"] for item in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == len(set(seen))
    assert seen == sorted(seen)  # Lowercase hyphenated UUIDs sort as the database's uuid order.
    assert created <= set(seen)
    with migrator.connect() as connection:
        total = connection.execute(text("SELECT count(*) FROM api_credentials")).scalar_one()
    assert len(seen) == total


def test_a_cursor_from_another_list_is_422(client: TestClient, migrator: Engine) -> None:
    _, admin_token = make(migrator, "admin")
    for _ in range(2):
        body = {"slug": unique_slug()}
        client.post("/api/v1/services", headers=bearer(admin_token), json=body)
    other = client.get("/api/v1/services", params={"limit": 1}, headers=bearer(admin_token))
    cursor = other.json()["next_cursor"]
    assert cursor is not None
    response = client.get(PATH, params={"cursor": cursor}, headers=bearer(admin_token))
    assert response.status_code == 422


# --- revocation ------------------------------------------------------------------------------


def test_revoke_uses_database_time_and_takes_effect_on_the_next_request(
    client: TestClient, migrator: Engine
) -> None:
    _, admin_token = make(migrator, "admin")
    target_id, target_token = make(migrator, "read")
    assert client.get("/api/v1/services", headers=bearer(target_token)).status_code == 200
    response = client.post(revoke_url(target_id), headers=bearer(admin_token))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == FIELDS and body["id"] == target_id
    stored, _ = row_state(migrator, target_id)
    assert stored is not None
    assert body["revoked_at"] == rfc3339(stored)
    assert not body["revoked_at"].startswith("2001")
    with migrator.connect() as connection:
        assert connection.execute(
            text("SELECT revoked_at <= now() FROM api_credentials WHERE id = :id"),
            {"id": target_id},
        ).scalar_one()
    assert client.get("/api/v1/services", headers=bearer(target_token)).status_code == 401  # AC11


def test_revoking_twice_is_200_and_leaves_the_row_unwritten(
    client: TestClient, migrator: Engine
) -> None:
    _, admin_token = make(migrator, "admin")
    target_id, _ = make(migrator, "read")
    first = client.post(revoke_url(target_id), headers=bearer(admin_token))
    state = row_state(migrator, target_id)
    second = client.post(revoke_url(target_id), headers=bearer(admin_token))
    assert (first.status_code, second.status_code) == (200, 200)
    assert second.json() == first.json()
    assert row_state(migrator, target_id) == state  # Same revoked_at, same xmin: no write.


def test_an_already_revoked_credential_keeps_its_original_time(
    client: TestClient, migrator: Engine
) -> None:
    _, admin_token = make(migrator, "admin")
    target_id, _ = make(migrator, "read", revoked="now() - interval '1 hour'")
    before = row_state(migrator, target_id)
    response = client.post(revoke_url(target_id), headers=bearer(admin_token))
    assert response.status_code == 200
    assert response.json()["revoked_at"] == rfc3339(before[0])
    assert row_state(migrator, target_id) == before


def test_unknown_id_is_404_and_a_bad_id_is_422(client: TestClient, migrator: Engine) -> None:
    _, admin_token = make(migrator, "admin")
    unknown = client.post(revoke_url(str(uuid.uuid4())), headers=bearer(admin_token))
    assert unknown.status_code == 404 and unknown.json()["code"] == "not_found"
    assert client.post(revoke_url("nope"), headers=bearer(admin_token)).status_code == 422


def test_other_scopes_cannot_revoke_and_the_row_is_untouched(
    client: TestClient, migrator: Engine
) -> None:
    target_id, _ = make(migrator, "read")
    before = row_state(migrator, target_id)
    for scope in ("read", "ingest"):
        _, token = make(migrator, scope)
        assert client.post(revoke_url(target_id), headers=bearer(token)).status_code == 403
    assert client.post(revoke_url(target_id)).status_code == 401
    assert row_state(migrator, target_id) == before


def test_an_admin_can_revoke_itself_and_is_then_locked_out(
    client: TestClient, migrator: Engine
) -> None:
    own_id, own_token = make(migrator, "admin")
    other_id, _ = make(migrator, "admin")
    assert client.post(revoke_url(own_id), headers=bearer(own_token)).status_code == 200
    assert client.get(PATH, headers=bearer(own_token)).status_code == 401
    assert row_state(migrator, other_id)[0] is None  # Only the named credential changed.


def test_an_expired_credential_can_be_revoked(client: TestClient, migrator: Engine) -> None:
    _, admin_token = make(migrator, "admin")
    expired_id, _ = make(migrator, "read", expires="now() - interval '1 second'")
    response = client.post(revoke_url(expired_id), headers=bearer(admin_token))
    assert response.status_code == 200 and response.json()["revoked_at"] is not None


# --- concurrency -----------------------------------------------------------------------------

_BLOCKED = (
    "SELECT count(*) FROM pg_stat_activity "
    "WHERE usename = 'shiptrace_app' AND wait_event_type = 'Lock'"
)
_UNFILTERED = "UPDATE api_credentials SET revoked_at = now() WHERE id = :id"


def hold_then_race(
    migrated_database: Database,
    engine_for: EngineFor,
    credential_id: str,
    second: Callable[[Engine], object],
) -> tuple[list[object], list[BaseException], bool]:
    """Connection one revokes and holds its transaction open; connection two starts its own,
    blocks on the row lock (seen by an observer, no sleeps), and runs on once one commits."""
    app = engine_for(migrated_database.app_url)
    other = engine_for(migrated_database.app_url)  # A second pool, so a second real connection.
    observer = engine_for(migrated_database.admin_url)  # Only a superuser sees others' waits.
    outcome: list[object] = []
    errors: list[BaseException] = []

    def loser() -> None:
        try:
            outcome.append(second(other))
        except BaseException as error:  # noqa: BLE001 - asserted by the caller.
            errors.append(error)

    thread = threading.Thread(target=loser)
    waited = False
    with app.connect() as first:
        transaction = first.begin()
        first.execute(text(_UNFILTERED + " AND revoked_at IS NULL"), {"id": credential_id})
        thread.start()
        try:
            for _ in range(500):
                with observer.connect() as connection:
                    waited = bool(connection.execute(text(_BLOCKED)).scalar_one())
                if waited:
                    break
        finally:
            transaction.commit()  # Always release, so a failure cannot leak into other tests.
            thread.join(timeout=30)
    assert not thread.is_alive()
    return outcome, errors, waited


def test_concurrent_revocation_loser_waits_and_changes_nothing(
    migrated_database: Database, migrator: Engine, engine_for: EngineFor
) -> None:
    target_id, _ = make(migrator, "read")
    outcome, errors, waited = hold_then_race(
        migrated_database,
        engine_for,
        target_id,
        lambda engine: PostgresCredentialAdmin(engine).revoke(uuid.UUID(target_id)),
    )
    assert waited, "the second revoker never waited on the first"
    assert errors == []
    (record,) = outcome
    assert isinstance(record, CredentialRecord)
    stored, _ = row_state(migrator, target_id)
    assert record.revoked_at == stored  # The winner's time, returned by the loser.


def test_an_unfiltered_update_that_loses_the_race_is_refused_by_the_guard(
    migrated_database: Database, migrator: Engine, engine_for: EngineFor
) -> None:
    """Why the filter matters: the same race without `revoked_at IS NULL` fails (ADR-0012)."""
    target_id, _ = make(migrator, "read")

    def unfiltered(engine: Engine) -> None:
        with engine.begin() as connection:
            connection.execute(text(_UNFILTERED), {"id": target_id})

    _, errors, waited = hold_then_race(migrated_database, engine_for, target_id, unfiltered)
    assert waited
    (error,) = errors
    assert isinstance(error, DBAPIError)
    assert getattr(error.orig, "sqlstate", None) == CHECK_VIOLATION


def test_the_runtime_role_may_still_update_only_two_columns(
    migrator: Engine,
) -> None:
    """CP8 added no grant: the runtime role may update only revoked_at and last_used_at."""
    with migrator.connect() as connection:
        columns = set(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.column_privileges "
                    "WHERE table_name = 'api_credentials' AND grantee = 'shiptrace_app' "
                    "AND privilege_type = 'UPDATE'"
                )
            ).scalars()
        )
    assert columns == {"revoked_at", "last_used_at"}
