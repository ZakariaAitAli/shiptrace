"""Listing and revoking credentials as the runtime role (ADR-0012, migration 0003).

Only metadata columns are selected: secret_sha256 is readable by the runtime role (the
authentication lookup needs it) but never leaves the database through here. Revocation is a
filtered UPDATE, so a lost race updates no row instead of tripping the guard trigger.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine, Row
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import StoreUnavailable
from shiptrace.application.credential_admin import CredentialRecord
from shiptrace.domain.credentials import Scope

# Written out literally; the only variable parts are bound parameters. id is unique, so the order
# is total and a keyset cursor on it never repeats or skips a row.
_COLUMNS = (
    "SELECT c.id, c.name, c.scope, s.slug AS service, e.slug AS environment, c.display_prefix, "
    "c.created_at, c.expires_at, c.revoked_at, c.last_used_at "
    "FROM api_credentials c "
    "LEFT JOIN services s ON s.id = c.service_id "
    "LEFT JOIN environments e ON e.id = c.environment_id "
)
_FIRST_PAGE = text(_COLUMNS + "ORDER BY c.id LIMIT :limit")
_NEXT_PAGE = text(_COLUMNS + "WHERE c.id > :after ORDER BY c.id LIMIT :limit")
_ONE = text(_COLUMNS + "WHERE c.id = :id")

# revoked_at must change from NULL to exactly now() (the guard); the filter makes a repeat, or a
# lost race, a no-op. Under READ COMMITTED the loser waits for the winner's commit, re-checks the
# filter against the committed row and updates nothing.
_REVOKE = text(
    "UPDATE api_credentials SET revoked_at = now() WHERE id = :id AND revoked_at IS NULL"
)


def _record(row: Row[tuple[object, ...]]) -> CredentialRecord:
    return CredentialRecord(
        id=row.id,
        name=row.name,
        scope=Scope(row.scope),
        service=row.service,
        environment=row.environment,
        display_prefix=row.display_prefix,
        created_at=row.created_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
    )


class PostgresCredentialAdmin:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def list_after(self, after: uuid.UUID | None, limit: int) -> list[CredentialRecord]:
        params: dict[str, object] = {"limit": limit}
        statement = _FIRST_PAGE
        if after is not None:
            statement, params["after"] = _NEXT_PAGE, after
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(statement, params).all()
        except SQLAlchemyError:
            raise StoreUnavailable from None  # Never the statement or a bound value.
        return [_record(row) for row in rows]

    def revoke(self, credential_id: uuid.UUID) -> CredentialRecord | None:
        try:
            with self._engine.begin() as connection:
                return self._revoke(connection, credential_id)
        except SQLAlchemyError:
            raise StoreUnavailable from None

    @staticmethod
    def _revoke(connection: Connection, credential_id: uuid.UUID) -> CredentialRecord | None:
        connection.execute(_REVOKE, {"id": credential_id})
        # A new statement sees the winner's commit under READ COMMITTED, and our own update.
        row = connection.execute(_ONE, {"id": credential_id}).one_or_none()
        return None if row is None else _record(row)
