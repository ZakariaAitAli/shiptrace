"""Credential lookup by digest, and the admin bootstrap insert.

Expiry and revocation are decided by database time.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.application.credentials import CredentialNotStored, WrongDatabaseRole
from shiptrace.domain.credentials import Scope

# Scope is fixed here, not a parameter: this path can only ever create an unbound admin.
_INSERT_ADMIN = text(
    "INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix) "
    "VALUES (:name, 'admin', :secret_digest, :prefix) RETURNING id"
)

# Any revocation counts, whatever its timestamp; expiry is exclusive.
_FIND_ACTIVE = text(
    "SELECT id, scope, service_id, environment_id FROM api_credentials "
    "WHERE secret_sha256 = :secret_digest AND revoked_at IS NULL "
    "AND (expires_at IS NULL OR expires_at > now())"
)


class PostgresCredentialStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def find_active(self, secret_digest: bytes) -> Principal | None:
        try:
            with self._engine.connect() as connection:
                row = connection.execute(
                    _FIND_ACTIVE, {"secret_digest": secret_digest}
                ).one_or_none()
        except SQLAlchemyError:
            # Dropped, not chained: SQLAlchemy errors carry the statement and the bound digest.
            raise StoreUnavailable from None
        if row is None:
            return None
        return Principal(
            id=row.id,
            scope=Scope(row.scope),
            service_id=row.service_id,
            environment_id=row.environment_id,
        )


class PostgresAdminCredentialWriter:
    """Inserts one admin credential in one transaction, only as the required database role."""

    def __init__(self, engine: Engine, required_role: str) -> None:
        self._engine = engine
        self._required_role = required_role

    def add_admin(self, name: str, secret_digest: bytes, prefix: str) -> uuid.UUID:
        try:
            with self._engine.begin() as connection:
                # The URL was checked already; this checks what the server actually granted.
                if connection.execute(text("SELECT current_user")).scalar_one() != (
                    self._required_role
                ):
                    raise WrongDatabaseRole
                credential_id: uuid.UUID = connection.execute(
                    _INSERT_ADMIN,
                    {"name": name, "secret_digest": secret_digest, "prefix": prefix},
                ).scalar_one()
        except SQLAlchemyError:
            # Dropped, not chained: the statement and bound values must not travel onward.
            raise CredentialNotStored from None
        return credential_id
