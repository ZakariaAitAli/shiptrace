"""Credential lookup by digest, and the admin bootstrap insert.

Expiry and revocation are decided by database time.
"""

import contextlib
import logging
import uuid

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.application.credentials import CredentialNotStored, WrongDatabaseRole
from shiptrace.domain.credentials import Scope

# Scope is fixed here, not a parameter: this path can only ever create an unbound admin.
_INSERT_ADMIN = text(
    "INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix) "
    "VALUES (:name, 'admin', :secret_digest, :prefix) RETURNING id"
)

_log = logging.getLogger(__name__)

# Any revocation counts, whatever its timestamp; expiry is exclusive. `usage_stale` is decided by
# the database clock in the same statement, so the common case costs no second round trip and no
# write (ADR-0005: last_used_at changes at most once per 5 minutes per credential).
_FIND_ACTIVE = text(
    "SELECT id, scope, service_id, environment_id, "
    "(last_used_at IS NULL OR last_used_at < now() - interval '5 minutes') AS usage_stale "
    "FROM api_credentials "
    "WHERE secret_sha256 = :secret_digest AND revoked_at IS NULL "
    "AND (expires_at IS NULL OR expires_at > now())"
)

# Filtered, never unconditional (ADR-0012): under READ COMMITTED a concurrent toucher that commits
# first makes this filter fail on re-check, so the loser updates no row instead of tripping the
# guard trigger. The active filters stop a credential revoked or expired since the lookup from
# being marked used. now() is this new transaction's start, which the guard requires.
# Transaction-local, so it covers only the usage write: neither the lookup nor the pooled
# connection's later use is affected. A row lock held longer than this (a slow revoker, say) makes
# the touch give up with 55P03 instead of stalling the request; the use is then simply unrecorded.
_TOUCH_LOCK_TIMEOUT = text("SET LOCAL lock_timeout = '100ms'")
_TOUCH = text(
    "UPDATE api_credentials SET last_used_at = now() WHERE id = :id AND revoked_at IS NULL "
    "AND (expires_at IS NULL OR expires_at > now()) "
    "AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')"
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
                connection.commit()  # Ends the lookup, so the touch gets a fresh now().
                if row is not None and row.usage_stale:
                    self._touch(connection, row.id)
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

    @staticmethod
    def _touch(connection: Connection, credential_id: uuid.UUID) -> None:
        """Best effort: authentication has already succeeded, so no failure here may undo it."""
        try:
            connection.execute(_TOUCH_LOCK_TIMEOUT)
            connection.execute(_TOUCH, {"id": credential_id})
            connection.commit()
        except SQLAlchemyError:
            _log.warning("credential usage not recorded")  # No detail: it may carry bound values.
            with contextlib.suppress(SQLAlchemyError):  # The connection is discarded on release.
                connection.rollback()


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
