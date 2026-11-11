"""Credential lookup by digest, and the admin bootstrap insert.

Expiry and revocation are decided by database time.
"""

import contextlib
import logging
import uuid

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import InvariantFault, Principal, StoreUnavailable
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
#
# The bound service and environment come back as ids and canonical slugs in the same statement.
# The joins are LEFT because only an ingest credential is bound; for it both always match, since
# the binding check requires both ids and the foreign keys restrict deletion (migration 0002).
_FIND_ACTIVE = text(
    "SELECT c.id, c.scope, c.service_id, c.environment_id, "
    "s.slug AS service_slug, e.slug AS environment_slug, "
    "(c.last_used_at IS NULL OR c.last_used_at < now() - interval '5 minutes') AS usage_stale "
    "FROM api_credentials AS c "
    "LEFT JOIN services AS s ON s.id = c.service_id "
    "LEFT JOIN environments AS e ON e.id = c.environment_id "
    "WHERE c.secret_sha256 = :secret_digest AND c.revoked_at IS NULL "
    "AND (c.expires_at IS NULL OR c.expires_at > now())"
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


def build_principal(
    *,
    credential_id: uuid.UUID,
    scope: str,
    service_id: uuid.UUID | None,
    environment_id: uuid.UUID | None,
    service_slug: str | None,
    environment_slug: str | None,
) -> Principal:
    """The principal for one credential row, failing closed on an impossible binding.

    The database already forbids it (the binding check and the foreign keys), so this is the last
    line if a row ever disagrees: an ingest credential must have all four values, any other scope
    none. The credential is then neither accepted nor reported as invalid. This is a data fault, not
    an outage, so it raises the non-retryable InvariantFault. The log line carries no id or slug."""
    bound = (service_id, environment_id, service_slug, environment_slug)
    is_ingest = Scope(scope) is Scope.INGEST
    consistent = all(v is not None for v in bound) if is_ingest else all(v is None for v in bound)
    if not consistent:
        _log.error("credential binding is inconsistent")
        raise InvariantFault
    return Principal(
        id=credential_id,
        scope=Scope(scope),
        service_id=service_id,
        environment_id=environment_id,
        service_slug=service_slug,
        environment_slug=environment_slug,
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
        return build_principal(
            credential_id=row.id,
            scope=row.scope,
            service_id=row.service_id,
            environment_id=row.environment_id,
            service_slug=row.service_slug,
            environment_slug=row.environment_slug,
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
