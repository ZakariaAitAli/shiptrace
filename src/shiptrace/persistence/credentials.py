"""Credential lookup by digest. Expiry and revocation are decided by database time."""

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.domain.credentials import Scope

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
