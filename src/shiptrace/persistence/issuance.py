"""Issuing read and ingest credentials as the runtime role (ADR-0012, migration 0003).

Kept apart from the authentication lookup in persistence.credentials, which must never bring an
expiry back into Python (test_auth_clock). Here expiry is returned only to be shown in the 201.
"""

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import StoreUnavailable
from shiptrace.application.credentials import (
    NewCredential,
    StoredCredential,
    UnregisteredBinding,
)

# Both slugs in one read; a NULL id means that slug is not registered. Registry rows are never
# deleted by the runtime role, so an id found here is still there at the insert.
_RESOLVE_BINDING = text(
    "SELECT (SELECT id FROM services WHERE slug = :service) AS service_id, "
    "(SELECT id FROM environments WHERE slug = :environment) AS environment_id"
)

# id and created_at take their defaults. Expiry is absolute database time, 24-hour days, as the
# guard requires (ADR-0012); make_interval is strict, so a NULL day count gives a NULL expiry.
_INSERT_ISSUED = text(
    "INSERT INTO api_credentials "
    "(name, scope, service_id, environment_id, secret_sha256, display_prefix, expires_at) "
    "VALUES (:name, :scope, :service_id, :environment_id, :secret_digest, :prefix, "
    "now() + make_interval(hours => 24 * CAST(:days AS integer))) "
    "RETURNING id, created_at, expires_at"
)


class PostgresCredentialIssuer:
    """Issues read and ingest credentials as the runtime role, in one transaction each. The
    database refuses admin scope and any other expiry for this role, whatever is passed here."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def add(self, credential: NewCredential, secret_digest: bytes, prefix: str) -> StoredCredential:
        service_id = environment_id = None
        try:
            with self._engine.begin() as connection:
                if credential.service is not None or credential.environment is not None:
                    found = connection.execute(
                        _RESOLVE_BINDING,
                        {"service": credential.service, "environment": credential.environment},
                    ).one()
                    service_id, environment_id = found.service_id, found.environment_id
                    unknown = tuple(
                        name
                        for name, slug, row_id in (
                            ("service", credential.service, service_id),
                            ("environment", credential.environment, environment_id),
                        )
                        if slug is not None and row_id is None
                    )
                    if unknown:
                        raise UnregisteredBinding(unknown)  # Rolls back; nothing was written.
                row = connection.execute(
                    _INSERT_ISSUED,
                    {
                        "name": credential.name,
                        "scope": credential.scope.value,
                        "service_id": service_id,
                        "environment_id": environment_id,
                        "secret_digest": secret_digest,
                        "prefix": prefix,
                        "days": credential.expires_in_days,
                    },
                ).one()
        except SQLAlchemyError:
            # Dropped, not chained: the statement and the bound digest must not travel onward.
            raise StoreUnavailable from None
        return StoredCredential(id=row.id, created_at=row.created_at, expires_at=row.expires_at)
