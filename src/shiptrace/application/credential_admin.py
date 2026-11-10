"""Listing and revoking credentials (spec §5). Authorized here as well as at the route.

A record is metadata only. It has no field for a token or a digest, so no layer above the store
can leak one. Revocation time is the database's; no caller can supply it.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from shiptrace.application.access import Principal, authorize
from shiptrace.application.registry import MAX_PAGE, InvalidPage
from shiptrace.domain.credentials import Action, Scope


class CredentialNotFound(Exception):
    """No credential has this id."""


@dataclass(frozen=True)
class CredentialRecord:
    id: uuid.UUID
    name: str
    scope: Scope
    service: str | None  # Slugs, as in the issuance response.
    environment: str | None
    display_prefix: str
    created_at: datetime  # The timestamps are all assigned by the database.
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None


@dataclass(frozen=True)
class CredentialPage:
    items: list[CredentialRecord]
    next_after: uuid.UUID | None  # The last id of a full page, or None at the end.


class CredentialAdmin(Protocol):
    def list_after(self, after: uuid.UUID | None, limit: int) -> list[CredentialRecord]:
        """Up to `limit` credentials with ids greater than `after`, in id order."""

    def revoke(self, credential_id: uuid.UUID) -> CredentialRecord | None:
        """Revokes at database time unless already revoked, and returns the row as stored, or
        None when no credential has this id. A repeat changes nothing."""


def list_credentials(
    principal: Principal, after: uuid.UUID | None, limit: int, store: CredentialAdmin
) -> CredentialPage:
    authorize(principal, Action.LIST_CREDENTIALS)
    if not 1 <= limit <= MAX_PAGE:
        raise InvalidPage
    # One extra row tells whether another page exists, so a full last page ends the walk.
    rows = store.list_after(after, limit + 1)
    if len(rows) > limit:
        return CredentialPage(items=rows[:limit], next_after=rows[limit - 1].id)
    return CredentialPage(items=rows, next_after=None)


def revoke_credential(
    principal: Principal, credential_id: uuid.UUID, store: CredentialAdmin
) -> CredentialRecord:
    authorize(principal, Action.REVOKE_CREDENTIAL)
    record = store.revoke(credential_id)
    if record is None:
        raise CredentialNotFound
    return record
