"""Authenticating API credentials and authorizing actions (ADR-0005). Deny by default."""

import uuid
from dataclasses import dataclass
from typing import Protocol

from shiptrace.domain.credentials import Action, Scope, digest, is_allowed, is_well_formed


class Unauthenticated(Exception):
    """No usable credential: missing, malformed, unknown, expired or revoked. Never says which."""


class Forbidden(Exception):
    """A valid credential whose scope does not allow the action."""


class StoreUnavailable(Exception):
    """The credential store could not answer. Not an authentication failure."""


@dataclass(frozen=True)
class Principal:
    """Who is calling. Holds no secret material.

    An ingest credential is bound to one service and one environment: their ids, and the canonical
    slugs the store read with them, so a request's names can be compared (R11) without being
    resolved. Other scopes carry none of the four."""

    id: uuid.UUID
    scope: Scope
    service_id: uuid.UUID | None
    environment_id: uuid.UUID | None
    service_slug: str | None = None
    environment_slug: str | None = None


class CredentialStore(Protocol):
    def find_active(self, secret_digest: bytes) -> Principal | None:
        """The unexpired, unrevoked credential with this digest, by the store's own clock."""


def authenticate(token: str | None, store: CredentialStore) -> Principal:
    # Malformed input is refused before any lookup, so arbitrary values never reach the store.
    if token is None or not is_well_formed(token):
        raise Unauthenticated
    principal = store.find_active(digest(token))
    if principal is None:
        raise Unauthenticated
    return principal


def authorize(principal: Principal, action: Action) -> None:
    if not is_allowed(principal.scope, action):
        raise Forbidden
