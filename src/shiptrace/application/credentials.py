"""Issuing credential tokens. Randomness lives here, because the domain stays deterministic."""

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from shiptrace.application.access import Principal, authorize
from shiptrace.domain.credentials import (
    SECRET_BYTES,
    Action,
    Scope,
    digest,
    display_prefix,
    token_from_secret,
)
from shiptrace.domain.names import is_valid_credential_name, is_valid_slug

# Admin is absent on purpose: admin credentials come only from the bootstrap CLI (ADR-0012).
ISSUABLE = frozenset({Scope.READ, Scope.INGEST})
MAX_EXPIRY_DAYS = 365


class InvalidCredentialName(ValueError):
    """The name breaks the spec §5 rule. Raised before anything is generated or written."""


class CredentialNotStored(Exception):
    """The write failed, or its outcome is unknown: a commit whose acknowledgement was lost may
    have stored the row. No token exists outside this process either way, so such a row is
    unusable; the display prefix, which is not secret, identifies it."""

    def __init__(self, display_prefix: str | None = None) -> None:
        super().__init__()
        self.display_prefix = display_prefix


class WrongDatabaseRole(Exception):
    """The connection is not the role allowed to create admin credentials."""


class AdminCredentialWriter(Protocol):
    def add_admin(self, name: str, secret_digest: bytes, prefix: str) -> uuid.UUID:
        """Commits one admin credential and returns its id, or raises."""


@dataclass(frozen=True)
class IssuedCredential:
    id: uuid.UUID
    display_prefix: str
    token: str = field(repr=False)  # Shown to the operator once; never in a repr or traceback.


def new_token() -> str:
    """A fresh token from the operating system's CSPRNG. Shown once; only its digest is stored."""
    return token_from_secret(secrets.token_bytes(SECRET_BYTES))


def create_admin_credential(name: str, writer: AdminCredentialWriter) -> IssuedCredential:
    """The token leaves this function only after the writer has committed its digest."""
    if not is_valid_credential_name(name):
        raise InvalidCredentialName
    token = new_token()
    prefix = display_prefix(token)
    try:
        credential_id = writer.add_admin(name, digest(token), prefix)
    except CredentialNotStored:
        raise CredentialNotStored(prefix) from None
    return IssuedCredential(id=credential_id, display_prefix=prefix, token=token)


@dataclass(frozen=True)
class FieldProblem:
    """Which request field broke which rule. Never the value."""

    field: str
    rule: str


class IssuanceRejected(ValueError):
    """The request breaks the issuance rules (spec §5). Nothing was generated or written."""

    def __init__(self, problems: tuple[FieldProblem, ...]) -> None:
        super().__init__()
        self.problems = problems


class UnregisteredBinding(Exception):
    """A service or environment slug names nothing registered. Nothing was written."""

    def __init__(self, fields: tuple[str, ...]) -> None:
        super().__init__()
        self.fields = fields


@dataclass(frozen=True)
class NewCredential:
    """What an admin asks for. Slugs, not ids: the store resolves them in its own transaction."""

    name: str
    scope: Scope
    service: str | None
    environment: str | None
    expires_in_days: int | None


@dataclass(frozen=True)
class StoredCredential:
    id: uuid.UUID
    created_at: datetime  # Database time, as is expires_at.
    expires_at: datetime | None


class CredentialIssuer(Protocol):
    def add(self, credential: NewCredential, secret_digest: bytes, prefix: str) -> StoredCredential:
        """Commits one read or ingest credential, computing expiry from database time, or raises
        UnregisteredBinding naming every unknown slug."""


@dataclass(frozen=True)
class IssuedApiCredential:
    id: uuid.UUID
    name: str
    scope: Scope
    service: str | None
    environment: str | None
    display_prefix: str
    created_at: datetime
    expires_at: datetime | None
    token: str = field(repr=False)  # Shown to the caller once; never in a repr or traceback.


def _problems(request: NewCredential) -> list[FieldProblem]:
    found = []
    if not is_valid_credential_name(request.name):
        found.append(FieldProblem("name", "credential_name_format"))
    # A plain string is never trusted as a Scope, as in domain.is_allowed.
    if not isinstance(request.scope, Scope) or request.scope not in ISSUABLE:
        found.append(FieldProblem("scope", "scope_not_issuable"))
    for name, slug in (("service", request.service), ("environment", request.environment)):
        if request.scope is Scope.INGEST and slug is None:
            found.append(FieldProblem(name, "required_for_ingest"))
        elif request.scope is Scope.READ and slug is not None:
            found.append(FieldProblem(name, "forbidden_for_read"))
        elif slug is not None and not is_valid_slug(slug):
            found.append(FieldProblem(name, "slug_format"))
    days = request.expires_in_days
    if days is not None and (
        type(days) is not int or not 1 <= days <= MAX_EXPIRY_DAYS  # bool is not a day count.
    ):
        found.append(FieldProblem("expires_in_days", "expiry_range"))
    return found


def issue_credential(
    principal: Principal, request: NewCredential, issuer: CredentialIssuer
) -> IssuedApiCredential:
    """Authorized here as well as at the route. The token leaves only after its digest is
    committed; the token itself is never passed to the store."""
    authorize(principal, Action.ISSUE_CREDENTIAL)
    problems = _problems(request)
    if problems:
        raise IssuanceRejected(tuple(problems))
    token = new_token()
    prefix = display_prefix(token)
    try:
        stored = issuer.add(request, digest(token), prefix)
    except UnregisteredBinding as unknown:
        problems = [FieldProblem(name, "not_registered") for name in unknown.fields]
        raise IssuanceRejected(tuple(problems)) from None
    return IssuedApiCredential(
        id=stored.id,
        name=request.name,
        scope=request.scope,
        service=request.service,
        environment=request.environment,
        display_prefix=prefix,
        created_at=stored.created_at,
        expires_at=stored.expires_at,
        token=token,
    )
