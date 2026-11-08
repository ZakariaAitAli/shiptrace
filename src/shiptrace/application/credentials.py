"""Issuing credential tokens. Randomness lives here, because the domain stays deterministic."""

import secrets
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from shiptrace.domain.credentials import SECRET_BYTES, digest, display_prefix, token_from_secret
from shiptrace.domain.names import is_valid_credential_name


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
