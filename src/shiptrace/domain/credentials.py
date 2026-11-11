"""API credential tokens and scope rules (ADR-0005). Pure: the random secret comes in as bytes."""

import base64
import hashlib
import re
from enum import StrEnum

TOKEN_PREFIX = "st1_"  # noqa: S105 - a public format marker that secret scanners match, not a secret.
SECRET_BYTES = 32  # 256 bits.
_TOKEN = re.compile(re.escape(TOKEN_PREFIX) + r"[A-Za-z0-9_-]{43}", re.ASCII)
_DISPLAY_LENGTH = len(TOKEN_PREFIX) + 4


class Scope(StrEnum):
    ADMIN = "admin"
    READ = "read"
    INGEST = "ingest"


class Action(StrEnum):
    REGISTER = "register"
    VIEW_REGISTRY = "view_registry"
    ISSUE_CREDENTIAL = "issue_credential"
    LIST_CREDENTIALS = "list_credentials"
    REVOKE_CREDENTIAL = "revoke_credential"
    INGEST_EVENT = "ingest_event"


# Deny by default: an action is allowed only for the scopes listed here.
_ALLOWED: dict[Action, frozenset[Scope]] = {
    Action.REGISTER: frozenset({Scope.ADMIN}),
    Action.VIEW_REGISTRY: frozenset({Scope.ADMIN, Scope.READ}),
    Action.ISSUE_CREDENTIAL: frozenset({Scope.ADMIN}),
    Action.LIST_CREDENTIALS: frozenset({Scope.ADMIN}),
    Action.REVOKE_CREDENTIAL: frozenset({Scope.ADMIN}),
    Action.INGEST_EVENT: frozenset({Scope.INGEST}),  # Spec §5: ingest only, not even admin.
}


def is_allowed(scope: Scope, action: Action) -> bool:
    """True only for a Scope listed for an Action. Plain strings are never trusted for either:
    StrEnum members hash and compare as strings, so a dict lookup alone would accept them."""
    return (
        isinstance(scope, Scope)
        and isinstance(action, Action)
        and scope in _ALLOWED.get(action, frozenset())
    )


def token_from_secret(secret: bytes) -> str:
    if len(secret) != SECRET_BYTES:
        raise ValueError(f"a credential secret must be {SECRET_BYTES} bytes")
    return TOKEN_PREFIX + base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")


def is_well_formed(token: str) -> bool:
    return _TOKEN.fullmatch(token) is not None


def _require_token(token: str) -> None:
    if not is_well_formed(token):
        raise ValueError("not a credential token")  # Never echo the value.


def digest(token: str) -> bytes:
    """The stored form of a token: SHA-256 of the whole token string."""
    _require_token(token)
    return hashlib.sha256(token.encode("ascii")).digest()


def display_prefix(token: str) -> str:
    """Enough to tell credentials apart in a list: the prefix and 24 of the 256 secret bits."""
    _require_token(token)
    return token[:_DISPLAY_LENGTH]
