"""Authentication and authorization use cases, with the credential store replaced by a dict."""

import uuid
from dataclasses import dataclass, field

import pytest

from shiptrace.application.access import (
    Forbidden,
    Principal,
    StoreUnavailable,
    Unauthenticated,
    authenticate,
    authorize,
)
from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import Action, Scope, digest

ADMIN = Principal(id=uuid.uuid4(), scope=Scope.ADMIN, service_id=None, environment_id=None)


@dataclass
class DictStore:
    known: dict[bytes, Principal] = field(default_factory=dict)
    looked_up: list[bytes] = field(default_factory=list)
    broken: bool = False

    def find_active(self, secret_digest: bytes) -> Principal | None:
        if self.broken:
            raise StoreUnavailable
        self.looked_up.append(secret_digest)
        return self.known.get(secret_digest)


def test_known_token_authenticates() -> None:
    token = new_token()
    store = DictStore({digest(token): ADMIN})
    assert authenticate(token, store) == ADMIN


def test_lookup_uses_the_digest_never_the_token() -> None:
    token = new_token()
    store = DictStore()
    with pytest.raises(Unauthenticated):
        authenticate(token, store)
    assert store.looked_up == [digest(token)]


@pytest.mark.parametrize("token", [None, "", "st1_short", "Bearer x", "st2_" + "A" * 43])
def test_missing_or_malformed_tokens_never_reach_the_store(token: str | None) -> None:
    store = DictStore()
    with pytest.raises(Unauthenticated):
        authenticate(token, store)
    assert store.looked_up == []


def test_unknown_token_is_unauthenticated() -> None:
    with pytest.raises(Unauthenticated):
        authenticate(new_token(), DictStore())


def test_store_failure_is_not_turned_into_unauthenticated() -> None:
    """An outage must surface as unavailable, never as a misleading 401."""
    with pytest.raises(StoreUnavailable):
        authenticate(new_token(), DictStore(broken=True))


@pytest.mark.parametrize(
    ("scope", "action", "allowed"),
    [
        (Scope.ADMIN, Action.REGISTER, True),
        (Scope.READ, Action.VIEW_REGISTRY, True),
        (Scope.READ, Action.REGISTER, False),
        (Scope.INGEST, Action.VIEW_REGISTRY, False),
        (Scope.INGEST, Action.REGISTER, False),
    ],
)
def test_authorize_follows_the_scope_rules(scope: Scope, action: Action, allowed: bool) -> None:
    principal = Principal(id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None)
    if allowed:
        authorize(principal, action)
    else:
        with pytest.raises(Forbidden):
            authorize(principal, action)
