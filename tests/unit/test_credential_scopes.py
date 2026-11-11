"""Scope rules for S1 (spec §1 and §5): deny by default, exhaustively checked."""

import pytest

from shiptrace.domain.credentials import Action, Scope, is_allowed

# Every scope and action pair. A new scope or action fails test_matrix_is_complete until listed.
EXPECTED = {
    (Scope.ADMIN, Action.REGISTER): True,
    (Scope.ADMIN, Action.VIEW_REGISTRY): True,
    (Scope.READ, Action.REGISTER): False,
    (Scope.READ, Action.VIEW_REGISTRY): True,
    (Scope.INGEST, Action.REGISTER): False,
    (Scope.INGEST, Action.VIEW_REGISTRY): False,
    (Scope.ADMIN, Action.ISSUE_CREDENTIAL): True,
    (Scope.READ, Action.ISSUE_CREDENTIAL): False,
    (Scope.INGEST, Action.ISSUE_CREDENTIAL): False,
    (Scope.ADMIN, Action.LIST_CREDENTIALS): True,
    (Scope.READ, Action.LIST_CREDENTIALS): False,
    (Scope.INGEST, Action.LIST_CREDENTIALS): False,
    (Scope.ADMIN, Action.REVOKE_CREDENTIAL): True,
    (Scope.READ, Action.REVOKE_CREDENTIAL): False,
    (Scope.INGEST, Action.REVOKE_CREDENTIAL): False,
    # Spec §5: POST /deployment-events is ingest only. Admin and read cannot record events.
    (Scope.ADMIN, Action.INGEST_EVENT): False,
    (Scope.READ, Action.INGEST_EVENT): False,
    (Scope.INGEST, Action.INGEST_EVENT): True,
}


def test_scope_values_are_the_stored_names() -> None:
    assert {scope.value for scope in Scope} == {"admin", "read", "ingest"}


def test_matrix_is_complete() -> None:
    assert set(EXPECTED) == {(scope, action) for scope in Scope for action in Action}


@pytest.mark.parametrize(("pair", "allowed"), EXPECTED.items())
def test_scope_matrix(pair: tuple[Scope, Action], allowed: bool) -> None:
    scope, action = pair
    assert is_allowed(scope, action) is allowed


@pytest.mark.parametrize("scope", ["admin", "ADMIN", "", "superuser"])
def test_values_that_are_not_a_scope_are_denied(scope: str) -> None:
    """A raw string, even the right one, is not trusted as a scope."""
    assert is_allowed(scope, Action.REGISTER) is False  # type: ignore[arg-type]


@pytest.mark.parametrize("action", ["register", "view_registry", "REGISTER", ""])
def test_values_that_are_not_an_action_are_denied(action: str) -> None:
    """StrEnum members hash and compare as their strings, so a raw string would find the rule."""
    assert is_allowed(Scope.ADMIN, action) is False  # type: ignore[arg-type]
