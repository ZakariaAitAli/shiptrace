"""Issuing read and ingest credentials (spec §5, credential issuance): the use case's own rules,
checked here without HTTP so that they hold whatever calls it."""

import uuid
from dataclasses import replace

import pytest

from shiptrace.application.access import Forbidden, Principal
from shiptrace.application.credentials import (
    FieldProblem,
    IssuanceRejected,
    NewCredential,
    issue_credential,
)
from shiptrace.domain.credentials import Scope, digest, display_prefix, is_well_formed

from .fakes import DictIssuer

READ = NewCredential("dashboard reader", Scope.READ, None, None, None)
INGEST = NewCredential("ci", Scope.INGEST, "payments-api", "production", 30)


def principal(scope: Scope) -> Principal:
    return Principal(id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None)


ADMIN = principal(Scope.ADMIN)


@pytest.fixture
def issuer() -> DictIssuer:
    return DictIssuer(services={"payments-api"}, environments={"production"})


@pytest.mark.parametrize("request_", [READ, INGEST], ids=["read", "ingest"])
def test_issues_and_returns_the_token_whose_digest_was_stored(
    issuer: DictIssuer, request_: NewCredential
) -> None:
    issued = issue_credential(ADMIN, request_, issuer)
    assert is_well_formed(issued.token)
    [(stored_request, stored_digest, stored_prefix)] = issuer.added
    assert stored_request == request_
    assert stored_digest == digest(issued.token)
    assert stored_prefix == issued.display_prefix == display_prefix(issued.token)
    assert issued.id == issuer.ids[0]
    assert (issued.name, issued.scope, issued.service, issued.environment) == (
        request_.name,
        request_.scope,
        request_.service,
        request_.environment,
    )


def test_each_issue_gets_a_fresh_token(issuer: DictIssuer) -> None:
    first = issue_credential(ADMIN, READ, issuer)
    second = issue_credential(ADMIN, READ, issuer)  # Same name: names are not unique.
    assert first.token != second.token
    assert first.id != second.id


def test_token_is_not_in_the_repr(issuer: DictIssuer) -> None:
    issued = issue_credential(ADMIN, READ, issuer)
    assert issued.token not in repr(issued)


@pytest.mark.parametrize("scope", [Scope.READ, Scope.INGEST])
def test_only_admin_may_issue(issuer: DictIssuer, scope: Scope) -> None:
    with pytest.raises(Forbidden):
        issue_credential(principal(scope), READ, issuer)
    assert issuer.added == []


@pytest.mark.parametrize(
    ("request_", "problems"),
    [
        (replace(READ, scope=Scope.ADMIN), [FieldProblem("scope", "scope_not_issuable")]),
        (replace(READ, scope="read"), [FieldProblem("scope", "scope_not_issuable")]),  # type: ignore[arg-type]
        (replace(READ, name="-bad"), [FieldProblem("name", "credential_name_format")]),
        (replace(READ, name="x" * 65), [FieldProblem("name", "credential_name_format")]),
        (replace(READ, expires_in_days=0), [FieldProblem("expires_in_days", "expiry_range")]),
        (replace(READ, expires_in_days=366), [FieldProblem("expires_in_days", "expiry_range")]),
        (replace(READ, expires_in_days=True), [FieldProblem("expires_in_days", "expiry_range")]),
        (
            replace(READ, service="payments-api"),
            [FieldProblem("service", "forbidden_for_read")],
        ),
        (
            replace(READ, service="payments-api", environment="production"),
            [
                FieldProblem("service", "forbidden_for_read"),
                FieldProblem("environment", "forbidden_for_read"),
            ],
        ),
        (
            replace(INGEST, environment=None),
            [FieldProblem("environment", "required_for_ingest")],
        ),
        (
            replace(INGEST, service=None, environment=None),
            [
                FieldProblem("service", "required_for_ingest"),
                FieldProblem("environment", "required_for_ingest"),
            ],
        ),
        (replace(INGEST, service="Bad--slug"), [FieldProblem("service", "slug_format")]),
    ],
)
def test_invalid_requests_are_rejected_before_anything_is_written(
    issuer: DictIssuer, request_: NewCredential, problems: list[FieldProblem]
) -> None:
    with pytest.raises(IssuanceRejected) as caught:
        issue_credential(ADMIN, request_, issuer)
    assert list(caught.value.problems) == problems
    assert issuer.added == []


@pytest.mark.parametrize("days", [1, 365])
def test_expiry_bounds_are_accepted(issuer: DictIssuer, days: int) -> None:
    issued = issue_credential(ADMIN, replace(READ, expires_in_days=days), issuer)
    assert issued.expires_at is not None


@pytest.mark.parametrize(
    ("service", "environment", "fields"),
    [
        ("unknown-service", "production", ["service"]),
        ("payments-api", "unknown-env", ["environment"]),
        ("unknown-service", "unknown-env", ["service", "environment"]),
    ],
)
def test_unregistered_bindings_name_each_field(
    issuer: DictIssuer, service: str, environment: str, fields: list[str]
) -> None:
    with pytest.raises(IssuanceRejected) as caught:
        issue_credential(ADMIN, replace(INGEST, service=service, environment=environment), issuer)
    assert list(caught.value.problems) == [FieldProblem(f, "not_registered") for f in fields]
    assert issuer.added == []
