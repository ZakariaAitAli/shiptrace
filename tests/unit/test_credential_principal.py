"""The principal a credential lookup returns: bound ids with their canonical slugs, or nothing.

The slugs let the ingest use case apply R11 without resolving the submitted names, so an ingest
principal that lacks any of the four values, or any other principal that has one, is refused."""

import dataclasses
import logging
import uuid

import pytest

from shiptrace.application.access import InvariantFault, Principal
from shiptrace.domain.credentials import Scope
from shiptrace.persistence.credentials import build_principal

ID = uuid.uuid4()
SERVICE_ID = uuid.uuid4()
ENVIRONMENT_ID = uuid.uuid4()
SENTINEL = "sentinel-slug-do-not-log"


def test_legacy_positional_constructions_still_work() -> None:
    principal = Principal(ID, Scope.READ, None, None)
    assert (principal.service_id, principal.environment_id) == (None, None)
    assert (principal.service_slug, principal.environment_slug) == (None, None)
    assert principal == Principal(id=ID, scope=Scope.READ, service_id=None, environment_id=None)


def test_the_original_four_fields_keep_their_positions() -> None:
    names = [f.name for f in dataclasses.fields(Principal)]
    assert names[:4] == ["id", "scope", "service_id", "environment_id"]
    assert names[4:] == ["service_slug", "environment_slug"]


def test_slugs_are_part_of_the_value() -> None:
    bound = Principal(ID, Scope.INGEST, SERVICE_ID, ENVIRONMENT_ID, "payments-api", "production")
    assert bound.service_slug == "payments-api"
    assert bound.environment_slug == "production"
    assert bound != Principal(ID, Scope.INGEST, SERVICE_ID, ENVIRONMENT_ID, "other", "production")
    with pytest.raises(dataclasses.FrozenInstanceError):
        bound.service_slug = "other"  # type: ignore[misc]


def test_an_ingest_row_with_all_four_values_becomes_a_bound_principal() -> None:
    principal = build_principal(
        credential_id=ID,
        scope="ingest",
        service_id=SERVICE_ID,
        environment_id=ENVIRONMENT_ID,
        service_slug="payments-api",
        environment_slug="production",
    )
    assert principal == Principal(
        ID, Scope.INGEST, SERVICE_ID, ENVIRONMENT_ID, "payments-api", "production"
    )


@pytest.mark.parametrize("scope", ["admin", "read"])
def test_unbound_scopes_carry_no_binding(scope: str) -> None:
    principal = build_principal(
        credential_id=ID,
        scope=scope,
        service_id=None,
        environment_id=None,
        service_slug=None,
        environment_slug=None,
    )
    assert principal == Principal(ID, Scope(scope), None, None, None, None)


MISSING = [
    ("service_id", None, ENVIRONMENT_ID, SENTINEL, SENTINEL),
    ("environment_id", SERVICE_ID, None, SENTINEL, SENTINEL),
    ("service_slug", SERVICE_ID, ENVIRONMENT_ID, None, SENTINEL),
    ("environment_slug", SERVICE_ID, ENVIRONMENT_ID, SENTINEL, None),
    ("all four", None, None, None, None),
]


@pytest.mark.parametrize(
    ("missing", "service_id", "environment_id", "service_slug", "environment_slug"),
    MISSING,
    ids=[m[0] for m in MISSING],
)
def test_an_ingest_row_with_a_missing_binding_fails_closed_without_detail(
    missing: str,
    service_id: uuid.UUID | None,
    environment_id: uuid.UUID | None,
    service_slug: str | None,
    environment_slug: str | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG), pytest.raises(InvariantFault) as caught:
        build_principal(
            credential_id=ID,
            scope="ingest",
            service_id=service_id,
            environment_id=environment_id,
            service_slug=service_slug,
            environment_slug=environment_slug,
        )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert SENTINEL not in caplog.text
    assert str(SERVICE_ID) not in caplog.text
    assert caplog.records, "an inconsistent credential must leave a trace"


@pytest.mark.parametrize("scope", ["admin", "read"])
@pytest.mark.parametrize(
    ("service_id", "environment_id", "service_slug", "environment_slug"),
    [
        (SERVICE_ID, None, None, None),
        (None, ENVIRONMENT_ID, None, None),
        (None, None, SENTINEL, None),
        (None, None, None, SENTINEL),
    ],
)
def test_an_unbound_scope_that_carries_a_binding_fails_closed(
    scope: str,
    service_id: uuid.UUID | None,
    environment_id: uuid.UUID | None,
    service_slug: str | None,
    environment_slug: str | None,
) -> None:
    with pytest.raises(InvariantFault):
        build_principal(
            credential_id=ID,
            scope=scope,
            service_id=service_id,
            environment_id=environment_id,
            service_slug=service_slug,
            environment_slug=environment_slug,
        )
