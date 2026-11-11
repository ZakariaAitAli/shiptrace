"""The ingest use case (spec §3 and §5; ARCHITECTURE §4), without HTTP and without a database.

Order under test: scope, then the principal's binding, then field validation, then R11 (exact slug
match), then the store. A refusal at any step must leave the store untouched.
"""

import inspect
import logging
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

import pytest

from shiptrace.application.access import Forbidden, InvariantFault, Principal, StoreUnavailable
from shiptrace.application.credentials import FieldProblem
from shiptrace.application.deployments import Accepted, DeploymentTarget, Outcome
from shiptrace.application.ingest import EventRejected, ingest_event
from shiptrace.domain.credentials import Scope
from shiptrace.domain.deployments import (
    Duplicate,
    EventType,
    NewEvent,
    Reject,
    RejectReason,
    StoredEvent,
)

SENTINEL = "SENTINEL-" + uuid.uuid4().hex
SHA = "0123456789abcdef0123456789abcdef01234567"
SERVICE_ID = uuid.uuid4()
ENVIRONMENT_ID = uuid.uuid4()
CREDENTIAL_ID = uuid.uuid4()

INGEST = Principal(
    id=CREDENTIAL_ID,
    scope=Scope.INGEST,
    service_id=SERVICE_ID,
    environment_id=ENVIRONMENT_ID,
    service_slug="payments-api",
    environment_slug="production",
)
BODY: dict[str, object] = {
    "service": "payments-api",
    "environment": "production",
    "deployment_key": "gha-12345678-1",
    "type": "succeeded",
    "version": "1.4.2",
    "commit_sha": SHA,
}
REQUIRED = ("service", "environment", "deployment_key", "type", "version", "commit_sha")
OPTIONAL = ("source_url", "reason")
ALL_FIELDS = (*REQUIRED, *OPTIONAL)


@dataclass
class RecordingStore:
    outcome: Outcome = field(default_factory=lambda: Accepted(uuid.uuid4(), 1, None))  # type: ignore[arg-type]
    error: Exception | None = None
    calls: list[tuple[DeploymentTarget, NewEvent, uuid.UUID]] = field(default_factory=list)

    def record(
        self, target: DeploymentTarget, event: NewEvent, credential_id: uuid.UUID
    ) -> Outcome:
        self.calls.append((target, event, credential_id))
        if self.error is not None:
            raise self.error
        return self.outcome


def body(**changes: object) -> dict[str, object]:
    merged = {**BODY, **changes}
    return {k: v for k, v in merged.items() if v is not ...}


def problems_of(rejected: pytest.ExceptionInfo[EventRejected]) -> set[FieldProblem]:
    return set(rejected.value.problems)


# Authorization: scope first


@pytest.mark.parametrize("scope", [Scope.READ, Scope.ADMIN])
def test_only_an_ingest_scope_may_record_an_event(scope: Scope) -> None:
    store = RecordingStore()
    caller = replace(INGEST, scope=scope)
    with pytest.raises(Forbidden):
        ingest_event(caller, body(), store)
    assert store.calls == []


def test_a_refused_scope_is_decided_before_the_body_is_read() -> None:
    """An invalid body from a wrong-scope caller is 403, not 422: nothing about the body is told."""
    store = RecordingStore()
    with pytest.raises(Forbidden):
        ingest_event(replace(INGEST, scope=Scope.READ), {"nonsense": 1}, store)
    assert store.calls == []


@pytest.mark.parametrize("scope", ["ingest", "INGEST", ""])
def test_a_plain_string_is_not_trusted_as_a_scope(scope: str) -> None:
    store = RecordingStore()
    with pytest.raises(Forbidden):
        ingest_event(replace(INGEST, scope=scope), body(), store)  # type: ignore[arg-type]
    assert store.calls == []


UNBOUND = [
    {"service_id": None},
    {"environment_id": None},
    {"service_slug": None},
    {"environment_slug": None},
    {"service_id": None, "environment_id": None, "service_slug": None, "environment_slug": None},
]


@pytest.mark.parametrize("missing", UNBOUND)
def test_an_ingest_principal_without_its_full_binding_is_a_fault_not_a_request_error(
    missing: dict[str, Any],
) -> None:
    store = RecordingStore()
    with pytest.raises(InvariantFault):
        ingest_event(replace(INGEST, **missing), body(), store)
    assert store.calls == []


# R11: exact binding


@pytest.mark.parametrize(
    ("service", "environment"),
    [
        ("billing-api", "production"),
        ("payments-api", "staging"),
        ("billing-api", "staging"),
        ("production", "payments-api"),  # swapped
        ("payments", "production"),  # a prefix
        ("payments-api-2", "production"),
    ],
)
def test_a_service_or_environment_other_than_the_binding_is_forbidden(
    service: str, environment: str
) -> None:
    store = RecordingStore()
    with pytest.raises(Forbidden):
        ingest_event(INGEST, body(service=service, environment=environment), store)
    assert store.calls == []


@pytest.mark.parametrize("service", ["Payments-api", "PAYMENTS-API", " payments-api"])
def test_matching_is_exact_and_never_folds_or_trims(service: str) -> None:
    """A slug that differs only in case or whitespace is not a valid slug at all (422): it is
    refused before R11 and never matched, and certainly never accepted as the bound one."""
    store = RecordingStore()
    with pytest.raises(EventRejected):
        ingest_event(INGEST, body(service=service), store)
    assert store.calls == []


def test_the_same_refusal_whatever_the_requested_target_holds() -> None:
    """R11 sees slugs only. Stores that hold or lack the target give the same answer, because the
    store is never asked; the use case has no other way to look a target up."""
    outcomes = []
    for store in (RecordingStore(outcome=Reject(RejectReason.EVENT_CONFLICT)), RecordingStore()):
        with pytest.raises(Forbidden) as caught:
            ingest_event(INGEST, body(service="billing-api"), store)
        outcomes.append((type(caught.value), caught.value.args, caught.value.__cause__))
        assert store.calls == []
    assert outcomes[0] == outcomes[1]


def test_the_use_case_is_given_no_way_to_resolve_a_submitted_slug() -> None:
    assert list(inspect.signature(ingest_event).parameters) == ["principal", "body", "store"]


def test_the_target_is_the_principals_ids_and_the_credential_is_the_principal() -> None:
    store = RecordingStore()
    ingest_event(INGEST, body(), store)
    [(target, event, credential_id)] = store.calls
    assert target == DeploymentTarget(SERVICE_ID, ENVIRONMENT_ID, "gha-12345678-1")
    assert credential_id == CREDENTIAL_ID
    assert event == NewEvent(EventType.SUCCEEDED, "1.4.2", SHA, None, None)


# Validation


def test_optional_fields_omitted_and_null_are_the_same() -> None:
    omitted, null = RecordingStore(), RecordingStore()
    ingest_event(INGEST, body(), omitted)
    ingest_event(INGEST, body(source_url=None, reason=None), null)
    assert omitted.calls == null.calls
    assert omitted.calls[0][1].source_url is None
    assert omitted.calls[0][1].reason is None


def test_optional_fields_are_passed_through_unchanged() -> None:
    store = RecordingStore()
    reason = "rollback\tbecause\nof  x "  # Whitespace is kept: values are never normalized.
    url = "https://ci.example/runs/1?a=%41#frag"
    ingest_event(INGEST, body(source_url=url, reason=reason), store)
    event = store.calls[0][1]
    assert (event.source_url, event.reason) == (url, reason)


@pytest.mark.parametrize("name", REQUIRED)
@pytest.mark.parametrize("how", ["omitted", "null"])
def test_a_required_field_that_is_omitted_or_null_is_refused(name: str, how: str) -> None:
    store = RecordingStore()
    with pytest.raises(EventRejected) as rejected:
        ingest_event(INGEST, body(**{name: ... if how == "omitted" else None}), store)
    assert problems_of(rejected) == {FieldProblem(name, "required")}
    assert store.calls == []


@pytest.mark.parametrize("name", ALL_FIELDS)
def test_an_empty_string_is_refused_for_every_field(name: str) -> None:
    store = RecordingStore()
    with pytest.raises(EventRejected) as rejected:
        ingest_event(INGEST, body(**{name: ""}), store)
    [problem] = rejected.value.problems
    assert problem.field == name
    assert store.calls == []


@pytest.mark.parametrize("name", ALL_FIELDS)
@pytest.mark.parametrize("value", [1, 1.5, True, False, [], {}, b"x", ["a"], 0])
def test_a_value_that_is_not_a_string_is_refused_never_coerced(name: str, value: object) -> None:
    store = RecordingStore()
    with pytest.raises(EventRejected) as rejected:
        ingest_event(INGEST, body(**{name: value}), store)
    assert problems_of(rejected) == {FieldProblem(name, "type")}
    assert store.calls == []


FORMATS = [
    ("deployment_key", "-leading-hyphen"),
    ("deployment_key", "a" * 129),
    ("deployment_key", "has space"),
    ("version", "_1"),
    ("version", "1" * 129),
    ("commit_sha", SHA.upper()),
    ("commit_sha", SHA[:39]),
    ("commit_sha", SHA + "0"),
    ("type", "Succeeded"),
    ("type", "deployed"),
    ("type", "revert"),
    ("type", " succeeded"),
    ("source_url", "http://ci.example/1"),
    ("source_url", "https://user@ci.example/1"),
    ("source_url", "https://ci.example/a b"),
    ("reason", "x" * 501),
    ("reason", "bell\x07"),
    ("reason", "nul\x00"),
    ("reason", "bidi‮"),
    ("service", "Payments"),
    ("service", "a--b"),
    ("environment", "-prod"),
    ("environment", "prod-"),
]


@pytest.mark.parametrize(("name", "value"), FORMATS)
def test_a_value_that_breaks_its_format_is_refused(name: str, value: str) -> None:
    store = RecordingStore()
    with pytest.raises(EventRejected) as rejected:
        ingest_event(INGEST, body(**{name: value}), store)
    assert problems_of(rejected) == {FieldProblem(name, "format")}
    assert store.calls == []


@pytest.mark.parametrize(
    "extra",
    ["extra", "received_at", "created_at", "id", "seq", "status", "credential_id", "Service", ""],
)
def test_an_unknown_field_is_refused_and_a_client_cannot_supply_a_timestamp(extra: str) -> None:
    store = RecordingStore()
    with pytest.raises(EventRejected) as rejected:
        ingest_event(INGEST, {**BODY, extra: "2026-01-01T00:00:00Z"}, store)
    assert problems_of(rejected) == {FieldProblem("", "unknown_field")}
    assert store.calls == []


def test_every_problem_is_reported_once_in_field_order() -> None:
    store = RecordingStore()
    bad = {
        "service": "UPPER",
        "environment": 5,
        "deployment_key": None,
        "type": "nope",
        "version": "",
        "commit_sha": "zz",
        "source_url": "ftp://x",
        "reason": "x" * 501,
        "stowaway": 1,
    }
    with pytest.raises(EventRejected) as rejected:
        ingest_event(INGEST, bad, store)
    assert rejected.value.problems == (
        FieldProblem("", "unknown_field"),
        FieldProblem("service", "format"),
        FieldProblem("environment", "type"),
        FieldProblem("deployment_key", "required"),
        FieldProblem("type", "format"),
        FieldProblem("version", "format"),
        FieldProblem("commit_sha", "format"),
        FieldProblem("source_url", "format"),
        FieldProblem("reason", "format"),
    )
    assert store.calls == []


def test_validation_precedes_r11_so_a_wrong_but_well_formed_binding_with_a_bad_body_is_422() -> (
    None
):
    """ARCHITECTURE §4 step 3: validate the body, then compare slugs. R11 still answers before the
    store is touched, and format errors reveal nothing about whether a target exists."""
    with pytest.raises(EventRejected):
        ingest_event(INGEST, body(service="billing-api", version="!"), RecordingStore())
    with pytest.raises(Forbidden):
        ingest_event(INGEST, body(service="billing-api"), RecordingStore())


def test_the_body_is_not_modified() -> None:
    original = body(reason="r", source_url="https://ci.example/1")
    snapshot = dict(original)
    ingest_event(INGEST, original, RecordingStore())
    assert original == snapshot


# Outcomes and errors pass through untouched

STORED = StoredEvent(id=uuid.uuid4(), type=EventType.SUCCEEDED, source_url=None, reason=None)
OUTCOMES: list[Outcome] = [
    Accepted(uuid.uuid4(), 7, None),  # type: ignore[arg-type]
    Duplicate(STORED),
    *[Reject(reason) for reason in RejectReason],
]


@pytest.mark.parametrize(
    "outcome", OUTCOMES, ids=lambda o: type(o).__name__ + str(getattr(o, "reason", ""))
)
def test_every_outcome_is_returned_as_the_store_gave_it(outcome: Outcome) -> None:
    assert ingest_event(INGEST, body(), RecordingStore(outcome=outcome)) is outcome


@pytest.mark.parametrize("error", [StoreUnavailable(), InvariantFault()])
def test_store_errors_propagate_as_the_same_object(error: Exception) -> None:
    with pytest.raises(type(error)) as caught:
        ingest_event(INGEST, body(), RecordingStore(error=error))
    assert caught.value is error


# Nothing sensitive in an error or a log


def test_nothing_the_client_sent_reaches_an_error_or_a_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = {"reason": SENTINEL, "source_url": f"https://ci.example/{SENTINEL}"}
    attempts: list[tuple[Principal, dict[str, object], RecordingStore]] = [
        (INGEST, body(**secret), RecordingStore()),  # success
        (INGEST, body(**secret, version=SENTINEL), RecordingStore()),  # validation failure
        (INGEST, body(**secret, service="billing-api"), RecordingStore()),  # R11
        (replace(INGEST, scope=Scope.READ), body(**secret), RecordingStore()),  # scope
        (INGEST, body(**secret), RecordingStore(error=InvariantFault())),  # store fault
        (INGEST, {**body(**secret), SENTINEL: SENTINEL}, RecordingStore()),  # unknown field
    ]
    with caplog.at_level(logging.DEBUG):
        for principal, payload, store in attempts:
            try:
                ingest_event(principal, payload, store)
            except Exception as error:  # noqa: BLE001 - inspecting every error category
                assert SENTINEL not in repr(error) + str(error) + repr(error.args)
                assert error.__cause__ is None
                if isinstance(error, EventRejected):
                    assert SENTINEL not in repr(error.problems)
    assert SENTINEL not in caplog.text
