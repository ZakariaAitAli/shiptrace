"""POST /api/v1/deployment-events (spec §3 and §5), through the real app with in-memory stores.

The order under test is: authenticate, scope, the principal's binding, field validation, R11, then
the store. A request refused at any step before the last must leave the store untouched, and the
body is not read at all until the caller is authenticated and allowed.
"""

import json
import logging
import uuid
from dataclasses import dataclass, replace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api
from shiptrace.application.access import InvariantFault, Principal, StoreUnavailable
from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import Scope, digest

from .fakes import DictCredentialAdmin, DictDeployments, DictIssuer, DictRegistry, DictStore

PATH = "/api/v1/deployment-events"
SHA = "0123456789abcdef0123456789abcdef01234567"
SENTINEL = "SENTINEL-" + uuid.uuid4().hex
PROBLEM_KEYS = {"type", "title", "status", "detail", "code"}
SERVICE_ID, ENVIRONMENT_ID, INGEST_ID = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
BOUND = Principal(
    id=INGEST_ID,
    scope=Scope.INGEST,
    service_id=SERVICE_ID,
    environment_id=ENVIRONMENT_ID,
    service_slug="payments-api",
    environment_slug="production",
)
BODY: dict[str, Any] = {
    "service": "payments-api",
    "environment": "production",
    "deployment_key": "gha-12345678-1",
    "type": "started",
    "version": "1.4.2",
    "commit_sha": SHA,
}
# Written out here, not read from the code, so a changed or request-derived text fails a test.
CONFLICTS = {
    "event_conflict": (
        "Event conflict",
        "An event of this type with different content is already recorded.",
    ),
    "deployment_attribute_conflict": (
        "Deployment attribute conflict",
        "The version or commit differs from the recorded deployment.",
    ),
    "terminal_conflict": (
        "Terminal conflict",
        "A different terminal event is already recorded for this deployment.",
    ),
    "revert_requires_success": (
        "Revert requires success",
        "A revert is accepted only after a succeeded event is recorded. Retry later.",
    ),
    "revert_not_applicable": (
        "Revert not applicable",
        "The deployment did not succeed, so it cannot be reverted.",
    ),
}


@dataclass
class Rig:
    client: TestClient
    deployments: DictDeployments
    tokens: dict[str, str]

    def auth(self, who: str = "ingest") -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[who]}"}

    def post(self, body: object = None, who: str | None = "ingest", **changes: object) -> Any:
        payload = {**BODY, **changes} if body is None else body
        headers = {} if who is None else self.auth(who)
        return self.client.post(PATH, json=payload, headers=headers)


@pytest.fixture
def rig() -> Rig:
    unbound = replace(BOUND, id=uuid.uuid4(), service_id=None, service_slug=None)
    principals = {
        "ingest": BOUND,
        "unbound": unbound,
        "read": Principal(uuid.uuid4(), Scope.READ, None, None),
        "admin": Principal(uuid.uuid4(), Scope.ADMIN, None, None),
    }
    tokens = {name: new_token() for name in principals}
    store = DictStore({digest(tokens[name]): p for name, p in principals.items()})
    deployments = DictDeployments()
    app = build_api(
        readiness=lambda: True,
        docs_enabled=False,
        credentials=store,
        registry=DictRegistry(),
        issuer=DictIssuer(),
        credential_admin=DictCredentialAdmin(),
        deployments=deployments,
    )
    return Rig(TestClient(app, raise_server_exceptions=False), deployments, tokens)


def assert_problem(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert set(body) >= PROBLEM_KEYS
    assert (body["status"], body["code"]) == (status, code)
    assert body["type"] == f"urn:shiptrace:problem:{code}"
    return body


# The success contract


def test_a_new_event_is_201_with_its_database_id_and_type(rig: Rig) -> None:
    response = rig.post(type="succeeded", reason="ok", source_url="https://ci.example/runs/1")
    assert response.status_code == 201
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert set(body) == {"id", "type", "duplicate"}
    stored = next(iter(rig.deployments.stored.values()))[2][0]
    assert body == {"id": str(stored.id), "type": "succeeded", "duplicate": False}


def test_a_replay_is_200_and_returns_the_original_event_without_writing(rig: Rig) -> None:
    first = rig.post(reason="same")
    again = rig.post(reason="same")
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.headers["content-type"] == "application/json"
    assert again.json() == {**first.json(), "duplicate": True}
    assert rig.deployments.events() == 1


def test_out_of_order_and_lost_started_events_are_201(rig: Rig) -> None:
    assert rig.post(type="succeeded").status_code == 201  # R8
    assert rig.post(type="started").status_code == 201  # R7
    assert rig.post(type="reverted").status_code == 201  # R9 satisfied


def test_the_response_echoes_no_request_value(rig: Rig) -> None:
    response = rig.post(reason=SENTINEL, source_url=f"https://ci.example/{SENTINEL}")
    assert SENTINEL not in response.text
    assert set(response.json()) == {"id", "type", "duplicate"}


def test_the_target_and_attribution_come_from_the_credential_not_the_body(rig: Rig) -> None:
    rig.post()
    [(target, event, credential_id)] = rig.deployments.calls
    assert (target.service_id, target.environment_id) == (SERVICE_ID, ENVIRONMENT_ID)
    assert target.deployment_key == BODY["deployment_key"]
    assert credential_id == INGEST_ID
    assert event.type.value == "started"


# The conflicts, as problem documents


@pytest.mark.parametrize(
    ("code", "setup", "request_"),
    [
        ("event_conflict", [{"reason": "a"}], {"reason": "b"}),
        ("deployment_attribute_conflict", [{}], {"version": "2.0.0"}),
        ("terminal_conflict", [{"type": "succeeded"}], {"type": "failed"}),
        ("revert_requires_success", [], {"type": "reverted"}),
        ("revert_not_applicable", [{"type": "failed"}], {"type": "reverted"}),
    ],
)
def test_each_rejection_is_a_409_problem_with_its_stable_code(
    rig: Rig, code: str, setup: list[dict[str, Any]], request_: dict[str, Any]
) -> None:
    for step in setup:
        assert rig.post(**step).status_code == 201
    before = rig.deployments.events()
    response = rig.post(**request_)
    body = assert_problem(response, 409, code)
    assert (body["title"], body["detail"]) == CONFLICTS[code]
    assert set(body) == PROBLEM_KEYS
    assert rig.deployments.events() == before  # Nothing was written.


def test_no_conflict_carries_a_retry_after_header(rig: Rig) -> None:
    """The spec asks for Retry-After on 503 only. Retryability of R9 is carried by its code."""
    rig.post(type="failed")
    responses = [
        rig.post(type="reverted"),  # revert_not_applicable
        rig.post(type="succeeded"),  # terminal_conflict
        rig.post(reason="x", type="failed"),  # event_conflict
        rig.post(version="9.9.9", type="failed"),  # deployment_attribute_conflict
        rig.post(type="reverted", deployment_key="never-existed"),  # revert_requires_success
    ]
    assert [r.status_code for r in responses] == [409] * 5
    assert all("retry-after" not in r.headers for r in responses)


def test_a_revert_refused_for_lack_of_success_is_accepted_when_retried(rig: Rig) -> None:
    assert rig.post(type="reverted").status_code == 409
    assert rig.deployments.events() == 0  # No deployment was created.
    assert rig.post(type="succeeded").status_code == 201
    assert rig.post(type="reverted").status_code == 201


# Authentication and scope come first, and the body is not read before them


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Bearer", "Bearer st1_short", f"Bearer {new_token()}"],
    ids=["missing", "empty", "bare", "malformed", "unknown"],
)
def test_unauthenticated_calls_are_401_even_with_a_hostile_body(
    rig: Rig, authorization: str | None
) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}
    for content in (b"{not json", b"", b"[" * 200_000, b"\xff\xfe", b'{"service": 1}'):
        response = rig.client.post(
            PATH, content=content, headers={**headers, "Content-Type": "application/json"}
        )
        assert_problem(response, 401, "unauthenticated")
        assert response.headers["www-authenticate"] == "Bearer"
    assert rig.deployments.calls == []


@pytest.mark.parametrize("who", ["read", "admin"])
def test_a_read_or_admin_credential_is_403_before_the_body_or_the_store(rig: Rig, who: str) -> None:
    for content in (b"{not json", b'{"nonsense": 1}', b""):
        response = rig.client.post(
            PATH, content=content, headers={**rig.auth(who), "Content-Type": "application/json"}
        )
        assert_problem(response, 403, "forbidden")
    assert_problem(rig.post(who=who), 403, "forbidden")
    assert rig.deployments.calls == []


# Validation: 422 with locations and rules, never values


def test_a_valid_body_with_the_wrong_service_or_environment_is_403(rig: Rig) -> None:
    for changes in (
        {"service": "billing-api"},
        {"environment": "staging"},
        {"service": "billing-api", "environment": "staging"},
        {"service": "environment", "environment": "payments-api"},
    ):
        assert_problem(rig.post(**changes), 403, "forbidden")
    assert rig.deployments.calls == []


def test_r11_and_scope_denial_are_indistinguishable(rig: Rig) -> None:
    by_scope = rig.post(who="read")
    by_binding = rig.post(service="billing-api")
    unregistered = rig.post(service="never-registered-anywhere")
    assert by_scope.status_code == by_binding.status_code == unregistered.status_code == 403
    assert by_scope.json() == by_binding.json() == unregistered.json()
    assert dict(by_scope.headers).keys() == dict(by_binding.headers).keys()
    assert "www-authenticate" not in by_binding.headers


@pytest.mark.parametrize(
    ("changes", "location", "rule"),
    [
        ({"version": "!bad"}, "body.version", "format"),
        ({"commit_sha": SHA.upper()}, "body.commit_sha", "format"),
        ({"type": "deployed"}, "body.type", "format"),
        ({"deployment_key": ""}, "body.deployment_key", "format"),
        ({"service": "Payments"}, "body.service", "format"),
        ({"source_url": "http://ci.example/1"}, "body.source_url", "format"),
        ({"reason": "bell\x07"}, "body.reason", "format"),
        ({"version": 1}, "body.version", "type"),
        ({"reason": True}, "body.reason", "type"),
        ({"version": None}, "body.version", "required"),
        ({"extra": "x"}, "body", "unknown_field"),
        ({"received_at": "2026-01-01T00:00:00Z"}, "body", "unknown_field"),
    ],
)
def test_an_invalid_field_is_422_naming_the_field_and_rule(
    rig: Rig, changes: dict[str, Any], location: str, rule: str
) -> None:
    response = rig.post(**changes)
    body = assert_problem(response, 422, "validation_failed")
    assert body["errors"] == [{"location": location, "rule": rule}]
    assert rig.deployments.calls == []


def test_every_problem_is_reported_and_no_value_is_echoed(rig: Rig) -> None:
    response = rig.post(
        version=SENTINEL + "!",
        reason="x" * 501,
        source_url=SENTINEL,
        deployment_key=None,
        stowaway=SENTINEL,
    )
    body = assert_problem(response, 422, "validation_failed")
    assert body["errors"] == [
        {"location": "body", "rule": "unknown_field"},
        {"location": "body.deployment_key", "rule": "required"},
        {"location": "body.version", "rule": "format"},
        {"location": "body.source_url", "rule": "format"},
        {"location": "body.reason", "rule": "format"},
    ]
    assert SENTINEL not in response.text


@pytest.mark.parametrize("content", [b"{not json", b"", b"[" * 200_000, b"\xff\xfe\xfd"])
def test_an_unparsable_body_is_422_not_500(rig: Rig, content: bytes) -> None:
    response = rig.client.post(
        PATH, content=content, headers={**rig.auth(), "Content-Type": "application/json"}
    )
    body = assert_problem(response, 422, "validation_failed")
    assert body["errors"] == [{"location": "body", "rule": "unparsable"}]
    assert rig.deployments.calls == []


@pytest.mark.parametrize("payload", [[], [BODY], "text", 1, 1.5, True, None])
def test_a_body_that_is_not_an_object_is_422(rig: Rig, payload: object) -> None:
    # Explicit content: httpx sends no body at all for json=None, and JSON null is a case here.
    response = rig.client.post(
        PATH,
        content=json.dumps(payload),
        headers={**rig.auth(), "Content-Type": "application/json"},
    )
    body = assert_problem(response, 422, "validation_failed")
    assert body["errors"] == [{"location": "body", "rule": "object_required"}]
    assert rig.deployments.calls == []


# Precedence: scope, binding, validation, R11, store


def test_validation_precedes_r11_and_an_unbound_principal_precedes_validation(rig: Rig) -> None:
    assert_problem(rig.post(service="billing-api", version="!"), 422, "validation_failed")
    assert_problem(rig.post(service="billing-api"), 403, "forbidden")
    # A credential whose binding is incomplete is a server fault, even for an invalid body.
    assert_problem(rig.post(who="unbound", version="!"), 500, "internal_error")
    assert_problem(rig.post(who="unbound"), 500, "internal_error")
    # And scope precedes everything else.
    assert_problem(rig.post(who="read", version="!", service="billing-api"), 403, "forbidden")
    assert rig.deployments.calls == []


# Store failures


def test_an_unavailable_store_is_503_with_retry_after(rig: Rig) -> None:
    rig.deployments.error = StoreUnavailable()
    response = rig.post()
    body = assert_problem(response, 503, "unavailable")
    assert set(body) == PROBLEM_KEYS
    assert response.headers["retry-after"].isdigit()


def test_an_invariant_fault_is_500_and_not_retryable(rig: Rig) -> None:
    rig.deployments.error = InvariantFault()
    response = rig.post()
    assert_problem(response, 500, "internal_error")
    assert "retry-after" not in response.headers


def test_an_unexpected_store_exception_reveals_nothing(rig: Rig) -> None:
    rig.deployments.error = RuntimeError(f"INSERT ... {SENTINEL} Key (reason)=({SENTINEL})")
    response = rig.post(reason=SENTINEL)
    assert_problem(response, 500, "internal_error")
    assert SENTINEL not in response.text


# Nothing sensitive in a response or a log


def test_no_response_or_log_line_holds_a_token_a_reason_or_a_url(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    secret = {"reason": SENTINEL, "source_url": f"https://ci.example/{SENTINEL}"}
    token = rig.tokens["ingest"]
    with caplog.at_level(logging.DEBUG):
        responses = [
            rig.post(**secret),  # 201
            rig.post(**secret),  # 200
            rig.post(**{**secret, "reason": SENTINEL + "2"}),  # 409
            rig.post(**secret, version=SENTINEL + "!"),  # 422
            rig.post(**secret, service="billing-api"),  # 403
            rig.post(**secret, who="read"),  # 403
            rig.post(**secret, who=None),  # 401
        ]
        rig.deployments.error = InvariantFault()
        responses.append(rig.post(**secret))  # 500
        rig.deployments.error = StoreUnavailable()
        responses.append(rig.post(**secret))  # 503
    assert [r.status_code for r in responses] == [201, 200, 409, 422, 403, 403, 401, 500, 503]
    for response in responses:
        assert SENTINEL not in response.text
        assert token not in response.text
    assert SENTINEL not in caplog.text
    assert token not in caplog.text


def test_the_route_requires_post(rig: Rig) -> None:
    response = rig.client.get(PATH, headers=rig.auth())
    assert_problem(response, 405, "method_not_allowed")
    assert "POST" in response.headers["allow"]
