"""HTTP contract of GET /api/v1/deployments and GET /api/v1/deployments/{id} (spec §5), via the
real app with an in-memory history. Real-database behaviour is in the integration tests."""

import base64
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api
from shiptrace.api.credentials import encode_cursor as credentials_cursor
from shiptrace.api.deployments import encode_cursor
from shiptrace.application.access import InvariantFault, Principal, StoreUnavailable
from shiptrace.application.credentials import new_token
from shiptrace.application.deployment_reads import (
    DeploymentDetail,
    DeploymentEventRecord,
    DeploymentFilter,
)
from shiptrace.domain.credentials import Scope, digest
from shiptrace.domain.deployments import EventType, Status

from .fakes import (
    FIXED_TIME,
    DictCredentialAdmin,
    DictDeploymentReads,
    DictDeployments,
    DictIssuer,
    DictRegistry,
    DictStore,
    deployment_summary,
)

PATH = "/api/v1/deployments"
FIXED = FIXED_TIME.isoformat().replace("+00:00", "Z")
SUMMARY_FIELDS = {
    "id",
    "service",
    "environment",
    "deployment_key",
    "version",
    "commit_sha",
    "status",
    "created_at",
}
EVENT_FIELDS = {"id", "type", "received_at", "source_url", "reason"}
HOSTILE = '<script>alert("x")</script>\n‭'


@pytest.fixture
def tokens() -> dict[Scope, str]:
    return {scope: new_token() for scope in Scope}


@pytest.fixture
def reads() -> DictDeploymentReads:
    return DictDeploymentReads()


@pytest.fixture
def client(tokens: dict[Scope, str], reads: DictDeploymentReads) -> TestClient:
    store = DictStore(
        {
            digest(token): Principal(uuid.uuid4(), scope, None, None)
            for scope, token in tokens.items()
        }
    )
    app = build_api(
        readiness=lambda: True,
        docs_enabled=False,
        credentials=store,
        registry=DictRegistry(),
        issuer=DictIssuer(),
        credential_admin=DictCredentialAdmin(),
        deployments=DictDeployments(),
        deployment_reads=reads,
    )
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def read(tokens: dict[Scope, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens[Scope.READ]}"}


def detail_of(n: int, **changes: object) -> DeploymentDetail:
    """A reverted deployment with three events; the last carries hostile text."""
    events = (
        DeploymentEventRecord(
            seq=11,
            id=uuid.UUID(int=901),
            type=EventType.STARTED,
            source_url=None,
            reason=None,
            credential_id=uuid.UUID(int=555),
            received_at=FIXED_TIME,
        ),
        DeploymentEventRecord(
            seq=12,
            id=uuid.UUID(int=902),
            type=EventType.SUCCEEDED,
            source_url="https://ci.example/runs/1",
            reason=None,
            credential_id=uuid.UUID(int=555),
            received_at=FIXED_TIME,
        ),
        DeploymentEventRecord(
            seq=15,
            id=uuid.UUID(int=903),
            type=EventType.REVERTED,
            source_url=None,
            reason=HOSTILE,
            credential_id=uuid.UUID(int=556),
            received_at=FIXED_TIME,
        ),
    )
    return DeploymentDetail(
        deployment=deployment_summary(n, status=Status.REVERTED, **changes), events=events
    )


def errors(response: Any) -> list[dict[str, str]]:
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["code"] == "validation_failed"
    found: list[dict[str, str]] = body["errors"]
    return found


# History


def test_history_item_has_exactly_the_documented_fields(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    reads.items.append(deployment_summary(7, status=Status.SUCCEEDED))
    response = client.get(PATH, headers=read)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "next_cursor"}
    assert body["next_cursor"] is None
    assert body["items"] == [
        {
            "id": str(uuid.UUID(int=7)),
            "service": "payments-api",
            "environment": "production",
            "deployment_key": "key-7",
            "version": "1.4.2",
            "commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "status": "succeeded",
            "created_at": FIXED,
        }
    ]


def test_an_empty_history_is_an_empty_page(client: TestClient, read: dict[str, str]) -> None:
    assert client.get(PATH, headers=read).json() == {"items": [], "next_cursor": None}


def test_admin_reads_history_too(
    client: TestClient, tokens: dict[Scope, str], reads: DictDeploymentReads
) -> None:
    reads.items.append(deployment_summary(1))
    response = client.get(PATH, headers={"Authorization": f"Bearer {tokens[Scope.ADMIN]}"})
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1


def test_pages_walk_every_deployment_once_newest_first(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    reads.items.extend(deployment_summary(n) for n in range(1, 6))
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params: dict[str, str | int] = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        body = client.get(PATH, headers=read, params=params).json()
        pages += 1
        seen += [item["id"] for item in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == [str(uuid.UUID(int=n)) for n in (5, 4, 3, 2, 1)]
    assert pages == 3


def test_the_default_page_is_fifty(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    reads.items.extend(deployment_summary(n) for n in range(1, 61))
    body = client.get(PATH, headers=read).json()
    assert len(body["items"]) == 50
    assert body["next_cursor"] == encode_cursor(uuid.UUID(int=11))


def test_filters_reach_the_read_model_as_sent(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    reads.items.append(deployment_summary(1, status=Status.FAILED))
    reads.items.append(deployment_summary(2, status=Status.SUCCEEDED))
    reads.items.append(deployment_summary(3, service="billing", status=Status.FAILED))
    params = {"service": "payments-api", "environment": "production", "status": "failed"}
    body = client.get(PATH, headers=read, params=params).json()
    assert [item["id"] for item in body["items"]] == [str(uuid.UUID(int=1))]
    assert reads.calls == [
        (DeploymentFilter("payments-api", "production", Status.FAILED), None, 51)
    ]


def test_a_slug_that_names_nothing_is_an_empty_page(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    reads.items.append(deployment_summary(1))
    response = client.get(PATH, headers=read, params={"service": "no-such-service"})
    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}


@pytest.mark.parametrize(
    ("params", "location", "rule"),
    [
        ({"service": "Payments"}, "query.service", "slug_format"),
        ({"service": ""}, "query.service", "slug_format"),
        ({"environment": "a--b"}, "query.environment", "slug_format"),
        ({"status": "done"}, "query.status", "enum"),
        ({"status": "SUCCEEDED"}, "query.status", "enum"),
        ({"status": "failed"}, "query.status", "requires_service_and_environment"),
        (
            {"status": "failed", "service": "payments-api"},
            "query.status",
            "requires_service_and_environment",
        ),
        (
            {"status": "failed", "environment": "production"},
            "query.status",
            "requires_service_and_environment",
        ),
        ({"limit": "0"}, "query.limit", "greater_than_equal"),
        ({"limit": "101"}, "query.limit", "less_than_equal"),
        ({"limit": "ten"}, "query.limit", "int_parsing"),
        ({"cursor": "not a cursor"}, "query.cursor", "invalid_cursor"),
        ({"cursor": ""}, "query.cursor", "invalid_cursor"),
    ],
)
def test_an_invalid_query_is_422_naming_place_and_rule_and_never_reaches_the_read_model(
    client: TestClient,
    read: dict[str, str],
    reads: DictDeploymentReads,
    params: dict[str, str],
    location: str,
    rule: str,
) -> None:
    response = client.get(PATH, headers=read, params=params)
    assert errors(response) == [{"location": location, "rule": rule}]
    if rule != "requires_service_and_environment":  # Its values are valid, and "failed" is a word.
        assert all(value not in response.text for value in params.values() if value)
    assert reads.calls == []


def test_a_cursor_from_another_list_is_refused(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    foreign = credentials_cursor(uuid.UUID(int=3))
    response = client.get(PATH, headers=read, params={"cursor": foreign})
    assert errors(response) == [{"location": "query.cursor", "rule": "invalid_cursor"}]
    assert reads.calls == []


def test_only_the_exact_cursor_form_is_accepted(client: TestClient, read: dict[str, str]) -> None:
    good = encode_cursor(uuid.UUID(int=3))
    assert client.get(PATH, headers=read, params={"cursor": good}).status_code == 200
    # The same position with the UUID in capitals decodes, but is not the form the server issues.
    capitals = base64.urlsafe_b64encode(
        f"v1:deployments:{str(uuid.UUID(int=0xABCDEF)).upper()}".encode()
    ).decode()
    assert "=" not in capitals
    for altered in (good + "A", good[:-1], good + "=", capitals.rstrip("=")):
        response = client.get(PATH, headers=read, params={"cursor": altered})
        assert errors(response) == [{"location": "query.cursor", "rule": "invalid_cursor"}]


# Detail


def test_detail_has_exactly_the_documented_fields_and_events_in_order(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    detail = detail_of(9)
    reads.details[detail.deployment.id] = detail
    response = client.get(f"{PATH}/{detail.deployment.id}", headers=read)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert set(body) == SUMMARY_FIELDS | {"events"}
    assert body["id"] == str(detail.deployment.id)
    assert body["status"] == "reverted"
    assert body["created_at"] == FIXED
    assert [set(event) for event in body["events"]] == [EVENT_FIELDS] * 3
    assert [event["type"] for event in body["events"]] == ["started", "succeeded", "reverted"]
    assert body["events"][1] == {
        "id": str(uuid.UUID(int=902)),
        "type": "succeeded",
        "received_at": FIXED,
        "source_url": "https://ci.example/runs/1",
        "reason": None,
    }


def test_detail_returns_reason_text_unchanged_as_json(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    detail = detail_of(9)
    reads.details[detail.deployment.id] = detail
    response = client.get(f"{PATH}/{detail.deployment.id}", headers=read)
    assert response.json()["events"][2]["reason"] == HOSTILE
    assert response.headers["content-type"] == "application/json"


def test_responses_carry_no_internal_identifier(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    """Service, environment and credential ids and `seq` stay inside the service."""
    detail = detail_of(9)
    reads.details[detail.deployment.id] = detail
    reads.items.append(detail.deployment)
    internal = [
        str(detail.deployment.service_id),
        str(detail.deployment.environment_id),
        str(uuid.UUID(int=555)),
        str(uuid.UUID(int=556)),
        "credential",
        "seq",
    ]
    for text in (
        client.get(f"{PATH}/{detail.deployment.id}", headers=read).text,
        client.get(PATH, headers=read).text,
    ):
        assert all(value not in text for value in internal)


def test_an_unknown_deployment_is_404(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    missing = uuid.UUID(int=404)
    response = client.get(f"{PATH}/{missing}", headers=read)
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == "not_found"
    assert str(missing) not in response.text
    assert reads.gets == [missing]


def test_an_id_that_is_not_a_uuid_is_422_and_never_reaches_the_read_model(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    response = client.get(f"{PATH}/not-a-uuid", headers=read)
    assert errors(response) == [{"location": "path.deployment_id", "rule": "uuid_parsing"}]
    assert "not-a-uuid" not in response.text
    assert reads.gets == []


# Authentication and authorization come before everything else


@pytest.mark.parametrize("url", [PATH + "?limit=0&status=nope", PATH + "/not-a-uuid"])
def test_a_caller_without_a_credential_learns_nothing_about_validity(
    client: TestClient, reads: DictDeploymentReads, url: str
) -> None:
    response = client.get(url)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert reads.calls == [] and reads.gets == []


@pytest.mark.parametrize("url", [PATH, PATH + "?limit=0", PATH + f"/{uuid.UUID(int=9)}"])
def test_an_ingest_credential_is_refused_before_anything_is_read(
    client: TestClient, tokens: dict[Scope, str], reads: DictDeploymentReads, url: str
) -> None:
    reads.details[uuid.UUID(int=9)] = detail_of(9)
    response = client.get(url, headers={"Authorization": f"Bearer {tokens[Scope.INGEST]}"})
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
    assert reads.calls == [] and reads.gets == []


# Failures of the store


@pytest.mark.parametrize("url", [PATH, PATH + f"/{uuid.UUID(int=9)}"])
def test_an_unavailable_store_is_503_with_retry_after(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads, url: str
) -> None:
    reads.error = StoreUnavailable()
    response = client.get(url, headers=read)
    assert response.status_code == 503
    assert response.json()["code"] == "unavailable"
    assert response.headers["retry-after"] == "1"


@pytest.mark.parametrize("url", [PATH, PATH + f"/{uuid.UUID(int=9)}"])
def test_corrupt_stored_state_is_a_plain_500(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads, url: str
) -> None:
    reads.error = InvariantFault()
    response = client.get(url, headers=read)
    assert response.status_code == 500
    body = response.json()
    assert body["code"] == "internal_error"
    assert set(body) == {"type", "title", "status", "detail", "code"}


LATEST = "/api/v1/services/payments-api/environments/production/latest"


def test_latest_returns_only_the_public_summary(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    reads.latest_result = deployment_summary(7, status=Status.SUCCEEDED)
    response = client.get(LATEST, headers=read)
    assert response.status_code == 200
    assert set(response.json()) == SUMMARY_FIELDS
    assert response.json()["id"] == str(uuid.UUID(int=7))
    assert response.json()["status"] == "succeeded"
    assert reads.latest_calls == [("payments-api", "production")]


def test_latest_without_a_success_is_json_null(client: TestClient, read: dict[str, str]) -> None:
    response = client.get(LATEST, headers=read)
    assert response.status_code == 200
    assert response.json() is None


@pytest.mark.parametrize("scope,expected", [(None, 401), (Scope.INGEST, 403)])
def test_latest_authentication_precedes_slug_validation(
    client: TestClient,
    tokens: dict[Scope, str],
    reads: DictDeploymentReads,
    scope: Scope | None,
    expected: int,
) -> None:
    headers = {} if scope is None else {"Authorization": f"Bearer {tokens[scope]}"}
    response = client.get(LATEST.replace("payments-api", "BAD"), headers=headers)
    assert response.status_code == expected
    assert reads.latest_calls == []


def test_latest_invalid_slug_is_sanitized(
    client: TestClient, read: dict[str, str], reads: DictDeploymentReads
) -> None:
    response = client.get(LATEST.replace("payments-api", "PRIVATE_BAD"), headers=read)
    assert response.status_code == 422
    assert "PRIVATE_BAD" not in response.text
    assert reads.latest_calls == []


@pytest.mark.parametrize("fault,status", [(StoreUnavailable(), 503), (InvariantFault(), 500)])
def test_latest_store_fault_uses_existing_safe_handlers(
    client: TestClient,
    read: dict[str, str],
    reads: DictDeploymentReads,
    fault: Exception,
    status: int,
) -> None:
    reads.error = fault
    response = client.get(LATEST, headers=read)
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    assert {"type", "title", "status", "detail", "code"} <= set(response.json())
    assert "traceback" not in response.text.lower()
