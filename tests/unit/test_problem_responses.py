"""RFC 9457 problem responses and bearer protection, through the real app with a fake store.

No production route is protected yet (CP5 adds them), so the tests attach probe routes.
"""

import uuid
from dataclasses import dataclass, field

import httpx2
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, Field

from shiptrace.api.app import build_api
from shiptrace.api.auth import require
from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import Action, Scope, digest

PROBLEM_KEYS = {"type", "title", "status", "detail", "code"}
# Written out here, not read from the code, so a changed or request-derived text fails a test.
FIXED_TEXT = {
    "unauthenticated": ("Unauthenticated", "A valid bearer credential is required."),
    "forbidden": ("Forbidden", "The credential does not allow this action."),
    "not_found": ("Not found", "The requested resource does not exist."),
    "method_not_allowed": ("Method not allowed", "The resource does not support this method."),
    "validation_failed": ("Validation failed", "The request is not valid."),
    "internal_error": ("Internal error", "The request could not be completed."),
    "unavailable": ("Service unavailable", "A dependency is unavailable. Retry later."),
}
SENTINEL = "SENTINEL-" + uuid.uuid4().hex
PROBE = "/api/v1/_probe"


@dataclass
class DictStore:
    known: dict[bytes, Principal] = field(default_factory=dict)
    broken: bool = False

    def find_active(self, secret_digest: bytes) -> Principal | None:
        if self.broken:
            raise StoreUnavailable
        return self.known.get(secret_digest)


class ProbeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=r"^[a-z]+$", max_length=10)


def principal(scope: Scope) -> Principal:
    return Principal(id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None)


def probe_app(store: DictStore) -> FastAPI:
    app = build_api(readiness=lambda: True, docs_enabled=False, credentials=store)

    def view() -> dict[str, str]:
        return {"status": "ok"}

    def register(body: ProbeBody) -> dict[str, str]:
        return {"slug": body.slug}

    def explode() -> dict[str, str]:
        raise RuntimeError(SENTINEL)

    app.add_api_route(
        PROBE, view, methods=["GET"], dependencies=[Depends(require(Action.VIEW_REGISTRY))]
    )
    app.add_api_route(
        PROBE, register, methods=["POST"], dependencies=[Depends(require(Action.REGISTER))]
    )
    app.add_api_route("/api/v1/_explode", explode, methods=["GET"])
    return app


@pytest.fixture
def tokens() -> dict[Scope, str]:
    return {scope: new_token() for scope in Scope}


@pytest.fixture
def client(tokens: dict[Scope, str]) -> TestClient:
    store = DictStore({digest(token): principal(scope) for scope, token in tokens.items()})
    return TestClient(probe_app(store), raise_server_exceptions=False)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def assert_problem(response: httpx2.Response, status: int, code: str) -> dict[str, object]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, object] = response.json()
    # Exactly these members: nothing extra, such as an instance URL that would echo the query.
    assert set(body) == (PROBLEM_KEYS | {"errors"} if code == "validation_failed" else PROBLEM_KEYS)
    assert (body["title"], body["detail"]) == FIXED_TEXT[code]
    assert body["type"] == f"urn:shiptrace:problem:{code}"
    assert body["status"] == status
    assert body["code"] == code
    return body


def test_valid_credential_with_the_right_scope_passes(
    client: TestClient, tokens: dict[Scope, str]
) -> None:
    for scope in (Scope.READ, Scope.ADMIN):
        response = client.get(PROBE, headers=bearer(tokens[scope]))
        assert response.status_code == 200, scope
        assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer st1_short"},
        {"Authorization": "Bearer st2_" + "A" * 43},
    ],
)
def test_missing_or_malformed_credentials_are_401(
    client: TestClient, headers: dict[str, str]
) -> None:
    response = client.get(PROBE, headers=headers)
    assert_problem(response, 401, "unauthenticated")
    assert response.headers["www-authenticate"] == "Bearer"


def test_unknown_credential_is_401(client: TestClient) -> None:
    response = client.get(PROBE, headers=bearer(new_token()))
    assert_problem(response, 401, "unauthenticated")
    assert response.headers["www-authenticate"] == "Bearer"


def test_every_401_is_identical(client: TestClient) -> None:
    """No oracle: missing, malformed and unknown credentials cannot be told apart."""
    responses = [
        client.get(PROBE),
        client.get(PROBE, headers={"Authorization": "Bearer st1_short"}),
        client.get(PROBE, headers=bearer(new_token())),
    ]
    assert len({(r.content, r.headers["www-authenticate"]) for r in responses}) == 1


def test_two_authorization_headers_are_401(client: TestClient, tokens: dict[Scope, str]) -> None:
    value = f"Bearer {tokens[Scope.ADMIN]}"
    response = client.get(PROBE, headers=[("Authorization", value), ("Authorization", value)])
    assert_problem(response, 401, "unauthenticated")


@pytest.mark.parametrize(
    ("scope", "method"), [(Scope.INGEST, "GET"), (Scope.READ, "POST"), (Scope.INGEST, "POST")]
)
def test_wrong_scope_is_403_without_a_challenge(
    client: TestClient, tokens: dict[Scope, str], scope: Scope, method: str
) -> None:
    response = client.request(method, PROBE, headers=bearer(tokens[scope]), json={"slug": "ok"})
    assert_problem(response, 403, "forbidden")
    assert "www-authenticate" not in response.headers


def test_authentication_comes_before_schema_validation(client: TestClient) -> None:
    """For a well-formed JSON body, an anonymous caller learns nothing about the schema.

    A body that is not JSON at all is rejected by FastAPI before dependencies run, so it gets
    422 without authentication; it reveals no schema and echoes nothing (V121).
    """
    response = client.post(PROBE, json={"slug": 1, "extra": True})
    assert_problem(response, 401, "unauthenticated")


def test_validation_failure_lists_locations_and_rules_never_values(
    client: TestClient, tokens: dict[Scope, str]
) -> None:
    response = client.post(
        PROBE, headers=bearer(tokens[Scope.ADMIN]), json={"slug": SENTINEL, SENTINEL: SENTINEL}
    )
    body = assert_problem(response, 422, "validation_failed")
    assert set(body) == PROBLEM_KEYS | {"errors"}
    assert SENTINEL not in response.text
    errors = body["errors"]
    assert isinstance(errors, list) and errors
    assert all(set(error) == {"location", "rule"} for error in errors)
    assert {"location": "body.slug", "rule": "string_too_long"} in errors  # the sentinel is long
    assert {"location": "body", "rule": "extra_forbidden"} in errors


def test_unparsable_json_is_a_validation_failure(
    client: TestClient, tokens: dict[Scope, str]
) -> None:
    response = client.post(
        PROBE,
        headers={**bearer(tokens[Scope.ADMIN]), "Content-Type": "application/json"},
        content=b'{"slug": ' + SENTINEL.encode(),
    )
    assert_problem(response, 422, "validation_failed")
    assert SENTINEL not in response.text


@pytest.mark.parametrize("authorized", [True, False])
def test_undecodable_body_is_a_client_error_not_500(
    client: TestClient, tokens: dict[Scope, str], authorized: bool
) -> None:
    """Invalid UTF-8 makes FastAPI raise HTTP 400 before any dependency runs."""
    headers = {"Content-Type": "application/json"}
    if authorized:
        headers.update(bearer(tokens[Scope.ADMIN]))
    response = client.post(PROBE, headers=headers, content=b'{"slug": "\xff\xfe"}')
    body = assert_problem(response, 422, "validation_failed")
    assert body["errors"] == [{"location": "body", "rule": "unparsable"}]


def test_unknown_route_is_a_404_problem(client: TestClient) -> None:
    assert_problem(client.get("/api/v1/nothing-here"), 404, "not_found")


def test_wrong_method_is_a_405_problem_that_keeps_allow(client: TestClient) -> None:
    response = client.delete(PROBE)
    assert_problem(response, 405, "method_not_allowed")
    # Every method the path supports, across its separate GET and POST routes. Starlette's own
    # 405 named only the first route's methods. FastAPI routes do not serve HEAD for GET.
    allowed = set(response.headers["allow"].replace(" ", "").split(","))
    assert allowed == {"GET", "POST"}


def test_store_outage_is_503_with_retry_after(tokens: dict[Scope, str]) -> None:
    client = TestClient(probe_app(DictStore(broken=True)), raise_server_exceptions=False)
    response = client.get(PROBE, headers=bearer(tokens[Scope.ADMIN]))
    assert_problem(response, 503, "unavailable")
    assert response.headers["retry-after"].isdigit()


def test_unexpected_errors_are_500_and_reveal_nothing(client: TestClient) -> None:
    response = client.get("/api/v1/_explode")
    assert_problem(response, 500, "internal_error")
    assert SENTINEL not in response.text
    assert "Traceback" not in response.text and "RuntimeError" not in response.text


def test_titles_and_details_are_fixed_per_code(
    client: TestClient, tokens: dict[Scope, str]
) -> None:
    first = client.get(PROBE).json()
    second = client.get(PROBE, headers=bearer(new_token())).json()
    assert (first["title"], first["detail"]) == (second["title"], second["detail"])


def test_no_response_contains_the_credential(client: TestClient, tokens: dict[Scope, str]) -> None:
    token = tokens[Scope.READ]
    responses = [
        client.post(PROBE, headers=bearer(token), json={"slug": "ok"}),  # 403
        client.get("/api/v1/nothing", headers=bearer(token)),  # 404
        client.delete(PROBE, headers=bearer(token)),  # 405
        client.get(PROBE, headers={"Authorization": f"Bearer {token} x"}),  # 401
    ]
    for response in responses:
        assert token not in response.text
        assert token not in str(response.headers)
        assert digest(token).hex() not in response.text
