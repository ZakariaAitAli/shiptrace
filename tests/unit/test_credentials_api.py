"""HTTP contract of POST /api/v1/credentials (spec §5), via the real app with in-memory stores."""

import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api
from shiptrace.api.credentials import IssuedResponse
from shiptrace.application.access import Principal
from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import Scope, digest, display_prefix, is_well_formed

from .fakes import FIXED_TIME, DictIssuer, DictRegistry, DictStore

PATH = "/api/v1/credentials"
SENTINEL = "zz" + uuid.uuid4().hex[:8]
READ = {"name": "reader", "scope": "read"}
INGEST = {
    "name": "ci payments",
    "scope": "ingest",
    "service": "payments-api",
    "environment": "production",
    "expires_in_days": 90,
}
FIELDS = {
    "id",
    "name",
    "scope",
    "service",
    "environment",
    "display_prefix",
    "created_at",
    "expires_at",
    "token",
}


@pytest.fixture
def tokens() -> dict[Scope, str]:
    return {scope: new_token() for scope in Scope}


@pytest.fixture
def issuer() -> DictIssuer:
    return DictIssuer(services={"payments-api"}, environments={"production"})


def app_with(tokens: dict[Scope, str], issuer: DictIssuer) -> TestClient:
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
        issuer=issuer,
    )
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client(tokens: dict[Scope, str], issuer: DictIssuer) -> TestClient:
    return app_with(tokens, issuer)


@pytest.fixture
def admin(tokens: dict[Scope, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens[Scope.ADMIN]}"}


def test_ingest_issue_is_201_with_every_field_and_no_store(
    client: TestClient, admin: dict[str, str], issuer: DictIssuer
) -> None:
    response = client.post(PATH, headers=admin, json=INGEST)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == FIELDS
    assert is_well_formed(body["token"])
    [(_, stored_digest, _)] = issuer.added
    assert stored_digest == digest(body["token"])
    assert body["display_prefix"] == display_prefix(body["token"])
    assert body["id"] == str(issuer.ids[0])
    assert body["name"] == "ci payments"
    assert body["scope"] == "ingest"
    assert (body["service"], body["environment"]) == ("payments-api", "production")
    assert body["created_at"] == FIXED_TIME.isoformat().replace("+00:00", "Z")
    expires = FIXED_TIME + timedelta(days=90)
    assert body["expires_at"] == expires.isoformat().replace("+00:00", "Z")


@pytest.mark.parametrize(
    "body", [READ, {**READ, "service": None, "environment": None, "expires_in_days": None}]
)
def test_read_issue_has_null_bindings_and_expiry(
    client: TestClient, admin: dict[str, str], body: dict[str, object]
) -> None:
    response = client.post(PATH, headers=admin, json=body)
    assert response.status_code == 201
    issued = response.json()
    assert issued["scope"] == "read"
    assert issued["service"] is None
    assert issued["environment"] is None
    assert issued["expires_at"] is None


@pytest.mark.parametrize("scope", [Scope.READ, Scope.INGEST])
def test_non_admin_is_403_and_nothing_is_written(
    client: TestClient, tokens: dict[Scope, str], issuer: DictIssuer, scope: Scope
) -> None:
    response = client.post(PATH, headers={"Authorization": f"Bearer {tokens[scope]}"}, json=READ)
    assert response.status_code == 403
    assert "token" not in response.json()
    assert issuer.added == []


def test_missing_credential_is_401(client: TestClient, issuer: DictIssuer) -> None:
    assert client.post(PATH, json=READ).status_code == 401
    assert issuer.added == []


@pytest.mark.parametrize(
    ("body", "errors"),
    [
        ({**READ, "scope": "admin"}, [("body.scope", "scope_not_issuable")]),
        ({**READ, "scope": SENTINEL}, [("body.scope", "scope_not_issuable")]),
        ({**READ, "scope": "READ"}, [("body.scope", "scope_not_issuable")]),
        ({**READ, "name": SENTINEL + "!"}, [("body.name", "credential_name_format")]),
        ({**READ, "name": 7}, [("body.name", "string_type")]),
        ({"scope": "read"}, [("body.name", "missing")]),
        ({"name": "x"}, [("body.scope", "missing")]),
        ({**READ, SENTINEL: 1}, [("body", "extra_forbidden")]),
        ({**READ, "token": new_token()}, [("body", "extra_forbidden")]),
        ({**READ, "expires_at": "2027-01-01T00:00:00Z"}, [("body", "extra_forbidden")]),
        ({**READ, "expires_in_days": 0}, [("body.expires_in_days", "greater_than_equal")]),
        ({**READ, "expires_in_days": 366}, [("body.expires_in_days", "less_than_equal")]),
        ({**READ, "expires_in_days": "30"}, [("body.expires_in_days", "int_type")]),
        ({**READ, "expires_in_days": 30.0}, [("body.expires_in_days", "int_type")]),
        ({**READ, "expires_in_days": True}, [("body.expires_in_days", "int_type")]),
        ({**INGEST, "service": "Bad--" + SENTINEL}, [("body.service", "slug_format")]),
        ({**READ, "service": "payments-api"}, [("body.service", "forbidden_for_read")]),
        (
            {**READ, "service": "payments-api", "environment": "production"},
            [("body.service", "forbidden_for_read"), ("body.environment", "forbidden_for_read")],
        ),
        ({**INGEST, "environment": None}, [("body.environment", "required_for_ingest")]),
        (
            {"name": "ci", "scope": "ingest"},
            [("body.service", "required_for_ingest"), ("body.environment", "required_for_ingest")],
        ),
        ({**INGEST, "service": "zz-" + SENTINEL}, [("body.service", "not_registered")]),
        ({**INGEST, "environment": "zz-" + SENTINEL}, [("body.environment", "not_registered")]),
        (
            {**INGEST, "service": "zz-" + SENTINEL, "environment": "zz-" + SENTINEL},
            [("body.service", "not_registered"), ("body.environment", "not_registered")],
        ),
    ],
)
def test_invalid_requests_are_422_naming_fields_never_values(
    client: TestClient,
    admin: dict[str, str],
    issuer: DictIssuer,
    body: dict[str, object],
    errors: list[tuple[str, str]],
) -> None:
    response = client.post(PATH, headers=admin, json=body)
    assert response.status_code == 422
    problem = response.json()
    assert problem["code"] == "validation_failed"
    assert [(e["location"], e["rule"]) for e in problem["errors"]] == errors
    assert SENTINEL not in response.text
    assert "st1_" not in response.text
    assert issuer.added == []


def test_store_outage_is_503_without_a_token(
    tokens: dict[Scope, str], admin: dict[str, str]
) -> None:
    broken = DictIssuer(services={"payments-api"}, environments={"production"}, broken=True)
    response = app_with(tokens, broken).post(PATH, headers=admin, json=READ)
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert "st1_" not in response.text


def test_response_model_repr_hides_the_token(client: TestClient, admin: dict[str, str]) -> None:
    """A logged or re-raised response model must not carry the token, as the use case's own
    result does not."""
    token = client.post(PATH, headers=admin, json=READ).json()["token"]
    model = IssuedResponse(
        id=uuid.uuid4(),
        name="reader",
        scope="read",
        service=None,
        environment=None,
        display_prefix=display_prefix(token),
        created_at=FIXED_TIME,
        expires_at=None,
        token=token,
    )
    assert token not in repr(model)
    assert token not in str(model)
