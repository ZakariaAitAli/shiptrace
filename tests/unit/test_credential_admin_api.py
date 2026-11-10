"""HTTP contract of GET /api/v1/credentials and POST /api/v1/credentials/{id}/revoke (spec §5),
via the real app with in-memory stores. Real-database behaviour is in the integration tests."""

import uuid

import pytest
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api
from shiptrace.application.access import Principal
from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import Scope, digest

from .fakes import FIXED_TIME, DictCredentialAdmin, DictIssuer, DictRegistry, DictStore

PATH = "/api/v1/credentials"
FIELDS = {
    "id",
    "name",
    "scope",
    "service",
    "environment",
    "display_prefix",
    "created_at",
    "expires_at",
    "revoked_at",
    "last_used_at",
}


@pytest.fixture
def tokens() -> dict[Scope, str]:
    return {scope: new_token() for scope in Scope}


@pytest.fixture
def admin_store() -> DictCredentialAdmin:
    return DictCredentialAdmin()


@pytest.fixture
def client(tokens: dict[Scope, str], admin_store: DictCredentialAdmin) -> TestClient:
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
        credential_admin=admin_store,
    )
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def admin(tokens: dict[Scope, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens[Scope.ADMIN]}"}


def test_list_item_has_exactly_the_documented_fields(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    record = admin_store.add_record(name="ci payments", scope=Scope.INGEST, service="s")
    response = client.get(PATH, headers=admin)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "next_cursor"}
    assert body["next_cursor"] is None
    (item,) = body["items"]
    assert set(item) == FIELDS
    assert item["id"] == str(record.id)
    assert item["scope"] == "ingest" and item["service"] == "s"
    assert item["created_at"] == FIXED_TIME.isoformat().replace("+00:00", "Z")
    assert item["revoked_at"] is None


def test_list_never_carries_a_token_or_digest(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    admin_store.add_record()
    text = client.get(PATH, headers=admin).text.lower()
    assert "token" not in text and "digest" not in text and "sha256" not in text


def test_pages_walk_every_row_once_in_id_order(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    created = [admin_store.add_record(name=f"c{n}").id for n in range(5)]
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params: dict[str, str | int] = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        body = client.get(PATH, headers=admin, params=params).json()
        pages += 1
        assert len(body["items"]) <= 2
        seen += [item["id"] for item in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert pages == 3
    assert seen == [str(i) for i in sorted(created)]


def test_a_full_last_page_has_no_next_cursor(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    for n in range(2):
        admin_store.add_record(name=f"c{n}")
    assert client.get(PATH, headers=admin, params={"limit": 2}).json()["next_cursor"] is None


@pytest.mark.parametrize("limit", ["0", "101", "-1", "x", ""])
def test_bad_limit_is_422(client: TestClient, admin: dict[str, str], limit: str) -> None:
    assert client.get(PATH, headers=admin, params={"limit": limit}).status_code == 422


@pytest.mark.parametrize(
    "cursor",
    ["", "x", "!!!", "djE6Y3JlZGVudGlhbHM6bm90LWEtdXVpZA", "djE6c2VydmljZXM6YWJj", "A" * 200],
    ids=["empty", "short", "alphabet", "not-uuid", "other-list", "long"],
)
def test_bad_cursor_is_422_without_echoing_it(
    client: TestClient, admin: dict[str, str], cursor: str
) -> None:
    response = client.get(PATH, headers=admin, params={"cursor": cursor})
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"
    assert cursor not in response.text or cursor == ""


def test_revoke_answers_200_with_the_object(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    record = admin_store.add_record()
    response = client.post(f"{PATH}/{record.id}/revoke", headers=admin)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == FIELDS
    assert body["id"] == str(record.id)
    assert body["revoked_at"] is not None
    assert "token" not in response.text.lower()


def test_revoking_twice_is_200_and_writes_once(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    record = admin_store.add_record()
    first = client.post(f"{PATH}/{record.id}/revoke", headers=admin)
    second = client.post(f"{PATH}/{record.id}/revoke", headers=admin)
    assert (first.status_code, second.status_code) == (200, 200)
    assert second.json() == first.json()
    assert admin_store.writes == 1


@pytest.mark.parametrize(
    "content",
    [b'{"revoked_at": "2001-01-01T00:00:00Z"}', b"{}", b"x"],
    ids=["json", "empty-json", "raw"],
)
def test_revoke_rejects_a_body_without_echoing_it(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin, content: bytes
) -> None:
    record = admin_store.add_record()
    response = client.post(f"{PATH}/{record.id}/revoke", headers=admin, content=content)
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_failed"
    assert body["errors"] == [{"location": "body", "rule": "body_not_allowed"}]
    assert "2001" not in response.text and "revoked_at" not in response.text
    assert admin_store.writes == 0 and admin_store.rows[record.id].revoked_at is None
    assert client.post(f"{PATH}/{record.id}/revoke", headers=admin).status_code == 200


def test_unknown_credential_is_404_and_a_non_uuid_is_422(
    client: TestClient, admin: dict[str, str]
) -> None:
    unknown = client.post(f"{PATH}/{uuid.uuid4()}/revoke", headers=admin)
    assert unknown.status_code == 404
    assert unknown.json()["code"] == "not_found"
    bad = client.post(f"{PATH}/not-a-uuid/revoke", headers=admin)
    assert bad.status_code == 422
    assert "not-a-uuid" not in bad.text


@pytest.mark.parametrize("scope", [Scope.READ, Scope.INGEST])
def test_other_scopes_cannot_list_or_revoke(
    client: TestClient,
    tokens: dict[Scope, str],
    admin_store: DictCredentialAdmin,
    scope: Scope,
) -> None:
    record = admin_store.add_record()
    headers = {"Authorization": f"Bearer {tokens[scope]}"}
    assert client.get(PATH, headers=headers).status_code == 403
    assert client.post(f"{PATH}/{record.id}/revoke", headers=headers).status_code == 403
    assert admin_store.writes == 0


def test_store_outage_is_503(
    client: TestClient, admin: dict[str, str], admin_store: DictCredentialAdmin
) -> None:
    record = admin_store.add_record()
    admin_store.broken = True
    assert client.get(PATH, headers=admin).status_code == 503
    assert client.post(f"{PATH}/{record.id}/revoke", headers=admin).status_code == 503
