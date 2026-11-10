"""HTTP contract of the registry routes (spec §5), through the real app with in-memory stores."""

import base64
import uuid
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api
from shiptrace.application.access import Principal
from shiptrace.application.credentials import new_token
from shiptrace.application.registry import InvalidPage, InvalidSlug, Kind
from shiptrace.domain.credentials import Scope, digest

from .fakes import DictIssuer, DictRegistry, DictStore

PATHS = {Kind.SERVICES: "/api/v1/services", Kind.ENVIRONMENTS: "/api/v1/environments"}
SENTINEL = "zz-" + uuid.uuid4().hex[:8]
MAX_PAGES = 20


@pytest.fixture
def tokens() -> dict[Scope, str]:
    return {scope: new_token() for scope in Scope}


@pytest.fixture
def registry() -> DictRegistry:
    return DictRegistry()


@pytest.fixture
def client(tokens: dict[Scope, str], registry: DictRegistry) -> TestClient:
    store = DictStore(
        {
            digest(token): Principal(
                id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None
            )
            for scope, token in tokens.items()
        }
    )
    app = build_api(
        readiness=lambda: True,
        docs_enabled=False,
        credentials=store,
        registry=registry,
        issuer=DictIssuer(),
    )
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def admin(tokens: dict[Scope, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens[Scope.ADMIN]}"}


@pytest.fixture
def reader(tokens: dict[Scope, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens[Scope.READ]}"}


@pytest.mark.parametrize("kind", list(Kind))
def test_register_returns_201_with_database_values(
    client: TestClient, admin: dict[str, str], registry: DictRegistry, kind: Kind
) -> None:
    response = client.post(PATHS[kind], headers=admin, json={"slug": "payments-api"})
    assert response.status_code == 201
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert set(body) == {"id", "slug", "created_at"}
    stored = registry.rows[kind]["payments-api"]
    assert body["id"] == str(stored.id)
    assert body["slug"] == "payments-api"
    assert datetime.fromisoformat(body["created_at"]) == stored.created_at


@pytest.mark.parametrize("kind", list(Kind))
def test_duplicate_is_409_already_exists(
    client: TestClient, admin: dict[str, str], kind: Kind
) -> None:
    client.post(PATHS[kind], headers=admin, json={"slug": "api"})
    response = client.post(PATHS[kind], headers=admin, json={"slug": "api"})
    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:shiptrace:problem:already_exists",
        "title": "Already exists",
        "status": 409,
        "detail": "A resource with this identifier already exists.",
        "code": "already_exists",
    }


def test_conflict_never_echoes_the_slug(client: TestClient, admin: dict[str, str]) -> None:
    client.post(PATHS[Kind.SERVICES], headers=admin, json={"slug": SENTINEL})
    response = client.post(PATHS[Kind.SERVICES], headers=admin, json={"slug": SENTINEL})
    assert response.status_code == 409
    assert SENTINEL not in response.text
    assert SENTINEL not in str(response.headers)


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({"slug": "Bad--" + SENTINEL}, {"location": "body.slug", "rule": "slug_format"}),
        ({"slug": "x" * 64}, {"location": "body.slug", "rule": "slug_format"}),
        ({"slug": 7}, {"location": "body.slug", "rule": "string_type"}),
        ({}, {"location": "body.slug", "rule": "missing"}),
        ({"slug": "api", SENTINEL: 1}, {"location": "body", "rule": "extra_forbidden"}),
    ],
)
def test_invalid_bodies_are_422_without_values(
    client: TestClient,
    admin: dict[str, str],
    registry: DictRegistry,
    body: object,
    error: dict[str, str],
) -> None:
    response = client.post(PATHS[Kind.SERVICES], headers=admin, json=body)
    assert response.status_code == 422
    assert error in response.json()["errors"]
    assert SENTINEL not in response.text
    assert registry.calls == 0


def register_many(client: TestClient, admin: dict[str, str], kind: Kind, count: int) -> list[str]:
    slugs = [f"s{index:03d}" for index in range(count)]
    for slug in reversed(slugs):
        assert client.post(PATHS[kind], headers=admin, json={"slug": slug}).status_code == 201
    return slugs


def walk(
    client: TestClient, headers: dict[str, str], path: str, limit: int | None
) -> list[list[str]]:
    pages: list[list[str]] = []
    params: dict[str, str | int] = {} if limit is None else {"limit": limit}
    for _ in range(MAX_PAGES):  # A cursor that is ignored would loop forever, not fail.
        response = client.get(path, headers=headers, params=params)
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"items", "next_cursor"}
        pages.append([item["slug"] for item in body["items"]])
        if body["next_cursor"] is None:
            return pages
        params = {**params, "cursor": body["next_cursor"]}
    raise AssertionError("pagination never reached the end")


def test_a_cursor_only_works_on_the_list_that_issued_it(
    client: TestClient, admin: dict[str, str]
) -> None:
    for kind in Kind:
        register_many(client, admin, kind, 2)
    cursor = client.get(PATHS[Kind.SERVICES], headers=admin, params={"limit": 1}).json()[
        "next_cursor"
    ]
    assert (
        client.get(PATHS[Kind.SERVICES], headers=admin, params={"cursor": cursor}).status_code
        == 200
    )
    response = client.get(PATHS[Kind.ENVIRONMENTS], headers=admin, params={"cursor": cursor})
    assert response.status_code == 422
    assert response.json()["errors"] == [{"location": "query.cursor", "rule": "invalid_cursor"}]


@pytest.mark.parametrize("kind", list(Kind))
def test_listing_pages_in_slug_order_and_ends_with_null(
    client: TestClient, admin: dict[str, str], reader: dict[str, str], kind: Kind
) -> None:
    slugs = register_many(client, admin, kind, 7)
    assert walk(client, reader, PATHS[kind], 3) == [slugs[0:3], slugs[3:6], slugs[6:7]]


def test_default_limit_is_50(client: TestClient, admin: dict[str, str]) -> None:
    slugs = register_many(client, admin, Kind.SERVICES, 51)
    assert walk(client, admin, PATHS[Kind.SERVICES], None) == [slugs[:50], slugs[50:]]


def test_empty_list_is_one_page_with_null_cursor(
    client: TestClient, reader: dict[str, str]
) -> None:
    assert walk(client, reader, PATHS[Kind.ENVIRONMENTS], None) == [[]]


def test_cursor_is_opaque(client: TestClient, admin: dict[str, str]) -> None:
    register_many(client, admin, Kind.SERVICES, 2)
    cursor = client.get(PATHS[Kind.SERVICES], headers=admin, params={"limit": 1}).json()[
        "next_cursor"
    ]
    assert cursor is not None and "s000" not in cursor


@pytest.mark.parametrize("limit", ["0", "101", "-1", "abc", ""])
def test_limit_outside_1_to_100_is_422(
    client: TestClient, reader: dict[str, str], limit: str
) -> None:
    response = client.get(PATHS[Kind.SERVICES], headers=reader, params={"limit": limit})
    assert response.status_code == 422
    assert response.json()["errors"][0]["location"] == "query.limit"


def encoded(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "!!!",
        "not base64 at all",
        encoded("v1:services:Bad--" + SENTINEL),  # decodes, but not to a valid slug
        encoded("v1:api"),  # no kind
        # Decodes to exactly "v1:services:ab", but sets a spare bit the server never sets.
        "djE6c2VydmljZXM6YWJ",
        encoded("v1:environments:api"),  # another list's position
        encoded("v2:services:api"),  # unknown version
        encoded("api"),  # no version
        base64.urlsafe_b64encode(b"\xff\xfe").decode(),  # padded: refused by the alphabet
        "__4",  # valid base64url, but the bytes are not UTF-8
        "A",  # passes the alphabet, but is not valid base64
        "A" * 500,  # too long
    ],
)
def test_malformed_cursor_is_422_without_echo(
    client: TestClient, reader: dict[str, str], registry: DictRegistry, cursor: str
) -> None:
    response = client.get(PATHS[Kind.SERVICES], headers=reader, params={"cursor": cursor})
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"
    assert response.json()["errors"] == [{"location": "query.cursor", "rule": "invalid_cursor"}]
    assert SENTINEL not in response.text
    assert registry.calls == 0


@pytest.mark.parametrize("kind", list(Kind))
def test_wrong_method_is_405_naming_both_methods(
    client: TestClient, admin: dict[str, str], kind: Kind
) -> None:
    """These routes come from an included router, unlike the CP3 probes added to the app."""
    response = client.delete(PATHS[kind], headers=admin)
    assert response.status_code == 405
    assert response.json()["code"] == "method_not_allowed"
    assert set(response.headers["allow"].replace(" ", "").split(",")) == {"GET", "POST"}


@pytest.mark.parametrize(
    ("error", "location"),
    [(InvalidSlug, "body.slug"), (InvalidPage, "query")],
)
def test_use_case_validation_errors_are_422_not_500(
    client: TestClient, admin: dict[str, str], error: type[Exception], location: str
) -> None:
    """The API validates first; if a use case ever sees bad input anyway, it is still a 422."""

    def raise_it() -> None:
        raise error

    client.app.add_api_route("/api/v1/_raise", raise_it, methods=["GET"])  # type: ignore[attr-defined]
    response = client.get("/api/v1/_raise", headers=admin)
    assert response.status_code == 422
    assert response.json()["errors"][0]["location"] == location


def test_store_outage_is_503(tokens: dict[Scope, str]) -> None:
    store = DictStore(
        {digest(tokens[Scope.ADMIN]): Principal(uuid.uuid4(), Scope.ADMIN, None, None)}
    )
    app = build_api(
        readiness=lambda: True,
        docs_enabled=False,
        credentials=store,
        registry=DictRegistry(broken=True),
        issuer=DictIssuer(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {tokens[Scope.ADMIN]}"}
    for response in (
        client.post(PATHS[Kind.SERVICES], headers=headers, json={"slug": "api"}),
        client.get(PATHS[Kind.SERVICES], headers=headers),
    ):
        assert response.status_code == 503
        assert response.headers["retry-after"].isdigit()
