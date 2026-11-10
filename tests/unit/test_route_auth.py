"""AC6, generated from the route table: every protected route refuses missing, malformed, unknown
and wrong-scope credentials. A new route is covered without editing this file.

Routes come from the real route table through fastapi.routing.iter_route_contexts, which resolves
the lazy wrappers FastAPI 0.162 keeps for included routers, so a route hidden from the OpenAPI
schema is still seen. Only the routes in PUBLIC may skip authentication.
"""

import uuid

import pytest
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api
from shiptrace.application.access import Principal
from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import Scope, digest

from .fakes import DictIssuer, DictRegistry, DictStore

TOKENS = {scope: new_token() for scope in Scope}
STORE = DictStore(
    {
        digest(token): Principal(id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None)
        for scope, token in TOKENS.items()
    }
)
APP = build_api(
    readiness=lambda: True,
    docs_enabled=False,
    credentials=STORE,
    registry=DictRegistry(),
    issuer=DictIssuer(),
)
# Which scopes may call each protected route; anything absent here fails the completeness test.
ALLOWED = {
    ("GET", "/api/v1/services"): {Scope.ADMIN, Scope.READ},
    ("POST", "/api/v1/services"): {Scope.ADMIN},
    ("GET", "/api/v1/environments"): {Scope.ADMIN, Scope.READ},
    ("POST", "/api/v1/environments"): {Scope.ADMIN},
    ("POST", "/api/v1/credentials"): {Scope.ADMIN},
}


# A valid body where a route needs more than a slug, so an allowed scope reaches the use case.
BODIES = {"/api/v1/credentials": {"name": "route auth", "scope": "read"}}
PUBLIC = {("GET", "/healthz"), ("GET", "/readyz")}


def all_routes() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for context in iter_route_contexts(APP.router.routes):
        if context.path is None:
            continue
        methods: set[str] = getattr(context.original_route, "methods", None) or set()
        found |= {(method, context.path) for method in methods}
    return found


def schema_routes() -> set[tuple[str, str]]:
    paths: dict[str, dict[str, object]] = APP.openapi()["paths"]
    return {(method.upper(), path) for path, operations in paths.items() for method in operations}


ROUTES = sorted(all_routes() - PUBLIC)
CLIENT = TestClient(APP, raise_server_exceptions=False)


def test_the_route_table_and_the_schema_agree() -> None:
    """A protected route hidden from the schema would show up here as a difference."""
    assert all_routes() >= PUBLIC
    assert schema_routes() == all_routes() - PUBLIC


def call(method: str, path: str, authorization: str | None) -> int:
    headers = {} if authorization is None else {"Authorization": authorization}
    body = BODIES.get(path, {"slug": "route-auth"}) if method == "POST" else None
    return CLIENT.request(method, path, headers=headers, json=body).status_code


def test_every_route_is_in_the_scope_table() -> None:
    assert len(ROUTES) >= 4
    assert set(ROUTES) == set(ALLOWED)


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Bearer",
        f"Basic {TOKENS[Scope.ADMIN]}",
        "Bearer st1_short",
        f"Bearer {new_token()}",
    ],
    ids=["missing", "empty", "bare", "basic", "malformed", "unknown"],
)
def test_unauthenticated_calls_are_401(method: str, path: str, authorization: str | None) -> None:
    assert call(method, path, authorization) == 401


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize("scope", list(Scope))
def test_each_scope_gets_exactly_its_access(method: str, path: str, scope: Scope) -> None:
    status = call(method, path, f"Bearer {TOKENS[scope]}")
    if scope in ALLOWED[(method, path)]:
        assert status in {200, 201, 409}, status
    else:
        assert status == 403
