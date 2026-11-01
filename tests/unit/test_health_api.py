"""HTTP contract of the health endpoints, with readiness replaced by a plain function."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from shiptrace.api.app import build_api


def client(ready: bool = True, docs_enabled: bool = False) -> TestClient:
    return TestClient(build_api(readiness=lambda: ready, docs_enabled=docs_enabled))


def test_healthz_never_consults_readiness() -> None:
    def fail() -> bool:
        raise AssertionError("healthz must not depend on readiness")

    app: FastAPI = build_api(readiness=fail, docs_enabled=False)
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_ok() -> None:
    response = client(ready=True).get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_unavailable_reveals_nothing() -> None:
    response = client(ready=False).get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_health_responses_are_not_cached() -> None:
    assert client().get("/readyz").headers["cache-control"] == "no-store"
    assert client().get("/healthz").headers["cache-control"] == "no-store"


def test_health_only_allows_get() -> None:
    assert client().post("/readyz").status_code == 405


def test_docs_are_absent_when_disabled() -> None:
    disabled = client(docs_enabled=False)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert disabled.get(path).status_code == 404


def test_docs_are_present_when_enabled() -> None:
    assert client(docs_enabled=True).get("/openapi.json").status_code == 200
