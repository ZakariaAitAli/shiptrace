"""What create_app decides from settings, without touching a database."""

import pytest
from fastapi.testclient import TestClient

from shiptrace.application.readiness import SchemaExpectation
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings

EXPECTED = SchemaExpectation(head="a", known=frozenset({"a"}))
USER = "shiptrace_app"
UNROUTABLE_HOST = "127.0.0.1:1"


def app_for(environment: str, query: str) -> TestClient:
    url = f"postgresql+psycopg://{USER}:{'password'}@{UNROUTABLE_HOST}/shiptrace{query}"
    settings = Settings.model_validate({"environment": environment, "database_url": url})
    return TestClient(create_app(settings, expected_schema=EXPECTED))


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/redoc"])
def test_production_exposes_no_api_documentation(path: str) -> None:
    client = app_for("production", "?sslmode=verify-full")
    assert client.get(path).status_code == 404


def test_local_exposes_api_documentation() -> None:
    assert app_for("local", "").get("/openapi.json").status_code == 200


def test_app_starts_while_database_is_unreachable() -> None:
    client = app_for("local", "")
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 503
