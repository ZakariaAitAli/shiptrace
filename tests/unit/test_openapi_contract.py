"""The retained schema must match the real application route and response contract."""

import json
from pathlib import Path

from shiptrace.bootstrap.openapi import schema


def test_the_committed_openapi_contract_matches_the_app() -> None:
    path = Path(__file__).parents[2] / "docs/api/openapi.json"
    assert json.loads(path.read_text()) == schema()


def test_schema_declares_bearer_auth_and_the_latest_problem_responses() -> None:
    contract = schema()
    assert contract["components"]["securitySchemes"]["BearerAuth"]["scheme"] == "bearer"
    for path, methods in contract["paths"].items():
        if path in {"/healthz", "/readyz"}:
            continue
        for operation in methods.values():
            assert {"BearerAuth": []} in operation["security"]
    latest = contract["paths"]["/api/v1/services/{service}/environments/{environment}/latest"][
        "get"
    ]
    for status in ["401", "403", "422", "500", "503"]:
        content = latest["responses"][status]["content"]
        assert set(content) == {"application/problem+json"}
        assert {"status", "code", "type", "title", "detail"} <= set(
            content["application/problem+json"]["schema"]["required"]
        )
