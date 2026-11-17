"""GET /api/v1/deployments and GET /api/v1/deployments/{id} against real PostgreSQL 18, through
the real composition root (`create_app`), as the runtime role.

Every deployment here is written through POST /api/v1/deployment-events with an ingest credential
and read back with a read credential, so these tests are the first to cover the whole path from a
pipeline's report to a reader's history. Events cannot be deleted, so the module uses a disposable
container and each test its own service and environment.
"""

# ruff: noqa: F811 - a fixture parameter is meant to shadow the imported fixture.
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine

from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import digest, display_prefix

# The fixtures are imported so pytest finds them here; each module gets its own container.
from .test_deployment_events_api_postgres import PATH as EVENTS
from .test_deployment_events_api_postgres import (
    Api,
    World,
    admin,  # noqa: F401
    api,  # noqa: F401
    assert_problem,
    bearer,
    counts,
    disposable,  # noqa: F401
    event,
    migrator,  # noqa: F401
    world,  # noqa: F401
)

PATH = "/api/v1/deployments"
REASON = '<script>alert("x")</script>\nrolled back'
SOURCE = "https://ci.example/runs/42?attempt=1#summary"


def report(api: Api, world: World, key: str, *types: str, **changes: Any) -> None:
    for event_type in types:
        body = event(world, deployment_key=key, type=event_type, **changes)
        response = api.client.post(EVENTS, headers=bearer(world.ingest), json=body)
        assert response.status_code == 201, response.text


def history(api: Api, world: World, token: str | None = None, **params: Any) -> dict[str, Any]:
    query = {"service": world.service, "environment": world.environment, **params}
    response = api.client.get(PATH, headers=bearer(token or world.read), params=query)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def stored_deployments(admin: Engine, world: World) -> list[dict[str, Any]]:
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id, deployment_key, version, commit_sha, created_at FROM deployments "
                "WHERE service_id = :service AND environment_id = :environment ORDER BY id DESC"
            ),
            {"service": world.service_id, "environment": world.environment_id},
        ).all()
    return [dict(row._mapping) for row in rows]


def rfc3339(value: Any) -> str:
    return str(value.isoformat()).replace("+00:00", "Z")


def test_reported_deployments_are_read_back_newest_first_with_derived_status(
    api: Api, world: World, admin: Engine
) -> None:
    report(api, world, "run-a", "started", "succeeded")
    report(api, world, "run-b", "failed")
    report(api, world, "run-c", "started")
    body = history(api, world)
    assert body["next_cursor"] is None
    stored = stored_deployments(admin, world)
    assert [row["deployment_key"] for row in stored] == ["run-c", "run-b", "run-a"]
    assert body["items"] == [
        {
            "id": str(row["id"]),
            "service": world.service,
            "environment": world.environment,
            "deployment_key": row["deployment_key"],
            "version": row["version"],
            "commit_sha": row["commit_sha"],
            "status": status,
            "created_at": rfc3339(row["created_at"]),
        }
        for row, status in zip(stored, ["in_progress", "failed", "succeeded"], strict=True)
    ]


def test_the_status_filter_and_paging_work_over_http(api: Api, world: World) -> None:
    for n in range(5):
        report(api, world, f"ok-{n}", "succeeded")
    report(api, world, "bad", "failed")
    succeeded = history(api, world, status="succeeded")["items"]
    assert [item["deployment_key"] for item in succeeded] == [f"ok-{n}" for n in (4, 3, 2, 1, 0)]
    assert [i["deployment_key"] for i in history(api, world, status="failed")["items"]] == ["bad"]
    assert history(api, world, status="reverted")["items"] == []

    keys: list[str] = []
    cursor = None
    pages = 0
    while True:
        params: dict[str, Any] = {"limit": 4} if cursor is None else {"limit": 4, "cursor": cursor}
        page = history(api, world, **params)
        pages += 1
        keys += [item["deployment_key"] for item in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert keys == ["bad", "ok-4", "ok-3", "ok-2", "ok-1", "ok-0"]
    assert pages == 2


def test_history_without_filters_spans_services_and_a_stranger_slug_is_empty(
    api: Api, world: World
) -> None:
    report(api, world, "run-a", "started")
    everything = api.client.get(PATH, headers=bearer(world.read), params={"limit": 100}).json()
    assert world.service in {item["service"] for item in everything["items"]}
    response = api.client.get(PATH, headers=bearer(world.read), params={"service": "no-such-svc"})
    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}
    # The other registered service has no deployment: the filter is exact, not a prefix.
    other = api.client.get(
        PATH, headers=bearer(world.read), params={"service": world.other_service}
    )
    assert other.json()["items"] == []


def test_detail_shows_every_event_as_stored_and_follows_a_later_revert(
    api: Api, world: World, admin: Engine
) -> None:
    report(api, world, "run-a", "started")
    report(api, world, "run-a", "succeeded", source_url=SOURCE)
    (item,) = history(api, world)["items"]
    url = f"{PATH}/{item['id']}"
    before = api.client.get(url, headers=bearer(world.read))
    assert before.status_code == 200
    assert before.json()["status"] == "succeeded"

    report(api, world, "run-a", "reverted", reason=REASON)
    response = api.client.get(url, headers=bearer(world.read))
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert {key: body[key] for key in item} == item | {"status": "reverted"}
    with admin.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id, type, received_at, source_url, reason FROM deployment_events "
                "WHERE deployment_id = :id ORDER BY seq"
            ),
            {"id": item["id"]},
        ).all()
    assert body["events"] == [
        {
            "id": str(row.id),
            "type": row.type,
            "received_at": rfc3339(row.received_at),
            "source_url": row.source_url,
            "reason": row.reason,
        }
        for row in rows
    ]
    assert [e["type"] for e in body["events"]] == ["started", "succeeded", "reverted"]
    assert body["events"][1]["source_url"] == SOURCE
    assert body["events"][2]["reason"] == REASON
    assert str(world.credential_id) not in response.text


def test_an_unknown_or_malformed_id_reveals_nothing(api: Api, world: World) -> None:
    missing = api.client.get(f"{PATH}/{uuid.uuid7()}", headers=bearer(world.read))
    assert_problem(missing, 404, "not_found")
    malformed = api.client.get(f"{PATH}/1' OR '1'='1", headers=bearer(world.read))
    body = assert_problem(malformed, 422, "validation_failed")
    assert body["errors"] == [{"location": "path.deployment_id", "rule": "uuid_parsing"}]


def test_only_live_read_and_admin_credentials_read(
    api: Api, world: World, migrator: Engine
) -> None:
    report(api, world, "run-a", "succeeded")
    (item,) = history(api, world)["items"]
    urls = (PATH, f"{PATH}/{item['id']}")
    for url in urls:
        assert api.client.get(url, headers=bearer(world.admin)).status_code == 200
        assert_problem(api.client.get(url, headers=bearer(world.ingest)), 403, "forbidden")
        assert_problem(api.client.get(url), 401, "unauthenticated")

    dead = {"revoked": new_token(), "expired": new_token()}
    with migrator.begin() as connection:  # The guard exempts the migrator from the expiry rule.
        for state, token in dead.items():
            connection.execute(
                text(
                    "INSERT INTO api_credentials (name, scope, secret_sha256, display_prefix, "
                    "expires_at, revoked_at) VALUES ('dead', 'read', :digest, :prefix, "
                    "CASE WHEN :expired THEN now() - interval '1 second' END, "
                    "CASE WHEN NOT :expired THEN now() END)"
                ),
                {
                    "digest": digest(token),
                    "prefix": display_prefix(token),
                    "expired": state == "expired",
                },
            )
    for token in dead.values():
        for url in urls:
            assert_problem(api.client.get(url, headers=bearer(token)), 401, "unauthenticated")


def test_revoking_a_read_credential_stops_its_next_read(api: Api, world: World) -> None:
    issued = api.client.post(
        "/api/v1/credentials", headers=bearer(world.admin), json={"name": "r", "scope": "read"}
    ).json()
    reader = bearer(issued["token"])
    assert api.client.get(PATH, headers=reader).status_code == 200
    revoke = f"/api/v1/credentials/{issued['id']}/revoke"
    assert api.client.post(revoke, headers=bearer(world.admin)).status_code == 200
    assert_problem(api.client.get(PATH, headers=reader), 401, "unauthenticated")


def test_reading_writes_no_deployment_or_event(api: Api, world: World, admin: Engine) -> None:
    report(api, world, "run-a", "started", "succeeded")
    before = counts(admin)
    (item,) = history(api, world)["items"]
    for _ in range(3):
        history(api, world, status="succeeded")
        assert api.client.get(f"{PATH}/{item['id']}", headers=bearer(world.read)).status_code == 200
    assert counts(admin) == before
