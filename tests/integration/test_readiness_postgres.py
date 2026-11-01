"""AC16 end to end: the real app, on the runtime role, against real PostgreSQL."""

import time
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine

from shiptrace.application.readiness import SchemaExpectation
from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings
from shiptrace.persistence.schema import expected_schema

from .conftest import Database, scalar, start_database

EngineFor = Callable[[str], Engine]


def app_client(database: Database, expected: SchemaExpectation | None = None) -> TestClient:
    settings = Settings.model_validate(
        {
            "environment": "test",
            "database_url": database.app_url,
            "readiness_cache_seconds": 0,
        }
    )
    return TestClient(create_app(settings, expected_schema=expected))


def test_ready_at_head(migrated_database: Database) -> None:
    with app_client(migrated_database) as client:
        assert client.get("/readyz").status_code == 200
        assert client.get("/healthz").status_code == 200


def test_not_ready_before_migrations_but_process_is_alive(empty_database: Database) -> None:
    with app_client(empty_database) as client:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200


def test_not_ready_when_schema_is_older_than_build(migrated_database: Database) -> None:
    current = expected_schema().head
    future_build = SchemaExpectation(head="future", known=frozenset({current, "future"}))
    with app_client(migrated_database, future_build) as client:
        assert client.get("/readyz").status_code == 503


def test_ready_when_schema_is_newer_than_build(migrated_database: Database) -> None:
    older_build = SchemaExpectation(head="older", known=frozenset({"older"}))
    with app_client(migrated_database, older_build) as client:
        assert client.get("/readyz").status_code == 200


def test_shutdown_closes_database_connections(
    migrated_database: Database, engine_for: EngineFor
) -> None:
    admin = engine_for(migrated_database.admin_url)
    count = "SELECT count(*) FROM pg_stat_activity WHERE usename = 'shiptrace_app'"
    with app_client(migrated_database) as client:
        assert client.get("/readyz").status_code == 200
        assert scalar(admin, count) == 1

    deadline = time.monotonic() + 5
    while scalar(admin, count) != 0:
        assert time.monotonic() < deadline, "connection still open after shutdown"
        time.sleep(0.05)


@pytest.fixture
def restartable_database() -> Iterator[Database]:
    database = start_database()
    from shiptrace.persistence.migrate import upgrade

    upgrade(database.migrator_url)
    yield database
    database.container.stop()


def test_outage_flips_readiness_and_recovers_without_restart(
    restartable_database: Database,
) -> None:
    docker = restartable_database.container.get_wrapped_container()
    with app_client(restartable_database) as client:
        assert client.get("/readyz").status_code == 200

        docker.stop(timeout=5)
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200

        docker.start()
        restartable_database.container._connect()
        assert client.get("/readyz").status_code == 200


def test_settings_url_uses_the_app_role(migrated_database: Database, engine_for: EngineFor) -> None:
    engine = engine_for(migrated_database.app_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT current_user")).scalar_one() == "shiptrace_app"
