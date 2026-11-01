"""Real PostgreSQL, initialized by the same bootstrap script Compose uses."""

import secrets
import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import pytest
from docker.errors import APIError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from testcontainers.community.postgres import PostgresContainer

from shiptrace.persistence.migrate import upgrade

IMAGE = (
    "postgres:18.6-trixie@sha256:3a4264520e121176619f54ff867d12774bc81e95e7b84db58d63bccdb6144b81"
)
BOOTSTRAP = Path(__file__).parents[2] / "deploy/postgres/bootstrap_roles.sql"
PORT_ATTEMPTS = 5


@dataclass(frozen=True)
class Database:
    container: PostgresContainer
    port: int
    admin_password: str
    app_password: str
    migrator_password: str

    def url(self, user: str, password: str) -> str:
        return (
            f"postgresql+psycopg://{user}:{quote(password, safe='')}"
            f"@127.0.0.1:{self.port}/shiptrace"
        )

    @property
    def admin_url(self) -> str:
        return self.url("shiptrace_admin", self.admin_password)

    @property
    def app_url(self) -> str:
        return self.url("shiptrace_app", self.app_password)

    @property
    def migrator_url(self) -> str:
        return self.url("shiptrace_migrator", self.migrator_password)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def start_database() -> Database:
    # Passwords hold URL-significant characters so that encoding bugs surface here.
    admin_password = secrets.token_urlsafe(16)
    app_password = secrets.token_urlsafe(16) + "/@:%"
    migrator_password = secrets.token_urlsafe(16) + "/@:%"
    for attempt in range(1, PORT_ATTEMPTS + 1):
        # A fixed port survives a container restart, which the outage test needs. The port is
        # chosen here, but Docker Desktop binds it on Windows, where it may be reserved.
        port = free_port()
        container = (
            PostgresContainer(
                IMAGE,
                username="shiptrace_admin",
                password=admin_password,
                dbname="shiptrace",
                driver="psycopg",
            )
            .with_env("SHIPTRACE_APP_PASSWORD", app_password)
            .with_env("SHIPTRACE_MIGRATOR_PASSWORD", migrator_password)
            .with_volume_mapping(
                str(BOOTSTRAP), "/docker-entrypoint-initdb.d/10-bootstrap-roles.sql", "ro"
            )
            .with_bind_ports(5432, port)
        )
        try:
            container.start()
        except APIError as error:
            container.stop()
            if "ports are not available" in str(error) and attempt < PORT_ATTEMPTS:
                continue
            raise
        return Database(container, port, admin_password, app_password, migrator_password)
    raise AssertionError("unreachable")


@pytest.fixture(scope="session")
def empty_database() -> Iterator[Database]:
    """Roles exist; no migration has run. Tests must leave it empty."""
    database = start_database()
    yield database
    database.container.stop()


@pytest.fixture(scope="session")
def migrated_database() -> Iterator[Database]:
    database = start_database()
    upgrade(database.migrator_url)
    yield database
    database.container.stop()


@pytest.fixture
def engine_for() -> Iterator[Callable[[str], Engine]]:
    engines: list[Engine] = []

    def build(url: str) -> Engine:
        engine = create_engine(url)
        engines.append(engine)
        return engine

    yield build
    for engine in engines:
        engine.dispose()


def scalar(engine: Engine, statement: str) -> object:
    with engine.connect() as connection:
        return connection.execute(text(statement)).scalar_one()
