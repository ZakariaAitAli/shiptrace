"""What schema this build expects, and what the database actually has."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.readiness import ProbeError, SchemaExpectation

MIGRATIONS = Path(__file__).parent / "migrations"


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    return config


def expected_schema() -> SchemaExpectation:
    scripts = ScriptDirectory.from_config(alembic_config())
    head = scripts.get_current_head()
    if head is None:
        raise RuntimeError("no migrations found")
    return SchemaExpectation(
        head=head, known=frozenset(script.revision for script in scripts.walk_revisions())
    )


class PostgresSchemaProbe:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def current_revision(self) -> str | None:
        try:
            with self._engine.connect() as connection:
                return connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one_or_none()
        except SQLAlchemyError as error:
            raise ProbeError from error
