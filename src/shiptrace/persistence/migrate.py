"""Runs migrations. Connects as the migrator role, never the runtime role."""

from alembic import command

from shiptrace.persistence.schema import alembic_config


def upgrade(url: str, revision: str = "head") -> None:
    config = alembic_config()
    config.attributes["url"] = url
    command.upgrade(config, revision)


def downgrade(url: str, revision: str) -> None:
    config = alembic_config()
    config.attributes["url"] = url
    command.downgrade(config, revision)
