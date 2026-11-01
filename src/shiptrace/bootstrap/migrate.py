"""Entry point for the one-shot migration step that runs before a rollout."""

from shiptrace.bootstrap.settings import MigrationSettings
from shiptrace.persistence.migrate import upgrade


def main() -> None:
    settings = MigrationSettings()  # type: ignore[call-arg]
    upgrade(settings.migrator_database_url.get_secret_value())


if __name__ == "__main__":
    main()
