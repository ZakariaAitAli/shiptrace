"""Entry point for the one-shot migration step that runs before a rollout."""

import os

from shiptrace.persistence.migrate import upgrade


def main() -> None:
    upgrade(os.environ["SHIPTRACE_MIGRATOR_DATABASE_URL"])


if __name__ == "__main__":
    main()
