"""Operator commands. Run as `shiptrace <command>`, or `python -m shiptrace.bootstrap.cli`.

    shiptrace create-admin-credential --name <name>

Creates the first admin credential, or a recovery one (ADR-0005), as the migrator role. The token
goes to stdout exactly once, after the commit; every other message goes to stderr. No option takes
a token or a scope, and no command changes an existing credential.

Exit codes: 0 created, 2 usage or invalid name, 3 configuration, output streams or database role
refused, 4 not stored or outcome unknown, 5 created but the token could not be written.
"""

import argparse
import sys

from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from shiptrace.application.credentials import (
    CredentialNotStored,
    WrongDatabaseRole,
    create_admin_credential,
)
from shiptrace.bootstrap.settings import MIGRATOR_ROLE, MigrationSettings, UnsafeConfiguration
from shiptrace.domain.names import is_valid_credential_name
from shiptrace.persistence.credentials import PostgresAdminCredentialWriter

CONNECT_TIMEOUT_SECONDS = 5
SESSION_OPTIONS = "-c lock_timeout=5000 -c statement_timeout=10000"

USAGE = 2
REFUSED = 3
NOT_STORED = 4
NOT_DELIVERED = 5


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="shiptrace", description="ShipTrace operator commands.")
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser(
        "create-admin-credential",
        help="create an admin API credential; its token is printed once",
    )
    create.add_argument("--name", required=True, help="1-64 letters, digits, space, . _ -")
    return root


def error(message: str) -> None:
    print(f"shiptrace: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)  # Usage errors exit 2 here.
    if not is_valid_credential_name(arguments.name):
        error("invalid name: use 1-64 letters, digits, space, '.', '_' or '-', alphanumeric ends")
        return USAGE
    # A closed fd makes Python set the stream to None, and print() then writes nowhere or to the
    # wrong stream. Refuse before anything is created, rather than lose the only copy of a token.
    if sys.stdout is None or sys.stderr is None:
        if sys.stderr is not None:
            error("stdout is closed, so the token could not be shown; nothing was created")
        return REFUSED
    try:
        settings = MigrationSettings()  # type: ignore[call-arg]
    except UnsafeConfiguration as refused:
        error(f"the migrator database URL was refused: {refused}")  # Messages never hold input.
        return REFUSED
    except ValidationError:
        error(
            "configuration refused: SHIPTRACE_ENVIRONMENT and SHIPTRACE_MIGRATOR_DATABASE_URL "
            "must both be set and valid"
        )
        return REFUSED
    engine = create_engine(
        settings.migrator_database_url.get_secret_value(),
        poolclass=NullPool,
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS, "options": SESSION_OPTIONS},
    )
    try:
        issued = create_admin_credential(
            arguments.name, PostgresAdminCredentialWriter(engine, MIGRATOR_ROLE)
        )
    except WrongDatabaseRole:
        error(f"the database role was refused: connect as {MIGRATOR_ROLE}")
        return REFUSED
    except CredentialNotStored as failure:
        error(
            "the credential may not have been stored: the database could not be reached, "
            "refused it, or did not confirm the commit"
        )
        if failure.display_prefix:
            error(
                f"if a credential with prefix {failure.display_prefix} exists, its token was "
                "never shown: it is unusable and should be revoked"
            )
        return NOT_STORED
    finally:
        engine.dispose()
    error(f"created admin credential {issued.id} ({issued.display_prefix}...)")
    error("the token is printed below once; store it now, it cannot be shown again")
    try:
        print(issued.token, flush=True)
    except OSError:  # Such as a broken pipe. The exception holds no token; nothing is retried.
        sys.stdout = None  # Stops a second failure at interpreter exit.
        error(
            f"created admin credential {issued.id}, but the token could not be written: "
            f"it is unusable and should be revoked"
        )
        return NOT_DELIVERED
    return 0


if __name__ == "__main__":
    sys.exit(main())
