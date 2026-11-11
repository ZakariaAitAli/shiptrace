"""The deployment store's SQL, as text: what it must never contain and what it must contain.

The runtime role has no UPDATE, DELETE or TRUNCATE on these tables, and FOR UPDATE needs UPDATE
(ARCHITECTURE §4). The event insert has no conflict target so both unique indexes arbitrate.
"""

import re

import pytest
from sqlalchemy import TextClause

from shiptrace.persistence import deployments

STATEMENTS: dict[str, TextClause] = {
    "read": deployments._READ,
    "insert_deployment": deployments._INSERT_DEPLOYMENT,
    "insert_event": deployments._INSERT_EVENT,
}


@pytest.mark.parametrize("name", STATEMENTS)
def test_no_statement_updates_deletes_truncates_or_locks_rows(name: str) -> None:
    sql = str(STATEMENTS[name]).upper()
    for word in ("UPDATE", "DELETE", "TRUNCATE", "FOR SHARE", "FOR NO KEY"):
        assert word not in sql, (name, word)


@pytest.mark.parametrize("name", ["insert_deployment", "insert_event"])
def test_inserts_use_on_conflict_do_nothing_without_a_target(name: str) -> None:
    sql = str(STATEMENTS[name])
    assert re.search(r"ON CONFLICT DO NOTHING", sql)
    assert not re.search(r"ON CONFLICT\s*\(", sql)
    assert "ON CONSTRAINT" not in sql


@pytest.mark.parametrize("name", ["insert_deployment", "insert_event"])
def test_inserts_never_name_a_database_generated_column(name: str) -> None:
    columns = re.search(r"\(([^)]*)\) VALUES", str(STATEMENTS[name]))
    assert columns is not None
    names = {c.strip() for c in columns.group(1).split(",")}
    assert not names & {"id", "seq", "created_at", "received_at"}


def test_every_value_is_a_bound_parameter() -> None:
    for name, statement in STATEMENTS.items():
        sql = str(statement)
        assert "'" not in sql, name  # No literal can carry input.
        assert "%" not in sql, name
