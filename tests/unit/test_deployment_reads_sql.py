"""The read adapter's SQL, as text: read-only, one statement each, and nothing but bound values.

The runtime role may only SELECT these tables, and FOR UPDATE needs the UPDATE it lacks
(ARCHITECTURE §4). What the statements return is the PostgreSQL tests' job.
"""

import re

import pytest
from sqlalchemy import TextClause

from shiptrace.persistence import deployment_reads

STATEMENTS: dict[str, TextClause] = {
    "list": deployment_reads._LIST,
    "get": deployment_reads._GET,
}
PARAMETERS = {
    "list": {"service", "environment", "after", "status", "limit"},
    "get": {"id"},
}


@pytest.mark.parametrize("name", STATEMENTS)
def test_a_statement_only_reads(name: str) -> None:
    sql = str(STATEMENTS[name]).upper()
    assert sql.startswith("SELECT ")
    for word in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "FOR UPDATE", "FOR SHARE", "LOCK "):
        assert word not in sql, (name, word)
    assert ";" not in sql  # One statement, so nothing can be appended to it.


@pytest.mark.parametrize("name", STATEMENTS)
def test_every_value_comes_in_as_a_bound_parameter(name: str) -> None:
    sql = str(STATEMENTS[name])
    assert set(re.findall(r"(?<!:):([a-z_]+)", sql)) == PARAMETERS[name]
    assert "%" not in sql and "{" not in sql  # No formatting placeholder survives into the text.


def test_history_is_newest_first_by_id_with_a_keyset() -> None:
    sql = str(STATEMENTS["list"])
    assert "d.id < CAST(:after AS uuid)" in sql
    assert "ORDER BY d.id DESC LIMIT :limit" in sql
    assert sql.rstrip().endswith("ORDER BY p.id DESC")


def test_the_events_of_a_deployment_are_collected_in_seq_order() -> None:
    assert "array_agg(x.type ORDER BY x.seq)" in str(STATEMENTS["list"])
    assert str(STATEMENTS["get"]).rstrip().endswith("ORDER BY v.seq")
