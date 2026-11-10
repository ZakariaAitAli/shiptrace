"""The revision chain of this build: each revision has one parent, and 0004 is expand-only."""

from alembic.script import ScriptDirectory

from shiptrace.persistence.schema import alembic_config, expected_schema


def test_the_head_is_0004_and_the_chain_is_linear() -> None:
    scripts = ScriptDirectory.from_config(alembic_config())
    assert expected_schema().head == "0004"
    parents = {s.revision: s.down_revision for s in scripts.walk_revisions()}
    assert parents == {"0004": "0003", "0003": "0002", "0002": "0001", "0001": None}


def test_0004_is_known_and_older_revisions_are_kept() -> None:
    known = expected_schema().known
    assert {"0001", "0002", "0003", "0004"} <= known
