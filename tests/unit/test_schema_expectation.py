"""The build's revision list decides older from newer, so it must be complete."""

import re

from shiptrace.persistence.schema import MIGRATIONS, expected_schema


def revisions_on_disk() -> set[str]:
    found = set()
    for path in (MIGRATIONS / "versions").glob("*.py"):
        match = re.search(r'^revision = "([^"]+)"', path.read_text(), re.MULTILINE)
        assert match, path.name
        found.add(match[1])
    return found


def test_every_revision_file_is_known() -> None:
    assert expected_schema().known == frozenset(revisions_on_disk())


def test_head_is_a_known_revision() -> None:
    expected = expected_schema()
    assert expected.head in expected.known
