"""Migration sources: no hidden characters, and 0004's SQL is the SQL that was verified.

Migrations are immutable once applied. The digest below pins every statement 0004 emits, upgrade
and downgrade, to the version the owner ran against PostgreSQL 18 (commit a1967d3). A change that
alters any statement fails here, and the remedy is a new migration, not a new digest."""

import hashlib
import importlib.util
import unicodedata
from pathlib import Path
from types import ModuleType

import pytest
from alembic import op

from shiptrace.persistence.schema import MIGRATIONS

VERSIONS = MIGRATIONS / "versions"
SOURCE_0004 = VERSIONS / "0004_deployments_and_events.py"
# sha256 of the 15 upgrade statements, a marker line, then the 4 downgrade statements, each joined
# by a newline, a NUL and a newline.
VERIFIED_0004_SQL = "a79916d8c7099f6f653f0080efd0ac8908dc36a5c3c54a0c1281dae99b550112"

BIDI_CONTROLS = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
ALLOWED_CONTROLS = {"\n", "\t"}


def hidden_characters(text: str) -> list[tuple[int, int]]:
    """(line, code point) of every control, format, separator or bidirectional character."""
    found = []
    for number, line in enumerate(text.split("\n"), start=1):
        for char in line:
            category = unicodedata.category(char)
            hidden = category in {"Cc", "Cf", "Zl", "Zp"} or char in BIDI_CONTROLS
            if hidden and char not in ALLOWED_CONTROLS:
                found.append((number, ord(char)))
    return found


def load(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"migration_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_detector_finds_bidirectional_and_invisible_characters() -> None:
    sample = "ok\nbad" + chr(0x202E) + "\nzero" + chr(0x200B) + "width\ntab\tis fine"
    assert hidden_characters(sample) == [(2, 0x202E), (3, 0x200B)]
    for char in BIDI_CONTROLS:
        assert hidden_characters("x" + char) == [(1, ord(char))]


# One historical exception, known and accepted (migration review F2, low severity). Migration 0004
# was committed with the four bidirectional characters that its reason check bans written out
# literally at the end of REASON_UNSAFE, at these places and in this order. Committed migrations are
# immutable and the pre-commit guard refuses any edit, so the source stays as it is; its SQL is
# pinned below and was verified against PostgreSQL. The exception is the exact (line, code point)
# list for that one file: a fifth character, a moved line or the same characters in any other
# migration fail this test. New migrations must not repeat it; build such characters with chr().
HISTORICAL_HIDDEN_CHARACTERS = {
    SOURCE_0004.name: [(46, 0x202A), (46, 0x202E), (46, 0x2066), (46, 0x2069)],
}


@pytest.mark.parametrize("path", sorted(VERSIONS.glob("*.py")), ids=lambda p: p.name)
def test_no_migration_source_hides_a_control_or_bidirectional_character(path: Path) -> None:
    expected = HISTORICAL_HIDDEN_CHARACTERS.get(path.name, [])
    assert hidden_characters(path.read_text(encoding="utf-8")) == expected


def test_the_historical_exception_is_on_the_reason_constant_of_0004() -> None:
    lines = SOURCE_0004.read_text(encoding="utf-8").split("\n")
    assert lines[45].startswith("REASON_UNSAFE = ")
    assert {number for number, _ in HISTORICAL_HIDDEN_CHARACTERS[SOURCE_0004.name]} == {46}


def test_0004_reason_check_names_exactly_the_forbidden_characters() -> None:
    expected = (
        r"[\u0001-\u0008\u000B-\u001F\u007F-\u009F"
        + chr(0x202A)
        + "-"
        + chr(0x202E)
        + chr(0x2066)
        + "-"
        + chr(0x2069)
        + "]"
    )
    assert expected == load(SOURCE_0004).REASON_UNSAFE


def test_0004_emits_the_sql_that_was_verified_against_postgresql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load(SOURCE_0004)
    recorded: list[str] = []
    monkeypatch.setattr(op, "execute", recorded.append)
    module.upgrade()
    upgrade = list(recorded)
    recorded.clear()
    module.downgrade()
    assert (len(upgrade), len(recorded)) == (15, 4)
    joined = "\n\x00\n".join([*upgrade, "--down--", *recorded])
    assert hashlib.sha256(joined.encode()).hexdigest() == VERIFIED_0004_SQL
