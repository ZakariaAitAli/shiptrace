"""Credential expiry and revocation are decided by PostgreSQL's now(), never by a Python clock.

The integration tests cannot tell the two clocks apart, because they share a host (V119). This is
a static guard instead: no module on the authentication path may import a clock, and the lookup
may not bring expiry or revocation timestamps back into Python, where they could be compared.
"""

import ast
from pathlib import Path

import pytest

import shiptrace

PACKAGE = Path(shiptrace.__file__).parent
AUTH_PATH = [
    "domain/credentials.py",
    "application/access.py",
    "persistence/credentials.py",
    "api/auth.py",
]
CLOCK_MODULES = {"datetime", "time", "calendar"}
DECISION_COLUMNS = {"expires_at", "revoked_at"}


def imported_modules(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


@pytest.mark.parametrize("module", AUTH_PATH)
def test_auth_path_imports_no_clock(module: str) -> None:
    tree = ast.parse((PACKAGE / module).read_text())
    assert not imported_modules(tree) & CLOCK_MODULES, module


def test_lookup_returns_no_timestamp_to_compare() -> None:
    """The decision stays in SQL: the rows that come back carry no expiry or revocation time."""
    tree = ast.parse((PACKAGE / "persistence/credentials.py").read_text())
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not attributes & DECISION_COLUMNS
