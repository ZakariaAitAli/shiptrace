"""Parsing the Authorization header: strict, so ambiguous input never reaches a lookup."""

import pytest

from shiptrace.api.auth import bearer_token
from shiptrace.application.credentials import new_token

TOKEN = new_token()


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
def test_bearer_scheme_is_case_insensitive(scheme: str) -> None:
    """RFC 9110 §11.1: authentication schemes are case-insensitive."""
    assert bearer_token([f"{scheme} {TOKEN}"]) == TOKEN


@pytest.mark.parametrize(
    "values",
    [
        [],
        [""],
        ["Bearer"],
        ["Bearer "],
        [f"Basic {TOKEN}"],
        [TOKEN],
        [f"Bearer  {TOKEN}"],  # two spaces
        [f"Bearer\t{TOKEN}"],
        [f" Bearer {TOKEN}"],
        [f"Bearer {TOKEN} "],
        [f"Bearer {TOKEN} extra"],
        [f"Bearer {TOKEN},Bearer {TOKEN}"],
        [f"Bearer {TOKEN}", f"Bearer {TOKEN}"],  # two headers are ambiguous, even if equal
        [f"Bearer {TOKEN}", "Bearer other"],
    ],
)
def test_anything_else_yields_no_token(values: list[str]) -> None:
    assert bearer_token(values) is None
