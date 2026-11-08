"""Slug and credential-name rules from spec §5, Input formats."""

import pytest

from shiptrace.domain.names import is_valid_credential_name, is_valid_slug

CYRILLIC_A = chr(0x0430)
FULLWIDTH_ONE = chr(0xFF11)
E_ACUTE = chr(0x00E9)
I_DIAERESIS = chr(0x00EF)
ZERO_WIDTH_SPACE = chr(0x200B)


@pytest.mark.parametrize(
    "slug",
    ["a", "0", "qa", "payments-api", "staging", "eu-west-1", "a1-b2-c3", "x" * 63, "a" + "-b" * 31],
)
def test_valid_slugs(slug: str) -> None:
    assert is_valid_slug(slug)


@pytest.mark.parametrize(
    "slug",
    [
        "",
        "x" * 64,
        "Payments",  # uppercase is rejected, never lowercased
        "-api",
        "api-",
        "-",
        "pay--ments",
        "pay_ments",
        "pay ments",
        "pay.ments",
        "pay/ments",
        "api\n",
        "\napi",
        "p" + CYRILLIC_A + "yments",
        "api" + FULLWIDTH_ONE,
        "caf" + E_ACUTE,
    ],
)
def test_invalid_slugs(slug: str) -> None:
    assert not is_valid_slug(slug)


@pytest.mark.parametrize(
    "name",
    [
        "a",
        "ci",
        "1st deploy",
        "payments prod 2026-11",
        "GitHub Actions.release_v2",
        "X" * 64,
        "a b",
    ],
)
def test_valid_credential_names(name: str) -> None:
    assert is_valid_credential_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "X" * 65,
        " lead",
        "trail ",
        "-dash",
        "ci-",
        ".ci",
        "dot.",
        "_ci",
        "ci_",
        "tab\tname",
        "line\nbreak",
        "name\n",
        "semi;colon",
        "quote'",
        "<script>",
        "na" + I_DIAERESIS + "ve",
        "zero" + ZERO_WIDTH_SPACE + "width",
    ],
)
def test_invalid_credential_names(name: str) -> None:
    assert not is_valid_credential_name(name)
