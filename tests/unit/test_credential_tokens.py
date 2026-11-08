"""Credential token format, digest and generation (ADR-0005)."""

import base64

import pytest

from shiptrace.application.credentials import new_token
from shiptrace.domain.credentials import (
    TOKEN_PREFIX,
    digest,
    display_prefix,
    is_well_formed,
    token_from_secret,
)

CYRILLIC_A = chr(0x0410)
FULLWIDTH_A = chr(0xFF21)

# A fixed secret, and the token ADR-0005 defines for it: the prefix, then unpadded base64url.
# Built at runtime, so no realistic token string is committed.
KNOWN_SECRET = bytes(range(32))
KNOWN_TOKEN = "st1_" + base64.urlsafe_b64encode(KNOWN_SECRET).rstrip(b"=").decode()
# SHA-256 of KNOWN_TOKEN, computed independently with hashlib.
KNOWN_DIGEST = bytes.fromhex("a137bf2ec9e1ff70ffb6fc262b65f68491e8c8e86b46f587020cdd90a26add5b")


def test_token_encodes_the_secret_as_unpadded_base64url_after_the_prefix() -> None:
    assert TOKEN_PREFIX == "st1_"
    assert len(KNOWN_TOKEN) == 47
    assert token_from_secret(KNOWN_SECRET) == KNOWN_TOKEN
    assert token_from_secret(bytes(32)) == TOKEN_PREFIX + "A" * 43
    # The two characters where base64url differs from standard base64 and its variants.
    assert token_from_secret(b"\xff" * 32) == TOKEN_PREFIX + "_" * 42 + "8"
    assert token_from_secret(b"\xfb\xef\xbe" * 10 + b"\xfb\xef") == TOKEN_PREFIX + "-" * 42 + "8"


@pytest.mark.parametrize("length", [0, 16, 31, 33, 64])
def test_secret_must_be_exactly_256_bits(length: int) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        token_from_secret(bytes(length))


def test_well_formed_token_is_accepted() -> None:
    assert is_well_formed(KNOWN_TOKEN)


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "st1_",
        KNOWN_TOKEN[4:],  # no prefix
        "st2_" + KNOWN_TOKEN[4:],
        "ST1_" + KNOWN_TOKEN[4:],
        KNOWN_TOKEN[:-1],  # 42 characters of secret
        KNOWN_TOKEN + "A",  # 44 characters of secret
        KNOWN_TOKEN[:-1] + "=",
        KNOWN_TOKEN[:-1] + "+",
        KNOWN_TOKEN[:-1] + "/",
        KNOWN_TOKEN + "\n",
        " " + KNOWN_TOKEN,
        KNOWN_TOKEN[:-1] + CYRILLIC_A,
        KNOWN_TOKEN[:-1] + FULLWIDTH_A,
        "Bearer " + KNOWN_TOKEN,
    ],
)
def test_malformed_tokens_are_refused(candidate: str) -> None:
    assert not is_well_formed(candidate)


def test_digest_is_sha256_of_the_whole_token() -> None:
    assert digest(KNOWN_TOKEN) == KNOWN_DIGEST


def test_digest_refuses_input_that_is_not_a_token() -> None:
    """Never hash arbitrary client input: a malformed value is rejected before any lookup."""
    with pytest.raises(ValueError, match="not a credential token"):
        digest(KNOWN_TOKEN[:-1])


def test_display_prefix_reveals_only_the_prefix_and_four_characters() -> None:
    assert display_prefix(KNOWN_TOKEN) == KNOWN_TOKEN[:8]
    assert len(display_prefix(KNOWN_TOKEN)) == 8


def test_display_prefix_refuses_malformed_tokens() -> None:
    with pytest.raises(ValueError, match="not a credential token"):
        display_prefix(KNOWN_TOKEN[:-1])


def secret_of(token: str) -> bytes:
    return base64.urlsafe_b64decode(token.removeprefix(TOKEN_PREFIX) + "=")


def test_new_tokens_are_well_formed_and_carry_256_random_bits() -> None:
    tokens = {new_token() for _ in range(1000)}
    assert len(tokens) == 1000
    assert all(is_well_formed(token) for token in tokens)
    secrets = [secret_of(token) for token in tokens]
    assert all(len(secret) == 32 for secret in secrets)
    # Each byte position takes many values across 1000 tokens; a constant or mostly fixed
    # generator fails here. A uniform source gives about 250 distinct values per position.
    assert all(len({secret[i] for secret in secrets}) > 200 for i in range(32))
