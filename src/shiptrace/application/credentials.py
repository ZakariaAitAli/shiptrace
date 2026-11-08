"""Issuing credential tokens. Randomness lives here, because the domain stays deterministic."""

import secrets

from shiptrace.domain.credentials import SECRET_BYTES, token_from_secret


def new_token() -> str:
    """A fresh token from the operating system's CSPRNG. Shown once; only its digest is stored."""
    return token_from_secret(secrets.token_bytes(SECRET_BYTES))
