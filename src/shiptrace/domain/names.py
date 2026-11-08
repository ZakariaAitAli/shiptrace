"""Name rules for registered things (spec §5, Input formats). Matched exactly, never normalized."""

import re

_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_CREDENTIAL_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,62}[A-Za-z0-9])?", re.ASCII)


def is_valid_slug(value: str) -> bool:
    """Service and environment slugs: lowercase ASCII letters, digits and single hyphens."""
    return _SLUG.fullmatch(value) is not None and "--" not in value


def is_valid_credential_name(value: str) -> bool:
    return _CREDENTIAL_NAME.fullmatch(value) is not None
