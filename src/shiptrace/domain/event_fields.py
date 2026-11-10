"""Event field rules from spec §5, Input formats. Pure: a value is accepted or refused, never
changed, so an accepted string is stored and compared exactly as the client sent it.

Every validator takes any object and answers False for a wrong type, so no value is coerced."""

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

_DEPLOYMENT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", re.ASCII)
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}", re.ASCII)

MAX_REASON_CODE_POINTS = 500
_ALLOWED_CONTROLS = frozenset("\n\t")
_BIDI_OVERRIDES_AND_ISOLATES = frozenset(
    chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))
)

MAX_URL_LENGTH = 2048
_SCHEME = "https://"
# RFC 3986 unreserved, reserved and '%': no whitespace, control, non-ASCII, backslash or any of
# the characters `"<>^`{|}` that the RFC leaves out.
_URL_CHARACTERS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.ASCII)
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})", re.ASCII)
_CONTROL_PERCENT = re.compile(r"%(?:[01][0-9A-Fa-f]|7[Ff])", re.ASCII)
_DIGITS_AND_DOTS = re.compile(r"[0-9.]+", re.ASCII)
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", re.ASCII)
_PORT = re.compile(r"[0-9]+", re.ASCII)
_MAX_HOST_LENGTH = 253
_MAX_PORT = 65535


def is_valid_deployment_key(value: object) -> bool:
    """Required. Case-sensitive."""
    return isinstance(value, str) and _DEPLOYMENT_KEY.fullmatch(value) is not None


def is_valid_version(value: object) -> bool:
    """Required."""
    return isinstance(value, str) and _VERSION.fullmatch(value) is not None


def is_valid_commit_sha(value: object) -> bool:
    """Required. Lowercase only: an uppercase digest is refused, never lowercased."""
    return isinstance(value, str) and _COMMIT_SHA.fullmatch(value) is not None


def is_valid_reason(value: object) -> bool:
    """Optional: None (omitted or null) is absent. Otherwise 1-500 code points; of the control
    characters only LF and TAB are allowed. NUL and lone surrogates (PostgreSQL cannot store them)
    and the bidirectional override and isolate characters are refused."""
    if value is None:
        return True
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_REASON_CODE_POINTS:
        return False
    return not any(_is_unsafe_reason_character(c) for c in value)


def _is_unsafe_reason_character(char: str) -> bool:
    if char in _BIDI_OVERRIDES_AND_ISOLATES:
        return True
    # Cc covers C0, DEL and C1; Cs is the surrogates.
    return unicodedata.category(char) in {"Cc", "Cs"} and char not in _ALLOWED_CONTROLS


def is_valid_source_url(value: object) -> bool:
    """Optional: None (omitted or null) is absent. The URL is display-only and never fetched."""
    if value is None:
        return True
    if not isinstance(value, str) or not 0 < len(value) <= MAX_URL_LENGTH:
        return False
    if _URL_CHARACTERS.fullmatch(value) is None:
        return False
    if not value.startswith(_SCHEME):
        return False
    if _BAD_PERCENT.search(value) or _CONTROL_PERCENT.search(value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    if "#" in parts.fragment:  # urlsplit stops at the first '#', so any left is a second one
        return False
    return _is_valid_authority(parts.netloc)


def _is_valid_authority(authority: str) -> bool:
    if "@" in authority:  # No user information.
        return False
    if authority.startswith("["):
        host, closing, rest = authority[1:].partition("]")
        if not closing or not _is_valid_ipv6(host):
            return False
        if not rest:
            return True
        return rest.startswith(":") and _is_valid_port(rest[1:])
    host, colon, port = authority.partition(":")
    return _is_valid_host(host) and (not colon or _is_valid_port(port))


def _is_valid_ipv6(host: str) -> bool:
    if "%" in host:  # A zone identifier.
        return False
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        return False
    return True


def _is_valid_host(host: str) -> bool:
    if _DIGITS_AND_DOTS.fullmatch(host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return True
    # Punycode labels (xn--) pass as ordinary labels; they are not decoded. An empty label, such
    # as from a leading, doubled or trailing dot, fails the label pattern.
    return len(host) <= _MAX_HOST_LENGTH and all(
        _DNS_LABEL.fullmatch(label) for label in host.split(".")
    )


def _is_valid_port(port: str) -> bool:
    return _PORT.fullmatch(port) is not None and 1 <= int(port) <= _MAX_PORT
