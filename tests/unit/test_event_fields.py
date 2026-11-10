"""Event field rules from spec §5, Input formats (approved 2026-11-10). Values are never changed."""

import pytest

from shiptrace.domain.event_fields import (
    is_valid_commit_sha,
    is_valid_deployment_key,
    is_valid_reason,
    is_valid_source_url,
    is_valid_version,
)

CYRILLIC_A = chr(0x0430)
FULLWIDTH_ONE = chr(0xFF11)
COMBINING_ACUTE = chr(0x0301)
LRM = chr(0x200E)
RLM = chr(0x200F)
NARROW_NBSP = chr(0x202F)
E_ACUTE = chr(0x00E9)
NOT_STRINGS: list[object] = [None, 1, 1.5, True, b"abc", ["a"], ("a",), {"a": 1}]
SHA40 = ("0123456789abcdef" * 3)[:40]
SHA64 = "0123456789abcdef" * 4


# --- deployment_key and version: required, exact ASCII patterns -------------------------------


@pytest.mark.parametrize(
    "value",
    ["gha-12345678-1", "a", "0", "Key", "A.b_c-d", "k" * 128, "9" + "-" * 127],
)
def test_valid_deployment_keys(value: str) -> None:
    assert is_valid_deployment_key(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "k" * 129,
        "-a",
        ".a",
        "_a",
        "a b",
        "a/b",
        "a+b",  # '+' is allowed in a version, not in a key
        "a:b",
        "a\n",  # fullmatch, so a trailing newline is not ignored
        "\na",
        E_ACUTE,
        "a" + E_ACUTE,
        CYRILLIC_A,
        FULLWIDTH_ONE,
        *NOT_STRINGS,
    ],
)
def test_invalid_deployment_keys(value: object) -> None:
    assert not is_valid_deployment_key(value)


@pytest.mark.parametrize(
    "value",
    ["1.4.2", "v1.4.2", "1.4.2-rc.1", "1.4.2+build.5", "2024.11.10_a", "a", "0", "v" * 128],
)
def test_valid_versions(value: str) -> None:
    assert is_valid_version(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "v" * 129,
        "+1",
        "-1",
        ".1",
        "1.4 2",
        "1.4.2 ",
        "release/1.4",
        "sha256:abc",
        "1@2",
        "1.4.2\n",
        E_ACUTE,
        CYRILLIC_A,
        FULLWIDTH_ONE,
        *NOT_STRINGS,
    ],
)
def test_invalid_versions(value: object) -> None:
    assert not is_valid_version(value)


# --- commit_sha: required, 40 or 64 lowercase hexadecimal characters --------------------------


@pytest.mark.parametrize("value", [SHA40, SHA64, "f" * 40, "0" * 64])
def test_valid_commit_shas(value: str) -> None:
    assert is_valid_commit_sha(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0123abc",  # abbreviated
        SHA40[:39],
        SHA40 + "0",
        SHA64[:63],
        SHA64 + "0",
        "a" * 48,
        "g" * 40,
        "A" + SHA40[1:],  # uppercase is rejected, never lowercased
        SHA64.upper(),
        " " + SHA40[1:],
        SHA40 + "\n",
        FULLWIDTH_ONE * 40,
        *NOT_STRINGS,
    ],
)
def test_invalid_commit_shas(value: object) -> None:
    assert not is_valid_commit_sha(value)


# --- reason: optional, 1-500 code points, LF and TAB only among controls ----------------------


@pytest.mark.parametrize(
    "value",
    [
        "health check timed out after 300s",
        "Zeitüberschreitung bei der Prüfung",
        "a",
        " ",
        "a" * 500,
        "line one\nline two",
        "col1\tcol2",
        "日本語" * 100,
        "\U0001f600" * 500,  # 500 code points, though 1000 UTF-16 units
        ("e" + COMBINING_ACUTE) * 250,  # combining marks count as code points
        LRM + RLM,  # directional marks are not overrides or isolates
        NARROW_NBSP + chr(0x206A) + chr(0x2028),  # neighbours of the rejected ranges
    ],
)
def test_valid_reasons(value: str) -> None:
    assert is_valid_reason(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 501,
        "\U0001f600" * 501,
        "a\x00b",
        "a\rb",
        "a\r\nb",
        "\x1b[31mred",
        "\x0b",
        "\x1f",
        "\x7f",
        "\x80",
        "\x85",
        "\x9f",
        "\ud800",  # lone surrogates cannot be stored as UTF-8
        "a\udfffb",
        *[chr(c) for c in range(0x202A, 0x202F)],  # bidirectional embeddings and overrides
        *[chr(c) for c in range(0x2066, 0x206A)],  # bidirectional isolates
        1,
        True,
        b"abc",
        ["a"],
    ],
)
def test_invalid_reasons(value: object) -> None:
    assert not is_valid_reason(value)


# --- null and empty are different things ------------------------------------------------------


def test_required_fields_reject_null() -> None:
    assert not is_valid_deployment_key(None)
    assert not is_valid_version(None)
    assert not is_valid_commit_sha(None)


def test_optional_fields_accept_null() -> None:
    assert is_valid_source_url(None)
    assert is_valid_reason(None)


def test_optional_fields_reject_the_empty_string() -> None:
    assert not is_valid_source_url("")
    assert not is_valid_reason("")


# --- source_url: optional, display-only ------------------------------------------------------

ORIGIN = "https://example.com/"


@pytest.mark.parametrize(
    "value",
    [
        "https://github.com/acme/payments/actions/runs/12345678",
        "https://ci.example.com:8443/job/pay/42?tab=log#step:3",
        "https://xn--bcher-kva.example/run/1",
        "https://ci.example.com",  # empty path
        "https://example.com?q=1",
        "https://example.com#frag",
        "https://Example.COM/Path",  # nothing is lowercased
        "https://a-b.c1.example/x",
        "https://1.2.3.4.example/x",  # digits and dots only is IPv4; this has letters
        "https://192.168.0.1/x",
        "https://192.168.0.1:8080/x",
        "https://[2001:db8::1]/x",
        "https://[::1]:8443/x",
        "https://[::ffff:192.0.2.1]/",
        "https://[2001:DB8::A]/",
        "https://example.com:1/",
        "https://example.com:65535/",
        "https://ci.example.com:0080/",  # leading zeros are fine when the value is 1-65535
        "https://example.com/a@b?x=y@z#f@g",  # '@' outside the authority is fine
        "https://example.com/a:b;c=d,e",
        "https://example.com/a%20b?q=a%26b#h%7E",
        "https://example.com/%2F%2f",  # an encoded slash is kept, never decoded
        "https://example.com/%80%FF%e4%bd%A0",  # octets from 0x80 up are not controls
        "https://example.com/#a?b",
        "https://example.com/?a?b#c",
        "https://example.com/a/../b/./c",
        "https://example.com/'()*!$&+",
        "https://" + ".".join(["a" * 63] * 3 + ["a" * 61]) + "/",  # 253 characters of host
        "https://" + "a" * 63 + ".example/",  # label of 63
        ORIGIN + "a" * (2048 - len(ORIGIN)),  # exactly 2048 characters
    ],
)
def test_valid_source_urls(value: str) -> None:
    assert len(value) <= 2048
    assert is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        ORIGIN + "a" * (2049 - len(ORIGIN)),  # 2049 characters
        "",
        *[v for v in NOT_STRINGS if v is not None],
    ],
)
def test_source_url_length_and_type(value: object) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com/",
        "HTTPS://example.com/",  # the scheme is matched exactly
        "Https://example.com/",
        "ftp://example.com/",
        "javascript:alert(1)",
        "https:/example.com",
        "https:example.com",
        "//example.com/",
        "example.com/x",
        "https://",
        "https:///x",
        "https://?q=1",
        "https://#frag",
        " https://example.com/",
        "https://example.com/ ",
    ],
)
def test_source_url_scheme_and_host_required(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://user@example.com/",
        "https://user:pw@example.com/",
        "https://@example.com/",
        "https://example.com@evil.example/",
        "https://:@example.com/",
        "https://[::1]@example.com/",
    ],
)
def test_source_url_rejects_userinfo(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/a b",
        "https://example.com/a\tb",
        "https://example.com/a\nb",
        "https://example.com/a\rb",
        "https://example.com/a\x00b",
        "https://example.com/a\x1fb",
        "https://example.com/a\x7fb",
        "https://example.com/\n",
        "https://example.com/\\path",
        "https://example.com\\@evil.example/",
        "https://example.com/a\\b",
        "https://example.com/aé",
        "https://bücher.example/",
        "https://example.com/" + FULLWIDTH_ONE,
        "https://example.com/‮",
        'https://example.com/a"b',
        "https://example.com/a<b",
        "https://example.com/a>b",
        "https://example.com/a^b",
        "https://example.com/a`b",
        "https://example.com/a{b",
        "https://example.com/a|b",
        "https://example.com/a}b",
    ],
)
def test_source_url_character_set(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/%",
        "https://example.com/a%",
        "https://example.com/%2",
        "https://example.com/%zz",
        "https://example.com/%2g",
        "https://example.com/%g2",
        "https://example.com/?q=%",
        "https://example.com/#%x",
        "https://example.com/%%20",
    ],
)
def test_source_url_malformed_percent_escapes(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/%00",
        "https://example.com/%0a",
        "https://example.com/%0A",
        "https://example.com/%0d",
        "https://example.com/%09",
        "https://example.com/%1f",
        "https://example.com/%1F",
        "https://example.com/%7f",
        "https://example.com/%7F",
        "https://example.com/?q=%00",
        "https://example.com/#%1b",
    ],
)
def test_source_url_encoded_control_octets(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/#a#b",
        "https://example.com/##",
        "https://example.com/?q#a#",
        "https://example.com#a#b",
    ],
)
def test_source_url_rejects_a_second_fragment_marker(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com:/",  # empty port
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:99999/",
        "https://example.com:-1/",
        "https://example.com:+80/",
        "https://example.com:80a/",
        "https://example.com:abc/",
        "https://example.com:80:90/",
        "https://example.com: 80/",
        "https://example.com:" + FULLWIDTH_ONE + "/",
        "https://[::1]:/",
        "https://[::1]:0/",
        "https://[::1]:65536/",
        "https://[::1]:80:90/",
    ],
)
def test_source_url_ports(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://999.1.1.1/",
        "https://256.0.0.1/",
        "https://1.2.3/",
        "https://1.2.3.4.5/",
        "https://01.1.1.1/",  # leading zeros are refused by IPv4Address
        "https://1.2.3.4./",
        "https://1..2.3/",
        "https://.1.2.3/",
        "https://123/",  # digits only is still not an IPv4 address
    ],
)
def test_source_url_malformed_ipv4(value: str) -> None:
    assert not is_valid_source_url(value)


def test_a_host_with_letters_is_a_dns_name_not_an_ipv4_address() -> None:
    assert is_valid_source_url("https://0x7f.0.0.1/")


@pytest.mark.parametrize(
    "value",
    [
        "https://-a.example/",
        "https://a-.example/",
        "https://a..example/",
        "https://.a.example/",
        "https://a.example./",  # no trailing dot
        "https://exa_mple.com/",
        "https://exa mple.com/",
        "https://exa!mple.com/",
        "https://exa$mple.com/",
        "https://exa'mple.com/",
        "https://" + "a" * 64 + ".example/",  # label of 64
        "https://" + ".".join(["a" * 63] * 3 + ["a" * 62]) + "/",  # 254 characters of host
        "https://" + FULLWIDTH_ONE + ".example/",
    ],
)
def test_source_url_dns_names(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://[fe80::1%25eth0]/",  # zone identifiers are rejected
        "https://[fe80::1%eth0]/",
        "https://[fe80::1%25]/",
        "https://[::1/",  # unclosed
        "https://[::1]x/",
        "https://[::1]]/",
        "https://[]/",
        "https://[zz::1]/",
        "https://[1:2:3]/",
        "https://[:::1]/",
        "https://[12345::1]/",
        "https://[1.2.3.4]/",  # an IPv4 address is not an IPv6 literal
        "https://[v1.fe]/",  # no IPvFuture
        "https://[::1 ]/",
        "https://::1/",  # brackets are required
        "https://2001:db8::1/",
        "https://example.com[::1]/",
    ],
)
def test_source_url_ipv6_literals(value: str) -> None:
    assert not is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/a?b=c&d=e#f",
        "https://example.com/?",
        "https://example.com/#",
        "https://example.com/?#",
    ],
)
def test_source_url_keeps_empty_query_and_fragment_valid(value: str) -> None:
    assert is_valid_source_url(value)


@pytest.mark.parametrize(
    "value",
    ["https://[", "https://[::1", "https://%", "https://\x00", "https://:", "\ud800", "https://]"],
)
def test_source_url_parser_errors_are_rejections_not_exceptions(value: str) -> None:
    assert not is_valid_source_url(value)
