"""Settings must refuse unsafe configuration and must never reveal a secret while doing so."""

import pytest
from pydantic import ValidationError

from shiptrace.bootstrap.settings import Settings, UnsafeConfiguration

SENTINEL = "sentinel-password-do-not-log"


def url(
    user: str = "shiptrace_app",
    password: str = SENTINEL,
    driver: str = "postgresql+psycopg",
    host: str = "db:5432",
    path: str = "/shiptrace",
    query: str = "",
) -> str:
    return f"{driver}://{user}:{password}@{host}{path}{query}"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHIPTRACE_ENVIRONMENT", raising=False)
    monkeypatch.delenv("SHIPTRACE_DATABASE_URL", raising=False)


def build(database_url: str | None = None, environment: str = "local", **more: object) -> Settings:
    values = {"environment": environment, "database_url": database_url or url(), **more}
    return Settings.model_validate(values)


def test_valid_settings_have_bounded_defaults() -> None:
    settings = build()
    assert settings.db_pool_size == 5
    assert settings.db_max_overflow == 5
    assert settings.db_pool_timeout_seconds == 3
    assert settings.db_statement_timeout_ms == 5000
    assert settings.db_lock_timeout_ms == 2000
    assert settings.db_connect_timeout_seconds == 3


def test_reads_prefixed_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIPTRACE_ENVIRONMENT", "local")
    monkeypatch.setenv("SHIPTRACE_DATABASE_URL", url())
    assert Settings().environment == "local"  # type: ignore[call-arg]


@pytest.mark.parametrize("missing", ["SHIPTRACE_ENVIRONMENT", "SHIPTRACE_DATABASE_URL"])
def test_required_values_have_no_default(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    monkeypatch.setenv("SHIPTRACE_ENVIRONMENT", "local")
    monkeypatch.setenv("SHIPTRACE_DATABASE_URL", url())
    monkeypatch.delenv(missing)
    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build(environment="staging")


@pytest.mark.parametrize(
    "database_url",
    [
        "not a url",
        url(driver="mysql"),
        url(driver="postgresql"),
        url(driver="postgresql+psycopg2"),
        url(host=""),
        url(path=""),
        url(user="postgres"),
        url(user="shiptrace_admin"),
        url(user="shiptrace_migrator"),
    ],
)
def test_unsafe_database_urls_are_rejected(database_url: str) -> None:
    with pytest.raises(UnsafeConfiguration):
        build(database_url)


@pytest.mark.parametrize("query", ["", "?sslmode=disable", "?sslmode=prefer", "?sslmode=require"])
def test_production_requires_verified_tls(query: str) -> None:
    with pytest.raises(UnsafeConfiguration):
        build(url(query=query), environment="production")


def test_production_accepts_verified_tls() -> None:
    settings = build(url(query="?sslmode=verify-full"), environment="production")
    assert settings.environment == "production"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("db_pool_size", 0),
        ("db_pool_size", 51),
        ("db_max_overflow", -1),
        ("db_pool_timeout_seconds", 0),
        ("db_statement_timeout_ms", 0),
        ("db_lock_timeout_ms", 0),
        ("db_connect_timeout_seconds", 1),
    ],
)
def test_limits_cannot_be_disabled(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        build(None, "local", **{field: value})


def test_lock_timeout_must_be_shorter_than_statement_timeout() -> None:
    with pytest.raises(ValidationError):
        build(db_lock_timeout_ms=6000, db_statement_timeout_ms=5000)


def test_settings_are_immutable() -> None:
    settings = build()
    with pytest.raises(ValidationError):
        settings.environment = "production"


def test_secret_is_absent_from_repr() -> None:
    settings = build()
    assert SENTINEL not in repr(settings)
    assert SENTINEL not in str(settings.model_dump())


@pytest.mark.parametrize("database_url", [url(driver="mysql"), url(user="postgres")])
def test_secret_is_absent_from_refusals(database_url: str) -> None:
    with pytest.raises(UnsafeConfiguration) as caught:
        build(database_url)
    assert SENTINEL not in str(caught.value)
    assert SENTINEL not in repr(caught.value)
    assert caught.value.__cause__ is None


def test_invalid_values_are_not_echoed_in_error_text() -> None:
    with pytest.raises(ValidationError) as caught:
        build(None, "local", db_pool_size=SENTINEL)
    assert SENTINEL not in str(caught.value)
