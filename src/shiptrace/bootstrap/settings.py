"""Validated configuration. Nothing sensitive has a default, and errors never echo input."""

from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

from shiptrace.persistence.engine import DatabaseOptions

RUNTIME_ROLE = "shiptrace_app"
MIGRATOR_ROLE = "shiptrace_migrator"
ALLOWED_URL_QUERY = frozenset({"sslmode", "sslrootcert"})

Environment = Literal["local", "test", "production"]


class UnsafeConfiguration(Exception):
    """A configuration was refused.

    Deliberately not a ValueError. Pydantic wraps those in a ValidationError whose `errors()`
    carries the raw input, password included, even with `hide_input_in_errors`. Every check
    that runs with a database URL in scope must raise this instead.
    """


def parse_database_url(value: SecretStr, role: str) -> URL:
    try:
        url = make_url(value.get_secret_value())
    except ArgumentError, ValueError:  # A password can be misread as a port.
        raise UnsafeConfiguration("database URL is malformed") from None
    if url.drivername != "postgresql+psycopg":
        raise UnsafeConfiguration("database URL must use postgresql+psycopg")
    if not url.host or not url.database:
        raise UnsafeConfiguration("database URL needs a host and database")
    if url.username != role:
        raise UnsafeConfiguration(f"database URL must connect as {role}")
    if not ALLOWED_URL_QUERY.issuperset(url.query):
        raise UnsafeConfiguration("database URL query may only set TLS options")
    return url


def require_verified_tls(value: SecretStr, role: str) -> None:
    if parse_database_url(value, role).query.get("sslmode") != "verify-full":
        raise UnsafeConfiguration("production requires sslmode=verify-full")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHIPTRACE_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    environment: Environment
    database_url: SecretStr

    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=5, ge=0, le=50)
    db_pool_timeout_seconds: int = Field(default=3, ge=1, le=30)
    db_statement_timeout_ms: int = Field(default=5000, ge=1, le=60_000)
    db_lock_timeout_ms: int = Field(default=2000, ge=1, le=60_000)
    db_connect_timeout_seconds: int = Field(default=3, ge=2, le=30)  # libpq minimum is 2.
    readiness_cache_seconds: float = Field(default=1.0, ge=0, le=30)

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        parse_database_url(value, RUNTIME_ROLE)
        return value

    @model_validator(mode="after")
    def validate_combinations(self) -> Self:
        if self.db_lock_timeout_ms >= self.db_statement_timeout_ms:
            raise UnsafeConfiguration("lock timeout must be shorter than statement timeout")
        if self.environment == "production":
            require_verified_tls(self.database_url, RUNTIME_ROLE)
            if self.readiness_cache_seconds == 0:
                raise UnsafeConfiguration("production must keep the readiness cache")
        return self

    def database_options(self) -> DatabaseOptions:
        return DatabaseOptions(
            pool_size=self.db_pool_size,
            max_overflow=self.db_max_overflow,
            pool_timeout_seconds=self.db_pool_timeout_seconds,
            statement_timeout_ms=self.db_statement_timeout_ms,
            lock_timeout_ms=self.db_lock_timeout_ms,
            connect_timeout_seconds=self.db_connect_timeout_seconds,
        )


class MigrationSettings(BaseSettings):
    """The most privileged credential gets the same checks as the runtime one."""

    model_config = SettingsConfigDict(
        env_prefix="SHIPTRACE_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    environment: Environment
    migrator_database_url: SecretStr

    @field_validator("migrator_database_url")
    @classmethod
    def validate_migrator_url(cls, value: SecretStr) -> SecretStr:
        parse_database_url(value, MIGRATOR_ROLE)
        return value

    @model_validator(mode="after")
    def validate_transport(self) -> Self:
        if self.environment == "production":
            require_verified_tls(self.migrator_database_url, MIGRATOR_ROLE)
        return self
