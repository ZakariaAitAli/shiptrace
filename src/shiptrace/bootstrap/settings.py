"""Validated configuration. Nothing sensitive has a default, and errors never echo input."""

from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from shiptrace.persistence.engine import DatabaseOptions

PRIVILEGED_USERS = frozenset({"postgres", "shiptrace_admin", "shiptrace_migrator"})


class UnsafeConfiguration(Exception):
    """A secret-bearing value was refused.

    Deliberately not a ValueError. Pydantic wraps those in a ValidationError whose `errors()`
    carries the raw input, password included, even with `hide_input_in_errors`.
    """


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHIPTRACE_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    environment: Literal["local", "test", "production"]
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
        try:
            url = make_url(value.get_secret_value())
        except ArgumentError:
            raise UnsafeConfiguration("database URL is malformed") from None
        if url.drivername != "postgresql+psycopg":
            raise UnsafeConfiguration("database URL must use postgresql+psycopg")
        if not url.host or not url.database or not url.username:
            raise UnsafeConfiguration("database URL needs a user, host and database")
        if url.username in PRIVILEGED_USERS:
            raise UnsafeConfiguration("the application must connect as its runtime role")
        return value

    @model_validator(mode="after")
    def validate_combinations(self) -> Self:
        if self.db_lock_timeout_ms >= self.db_statement_timeout_ms:
            raise ValueError("lock timeout must be shorter than statement timeout")
        if self.environment == "production":
            url = make_url(self.database_url.get_secret_value())
            if url.query.get("sslmode") != "verify-full":
                raise UnsafeConfiguration("production requires sslmode=verify-full")
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
