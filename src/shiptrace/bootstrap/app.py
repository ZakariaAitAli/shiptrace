"""Wires the application. Run with: uvicorn --factory shiptrace.bootstrap.app:create_app"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from shiptrace.api.app import build_api
from shiptrace.application.readiness import CachedCheck, SchemaExpectation, is_ready
from shiptrace.bootstrap.settings import Settings
from shiptrace.persistence.credentials import PostgresCredentialStore
from shiptrace.persistence.engine import build_engine
from shiptrace.persistence.issuance import PostgresCredentialIssuer
from shiptrace.persistence.registry import PostgresRegistry
from shiptrace.persistence.schema import PostgresSchemaProbe
from shiptrace.persistence.schema import expected_schema as build_expected_schema


def create_app(
    settings: Settings | None = None,
    expected_schema: SchemaExpectation | None = None,
) -> FastAPI:
    settings = settings or Settings()  # type: ignore[call-arg]
    expected = expected_schema or build_expected_schema()
    engine = build_engine(settings.database_url.get_secret_value(), settings.database_options())
    probe = PostgresSchemaProbe(engine)
    readiness = CachedCheck(lambda: is_ready(probe, expected), settings.readiness_cache_seconds)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    return build_api(
        readiness=readiness,
        docs_enabled=settings.environment != "production",
        credentials=PostgresCredentialStore(engine),
        registry=PostgresRegistry(engine),
        issuer=PostgresCredentialIssuer(engine),
        lifespan=lifespan,
    )
