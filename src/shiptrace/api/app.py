"""Builds the HTTP application from its collaborators."""

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from fastapi import FastAPI

from shiptrace.api.health import build_health_router

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


def build_api(
    readiness: Callable[[], bool],
    docs_enabled: bool,
    lifespan: Lifespan | None = None,
) -> FastAPI:
    app = FastAPI(
        title="ShipTrace",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.include_router(build_health_router(readiness))
    return app
