"""Builds the HTTP application from its collaborators."""

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from fastapi import FastAPI

from shiptrace.api.health import build_health_router
from shiptrace.api.problems import install_problem_handlers
from shiptrace.application.access import CredentialStore

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


def build_api(
    readiness: Callable[[], bool],
    docs_enabled: bool,
    credentials: CredentialStore,
    lifespan: Lifespan | None = None,
) -> FastAPI:
    app = FastAPI(
        title="ShipTrace",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.credentials = credentials  # Read by api.auth.require for every protected route.
    install_problem_handlers(app)
    app.include_router(build_health_router(readiness))
    return app
