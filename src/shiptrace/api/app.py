"""Builds the HTTP application from its collaborators."""

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from fastapi import FastAPI

from shiptrace.api.credentials import build_credentials_router
from shiptrace.api.health import build_health_router
from shiptrace.api.problems import install_problem_handlers
from shiptrace.api.registry import build_registry_router
from shiptrace.application.access import CredentialStore
from shiptrace.application.credentials import CredentialIssuer
from shiptrace.application.registry import Registry

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


def build_api(
    readiness: Callable[[], bool],
    docs_enabled: bool,
    credentials: CredentialStore,
    registry: Registry,
    issuer: CredentialIssuer,
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
    app.state.registry = registry
    app.state.issuer = issuer
    install_problem_handlers(app)
    app.include_router(build_health_router(readiness))
    app.include_router(build_registry_router())
    app.include_router(build_credentials_router())
    return app
