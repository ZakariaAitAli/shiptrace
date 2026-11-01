"""Health endpoints. Responses carry a status word and nothing else."""

from collections.abc import Callable

from fastapi import APIRouter, Response, status


def build_health_router(readiness: Callable[[], bool]) -> APIRouter:
    router = APIRouter()

    @router.get("/healthz", include_in_schema=False)
    def healthz(response: Response) -> dict[str, str]:
        """Process is alive. Never checks dependencies: restarting us cannot repair a database."""
        response.headers["Cache-Control"] = "no-store"
        return {"status": "ok"}

    @router.get("/readyz", include_in_schema=False)
    def readyz(response: Response) -> dict[str, str]:
        response.headers["Cache-Control"] = "no-store"
        if readiness():
            return {"status": "ok"}
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable"}

    return router
