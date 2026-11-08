"""RFC 9457 problem responses (spec §5, Errors). Titles and details are fixed per code.

No response carries a credential, a request value, an exception message or a stack trace.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.routing import Match

from shiptrace.application.access import Forbidden, StoreUnavailable, Unauthenticated

MEDIA_TYPE = "application/problem+json"
RETRY_AFTER_SECONDS = "1"

# code: (status, title, detail)
PROBLEMS: dict[str, tuple[int, str, str]] = {
    "unauthenticated": (401, "Unauthenticated", "A valid bearer credential is required."),
    "forbidden": (403, "Forbidden", "The credential does not allow this action."),
    "not_found": (404, "Not found", "The requested resource does not exist."),
    "method_not_allowed": (405, "Method not allowed", "The resource does not support this method."),
    "already_exists": (409, "Already exists", "A resource with this identifier already exists."),
    "validation_failed": (422, "Validation failed", "The request is not valid."),
    "internal_error": (500, "Internal error", "The request could not be completed."),
    "unavailable": (503, "Service unavailable", "A dependency is unavailable. Retry later."),
}
_BY_HTTP_STATUS = {404: "not_found", 405: "method_not_allowed"}


def problem(
    code: str,
    headers: Mapping[str, str] | None = None,
    errors: Sequence[Mapping[str, str]] | None = None,
) -> JSONResponse:
    status, title, detail = PROBLEMS[code]
    body: dict[str, Any] = {
        "type": f"urn:shiptrace:problem:{code}",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
    }
    if errors is not None:
        body["errors"] = list(errors)
    return JSONResponse(
        body, status_code=status, headers=dict(headers or {}), media_type=MEDIA_TYPE
    )


def validation_errors(error: RequestValidationError) -> list[dict[str, str]]:
    """Where and which rule, never the value. An unknown key is itself client input, so an
    `extra_forbidden` error points at the object that holds it, not at the key."""
    found = []
    for item in error.errors():
        location = list(item["loc"])
        if item["type"] == "extra_forbidden":
            location = location[:-1]
        found.append({"location": ".".join(str(part) for part in location), "rule": item["type"]})
    return found


def allowed_methods(request: Request) -> str:
    """Every method the path supports. Starlette's own 405 names only the first matching route,
    which is wrong when one path has a route per method."""
    methods: set[str] = set()
    for route in request.app.router.routes:
        match, _ = route.matches(request.scope)
        if match is Match.PARTIAL:
            methods |= getattr(route, "methods", None) or set()
    return ", ".join(sorted(methods))


def install_problem_handlers(app: FastAPI) -> None:
    async def unauthenticated(_: Request, __: Exception) -> JSONResponse:
        return problem("unauthenticated", headers={"WWW-Authenticate": "Bearer"})

    async def forbidden(_: Request, __: Exception) -> JSONResponse:
        return problem("forbidden")

    async def unavailable(_: Request, __: Exception) -> JSONResponse:
        return problem("unavailable", headers={"Retry-After": RETRY_AFTER_SECONDS})

    async def invalid(_: Request, error: Exception) -> JSONResponse:
        assert isinstance(error, RequestValidationError)  # noqa: S101 - registered for this type
        return problem("validation_failed", errors=validation_errors(error))

    async def http_error(request: Request, error: Exception) -> JSONResponse:
        assert isinstance(error, HTTPException)  # noqa: S101 - registered for this type
        if error.status_code == 400:
            # FastAPI raises 400 for a body it cannot decode, such as invalid UTF-8. A client
            # error, never a 500; it names no value.
            return problem("validation_failed", errors=[{"location": "body", "rule": "unparsable"}])
        code = _BY_HTTP_STATUS.get(error.status_code, "internal_error")
        headers = dict(error.headers or {})  # Protocol headers stay; the detail text is dropped.
        if code == "method_not_allowed":
            headers["Allow"] = allowed_methods(request)
        return problem(code, headers=headers)

    async def unexpected(_: Request, __: Exception) -> JSONResponse:
        return problem("internal_error")

    app.add_exception_handler(Unauthenticated, unauthenticated)
    app.add_exception_handler(Forbidden, forbidden)
    app.add_exception_handler(StoreUnavailable, unavailable)
    app.add_exception_handler(RequestValidationError, invalid)
    app.add_exception_handler(HTTPException, http_error)
    app.add_exception_handler(Exception, unexpected)
