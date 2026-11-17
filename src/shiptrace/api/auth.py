"""Bearer authentication for API routes. Every protected route depends on require(action)."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from shiptrace.application.access import Principal, authenticate, authorize
from shiptrace.domain.credentials import Action, is_well_formed


def bearer_token(values: list[str]) -> str | None:
    """The token from exactly one `Authorization: Bearer <token>` header, else None.

    The scheme is case-insensitive (RFC 9110 §11.1); everything else must be exact: one space,
    then a well-formed token and nothing more. More than one header is ambiguous, so it yields
    nothing.
    """
    if len(values) != 1:
        return None
    scheme, separator, token = values[0].partition(" ")
    if scheme.lower() != "bearer" or not separator or not is_well_formed(token):
        return None
    return token


_SCHEMA_BEARER = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


def require(action: Action) -> Callable[[Request], Principal]:
    """A dependency that authenticates the caller, then checks the action. Sync: it does I/O."""

    def dependency(
        request: Request,
        _schema_bearer: Annotated[
            HTTPAuthorizationCredentials | None, Security(_SCHEMA_BEARER)
        ] = None,
    ) -> Principal:
        # HTTPBearer supplies OpenAPI metadata only. Raw-header parsing below remains authoritative,
        # including duplicate-header refusal and the stricter token grammar.
        token = bearer_token(request.headers.getlist("authorization"))
        principal = authenticate(token, request.app.state.credentials)
        authorize(principal, action)
        return principal

    return dependency
