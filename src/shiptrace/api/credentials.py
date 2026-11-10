"""Credential issuance route (spec §5): POST /api/v1/credentials, admin only.

The body is checked field by field here; the binding rules and the registry lookup belong to the
use case, whose IssuanceRejected the problem handlers turn into a field-specific 422. The token is
in the 201 body only, marked no-store; nothing else in this module sees it.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic_core import PydanticCustomError

from shiptrace.api.auth import require
from shiptrace.api.registry import Slug
from shiptrace.application.access import Principal
from shiptrace.application.credentials import (
    ISSUABLE,
    MAX_EXPIRY_DAYS,
    CredentialIssuer,
    NewCredential,
    issue_credential,
)
from shiptrace.domain.credentials import Action, Scope
from shiptrace.domain.names import is_valid_credential_name

PATH = "/api/v1/credentials"


def _name(value: str) -> str:
    if not is_valid_credential_name(value):
        raise PydanticCustomError("credential_name_format", "not a valid credential name")
    return value


def _scope(value: str) -> str:
    if value not in {scope.value for scope in ISSUABLE}:
        raise PydanticCustomError("scope_not_issuable", "not an issuable scope")
    return value


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, AfterValidator(_name)]
    scope: Annotated[str, AfterValidator(_scope)]
    service: Slug | None = None
    environment: Slug | None = None
    # Strict: "30", 30.0 and true are not day counts.
    expires_in_days: Annotated[int, Field(strict=True, ge=1, le=MAX_EXPIRY_DAYS)] | None = None


class IssuedResponse(BaseModel):
    id: uuid.UUID
    name: str
    scope: str
    service: str | None
    environment: str | None
    display_prefix: str
    created_at: datetime
    expires_at: datetime | None
    token: str = Field(repr=False)  # In the body once; never in a repr, log or traceback.


def _issuer(request: Request) -> CredentialIssuer:
    issuer: CredentialIssuer = request.app.state.issuer
    return issuer


def build_credentials_router() -> APIRouter:
    router = APIRouter()

    @router.post(PATH, status_code=status.HTTP_201_CREATED, response_model=IssuedResponse)
    def issue(
        body: IssueRequest,
        response: Response,
        principal: Annotated[Principal, Depends(require(Action.ISSUE_CREDENTIAL))],
        issuer: Annotated[CredentialIssuer, Depends(_issuer)],
    ) -> IssuedResponse:
        request = NewCredential(
            name=body.name,
            scope=Scope(body.scope),
            service=body.service,
            environment=body.environment,
            expires_in_days=body.expires_in_days,
        )
        issued = issue_credential(principal, request, issuer)
        response.headers["Cache-Control"] = "no-store"  # The token must not be kept anywhere.
        return IssuedResponse(
            id=issued.id,
            name=issued.name,
            scope=issued.scope.value,
            service=issued.service,
            environment=issued.environment,
            display_prefix=issued.display_prefix,
            created_at=issued.created_at,
            expires_at=issued.expires_at,
            token=issued.token,
        )

    return router
