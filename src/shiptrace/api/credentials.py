"""Credential routes (spec §5), admin only: issue, list and revoke.

The body is checked field by field here; the binding rules and the registry lookup belong to the
use case, whose IssuanceRejected the problem handlers turn into a field-specific 422. The token is
in the 201 body only, marked no-store; nothing else in this module sees it. The list and revoke
responses are built from CredentialRecord, which has no field that could hold a secret.
"""

import base64
import binascii
import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic_core import PydanticCustomError

from shiptrace.api.auth import require
from shiptrace.api.registry import CURSOR_VERSION, DEFAULT_PAGE, Slug
from shiptrace.application.access import Principal
from shiptrace.application.credential_admin import (
    CredentialAdmin,
    CredentialRecord,
    list_credentials,
    revoke_credential,
)
from shiptrace.application.credentials import (
    ISSUABLE,
    MAX_EXPIRY_DAYS,
    CredentialIssuer,
    NewCredential,
    issue_credential,
)
from shiptrace.application.registry import MAX_PAGE
from shiptrace.domain.credentials import Action, Scope
from shiptrace.domain.names import is_valid_credential_name

PATH = "/api/v1/credentials"
_CURSOR_LABEL = "credentials"  # Inside every cursor, so a services cursor is refused here.
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,120}", re.ASCII)


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


class CredentialView(BaseModel):
    """Metadata only (spec §5). Deliberately no token or digest field."""

    id: uuid.UUID
    name: str
    scope: str
    service: str | None
    environment: str | None
    display_prefix: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None

    @classmethod
    def of(cls, record: CredentialRecord) -> CredentialView:
        return cls(
            id=record.id,
            name=record.name,
            scope=record.scope.value,
            service=record.service,
            environment=record.environment,
            display_prefix=record.display_prefix,
            created_at=record.created_at,
            expires_at=record.expires_at,
            revoked_at=record.revoked_at,
            last_used_at=record.last_used_at,
        )


class CredentialList(BaseModel):
    items: list[CredentialView]
    next_cursor: str | None


def encode_cursor(after: uuid.UUID) -> str:
    text = f"{CURSOR_VERSION}{_CURSOR_LABEL}:{after}"
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _invalid_cursor() -> RequestValidationError:
    return RequestValidationError(
        [{"type": "invalid_cursor", "loc": ("query", "cursor"), "msg": "", "input": None}]
    )


def decode_cursor(cursor: str) -> uuid.UUID:
    """The position in this list, or a 422. Only the exact form encode_cursor produces is
    accepted: the result must re-encode to the input, so non-canonical base64 or a UUID spelled
    another way fails."""
    if not _CURSOR.fullmatch(cursor):
        raise _invalid_cursor()
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("utf-8")
        prefix = f"{CURSOR_VERSION}{_CURSOR_LABEL}:"
        if not text.startswith(prefix):
            raise ValueError
        after = uuid.UUID(text.removeprefix(prefix))
    except binascii.Error, UnicodeDecodeError, ValueError:
        raise _invalid_cursor() from None
    if encode_cursor(after) != cursor:
        raise _invalid_cursor()
    return after


def _issuer(request: Request) -> CredentialIssuer:
    issuer: CredentialIssuer = request.app.state.issuer
    return issuer


async def _require_empty_body(request: Request) -> None:
    """Revocation takes no input, so any body is a client error. Only that a body exists is
    reported, never what it holds."""
    if await request.body():
        raise RequestValidationError(
            [{"type": "body_not_allowed", "loc": ("body",), "msg": "", "input": None}]
        )


def _admin(request: Request) -> CredentialAdmin:
    store: CredentialAdmin = request.app.state.credential_admin
    return store


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

    @router.get(PATH, response_model=CredentialList)
    def list_all(
        principal: Annotated[Principal, Depends(require(Action.LIST_CREDENTIALS))],
        store: Annotated[CredentialAdmin, Depends(_admin)],
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE,
        cursor: Annotated[str | None, Query()] = None,
    ) -> CredentialList:
        after = None if cursor is None else decode_cursor(cursor)
        page = list_credentials(principal, after, limit, store)
        next_cursor = None if page.next_after is None else encode_cursor(page.next_after)
        return CredentialList(
            items=[CredentialView.of(item) for item in page.items], next_cursor=next_cursor
        )

    @router.post(PATH + "/{credential_id}/revoke", response_model=CredentialView)
    def revoke(
        credential_id: uuid.UUID,
        principal: Annotated[Principal, Depends(require(Action.REVOKE_CREDENTIAL))],
        _: Annotated[None, Depends(_require_empty_body)],  # After auth: 401 and 403 come first.
        store: Annotated[CredentialAdmin, Depends(_admin)],
    ) -> CredentialView:
        return CredentialView.of(revoke_credential(principal, credential_id, store))

    return router
