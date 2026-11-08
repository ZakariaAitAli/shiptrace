"""Registry routes (spec §5): register and list services and environments.

Every route depends on require(action) from api.auth, and the use cases authorize again. A cursor
is an opaque, versioned encoding of the list's kind and the last slug on a page; anything that
does not decode to a position in that list is a 422 that names no value.
"""

import base64
import binascii
import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import AfterValidator, BaseModel, ConfigDict
from pydantic_core import PydanticCustomError

from shiptrace.api.auth import require
from shiptrace.application.access import Principal
from shiptrace.application.registry import (
    MAX_PAGE,
    Kind,
    Registry,
    RegistryEntry,
    list_page,
    register,
)
from shiptrace.domain.credentials import Action
from shiptrace.domain.names import is_valid_slug

DEFAULT_PAGE = 50
CURSOR_VERSION = "v1:"
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,120}", re.ASCII)


def _slug(value: str) -> str:
    if not is_valid_slug(value):
        raise PydanticCustomError("slug_format", "not a valid slug")
    return value


Slug = Annotated[str, AfterValidator(_slug)]


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: Slug


class Entry(BaseModel):
    id: uuid.UUID
    slug: str
    created_at: datetime

    @classmethod
    def of(cls, entry: RegistryEntry) -> Entry:
        return cls(id=entry.id, slug=entry.slug, created_at=entry.created_at)


class EntryList(BaseModel):
    items: list[Entry]
    next_cursor: str | None


def encode_cursor(kind: Kind, after: str) -> str:
    """The list's kind is inside, so a cursor works only on the list that issued it."""
    text = f"{CURSOR_VERSION}{kind.value}:{after}"
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _invalid_cursor() -> RequestValidationError:
    return RequestValidationError(
        [{"type": "invalid_cursor", "loc": ("query", "cursor"), "msg": "", "input": None}]
    )


def decode_cursor(kind: Kind, cursor: str) -> str:
    """The position in this list, or a 422. Only the exact form encode_cursor produces for this
    kind is accepted: the result must re-encode to the input, so non-canonical base64 fails."""
    if not _CURSOR.fullmatch(cursor):
        raise _invalid_cursor()
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("utf-8")
    except binascii.Error, UnicodeDecodeError:
        raise _invalid_cursor() from None
    prefix = f"{CURSOR_VERSION}{kind.value}:"
    after = text.removeprefix(prefix)
    if after == text or not is_valid_slug(after) or encode_cursor(kind, after) != cursor:
        raise _invalid_cursor()
    return after


def _registry(request: Request) -> Registry:
    registry: Registry = request.app.state.registry
    return registry


def _routes_for(router: APIRouter, kind: Kind) -> None:
    path = f"/api/v1/{kind.value}"

    @router.post(path, status_code=status.HTTP_201_CREATED, response_model=Entry)
    def create(
        body: RegisterRequest,
        principal: Annotated[Principal, Depends(require(Action.REGISTER))],
        registry: Annotated[Registry, Depends(_registry)],
    ) -> Entry:
        return Entry.of(register(principal, kind, body.slug, registry))

    @router.get(path, response_model=EntryList)
    def list_entries(
        principal: Annotated[Principal, Depends(require(Action.VIEW_REGISTRY))],
        registry: Annotated[Registry, Depends(_registry)],
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE,
        cursor: Annotated[str | None, Query()] = None,
    ) -> EntryList:
        after = None if cursor is None else decode_cursor(kind, cursor)
        page = list_page(principal, kind, after, limit, registry)
        next_cursor = None if page.next_after is None else encode_cursor(kind, page.next_after)
        return EntryList(items=[Entry.of(item) for item in page.items], next_cursor=next_cursor)


def build_registry_router() -> APIRouter:
    router = APIRouter()
    for kind in Kind:
        _routes_for(router, kind)
    return router
