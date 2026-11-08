"""Registering and listing services and environments (spec §5). Authorized here as well as at the
route, deny by default; slugs are checked against the CP1 rule before the store sees them."""

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from shiptrace.application.access import Principal, authorize
from shiptrace.domain.credentials import Action
from shiptrace.domain.names import is_valid_slug

MAX_PAGE = 100


class Kind(StrEnum):
    SERVICES = "services"
    ENVIRONMENTS = "environments"


class AlreadyExists(Exception):
    """A slug is already registered for this kind. The unique index decided it."""


class InvalidSlug(ValueError):
    """The slug breaks the spec §5 rule."""


class InvalidPage(ValueError):
    """The page size or position is outside the contract."""


@dataclass(frozen=True)
class RegistryEntry:
    id: uuid.UUID
    slug: str
    created_at: datetime  # Assigned by the database, never by this process.


@dataclass(frozen=True)
class Page:
    items: list[RegistryEntry]
    next_after: str | None  # The last slug of a full page, or None at the end.


class Registry(Protocol):
    def add(self, kind: Kind, slug: str) -> RegistryEntry | None:
        """Commits a new entry, or returns None when the slug already exists."""

    def list_after(self, kind: Kind, after: str | None, limit: int) -> list[RegistryEntry]:
        """Up to `limit` entries with slugs greater than `after`, in slug order."""


def register(principal: Principal, kind: Kind, slug: str, registry: Registry) -> RegistryEntry:
    authorize(principal, Action.REGISTER)
    if not is_valid_slug(slug):
        raise InvalidSlug
    entry = registry.add(kind, slug)
    if entry is None:
        raise AlreadyExists
    return entry


def list_page(
    principal: Principal, kind: Kind, after: str | None, limit: int, registry: Registry
) -> Page:
    authorize(principal, Action.VIEW_REGISTRY)
    if not 1 <= limit <= MAX_PAGE:
        raise InvalidPage
    if after is not None and not is_valid_slug(after):
        raise InvalidPage
    # One extra row tells whether another page exists, so a full last page ends the walk.
    rows = registry.list_after(kind, after, limit + 1)
    if len(rows) > limit:
        return Page(items=rows[:limit], next_after=rows[limit - 1].slug)
    return Page(items=rows, next_after=None)
