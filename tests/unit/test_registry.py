"""Registry use cases with the store replaced by sorted dicts: authorization, validation, paging."""

import uuid

import pytest

from shiptrace.application.access import Forbidden, Principal
from shiptrace.application.registry import (
    AlreadyExists,
    InvalidPage,
    InvalidSlug,
    Kind,
    list_page,
    register,
)
from shiptrace.domain.credentials import Scope

from .fakes import DictRegistry


def principal(scope: Scope) -> Principal:
    return Principal(id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None)


ADMIN = principal(Scope.ADMIN)


@pytest.mark.parametrize("kind", list(Kind))
def test_admin_registers_and_the_store_assigns_id_and_time(kind: Kind) -> None:
    registry = DictRegistry()
    entry = register(ADMIN, kind, "payments-api", registry)
    assert entry.slug == "payments-api"
    assert registry.rows[kind]["payments-api"] == entry


@pytest.mark.parametrize("kind", list(Kind))
def test_kinds_are_separate(kind: Kind) -> None:
    registry = DictRegistry()
    register(ADMIN, kind, "shared", registry)
    other = next(k for k in Kind if k is not kind)
    register(ADMIN, other, "shared", registry)  # The same slug in the other kind is fine.


def test_duplicate_slug_is_already_exists() -> None:
    registry = DictRegistry()
    register(ADMIN, Kind.SERVICES, "api", registry)
    with pytest.raises(AlreadyExists):
        register(ADMIN, Kind.SERVICES, "api", registry)


@pytest.mark.parametrize("scope", [Scope.READ, Scope.INGEST])
def test_only_admin_registers(scope: Scope) -> None:
    registry = DictRegistry()
    with pytest.raises(Forbidden):
        register(principal(scope), Kind.SERVICES, "api", registry)
    assert registry.calls == 0


@pytest.mark.parametrize("scope", [Scope.READ, Scope.ADMIN])
def test_read_and_admin_list(scope: Scope) -> None:
    registry = DictRegistry()
    register(ADMIN, Kind.SERVICES, "api", registry)
    page = list_page(principal(scope), Kind.SERVICES, None, 50, registry)
    assert [entry.slug for entry in page.items] == ["api"]


def test_ingest_cannot_list() -> None:
    registry = DictRegistry()
    with pytest.raises(Forbidden):
        list_page(principal(Scope.INGEST), Kind.SERVICES, None, 50, registry)
    assert registry.calls == 0


@pytest.mark.parametrize("slug", ["", "Api", "-api", "a--b", "x" * 64, "api\n"])
def test_invalid_slugs_never_reach_the_store(slug: str) -> None:
    registry = DictRegistry()
    with pytest.raises(InvalidSlug):
        register(ADMIN, Kind.SERVICES, slug, registry)
    assert registry.calls == 0


def walk(registry: DictRegistry, limit: int) -> list[list[str]]:
    pages, after = [], None
    for _ in range(20):  # A position that is ignored would loop forever, not fail.
        page = list_page(ADMIN, Kind.SERVICES, after, limit, registry)
        pages.append([entry.slug for entry in page.items])
        if page.next_after is None:
            return pages
        after = page.next_after
    raise AssertionError("pagination never reached the end")


def test_pages_cover_every_slug_once_in_order() -> None:
    registry = DictRegistry()
    slugs = [f"s{i:02d}" for i in range(7)]
    for slug in reversed(slugs):
        register(ADMIN, Kind.SERVICES, slug, registry)
    assert walk(registry, 3) == [slugs[0:3], slugs[3:6], slugs[6:7]]


def test_an_exact_final_page_has_no_next() -> None:
    """The store is asked for one row more than the limit, so a full last page ends the walk."""
    registry = DictRegistry()
    for slug in ("a", "b", "c", "d"):
        register(ADMIN, Kind.SERVICES, slug, registry)
    assert walk(registry, 2) == [["a", "b"], ["c", "d"]]


def test_empty_registry_is_one_empty_page() -> None:
    assert walk(DictRegistry(), 50) == [[]]


@pytest.mark.parametrize("limit", [0, -1, 101])
def test_limit_outside_1_to_100_is_invalid(limit: int) -> None:
    with pytest.raises(InvalidPage):
        list_page(ADMIN, Kind.SERVICES, None, limit, DictRegistry())


@pytest.mark.parametrize("limit", [1, 100])
def test_limit_bounds_are_inclusive(limit: int) -> None:
    list_page(ADMIN, Kind.SERVICES, None, limit, DictRegistry())


@pytest.mark.parametrize("after", ["", "Api", "a--b", "x" * 64])
def test_a_position_that_is_not_a_slug_is_invalid(after: str) -> None:
    with pytest.raises(InvalidPage):
        list_page(ADMIN, Kind.SERVICES, after, 50, DictRegistry())
