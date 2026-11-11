"""History and detail reads (spec §5, GET /deployments and GET /deployments/{id}), without HTTP.

Order under test: authorize, then validate, then the port. A refusal at either step must leave the
port untouched. Paging is keyset by id, newest first, with one extra row to learn whether another
page exists. Status filtering and the SQL behind it are the PostgreSQL tests' job.
"""

import uuid
from dataclasses import replace
from typing import Any

import pytest

from shiptrace.application.access import Forbidden, InvariantFault, Principal, StoreUnavailable
from shiptrace.application.credentials import FieldProblem
from shiptrace.application.deployment_reads import (
    DeploymentFilter,
    DeploymentNotFound,
    InvalidFilter,
    get_deployment,
    list_deployments,
)
from shiptrace.application.registry import MAX_PAGE, InvalidPage
from shiptrace.domain.credentials import Scope
from shiptrace.domain.deployments import Status

from .fakes import DictDeploymentReads, deployment_detail, deployment_summary


def principal(scope: Scope) -> Principal:
    return Principal(id=uuid.uuid4(), scope=scope, service_id=None, environment_id=None)


READER, ADMIN, INGEST = principal(Scope.READ), principal(Scope.ADMIN), principal(Scope.INGEST)
ANY = DeploymentFilter()
BOTH = DeploymentFilter(service="payments-api", environment="production")


@pytest.fixture
def reads() -> DictDeploymentReads:
    return DictDeploymentReads(items=[deployment_summary(n) for n in range(1, 6)])


# Authorization comes first


@pytest.mark.parametrize("who", [READER, ADMIN], ids=["read", "admin"])
def test_read_and_admin_may_list_and_get(who: Principal, reads: DictDeploymentReads) -> None:
    assert list_deployments(who, ANY, None, 10, reads).items
    reads.details[reads.items[0].id] = deployment_detail(reads.items[0])
    assert get_deployment(who, reads.items[0].id, reads).deployment == reads.items[0]


@pytest.mark.parametrize("who", [INGEST, replace(READER, scope="read")], ids=["ingest", "string"])  # type: ignore[arg-type]
def test_any_other_scope_is_forbidden_before_the_port(
    who: Principal, reads: DictDeploymentReads
) -> None:
    """An ingest credential only records; a plain string is never trusted as a scope."""
    with pytest.raises(Forbidden):
        list_deployments(who, ANY, None, 10, reads)
    with pytest.raises(Forbidden):
        get_deployment(who, uuid.uuid4(), reads)
    assert (reads.calls, reads.gets) == ([], [])


def test_authorization_is_decided_before_any_argument_is_checked(
    reads: DictDeploymentReads,
) -> None:
    with pytest.raises(Forbidden):
        bad_filters = DeploymentFilter(service="BAD", status=Status.FAILED)
        list_deployments(INGEST, bad_filters, "x", 0, reads)  # type: ignore[arg-type]
    assert reads.calls == []


# Validation


@pytest.mark.parametrize("limit", [0, -1, MAX_PAGE + 1, 10**9, True, 2.0, "5", None])
def test_a_page_size_outside_the_contract_is_refused(
    limit: Any, reads: DictDeploymentReads
) -> None:
    with pytest.raises(InvalidPage):
        list_deployments(READER, ANY, None, limit, reads)
    assert reads.calls == []


@pytest.mark.parametrize("limit", [1, 50, MAX_PAGE])
def test_the_page_size_bounds_are_inclusive(limit: int, reads: DictDeploymentReads) -> None:
    list_deployments(READER, ANY, None, limit, reads)
    assert reads.calls[-1][2] == limit + 1


@pytest.mark.parametrize("after", ["x", 5, b"x", "00000000-0000-0000-0000-000000000001"])
def test_a_position_that_is_not_a_uuid_is_refused(after: Any, reads: DictDeploymentReads) -> None:
    with pytest.raises(InvalidPage):
        list_deployments(READER, ANY, after, 10, reads)
    assert reads.calls == []


@pytest.mark.parametrize(
    ("filters", "problems"),
    [
        (DeploymentFilter(service="Payments"), [("service", "slug_format")]),
        (DeploymentFilter(service=""), [("service", "slug_format")]),
        (DeploymentFilter(environment="prod-"), [("environment", "slug_format")]),
        (DeploymentFilter(environment="a--b"), [("environment", "slug_format")]),
        (
            DeploymentFilter(service="X", environment="Y"),
            [("service", "slug_format"), ("environment", "slug_format")],
        ),
        (
            DeploymentFilter(service="ok", environment="ok", status="failed"),  # type: ignore[arg-type]
            [("status", "unknown_status")],
        ),
    ],
)
def test_a_malformed_filter_is_refused_with_field_and_rule(
    filters: DeploymentFilter, problems: list[tuple[str, str]], reads: DictDeploymentReads
) -> None:
    with pytest.raises(InvalidFilter) as caught:
        list_deployments(READER, filters, None, 10, reads)
    assert caught.value.problems == tuple(FieldProblem(f, r) for f, r in problems)
    assert reads.calls == []


@pytest.mark.parametrize(
    "filters",
    [
        DeploymentFilter(status=Status.FAILED),
        DeploymentFilter(service="payments-api", status=Status.FAILED),
        DeploymentFilter(environment="production", status=Status.FAILED),
    ],
    ids=["neither", "service-only", "environment-only"],
)
def test_a_status_filter_needs_both_a_service_and_an_environment(
    filters: DeploymentFilter, reads: DictDeploymentReads
) -> None:
    """Spec §5: status requires both of the other filters."""
    with pytest.raises(InvalidFilter) as caught:
        list_deployments(READER, filters, None, 10, reads)
    assert caught.value.problems == (FieldProblem("status", "requires_service_and_environment"),)
    assert reads.calls == []


@pytest.mark.parametrize("status", list(Status))
def test_every_status_is_accepted_with_both_filters(
    status: Status, reads: DictDeploymentReads
) -> None:
    list_deployments(READER, replace(BOTH, status=status), None, 10, reads)
    assert reads.calls[-1][0] == replace(BOTH, status=status)


def test_a_filter_by_service_or_environment_alone_is_accepted(reads: DictDeploymentReads) -> None:
    list_deployments(READER, DeploymentFilter(service="payments-api"), None, 10, reads)
    list_deployments(READER, DeploymentFilter(environment="production"), None, 10, reads)
    assert len(reads.calls) == 2


# Paging: keyset by id, newest first, one extra row to learn whether another page exists


def walk(reads: DictDeploymentReads, limit: int) -> list[list[uuid.UUID]]:
    pages, after = [], None
    while True:
        page = list_deployments(READER, ANY, after, limit, reads)
        pages.append([item.id for item in page.items])
        if page.next_after is None:
            return pages
        after = page.next_after
        assert len(pages) < 100, "the walk never ended"


@pytest.mark.parametrize("limit", [1, 2, 3, 4, 5, 6, 100])
def test_a_walk_returns_every_item_once_newest_first(
    limit: int, reads: DictDeploymentReads
) -> None:
    pages = walk(reads, limit)
    flat = [i for page in pages for i in page]
    assert flat == sorted((item.id for item in reads.items), reverse=True)
    assert all(len(page) == limit for page in pages[:-1])


def test_an_exact_multiple_ends_without_an_empty_extra_page(reads: DictDeploymentReads) -> None:
    reads.items = reads.items[:4]
    assert [len(p) for p in walk(reads, 2)] == [2, 2]


def test_the_port_is_asked_for_one_more_than_the_page(reads: DictDeploymentReads) -> None:
    after = uuid.UUID(int=4)
    page = list_deployments(READER, BOTH, after, 2, reads)
    assert reads.calls == [(BOTH, after, 3)]
    assert [item.id for item in page.items] == [uuid.UUID(int=3), uuid.UUID(int=2)]
    assert page.next_after == uuid.UUID(int=2)  # The last item shown, not the extra one.


def test_an_empty_result_is_an_empty_last_page() -> None:
    page = list_deployments(READER, ANY, None, 10, DictDeploymentReads())
    assert (page.items, page.next_after) == ([], None)


# Detail


def test_detail_is_returned_as_the_port_gave_it(reads: DictDeploymentReads) -> None:
    detail = deployment_detail(reads.items[0])
    reads.details[detail.deployment.id] = detail
    assert get_deployment(READER, detail.deployment.id, reads) is detail


def test_an_unknown_deployment_is_not_found(reads: DictDeploymentReads) -> None:
    with pytest.raises(DeploymentNotFound):
        get_deployment(READER, uuid.uuid4(), reads)


# Faults pass through untouched


@pytest.mark.parametrize("error", [StoreUnavailable(), InvariantFault()])
def test_store_errors_propagate_as_the_same_object(
    error: Exception, reads: DictDeploymentReads
) -> None:
    reads.error = error
    with pytest.raises(type(error)) as listing:
        list_deployments(READER, ANY, None, 10, reads)
    with pytest.raises(type(error)) as detail:
        get_deployment(READER, uuid.uuid4(), reads)
    assert listing.value is error and detail.value is error
