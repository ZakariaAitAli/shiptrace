"""Reading deployment history and one deployment's detail (spec §3 and §5). No HTTP, no database.

Both reads are for `read` and `admin` credentials, which are not bound to a target, so every
deployment is visible to them and no per-target isolation applies. Order: authorize, then validate,
then the port; a refusal at either step leaves the port untouched.

History pages by deployment id, newest first (ARCHITECTURE §3). The id is a UUIDv7 the database
generates when the row is inserted, so it sorts by creation time and the caller cannot choose it.
That is creation order and not commit order: a deployment whose transaction commits late can appear
behind a cursor that has already passed it, and a reload shows it.

A deployment's status is derived from its events by the domain (`derive_status`) and is never
stored. The result types below are the internal shapes a response schema will be built from; they
are not that schema.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from shiptrace.application.access import Principal, authorize
from shiptrace.application.credentials import FieldProblem
from shiptrace.application.registry import MAX_PAGE, InvalidPage
from shiptrace.domain.credentials import Action
from shiptrace.domain.deployments import EventType, Status
from shiptrace.domain.names import is_valid_slug


class DeploymentNotFound(Exception):
    """No deployment has this id."""


class InvalidFilter(ValueError):
    """A history filter breaks the contract. Says which filter broke which rule, never a value."""

    def __init__(self, problems: tuple[FieldProblem, ...]) -> None:
        super().__init__()
        self.problems = problems


@dataclass(frozen=True)
class DeploymentFilter:
    """Slugs, not ids: the API speaks slugs. A slug that names nothing matches nothing.

    `status` needs both of the others (spec §5), because deriving it costs a pass over events."""

    service: str | None = None
    environment: str | None = None
    status: Status | None = None


@dataclass(frozen=True)
class DeploymentSummary:
    """One deployment with its derived status."""

    id: uuid.UUID
    service_id: uuid.UUID
    service: str
    environment_id: uuid.UUID
    environment: str
    deployment_key: str
    version: str
    commit_sha: str
    created_at: datetime  # Database time.
    status: Status


@dataclass(frozen=True)
class DeploymentEventRecord:
    """One stored event, every column the database holds. What a response shows of it is for the
    response schema to decide."""

    seq: int
    id: uuid.UUID
    type: EventType
    source_url: str | None
    reason: str | None
    credential_id: uuid.UUID
    received_at: datetime  # Database time of the insert, not a commit order.


@dataclass(frozen=True)
class DeploymentDetail:
    deployment: DeploymentSummary
    events: tuple[DeploymentEventRecord, ...]  # In `seq` order.


@dataclass(frozen=True)
class DeploymentPage:
    items: list[DeploymentSummary]
    next_after: uuid.UUID | None  # The last id on a full page, or None at the end.


class DeploymentReads(Protocol):
    def list_after(
        self, filters: DeploymentFilter, after: uuid.UUID | None, limit: int
    ) -> list[DeploymentSummary]:
        """Up to `limit` deployments matching `filters` with ids below `after`, newest first."""

    def get(self, deployment_id: uuid.UUID) -> DeploymentDetail | None:
        """One deployment with all its events, or None."""


def _filter_problems(filters: DeploymentFilter) -> list[FieldProblem]:
    found = []
    for name, slug in (("service", filters.service), ("environment", filters.environment)):
        if slug is not None and (not isinstance(slug, str) or not is_valid_slug(slug)):
            found.append(FieldProblem(name, "slug_format"))
    if filters.status is not None:
        if not isinstance(filters.status, Status):  # A plain string is never trusted as a Status.
            found.append(FieldProblem("status", "unknown_status"))
        elif filters.service is None or filters.environment is None:
            found.append(FieldProblem("status", "requires_service_and_environment"))
    return found


def list_deployments(
    principal: Principal,
    filters: DeploymentFilter,
    after: uuid.UUID | None,
    limit: int,
    reads: DeploymentReads,
) -> DeploymentPage:
    authorize(principal, Action.VIEW_DEPLOYMENTS)
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:  # bool is not a page size.
        raise InvalidPage
    if after is not None and not isinstance(after, uuid.UUID):
        raise InvalidPage
    problems = _filter_problems(filters)
    if problems:
        raise InvalidFilter(tuple(problems))
    # One extra row tells whether another page exists, so a full last page ends the walk.
    rows = reads.list_after(filters, after, limit + 1)
    if len(rows) > limit:
        return DeploymentPage(items=rows[:limit], next_after=rows[limit - 1].id)
    return DeploymentPage(items=rows, next_after=None)


def get_deployment(
    principal: Principal, deployment_id: uuid.UUID, reads: DeploymentReads
) -> DeploymentDetail:
    authorize(principal, Action.VIEW_DEPLOYMENTS)
    detail = reads.get(deployment_id)
    if detail is None:
        raise DeploymentNotFound
    return detail
