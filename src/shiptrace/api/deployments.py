"""Deployment history and detail routes (spec §5), for read and admin credentials.

Thin adapters around `application.deployment_reads`, which authorizes again and owns the filter
rules. Both routes depend on require(action) first, so a caller with no credential, or with an
ingest one, learns nothing about whether a query or an id is valid.

The responses show what a reader of deployment history needs and nothing else: the internal ids of
the service, the environment and the reporting credential, and an event's `seq`, stay inside.
`reason` and `source_url` are returned exactly as stored, as JSON strings; a client that renders
them must escape them, and ShipTrace never fetches `source_url`.
"""

import base64
import binascii
import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel

from shiptrace.api.auth import require
from shiptrace.api.registry import CURSOR_VERSION, DEFAULT_PAGE, Slug
from shiptrace.application.access import Principal
from shiptrace.application.deployment_reads import (
    DeploymentDetail,
    DeploymentEventRecord,
    DeploymentFilter,
    DeploymentReads,
    DeploymentSummary,
    get_deployment,
    list_deployments,
)
from shiptrace.application.registry import MAX_PAGE
from shiptrace.domain.credentials import Action
from shiptrace.domain.deployments import Status

PATH = "/api/v1/deployments"
_CURSOR_LABEL = "deployments"  # Inside every cursor, so another list's cursor is refused here.
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,120}", re.ASCII)


class DeploymentView(BaseModel):
    id: uuid.UUID
    service: str
    environment: str
    deployment_key: str
    version: str
    commit_sha: str
    status: str  # Derived from the events on every read; never stored.
    created_at: datetime

    @classmethod
    def of(cls, summary: DeploymentSummary) -> DeploymentView:
        return cls(
            id=summary.id,
            service=summary.service,
            environment=summary.environment,
            deployment_key=summary.deployment_key,
            version=summary.version,
            commit_sha=summary.commit_sha,
            status=summary.status.value,
            created_at=summary.created_at,
        )


class EventView(BaseModel):
    id: uuid.UUID
    type: str
    received_at: datetime
    source_url: str | None
    reason: str | None

    @classmethod
    def of(cls, event: DeploymentEventRecord) -> EventView:
        return cls(
            id=event.id,
            type=event.type.value,
            received_at=event.received_at,
            source_url=event.source_url,
            reason=event.reason,
        )


class DeploymentDetailView(DeploymentView):
    events: list[EventView]  # In the order the server recorded them.

    @classmethod
    def of_detail(cls, detail: DeploymentDetail) -> DeploymentDetailView:
        summary = detail.deployment
        return cls(
            id=summary.id,
            service=summary.service,
            environment=summary.environment,
            deployment_key=summary.deployment_key,
            version=summary.version,
            commit_sha=summary.commit_sha,
            status=summary.status.value,
            created_at=summary.created_at,
            events=[EventView.of(event) for event in detail.events],
        )


class DeploymentList(BaseModel):
    items: list[DeploymentView]
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


def _reads(request: Request) -> DeploymentReads:
    reads: DeploymentReads = request.app.state.deployment_reads
    return reads


def build_deployments_router() -> APIRouter:
    router = APIRouter()

    @router.get(PATH, response_model=DeploymentList)
    def history(
        principal: Annotated[Principal, Depends(require(Action.VIEW_DEPLOYMENTS))],
        reads: Annotated[DeploymentReads, Depends(_reads)],
        service: Annotated[Slug | None, Query()] = None,
        environment: Annotated[Slug | None, Query()] = None,
        status: Annotated[Status | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE,
        cursor: Annotated[str | None, Query()] = None,
    ) -> DeploymentList:
        after = None if cursor is None else decode_cursor(cursor)
        filters = DeploymentFilter(service=service, environment=environment, status=status)
        page = list_deployments(principal, filters, after, limit, reads)
        next_cursor = None if page.next_after is None else encode_cursor(page.next_after)
        return DeploymentList(
            items=[DeploymentView.of(item) for item in page.items], next_cursor=next_cursor
        )

    @router.get(PATH + "/{deployment_id}", response_model=DeploymentDetailView)
    def detail(
        deployment_id: uuid.UUID,
        principal: Annotated[Principal, Depends(require(Action.VIEW_DEPLOYMENTS))],
        reads: Annotated[DeploymentReads, Depends(_reads)],
    ) -> DeploymentDetailView:
        return DeploymentDetailView.of_detail(get_deployment(principal, deployment_id, reads))

    return router
