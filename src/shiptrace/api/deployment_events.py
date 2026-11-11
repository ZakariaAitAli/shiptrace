"""POST /api/v1/deployment-events (spec §3 and §5), ingest scope only.

The route is a thin adapter around `application.ingest.ingest_event`, which owns every decision:
scope, the principal's binding, field validation, R11 and the store call, in that order. Two things
here protect that order from the framework:

- The body is not a FastAPI body parameter. FastAPI would parse it before dependencies run, so a
  caller with no credential could learn that a body is malformed, and it would validate fields
  before the use case's own order. Instead `require` runs first, then `_event_body` reads and
  parses the JSON, and the use case receives the raw object and validates it.
- A rejection is a return value of the use case, mapped here to its problem document. A conflict
  rolled back in the store; nothing about the request is echoed.

The success body names the event and says whether it was a replay. Its only request-derived value
is the event type, already validated against the closed set of types; it echoes nothing else.
"""

import uuid
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from shiptrace.api.auth import require
from shiptrace.api.problems import problem
from shiptrace.application.access import Principal
from shiptrace.application.deployments import Accepted, DeploymentStore
from shiptrace.application.ingest import ingest_event
from shiptrace.domain.credentials import Action
from shiptrace.domain.deployments import Duplicate, Reject

PATH = "/api/v1/deployment-events"


class RecordedEvent(BaseModel):
    id: uuid.UUID
    type: str
    duplicate: bool


def _unparsable(rule: str) -> RequestValidationError:
    return RequestValidationError([{"type": rule, "loc": ("body",), "msg": "", "input": None}])


async def _event_body(request: Request) -> dict[str, Any]:
    """The JSON object in the request body. Declared after `require`, so it runs only for a
    caller who is authenticated and allowed. Nothing about the content is kept in an error."""
    try:
        parsed = await request.json()
    except ValueError, RecursionError:  # Bad JSON, bad UTF-8, or nesting too deep to parse.
        raise _unparsable("unparsable") from None
    if not isinstance(parsed, dict):
        raise _unparsable("object_required")
    return parsed


def _deployments(request: Request) -> DeploymentStore:
    store: DeploymentStore = request.app.state.deployments
    return store


def build_deployment_events_router() -> APIRouter:
    router = APIRouter()

    @router.post(
        PATH,
        status_code=status.HTTP_201_CREATED,
        response_model=RecordedEvent,
        responses={200: {"model": RecordedEvent, "description": "A replay of a stored event."}},
    )
    def record_event(
        principal: Annotated[Principal, Depends(require(Action.INGEST_EVENT))],
        body: Annotated[dict[str, Any], Depends(_event_body)],
        store: Annotated[DeploymentStore, Depends(_deployments)],
        response: Response,
    ) -> RecordedEvent | JSONResponse:
        outcome = ingest_event(principal, body, store)
        if isinstance(outcome, Reject):
            return problem(outcome.reason.value)
        if isinstance(outcome, Duplicate):
            response.status_code = status.HTTP_200_OK
            original = outcome.original
            # The domain keeps a stored id opaque; the store hands back the database uuid.
            stored_id = cast("uuid.UUID", original.id)
            return RecordedEvent(id=stored_id, type=original.type.value, duplicate=True)
        assert isinstance(outcome, Accepted)  # noqa: S101 - the Outcome union is closed
        return RecordedEvent(id=outcome.event_id, type=str(body["type"]), duplicate=False)

    return router
