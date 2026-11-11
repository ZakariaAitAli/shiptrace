"""Recording one deployment event (spec §3 and §5; ARCHITECTURE §4). No HTTP, no database.

The order is part of the contract, and each step refuses before the next one runs:

1. Scope: only `ingest` may record events (`Forbidden`).
2. The principal's binding must be complete (`InvariantFault`: the credential store guarantees it).
3. Field validation, every problem at once (`EventRejected`). Format errors say nothing about
   whether any target exists.
4. R11: the body's slugs must equal the bound slugs exactly (`Forbidden`, from slugs alone).
5. The store, called with the principal's own service and environment ids. The submitted slugs are
   never resolved, so the answer cannot depend on what is registered.

The store's outcome, and its `StoreUnavailable` or `InvariantFault`, pass through unchanged.
The only log line is fixed text for an unbound principal: a body, a reason or a URL never reaches
a log line from this module.
"""

import logging
from collections.abc import Callable, Mapping
from typing import cast

from shiptrace.application.access import Forbidden, InvariantFault, Principal, authorize
from shiptrace.application.credentials import FieldProblem
from shiptrace.application.deployments import DeploymentStore, DeploymentTarget, Outcome
from shiptrace.domain.credentials import Action
from shiptrace.domain.deployments import EventType, NewEvent, binding_matches
from shiptrace.domain.event_fields import (
    is_valid_commit_sha,
    is_valid_deployment_key,
    is_valid_reason,
    is_valid_source_url,
    is_valid_version,
)
from shiptrace.domain.names import is_valid_slug

_log = logging.getLogger(__name__)

_EVENT_TYPES = frozenset(t.value for t in EventType)

# (field, required, check). Field order is the order problems are reported in. Every check takes a
# str: a value of any other type is refused before it, so nothing is coerced.
_FIELDS: tuple[tuple[str, bool, Callable[[str], bool]], ...] = (
    ("service", True, is_valid_slug),
    ("environment", True, is_valid_slug),
    ("deployment_key", True, is_valid_deployment_key),
    ("type", True, lambda value: value in _EVENT_TYPES),
    ("version", True, is_valid_version),
    ("commit_sha", True, is_valid_commit_sha),
    ("source_url", False, is_valid_source_url),
    ("reason", False, is_valid_reason),
)
_KNOWN = frozenset(name for name, _, _ in _FIELDS)


class EventRejected(ValueError):
    """The body breaks the event rules (spec §5). Nothing was stored. Carries which field broke
    which rule, never a value. An unknown field is reported against the body itself, field `""`,
    because its name is client input."""

    def __init__(self, problems: tuple[FieldProblem, ...]) -> None:
        super().__init__()
        self.problems = problems


def _problems(body: Mapping[str, object]) -> list[FieldProblem]:
    found = []
    if any(key not in _KNOWN for key in body):
        found.append(FieldProblem("", "unknown_field"))
    for name, required, is_valid in _FIELDS:
        value = body.get(name)
        if value is None:  # Omitted and null are the same.
            if required:
                found.append(FieldProblem(name, "required"))
        elif not isinstance(value, str):
            found.append(FieldProblem(name, "type"))
        elif not is_valid(value):  # Includes the empty string.
            found.append(FieldProblem(name, "format"))
    return found


def _required(body: Mapping[str, object], name: str) -> str:
    """A required field already validated, so it is a str."""
    return cast("str", body[name])


def _optional(body: Mapping[str, object], name: str) -> str | None:
    """An optional field already validated: a str, or None when omitted or null."""
    return cast("str | None", body.get(name))


def ingest_event(
    principal: Principal, body: Mapping[str, object], store: DeploymentStore
) -> Outcome:
    authorize(principal, Action.INGEST_EVENT)
    # build_principal already refuses an inconsistent binding. This repeats the check because a
    # test double can build a malformed Principal, and it narrows the four values for mypy.
    service_id, environment_id = principal.service_id, principal.environment_id
    bound_service, bound_environment = principal.service_slug, principal.environment_slug
    if (
        service_id is None
        or environment_id is None
        or bound_service is None
        or bound_environment is None
    ):
        _log.error("ingest principal is not bound")  # Fixed text: no id, slug or request value.
        raise InvariantFault
    problems = _problems(body)
    if problems:
        raise EventRejected(tuple(problems))
    if not binding_matches(
        bound_service, bound_environment, _required(body, "service"), _required(body, "environment")
    ):
        raise Forbidden  # R11: from slugs alone; the target is never looked up.

    target = DeploymentTarget(service_id, environment_id, _required(body, "deployment_key"))
    event = NewEvent(
        type=EventType(_required(body, "type")),
        version=_required(body, "version"),
        commit_sha=_required(body, "commit_sha"),
        source_url=_optional(body, "source_url"),
        reason=_optional(body, "reason"),
    )
    return store.record(target, event, principal.id)
