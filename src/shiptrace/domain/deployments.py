"""Deployment events, derived status and ingestion decisions (spec §3, ADR-0003, ADR-0004).
Pure: no clock, no I/O. Field formats are checked in event_fields; R11 is not decided here."""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class EventType(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REVERTED = "reverted"


class Status(StrEnum):
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REVERTED = "reverted"


# The types that share the one terminal slot of a deployment.
TERMINAL = frozenset({EventType.SUCCEEDED, EventType.FAILED, EventType.CANCELLED})


def derive_status(events: Iterable[EventType]) -> Status:
    """The status of a deployment holding exactly these event types.

    The result depends only on which types are present, never on their order. A set the ingestion
    rules can never produce raises ValueError: it means stored data is corrupt, not that a client
    erred, so it must not be mapped to a status.
    """
    counts = Counter(events)
    if not counts:
        raise ValueError("impossible event set: a deployment has at least one event")
    if any(not isinstance(t, EventType) for t in counts):
        raise ValueError("impossible event set: an entry is not an event type")
    if any(n > 1 for n in counts.values()):
        raise ValueError("impossible event set: a type occurs more than once")
    terminal = [t for t in counts if t in TERMINAL]
    if len(terminal) > 1:
        raise ValueError("impossible event set: more than one terminal event")
    if EventType.REVERTED in counts:
        if terminal != [EventType.SUCCEEDED]:
            raise ValueError("impossible event set: reverted requires succeeded")
        return Status.REVERTED
    if terminal:
        return Status(terminal[0].value)
    return Status.IN_PROGRESS


@dataclass(frozen=True)
class NewEvent:
    """An event as a client reported it, already format-checked."""

    type: EventType
    version: str
    commit_sha: str
    source_url: str | None
    reason: str | None


@dataclass(frozen=True)
class StoredEvent:
    """A committed event. `id` is opaque to the domain and handed back unchanged on a replay."""

    id: object
    type: EventType
    source_url: str | None
    reason: str | None


@dataclass(frozen=True)
class DeploymentFacts:
    """What is stored for one (service, environment, deployment_key)."""

    version: str
    commit_sha: str
    events: tuple[StoredEvent, ...]


class RejectReason(StrEnum):
    EVENT_CONFLICT = "event_conflict"  # R4
    DEPLOYMENT_ATTRIBUTE_CONFLICT = "deployment_attribute_conflict"  # R5
    TERMINAL_CONFLICT = "terminal_conflict"  # R6
    REVERT_REQUIRES_SUCCESS = "revert_requires_success"  # R9
    REVERT_NOT_APPLICABLE = "revert_not_applicable"  # R10

    @property
    def retryable(self) -> bool:
        """Only a revert that arrived before its `succeeded` can later be accepted unchanged."""
        return self is RejectReason.REVERT_REQUIRES_SUCCESS


@dataclass(frozen=True)
class Accept:
    """Write the event (R1, R2, R7, R8)."""


@dataclass(frozen=True)
class Duplicate:
    """Write nothing; answer with the stored event (R3)."""

    original: StoredEvent


@dataclass(frozen=True)
class Reject:
    reason: RejectReason


type Decision = Accept | Duplicate | Reject


def binding_matches(
    bound_service: str, bound_environment: str, service: str, environment: str
) -> bool:
    """R11: the event names exactly the service and environment its credential is bound to.

    It sees slugs only, never a registry or a deployment, so the answer is the same whether or not
    the target exists. Matching is exact: no case folding, trimming or Unicode normalization."""
    return service == bound_service and environment == bound_environment


def decide(incoming: NewEvent, existing: DeploymentFacts | None) -> Decision:
    """Classify one event against the committed state of its deployment (spec §3, Precedence).

    A snapshot is all this sees: the unique indexes decide races, and a lost race is classified
    by calling this again on a fresh read. Stored data that no rule could have produced raises
    ValueError, since that is corruption and not a client error.
    """
    if existing is None:
        if incoming.type is EventType.REVERTED:
            return Reject(RejectReason.REVERT_REQUIRES_SUCCESS)  # R9
        return Accept()  # R1, R8
    stored_types = [e.type for e in existing.events]
    derive_status(stored_types)  # Raises on an impossible set, including no events at all.

    if incoming.version != existing.version or incoming.commit_sha != existing.commit_sha:
        return Reject(RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT)  # R5

    for event in existing.events:
        if event.type is incoming.type:
            if event.reason == incoming.reason and event.source_url == incoming.source_url:
                return Duplicate(event)  # R3
            return Reject(RejectReason.EVENT_CONFLICT)  # R4

    terminal = [t for t in stored_types if t in TERMINAL]
    if incoming.type is EventType.REVERTED:
        if not terminal:
            return Reject(RejectReason.REVERT_REQUIRES_SUCCESS)  # R9
        if terminal != [EventType.SUCCEEDED]:
            return Reject(RejectReason.REVERT_NOT_APPLICABLE)  # R10
    elif incoming.type in TERMINAL and terminal:
        return Reject(RejectReason.TERMINAL_CONFLICT)  # R6
    return Accept()  # R2, R7
