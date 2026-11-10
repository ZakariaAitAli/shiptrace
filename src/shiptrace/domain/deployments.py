"""Deployment events and derived status (spec §3, ADR-0004). Pure: no clock, no I/O."""

from collections import Counter
from collections.abc import Iterable
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
