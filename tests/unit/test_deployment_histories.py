"""Histories of events through decide(), applied the way the store will apply them (spec AC4, the
pure half). Bounded and exhaustive: every ordering of at most five distinct events, no sampling.

Competing terminal events do not commute (the first committed wins, R6), so the final status is
compared only where the rules make it order independent, and otherwise with an oracle that names
the winner from the order of arrival."""

from collections.abc import Sequence
from dataclasses import dataclass
from itertools import permutations

import pytest

from shiptrace.domain.deployments import (
    TERMINAL,
    Accept,
    Decision,
    DeploymentFacts,
    Duplicate,
    EventType,
    NewEvent,
    Reject,
    RejectReason,
    Status,
    StoredEvent,
    decide,
    derive_status,
)

ST, S, F, C, R = (
    EventType.STARTED,
    EventType.SUCCEEDED,
    EventType.FAILED,
    EventType.CANCELLED,
    EventType.REVERTED,
)
VERSION = "1.4.2"
SHA = "0123456789abcdef0123456789abcdef01234567"

# The valid event sets of spec §3: what a deployment can hold.
VALID_SETS: list[tuple[EventType, ...]] = [
    (ST,),
    (S,),
    (F,),
    (C,),
    (ST, S),
    (ST, F),
    (ST, C),
    (S, R),
    (ST, S, R),
]


def incoming(kind: EventType) -> NewEvent:
    return NewEvent(type=kind, version=VERSION, commit_sha=SHA, source_url=None, reason=None)


@dataclass
class Store:
    """What S4 will do with a decision: write on Accept, nothing otherwise."""

    deployment: DeploymentFacts | None = None
    written: int = 0

    def submit(self, event: NewEvent) -> Decision:
        before = self.deployment
        decision = decide(event, before)
        if isinstance(decision, Accept):
            self.written += 1
            stored = StoredEvent(
                id=f"event-{self.written}",
                type=event.type,
                source_url=event.source_url,
                reason=event.reason,
            )
            events = (*(before.events if before else ()), stored)
            self.deployment = DeploymentFacts(
                version=event.version, commit_sha=event.commit_sha, events=events
            )
        else:
            assert self.deployment is before, "a rejection or replay must write nothing"
        self.check()
        return decision

    def types(self) -> list[EventType]:
        return [e.type for e in self.deployment.events] if self.deployment else []

    def check(self) -> None:
        """A deployment never exists without events, and holds a possible set."""
        if self.deployment is not None:
            assert self.deployment.events
            derive_status(self.types())  # Raises on an impossible set.


def is_retryable(decision: Decision) -> bool:
    return isinstance(decision, Reject) and decision.reason.retryable


def deliver(
    order: Sequence[EventType],
) -> tuple[Store, dict[EventType, list[Decision]], list[EventType]]:
    """Send each event once, in order, then retry retryable rejections until nothing changes."""
    store = Store()
    log: dict[EventType, list[Decision]] = {}
    pending: list[EventType] = []
    for kind in order:
        decision = store.submit(incoming(kind))
        log.setdefault(kind, []).append(decision)
        if is_retryable(decision):
            pending.append(kind)
    progress = True
    while pending and progress:
        progress = False
        for kind in list(pending):
            decision = store.submit(incoming(kind))
            log[kind].append(decision)
            if not is_retryable(decision):
                pending.remove(kind)
                progress = True
    return store, log, pending


# --- AC4, pure half: valid event sets in every order ------------------------------------------


@pytest.mark.parametrize("valid_set", VALID_SETS, ids=lambda s: "+".join(k.value for k in s))
def test_every_order_of_a_valid_set_reaches_the_same_status_with_every_event_stored_once(
    valid_set: tuple[EventType, ...],
) -> None:
    expected = derive_status(valid_set)
    for order in permutations(valid_set):
        store, log, pending = deliver(order)
        assert pending == [], order
        assert derive_status(store.types()) is expected, order
        assert sorted(store.types()) == sorted(valid_set), order
        assert store.written == len(valid_set), order
        for kind in valid_set:
            accepted = [d for d in log[kind] if isinstance(d, Accept)]
            assert len(accepted) == 1, (order, kind)


def test_a_rejected_revert_never_creates_a_deployment() -> None:
    store = Store()
    decision = store.submit(incoming(R))
    assert decision == Reject(RejectReason.REVERT_REQUIRES_SUCCESS)
    assert store.deployment is None
    assert store.written == 0


# --- Retryable revert ------------------------------------------------------------------------


def test_a_revert_that_arrives_first_is_accepted_when_retried_after_the_success() -> None:
    store = Store()
    first = store.submit(incoming(R))
    assert first == Reject(RejectReason.REVERT_REQUIRES_SUCCESS) and first.reason.retryable
    assert store.submit(incoming(ST)) == Accept()
    still_early = store.submit(incoming(R))  # started alone is not a committed success
    assert still_early == Reject(RejectReason.REVERT_REQUIRES_SUCCESS)
    assert store.submit(incoming(S)) == Accept()
    assert store.submit(incoming(R)) == Accept()
    assert derive_status(store.types()) is Status.REVERTED


def test_a_revert_retried_after_a_failure_is_not_applicable_and_stays_so() -> None:
    store = Store()
    assert is_retryable(store.submit(incoming(R)))
    assert store.submit(incoming(F)) == Accept()
    for _ in range(3):
        decision = store.submit(incoming(R))
        assert decision == Reject(RejectReason.REVERT_NOT_APPLICABLE)
        assert not is_retryable(decision)
    assert derive_status(store.types()) is Status.FAILED


# --- Replay idempotency ----------------------------------------------------------------------


def test_fifty_identical_submissions_store_one_event() -> None:
    store = Store()
    decisions = [store.submit(incoming(S)) for _ in range(50)]
    assert sum(isinstance(d, Accept) for d in decisions) == 1
    duplicates = [d for d in decisions if isinstance(d, Duplicate)]
    assert len(duplicates) == 49
    assert store.deployment is not None
    (only,) = store.deployment.events
    assert all(d.original is only for d in duplicates)


@pytest.mark.parametrize("order", list(permutations((ST, S, R))))
def test_replaying_any_stored_event_returns_it_and_writes_nothing(
    order: tuple[EventType, ...],
) -> None:
    store, _, _ = deliver(order)
    assert store.deployment is not None
    by_type = {e.type: e for e in store.deployment.events}
    for kind in order:
        decision = store.submit(incoming(kind))
        assert isinstance(decision, Duplicate)
        assert decision.original is by_type[kind]
    assert store.written == len(order)


# --- Terminal exclusivity: first committed wins, and orders may legitimately differ -----------


def first_terminal(order: Sequence[EventType]) -> EventType:
    return next(kind for kind in order if kind in TERMINAL)


@pytest.mark.parametrize("order", list(permutations((ST, S, F, C))))
def test_only_the_first_terminal_event_is_stored(order: tuple[EventType, ...]) -> None:
    winner = first_terminal(order)
    store, log, pending = deliver(order)
    assert pending == []
    assert [t for t in store.types() if t in TERMINAL] == [winner]
    assert derive_status(store.types()) is Status(winner.value)
    for loser in TERMINAL - {winner}:
        assert log[loser] == [Reject(RejectReason.TERMINAL_CONFLICT)]
    assert log[ST] == [Accept()]


def test_competing_terminals_do_not_converge_and_that_is_the_rule() -> None:
    finals = {derive_status(deliver(order)[0].types()) for order in permutations((ST, S, F, C))}
    assert finals == {Status.SUCCEEDED, Status.FAILED, Status.CANCELLED}


@pytest.mark.parametrize("order", list(permutations((ST, S, F, C, R))))
def test_with_a_revert_the_outcome_follows_the_first_terminal_event(
    order: tuple[EventType, ...],
) -> None:
    winner = first_terminal(order)
    store, log, pending = deliver(order)
    assert pending == []
    assert [t for t in store.types() if t in TERMINAL] == [winner]
    if winner is S:
        assert derive_status(store.types()) is Status.REVERTED
        assert log[R][-1] == Accept()
    else:
        assert derive_status(store.types()) is Status(winner.value)
        assert R not in store.types()
        assert log[R][-1] == Reject(RejectReason.REVERT_NOT_APPLICABLE)
    assert store.written == len(store.types())


# --- Stable rejections and corruption --------------------------------------------------------

REJECTIONS: list[tuple[tuple[EventType, ...], EventType, RejectReason]] = [
    ((ST,), R, RejectReason.REVERT_REQUIRES_SUCCESS),
    ((S,), F, RejectReason.TERMINAL_CONFLICT),
    ((F,), S, RejectReason.TERMINAL_CONFLICT),
    ((C,), R, RejectReason.REVERT_NOT_APPLICABLE),
    ((ST, F), R, RejectReason.REVERT_NOT_APPLICABLE),
    ((S, R), C, RejectReason.TERMINAL_CONFLICT),
]


@pytest.mark.parametrize(("present", "kind", "reason"), REJECTIONS)
def test_a_rejection_is_repeatable_and_changes_nothing(
    present: tuple[EventType, ...], kind: EventType, reason: RejectReason
) -> None:
    store, _, _ = deliver(present)
    snapshot = store.deployment
    for _ in range(5):
        assert store.submit(incoming(kind)) == Reject(reason)
    assert store.deployment is snapshot


def test_a_corrupt_store_is_an_error_not_a_decision() -> None:
    stored = (
        StoredEvent(id=1, type=S, source_url=None, reason=None),
        StoredEvent(id=2, type=F, source_url=None, reason=None),
    )
    corrupt = DeploymentFacts(version=VERSION, commit_sha=SHA, events=stored)
    for kind in (ST, S, F, C, R):
        # decide() itself must refuse, not rely on the store's own check afterwards.
        with pytest.raises(ValueError, match="impossible"):
            decide(incoming(kind), corrupt)
