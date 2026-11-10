"""Status derivation from stored event types (spec §3, ADR-0004). Status is never stored."""

from itertools import permutations

import pytest

from shiptrace.domain.deployments import TERMINAL, EventType, Status, derive_status

S, F, C = EventType.SUCCEEDED, EventType.FAILED, EventType.CANCELLED
STARTED, REVERTED = EventType.STARTED, EventType.REVERTED

VALID: list[tuple[list[EventType], Status]] = [
    ([STARTED], Status.IN_PROGRESS),
    ([S], Status.SUCCEEDED),
    ([F], Status.FAILED),
    ([C], Status.CANCELLED),
    ([STARTED, S], Status.SUCCEEDED),
    ([STARTED, F], Status.FAILED),
    ([STARTED, C], Status.CANCELLED),
    ([S, REVERTED], Status.REVERTED),
    ([STARTED, S, REVERTED], Status.REVERTED),
]

INVALID: list[list[EventType]] = [
    [],  # a deployment never exists without an event
    [REVERTED],  # R9: needs a committed succeeded
    [STARTED, REVERTED],
    [F, REVERTED],  # R10
    [C, REVERTED],  # R10
    [STARTED, F, REVERTED],
    [S, F],  # R6: one terminal slot
    [S, C],
    [F, C],
    [S, F, C],
    [STARTED, S, F],
    [S, S],  # one event per type
    [STARTED, STARTED],
    [REVERTED, S, REVERTED],
]


def test_event_types_match_the_spec_values() -> None:
    assert {t.value for t in EventType} == {
        "started",
        "succeeded",
        "failed",
        "cancelled",
        "reverted",
    }


def test_status_values_match_the_spec() -> None:
    assert {s.value for s in Status} == {
        "in_progress",
        "succeeded",
        "failed",
        "cancelled",
        "reverted",
    }


def test_terminal_is_exactly_the_three_terminal_slot_types() -> None:
    assert frozenset({S, F, C}) == TERMINAL


@pytest.mark.parametrize(("events", "expected"), VALID)
def test_valid_event_sets(events: list[EventType], expected: Status) -> None:
    assert derive_status(events) is expected


@pytest.mark.parametrize(("events", "expected"), VALID)
def test_status_is_independent_of_event_order(events: list[EventType], expected: Status) -> None:
    for ordering in permutations(events):
        assert derive_status(ordering) is expected


@pytest.mark.parametrize("events", INVALID)
def test_impossible_event_sets_are_rejected(events: list[EventType]) -> None:
    with pytest.raises(ValueError, match="impossible"):
        derive_status(events)


@pytest.mark.parametrize("events", INVALID)
def test_impossible_sets_are_rejected_in_every_order(events: list[EventType]) -> None:
    for ordering in permutations(events):
        with pytest.raises(ValueError, match="impossible"):
            derive_status(ordering)


def test_accepts_any_iterable_once() -> None:
    assert derive_status(iter([STARTED, S])) is Status.SUCCEEDED


def test_plain_strings_are_not_event_types() -> None:
    with pytest.raises(ValueError, match="impossible"):
        derive_status(["started"])  # type: ignore[list-item]


def test_error_names_the_broken_invariant() -> None:
    with pytest.raises(ValueError, match="impossible") as info:
        derive_status([S, F])
    assert "terminal" in str(info.value)
