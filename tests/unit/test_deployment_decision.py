"""Ingestion decisions R1 to R10 and their precedence (spec §3). R11 is the credential binding and
is not decided here."""

import dataclasses

import pytest

from shiptrace.domain.deployments import (
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
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
URL = "https://ci.example.com/run/1"


def stored(
    kind: EventType, *, reason: str | None = None, url: str | None = None, ident: object = None
) -> StoredEvent:
    return StoredEvent(
        id=ident if ident is not None else f"id-{kind.value}",
        type=kind,
        source_url=url,
        reason=reason,
    )


def facts(*kinds: EventType, version: str = VERSION, sha: str = SHA) -> DeploymentFacts:
    return DeploymentFacts(version=version, commit_sha=sha, events=tuple(stored(k) for k in kinds))


def incoming(
    kind: EventType,
    *,
    version: str = VERSION,
    sha: str = SHA,
    reason: str | None = None,
    url: str | None = None,
) -> NewEvent:
    return NewEvent(type=kind, version=version, commit_sha=sha, source_url=url, reason=reason)


def label(decision: Decision) -> str:
    match decision:
        case Accept():
            return "accept"
        case Duplicate():
            return "duplicate"
        case Reject(reason=reason):
            return reason.value


def rejected(decision: Decision) -> RejectReason:
    assert isinstance(decision, Reject), decision
    return decision.reason


# --- The whole table: every valid stored set against every incoming type ---------------------
# Stored events and the incoming event carry identical content, so only the rules decide.

DUP, ACC = "duplicate", "accept"
T6, R9, R10 = "terminal_conflict", "revert_requires_success", "revert_not_applicable"
#                    started succeeded failed cancelled reverted
MATRIX: dict[tuple[EventType, ...], tuple[str, str, str, str, str]] = {
    (ST,): (DUP, ACC, ACC, ACC, R9),
    (S,): (ACC, DUP, T6, T6, ACC),
    (F,): (ACC, T6, DUP, T6, R10),
    (C,): (ACC, T6, T6, DUP, R10),
    (ST, S): (DUP, DUP, T6, T6, ACC),
    (ST, F): (DUP, T6, DUP, T6, R10),
    (ST, C): (DUP, T6, T6, DUP, R10),
    (S, R): (ACC, DUP, T6, T6, DUP),
    (ST, S, R): (DUP, DUP, T6, T6, DUP),
}
ORDER = (ST, S, F, C, R)


@pytest.mark.parametrize(
    ("present", "kind", "expected"),
    [(p, k, row[i]) for p, row in MATRIX.items() for i, k in enumerate(ORDER)],
)
def test_decision_matrix(present: tuple[EventType, ...], kind: EventType, expected: str) -> None:
    assert label(decide(incoming(kind), facts(*present))) == expected


def test_the_matrix_covers_every_valid_event_set() -> None:
    assert len(MATRIX) == 9
    for present in MATRIX:
        derive_status(present)  # Each is a valid set (raises otherwise).


# --- R1, R8, R9: no deployment yet -----------------------------------------------------------


@pytest.mark.parametrize("kind", [ST, S, F, C])
def test_r1_and_r8_first_event_of_any_type_but_reverted_is_accepted(kind: EventType) -> None:
    assert decide(incoming(kind), None) == Accept()


def test_r9_reverted_with_no_deployment_requires_success() -> None:
    assert decide(incoming(R), None) == Reject(RejectReason.REVERT_REQUIRES_SUCCESS)


# --- R2, R7: a compatible new type ------------------------------------------------------------


@pytest.mark.parametrize("terminal", [S, F, C])
def test_r2_terminal_after_started_is_accepted(terminal: EventType) -> None:
    assert decide(incoming(terminal), facts(ST)) == Accept()


def test_r2_reverted_after_succeeded_is_accepted() -> None:
    assert decide(incoming(R), facts(S)) == Accept()
    assert decide(incoming(R), facts(ST, S)) == Accept()


@pytest.mark.parametrize(
    "present", [(S,), (F,), (C,), (S, R)], ids=["succeeded", "failed", "cancelled", "reverted"]
)
def test_r7_started_after_terminal_is_accepted_and_status_does_not_change(
    present: tuple[EventType, ...],
) -> None:
    assert decide(incoming(ST), facts(*present)) == Accept()
    assert derive_status([*present, ST]) is derive_status(present)


# --- R3: replay ------------------------------------------------------------------------------


def test_r3_exact_replay_returns_the_original_event_itself() -> None:
    original = stored(S, reason="ok", url=URL, ident="the-original")
    deployment = DeploymentFacts(version=VERSION, commit_sha=SHA, events=(stored(ST), original))
    decision = decide(incoming(S, reason="ok", url=URL), deployment)
    assert isinstance(decision, Duplicate)
    assert decision.original is original
    assert decision.original.id == "the-original"


def test_r3_replay_of_an_event_without_reason_or_url() -> None:
    assert isinstance(decide(incoming(ST), facts(ST)), Duplicate)


def test_r3_replay_does_not_change_what_it_was_given() -> None:
    deployment = facts(ST, S)
    before = dataclasses.replace(deployment)
    decide(incoming(S), deployment)
    assert deployment == before
    assert [e.type for e in deployment.events] == [ST, S]


# --- R4: same type, different content -------------------------------------------------------


@pytest.mark.parametrize(
    ("stored_reason", "stored_url", "new_reason", "new_url"),
    [
        ("a", None, "b", None),
        ("a", URL, "a", "https://ci.example.com/run/2"),
        (None, None, "late reason", None),  # absent differs from present
        ("had a reason", None, None, None),
        (None, None, None, URL),
        (None, URL, None, None),
        ("a", URL, "b", "https://ci.example.com/run/2"),
    ],
)
def test_r4_same_type_with_different_reason_or_url_conflicts(
    stored_reason: str | None, stored_url: str | None, new_reason: str | None, new_url: str | None
) -> None:
    deployment = DeploymentFacts(
        version=VERSION,
        commit_sha=SHA,
        events=(stored(F, reason=stored_reason, url=stored_url),),
    )
    decision = decide(incoming(F, reason=new_reason, url=new_url), deployment)
    assert decision == Reject(RejectReason.EVENT_CONFLICT)


def test_r4_comparison_is_exact() -> None:
    deployment = DeploymentFacts(
        version=VERSION, commit_sha=SHA, events=(stored(F, reason="Timed out"),)
    )
    assert rejected(decide(incoming(F, reason="timed out"), deployment)) is (
        RejectReason.EVENT_CONFLICT
    )


# --- R5: deployment attributes ---------------------------------------------------------------


@pytest.mark.parametrize("kind", [ST, S, F, C, R], ids=lambda k: k.value)
def test_r5_version_mismatch_conflicts_for_every_type(kind: EventType) -> None:
    assert decide(incoming(kind, version="1.4.3"), facts(ST, S)) == Reject(
        RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT
    )


def test_r5_commit_mismatch_conflicts() -> None:
    assert decide(incoming(F, sha=OTHER_SHA), facts(ST)) == Reject(
        RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT
    )


def test_r5_comparison_is_exact() -> None:
    assert rejected(decide(incoming(ST, version="V1.4.2"), facts(ST))) is (
        RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT
    )


def test_r5_wins_over_an_otherwise_exact_replay() -> None:
    decision = decide(incoming(ST, version="9.9.9"), facts(ST))
    assert rejected(decision) is RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT


def test_r5_wins_over_r4() -> None:
    deployment = DeploymentFacts(version=VERSION, commit_sha=SHA, events=(stored(ST, reason="a"),))
    decision = decide(incoming(ST, reason="b", sha=OTHER_SHA), deployment)
    assert rejected(decision) is RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT


def test_r5_wins_over_r6() -> None:
    decision = decide(incoming(F, version="9.9.9"), facts(S))
    assert rejected(decision) is RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT


@pytest.mark.parametrize("present", [(ST,), (F,), (C,)])
def test_r5_wins_over_r9_and_r10(present: tuple[EventType, ...]) -> None:
    decision = decide(incoming(R, version="9.9.9"), facts(*present))
    assert rejected(decision) is RejectReason.DEPLOYMENT_ATTRIBUTE_CONFLICT


def test_r5_does_not_apply_without_a_deployment() -> None:
    assert decide(incoming(S, version="anything"), None) == Accept()


# --- R6: one terminal event ------------------------------------------------------------------


@pytest.mark.parametrize(("have", "new"), [(S, F), (S, C), (F, S), (F, C), (C, S), (C, F)])
def test_r6_a_different_terminal_event_conflicts(have: EventType, new: EventType) -> None:
    assert decide(incoming(new), facts(ST, have)) == Reject(RejectReason.TERMINAL_CONFLICT)
    assert decide(incoming(new), facts(have)) == Reject(RejectReason.TERMINAL_CONFLICT)


def test_r6_holds_after_a_revert() -> None:
    assert rejected(decide(incoming(F), facts(S, R))) is RejectReason.TERMINAL_CONFLICT


def test_replay_of_the_stored_terminal_is_a_duplicate_not_a_terminal_conflict() -> None:
    assert isinstance(decide(incoming(F), facts(F)), Duplicate)


def test_changed_content_on_the_stored_terminal_is_r4_not_r6() -> None:
    deployment = DeploymentFacts(version=VERSION, commit_sha=SHA, events=(stored(F, reason="a"),))
    assert rejected(decide(incoming(F, reason="b"), deployment)) is RejectReason.EVENT_CONFLICT


# --- R9, R10, and a revert that is a replay --------------------------------------------------


@pytest.mark.parametrize("present", [(ST,)])
def test_r9_reverted_without_a_terminal_event_requires_success(
    present: tuple[EventType, ...],
) -> None:
    assert decide(incoming(R), facts(*present)) == Reject(RejectReason.REVERT_REQUIRES_SUCCESS)


@pytest.mark.parametrize("present", [(F,), (C,), (ST, F), (ST, C)])
def test_r10_reverted_after_failed_or_cancelled_is_not_applicable(
    present: tuple[EventType, ...],
) -> None:
    assert decide(incoming(R), facts(*present)) == Reject(RejectReason.REVERT_NOT_APPLICABLE)


def test_a_reverted_replay_is_a_duplicate_with_the_original_identity() -> None:
    original = stored(R, reason="rolled back", ident="rev-1")
    deployment = DeploymentFacts(version=VERSION, commit_sha=SHA, events=(stored(S), original))
    decision = decide(incoming(R, reason="rolled back"), deployment)
    assert isinstance(decision, Duplicate)
    assert decision.original is original


def test_a_reverted_replay_with_other_content_is_an_event_conflict_not_a_revert_error() -> None:
    deployment = DeploymentFacts(
        version=VERSION,
        commit_sha=SHA,
        events=(stored(S), stored(R, reason="a")),
    )
    assert rejected(decide(incoming(R, reason="b"), deployment)) is RejectReason.EVENT_CONFLICT


# --- Rejection codes and retryability --------------------------------------------------------


def test_rejection_codes_are_stable() -> None:
    assert {r.name: r.value for r in RejectReason} == {
        "EVENT_CONFLICT": "event_conflict",
        "DEPLOYMENT_ATTRIBUTE_CONFLICT": "deployment_attribute_conflict",
        "TERMINAL_CONFLICT": "terminal_conflict",
        "REVERT_REQUIRES_SUCCESS": "revert_requires_success",
        "REVERT_NOT_APPLICABLE": "revert_not_applicable",
    }


def test_only_revert_requires_success_is_retryable() -> None:
    assert {r for r in RejectReason if r.retryable} == {RejectReason.REVERT_REQUIRES_SUCCESS}


# --- Values are immutable, decisions deterministic ------------------------------------------


def test_value_types_are_frozen() -> None:
    event = stored(S)
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.reason = "changed"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts(S).version = "2"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        incoming(S).type = F  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        Reject(RejectReason.EVENT_CONFLICT).reason = RejectReason.TERMINAL_CONFLICT  # type: ignore[misc]


def test_a_decision_depends_only_on_its_inputs() -> None:
    deployment, event = facts(ST, S), incoming(F)
    assert decide(event, deployment) == decide(event, deployment)


def test_the_order_of_stored_events_does_not_change_the_decision() -> None:
    for kind in ORDER:
        forward = decide(incoming(kind), facts(ST, S, R))
        backward = decide(incoming(kind), facts(R, S, ST))
        assert label(forward) == label(backward)


# --- Corrupt stored data is an error, never a decision --------------------------------------

CORRUPT: list[tuple[EventType, ...]] = [
    (),
    (R,),
    (ST, R),
    (F, R),
    (C, R),
    (S, F),
    (S, C, F),
    (S, S),
    (ST, ST),
    (S, R, R),
]


@pytest.mark.parametrize("present", CORRUPT)
@pytest.mark.parametrize("kind", ORDER, ids=lambda k: k.value)
def test_impossible_stored_event_sets_raise(
    present: tuple[EventType, ...], kind: EventType
) -> None:
    with pytest.raises(ValueError, match="impossible"):
        decide(incoming(kind), facts(*present))


def test_corruption_is_reported_before_an_attribute_conflict() -> None:
    with pytest.raises(ValueError, match="impossible"):
        decide(incoming(ST, version="9.9.9"), facts(S, F))


def test_the_status_after_every_accepted_event_is_valid() -> None:
    for present in MATRIX:
        for kind in ORDER:
            if decide(incoming(kind), facts(*present)) == Accept():
                assert isinstance(derive_status([*present, kind]), Status)
