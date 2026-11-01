"""Readiness rules, including the expand/contract cases that a naive equality check would break."""

import threading
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from shiptrace.application.readiness import (
    CachedCheck,
    ProbeError,
    SchemaExpectation,
    is_ready,
)

EXPECTED = SchemaExpectation(head="c", known=frozenset({"a", "b", "c"}))


@dataclass
class FakeProbe:
    revision: str | None = "c"
    error: bool = False

    def current_revision(self) -> str | None:
        if self.error:
            raise ProbeError
        return self.revision


def test_ready_at_head() -> None:
    assert is_ready(FakeProbe("c"), EXPECTED)


@pytest.mark.parametrize("older", ["a", "b"])
def test_not_ready_when_schema_is_older_than_build(older: str) -> None:
    assert not is_ready(FakeProbe(older), EXPECTED)


def test_ready_when_schema_is_newer_than_build() -> None:
    """After an expand migration, the previous release keeps serving."""
    assert is_ready(FakeProbe("z-from-a-newer-release"), EXPECTED)


def test_rollback_past_a_contract_migration_is_not_detected_yet() -> None:
    """Records a known gap, not a wish: ADR-0011 forbids contract migrations until it is closed."""
    old_build = SchemaExpectation(head="a", known=frozenset({"a"}))
    assert is_ready(FakeProbe("contract-migration-this-build-cannot-use"), old_build)


def test_not_ready_without_a_schema() -> None:
    assert not is_ready(FakeProbe(None), EXPECTED)


def test_not_ready_when_probe_fails() -> None:
    assert not is_ready(FakeProbe(error=True), EXPECTED)


@dataclass
class FakeClock:
    now: float = 100.0

    def __call__(self) -> float:
        return self.now


@dataclass
class CountingCheck:
    results: Iterator[bool] = field(default_factory=lambda: iter([True, False, True]))
    calls: int = 0

    def __call__(self) -> bool:
        self.calls += 1
        return next(self.results)


def test_result_is_reused_within_ttl() -> None:
    clock, check = FakeClock(), CountingCheck()
    cached = CachedCheck(check, ttl_seconds=1.0, clock=clock)
    assert cached() is True
    clock.now += 0.99
    assert cached() is True
    assert check.calls == 1


def test_result_is_refreshed_after_ttl() -> None:
    clock, check = FakeClock(), CountingCheck()
    cached = CachedCheck(check, ttl_seconds=1.0, clock=clock)
    cached()
    clock.now += 1.0
    assert cached() is False
    assert check.calls == 2


class BlockingCheck:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self) -> bool:
        self.entered.set()
        self.release.wait(5)
        return True


def run_while_first_call_blocks(cached: CachedCheck, check: BlockingCheck) -> list[bool]:
    worker = threading.Thread(target=cached)
    worker.start()
    assert check.entered.wait(5)
    results: list[bool] = []
    caller = threading.Thread(target=lambda: results.append(cached()))
    caller.start()
    caller.join(1)
    blocked = caller.is_alive()
    check.release.set()
    worker.join(5)
    caller.join(5)
    assert not blocked, "second caller queued behind the running probe"
    return results


def test_concurrent_caller_does_not_queue_and_fails_closed() -> None:
    check = BlockingCheck()
    assert run_while_first_call_blocks(CachedCheck(check, ttl_seconds=1.0), check) == [False]


def test_expired_result_is_not_served_while_probe_is_running() -> None:
    clock = FakeClock()
    results = iter([True])
    check = BlockingCheck()

    def first_then_block() -> bool:
        return next(results, None) or check()

    cached = CachedCheck(first_then_block, ttl_seconds=1.0, clock=clock)
    assert cached() is True
    clock.now += 2
    assert run_while_first_call_blocks(cached, check) == [False]
