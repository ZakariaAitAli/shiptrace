"""Decides whether this build can serve traffic on the database it finds."""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class ProbeError(Exception):
    """The schema state could not be determined."""


class SchemaProbe(Protocol):
    def current_revision(self) -> str | None:
        """Returns the applied revision, None if there is none, or raises ProbeError."""


@dataclass(frozen=True)
class SchemaExpectation:
    head: str
    known: frozenset[str]


def is_ready(probe: SchemaProbe, expected: SchemaExpectation) -> bool:
    """Older than this build is not ready. Newer is ready: expand/contract keeps it compatible."""
    try:
        revision = probe.current_revision()
    except ProbeError:
        return False
    if revision is None:
        return False
    return revision == expected.head or revision not in expected.known


class CachedCheck:
    """Reuses a result briefly, so unauthenticated callers cannot drive database load."""

    def __init__(
        self,
        check: Callable[[], bool],
        ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._check = check
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._expires_at: float | None = None
        self._result = False

    def __call__(self) -> bool:
        with self._lock:
            now = self._clock()
            if self._expires_at is None or now >= self._expires_at:
                self._result = self._check()
                self._expires_at = self._clock() + self._ttl
            return self._result
