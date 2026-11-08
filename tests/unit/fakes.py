"""In-memory stand-ins for the credential store and the registry, shared by unit tests."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.application.registry import Kind, RegistryEntry

FIXED_TIME = datetime(2026, 11, 8, tzinfo=UTC)


@dataclass
class DictStore:
    known: dict[bytes, Principal] = field(default_factory=dict)
    broken: bool = False

    def find_active(self, secret_digest: bytes) -> Principal | None:
        if self.broken:
            raise StoreUnavailable
        return self.known.get(secret_digest)


@dataclass
class DictRegistry:
    rows: dict[Kind, dict[str, RegistryEntry]] = field(
        default_factory=lambda: {kind: {} for kind in Kind}
    )
    calls: int = 0
    broken: bool = False

    def add(self, kind: Kind, slug: str) -> RegistryEntry | None:
        self.calls += 1
        if self.broken:
            raise StoreUnavailable
        if slug in self.rows[kind]:
            return None
        entry = RegistryEntry(id=uuid.uuid4(), slug=slug, created_at=FIXED_TIME)
        self.rows[kind][slug] = entry
        return entry

    def list_after(self, kind: Kind, after: str | None, limit: int) -> list[RegistryEntry]:
        self.calls += 1
        if self.broken:
            raise StoreUnavailable
        slugs = sorted(s for s in self.rows[kind] if after is None or s > after)
        return [self.rows[kind][s] for s in slugs[:limit]]
