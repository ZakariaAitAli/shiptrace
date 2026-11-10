"""In-memory stand-ins for the credential store, the issuer and the registry, for unit tests."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.application.credentials import (
    NewCredential,
    StoredCredential,
    UnregisteredBinding,
)
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


@dataclass
class DictIssuer:
    services: set[str] = field(default_factory=set)
    environments: set[str] = field(default_factory=set)
    broken: bool = False
    added: list[tuple[NewCredential, bytes, str]] = field(default_factory=list)
    ids: list[uuid.UUID] = field(default_factory=list)

    def add(self, credential: NewCredential, secret_digest: bytes, prefix: str) -> StoredCredential:
        if self.broken:
            raise StoreUnavailable
        unknown = [
            name
            for name, slug, known in (
                ("service", credential.service, self.services),
                ("environment", credential.environment, self.environments),
            )
            if slug is not None and slug not in known
        ]
        if unknown:
            raise UnregisteredBinding(tuple(unknown))
        self.added.append((credential, secret_digest, prefix))
        self.ids.append(uuid.uuid4())
        days = credential.expires_in_days
        expires = None if days is None else FIXED_TIME + timedelta(days=days)
        return StoredCredential(id=self.ids[-1], created_at=FIXED_TIME, expires_at=expires)
