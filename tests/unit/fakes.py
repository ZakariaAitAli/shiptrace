"""In-memory stand-ins for the credential store, the issuer and the registry, for unit tests."""

import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

from shiptrace.application.access import Principal, StoreUnavailable
from shiptrace.application.credential_admin import CredentialRecord
from shiptrace.application.credentials import (
    NewCredential,
    StoredCredential,
    UnregisteredBinding,
)
from shiptrace.application.deployments import Accepted, DeploymentTarget, Outcome
from shiptrace.application.registry import Kind, RegistryEntry
from shiptrace.domain.credentials import Scope
from shiptrace.domain.deployments import Accept, DeploymentFacts, NewEvent, StoredEvent, decide

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


@dataclass
class DictCredentialAdmin:
    rows: dict[uuid.UUID, CredentialRecord] = field(default_factory=dict)
    broken: bool = False
    writes: int = 0  # Revocations that changed a row; a repeat must not add to it.

    def add_record(self, **overrides: object) -> CredentialRecord:
        values: dict[str, object] = {
            "id": uuid.uuid4(),
            "name": "reader",
            "scope": Scope.READ,
            "service": None,
            "environment": None,
            "display_prefix": "st1_AbCd",
            "created_at": FIXED_TIME,
            "expires_at": None,
            "revoked_at": None,
            "last_used_at": None,
        } | overrides
        record = CredentialRecord(**values)  # type: ignore[arg-type]
        self.rows[record.id] = record
        return record

    def list_after(self, after: uuid.UUID | None, limit: int) -> list[CredentialRecord]:
        if self.broken:
            raise StoreUnavailable
        ids = sorted(i for i in self.rows if after is None or i > after)
        return [self.rows[i] for i in ids[:limit]]

    def revoke(self, credential_id: uuid.UUID) -> CredentialRecord | None:
        if self.broken:
            raise StoreUnavailable
        record = self.rows.get(credential_id)
        if record is not None and record.revoked_at is None:
            record = replace(record, revoked_at=FIXED_TIME + timedelta(minutes=1))
            self.rows[credential_id] = record
            self.writes += 1
        return record


@dataclass
class DictDeployments:
    """A deployment store that applies the real domain rules in memory and records every call.

    `error` makes every call raise it; `calls` is how a test proves a request never reached the
    store. It models neither concurrency nor the database: the PostgreSQL tests do."""

    error: Exception | None = None
    calls: list[tuple[DeploymentTarget, NewEvent, uuid.UUID]] = field(default_factory=list)
    stored: dict[tuple[uuid.UUID, uuid.UUID, str], tuple[str, str, list[StoredEvent]]] = field(
        default_factory=dict
    )

    def record(
        self, target: DeploymentTarget, event: NewEvent, credential_id: uuid.UUID
    ) -> Outcome:
        self.calls.append((target, event, credential_id))
        if self.error is not None:
            raise self.error
        key = (target.service_id, target.environment_id, target.deployment_key)
        state = self.stored.get(key)
        facts = None if state is None else DeploymentFacts(state[0], state[1], tuple(state[2]))
        decision = decide(event, facts)
        if not isinstance(decision, Accept):
            return decision
        event_id = uuid.uuid4()
        written = StoredEvent(event_id, event.type, event.source_url, event.reason)
        if state is None:
            self.stored[key] = (event.version, event.commit_sha, [written])
        else:
            state[2].append(written)
        return Accepted(event_id=event_id, seq=self.events(), received_at=FIXED_TIME)

    def events(self) -> int:
        return sum(len(events) for _, _, events in self.stored.values())
