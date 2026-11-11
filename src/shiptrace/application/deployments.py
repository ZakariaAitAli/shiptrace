"""Recording one deployment event: the port the ingest use case calls (spec §3, ARCHITECTURE §4).

The store decides nothing about field formats or R11; callers validate first. It answers with the
domain's classification: written (`Accepted`), already stored (`Duplicate`) or refused (`Reject`).
`StoreUnavailable` means retry later; `InvariantFault` means stored data or a database rule is
wrong, and retrying will not help.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from shiptrace.domain.deployments import Duplicate, NewEvent, Reject


@dataclass(frozen=True)
class DeploymentTarget:
    """The identity of a deployment: the ids the credential is bound to, and the client's key."""

    service_id: uuid.UUID
    environment_id: uuid.UUID
    deployment_key: str


@dataclass(frozen=True)
class Accepted:
    """The event was written. All three values were assigned by the database."""

    event_id: uuid.UUID
    seq: int
    received_at: datetime


type Outcome = Accepted | Duplicate | Reject


class DeploymentStore(Protocol):
    def record(
        self, target: DeploymentTarget, event: NewEvent, credential_id: uuid.UUID
    ) -> Outcome:
        """Classify `event` against the committed state and write it if it is accepted."""
