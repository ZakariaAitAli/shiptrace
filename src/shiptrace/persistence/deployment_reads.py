"""Deployment history and detail from PostgreSQL (spec §3 and §5, ARCHITECTURE §3), read-only.

Every statement is one SELECT with bound parameters, so the runtime role needs nothing beyond the
SELECT it already has. Nothing here writes, locks or takes a transaction of its own that matters.

History pages by `deployments.id` descending with a keyset (`id < :after`). The id is a UUIDv7 the
database generates at insert (the runtime role cannot supply one), so it orders by creation time;
that is the documented meaning of "newest first", and it is creation order and not commit order.

A deployment's status is never stored. The page query keeps the choice of rows in SQL and derives
the status shown in the domain: it collects each page deployment's event types in `seq` order and
hands them to `derive_status`. The status filter is a SQL predicate and so is a second statement of
the same rule; a PostgreSQL test proves the two agree for every event set the database can hold (the
unique terminal index and the revert guard leave exactly the valid sets). A deployment with no
events, or a set the rules cannot produce, is corrupt: it raises `InvariantFault` rather than being
shown with a guessed status.
"""

import logging
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine, Row
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import InvariantFault, StoreUnavailable
from shiptrace.application.deployment_reads import (
    DeploymentDetail,
    DeploymentEventRecord,
    DeploymentFilter,
    DeploymentSummary,
)
from shiptrace.domain.deployments import EventType, derive_status
from shiptrace.persistence.deployments import classify_database_error

_log = logging.getLogger(__name__)

# Each :service, :environment, :after and :status is cast where it is used, so a NULL has a type.
# The inner query picks and limits the rows; the lateral join then collects only those rows' events.
# The status predicates are the SQL form of domain.derive_status for the sets the database can hold:
#   in_progress  no terminal event            succeeded  `succeeded` and no `reverted`
#   failed       `failed`                     cancelled  `cancelled`
#   reverted     `reverted` (which requires `succeeded`)
_LIST = text(
    "SELECT p.id, p.service_id, p.service, p.environment_id, p.environment, p.deployment_key, "
    "p.version, p.commit_sha, p.created_at, t.types "
    "FROM ("
    "SELECT d.id, d.service_id, s.slug AS service, d.environment_id, e.slug AS environment, "
    "d.deployment_key, d.version, d.commit_sha, d.created_at "
    "FROM deployments AS d "
    "JOIN services AS s ON s.id = d.service_id "
    "JOIN environments AS e ON e.id = d.environment_id "
    "WHERE (CAST(:service AS text) IS NULL OR s.slug = CAST(:service AS text)) "
    "AND (CAST(:environment AS text) IS NULL OR e.slug = CAST(:environment AS text)) "
    "AND (CAST(:after AS uuid) IS NULL OR d.id < CAST(:after AS uuid)) "
    "AND (CAST(:status AS text) IS NULL OR CASE CAST(:status AS text) "
    "WHEN 'in_progress' THEN NOT EXISTS (SELECT 1 FROM deployment_events AS x "
    "WHERE x.deployment_id = d.id AND x.type IN ('succeeded', 'failed', 'cancelled')) "
    "WHEN 'succeeded' THEN EXISTS (SELECT 1 FROM deployment_events AS x "
    "WHERE x.deployment_id = d.id AND x.type = 'succeeded') "
    "AND NOT EXISTS (SELECT 1 FROM deployment_events AS x "
    "WHERE x.deployment_id = d.id AND x.type = 'reverted') "
    "WHEN 'failed' THEN EXISTS (SELECT 1 FROM deployment_events AS x "
    "WHERE x.deployment_id = d.id AND x.type = 'failed') "
    "WHEN 'cancelled' THEN EXISTS (SELECT 1 FROM deployment_events AS x "
    "WHERE x.deployment_id = d.id AND x.type = 'cancelled') "
    "WHEN 'reverted' THEN EXISTS (SELECT 1 FROM deployment_events AS x "
    "WHERE x.deployment_id = d.id AND x.type = 'reverted') "
    "ELSE false END) "
    "ORDER BY d.id DESC LIMIT :limit"
    ") AS p "
    "LEFT JOIN LATERAL ("
    "SELECT array_agg(x.type ORDER BY x.seq) AS types "
    "FROM deployment_events AS x WHERE x.deployment_id = p.id"
    ") AS t ON true "
    "ORDER BY p.id DESC"
)

# One statement, so the deployment and its events come from one snapshot.
_GET = text(
    "SELECT d.id, d.service_id, s.slug AS service, d.environment_id, e.slug AS environment, "
    "d.deployment_key, d.version, d.commit_sha, d.created_at, "
    "v.seq, v.id AS event_id, v.type, v.source_url, v.reason, v.credential_id, v.received_at "
    "FROM deployments AS d "
    "JOIN services AS s ON s.id = d.service_id "
    "JOIN environments AS e ON e.id = d.environment_id "
    "LEFT JOIN deployment_events AS v ON v.deployment_id = d.id "
    "WHERE d.id = :id ORDER BY v.seq"
)


def _summary(row: Row[Any], types: list[str] | None) -> DeploymentSummary:
    """Raises ValueError for no events, a type the domain does not know, or an impossible set."""
    return DeploymentSummary(
        id=row.id,
        service_id=row.service_id,
        service=row.service,
        environment_id=row.environment_id,
        environment=row.environment,
        deployment_key=row.deployment_key,
        version=row.version,
        commit_sha=row.commit_sha,
        created_at=row.created_at,
        status=derive_status(EventType(value) for value in (types or [])),
    )


def _corrupt() -> InvariantFault:
    _log.error("deployment read invariant fault: stored state is impossible")  # Fixed text.
    return InvariantFault()


class PostgresDeploymentReads:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def list_after(
        self, filters: DeploymentFilter, after: uuid.UUID | None, limit: int
    ) -> list[DeploymentSummary]:
        failure: InvariantFault | StoreUnavailable
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(
                    _LIST,
                    {
                        "service": filters.service,
                        "environment": filters.environment,
                        "after": after,
                        "status": None if filters.status is None else filters.status.value,
                        "limit": limit,
                    },
                ).all()
            return [_summary(row, row.types) for row in rows]
        except SQLAlchemyError as error:
            failure = classify_database_error(error)
        except ValueError:
            failure = _corrupt()
        # Raised outside the except blocks, so neither __cause__ nor __context__ holds the driver
        # error, whose statement and bound values must not travel onward.
        raise failure

    def get(self, deployment_id: uuid.UUID) -> DeploymentDetail | None:
        failure: InvariantFault | StoreUnavailable
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(_GET, {"id": deployment_id}).all()
            if not rows:
                return None
            events = tuple(
                DeploymentEventRecord(
                    seq=row.seq,
                    id=row.event_id,
                    type=EventType(row.type),
                    source_url=row.source_url,
                    reason=row.reason,
                    credential_id=row.credential_id,
                    received_at=row.received_at,
                )
                for row in rows
                if row.seq is not None  # The LEFT JOIN's single row of a deployment with no events.
            )
            return DeploymentDetail(
                deployment=_summary(rows[0], [event.type.value for event in events]),
                events=events,
            )
        except SQLAlchemyError as error:
            failure = classify_database_error(error)
        except ValueError:
            failure = _corrupt()
        raise failure
