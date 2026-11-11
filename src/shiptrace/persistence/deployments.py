"""Deployments and their events in PostgreSQL (spec §3, ARCHITECTURE §4, ADR-0003).

One READ COMMITTED transaction per event. The domain's `decide` classifies against a snapshot; the
unique indexes settle every race, never a lock. The runtime role may only SELECT and INSERT these
tables, so there is no `FOR UPDATE`, `UPDATE` or `DELETE` anywhere here.

1. Read the deployment and its events by identity (one statement).
2. Absent: an initial `reverted` is rejected (R9) and creates nothing. Any other type inserts the
   deployment with `ON CONFLICT DO NOTHING`. A row back means this transaction created it. No row
   means another transaction holds the identity; `ON CONFLICT` waited for it to finish, so a
   *separate* read statement, which takes a new snapshot, sees the winner's committed state.
3. `decide` classifies. Reject and Duplicate write nothing and roll back, which also discards a
   deployment created in step 2.
4. Accept: insert the event with `ON CONFLICT DO NOTHING` and *no conflict target*, so both the
   one-per-type constraint and the one-terminal index arbitrate (naming one would turn a loss on the
   other into an error). A row back commits. No row back means a concurrent writer committed a
   conflicting event: read again in a new statement and classify that. If `decide` still says
   Accept there, nothing explains the conflict, which is a fault.

Ids, `seq` and timestamps are database defaults; the client supplies none. Errors are classified by
SQLSTATE alone and leave the module with no statement, parameter, message or DETAIL.
"""

import logging
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine, Row
from sqlalchemy.exc import InterfaceError, OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeout

from shiptrace.application.access import InvariantFault, StoreUnavailable
from shiptrace.application.deployments import Accepted, DeploymentTarget, Outcome
from shiptrace.domain.deployments import (
    Accept,
    DeploymentFacts,
    EventType,
    NewEvent,
    StoredEvent,
    decide,
)

_log = logging.getLogger(__name__)

_READ = text(
    "SELECT d.id AS deployment_id, d.version, d.commit_sha, "
    "e.id AS event_id, e.type, e.source_url, e.reason "
    "FROM deployments AS d LEFT JOIN deployment_events AS e ON e.deployment_id = d.id "
    "WHERE d.service_id = :service_id AND d.environment_id = :environment_id "
    "AND d.deployment_key = :deployment_key ORDER BY e.seq"
)
_INSERT_DEPLOYMENT = text(
    "INSERT INTO deployments (service_id, environment_id, deployment_key, version, commit_sha) "
    "VALUES (:service_id, :environment_id, :deployment_key, :version, :commit_sha) "
    "ON CONFLICT DO NOTHING RETURNING id"
)
# No conflict target on purpose: see the module docstring, step 4.
_INSERT_EVENT = text(
    "INSERT INTO deployment_events (deployment_id, type, source_url, reason, credential_id) "
    "VALUES (:deployment_id, :type, :source_url, :reason, :credential_id) "
    "ON CONFLICT DO NOTHING RETURNING id, seq, received_at"
)

# SQLSTATE classes and codes that mean "try again later": 08 connection, 40 transaction rollback
# (serialization, deadlock), 53 resources (too many connections), 57 operator intervention
# (statement_timeout 57014, shutdowns), and 55P03 lock_timeout while waiting for a writer.
_RETRYABLE_CLASSES = frozenset({"08", "40", "53", "57"})
_RETRYABLE_CODES = frozenset({"55P03"})


def classify_database_error(error: SQLAlchemyError) -> StoreUnavailable | InvariantFault:
    """Retryable or not, from the SQLSTATE alone; never the message, which is localized and may
    carry values. Anything not known to be a wait or an outage is a fault, including every
    constraint and trigger error: the validators and ON CONFLICT should make those unreachable.

    The result has no cause, no message and no context. The only thing logged for a fault is the
    SQLSTATE and the constraint name, a schema identifier that holds no row data."""
    orig = getattr(error, "orig", None)
    sqlstate: str | None = getattr(orig, "sqlstate", None)
    if sqlstate is None:
        # No server verdict: the connection or the pool failed before one existed.
        if isinstance(error, PoolTimeout | OperationalError | InterfaceError):
            return StoreUnavailable()
    elif sqlstate in _RETRYABLE_CODES or sqlstate[:2] in _RETRYABLE_CLASSES:
        return StoreUnavailable()
    constraint = getattr(getattr(orig, "diag", None), "constraint_name", None)
    _log.error(
        "deployment store invariant fault: sqlstate=%s constraint=%s",
        sqlstate if isinstance(sqlstate, str) else None,
        constraint if isinstance(constraint, str) else None,
    )
    return InvariantFault()


def _facts(rows: list[Row[Any]]) -> DeploymentFacts | None:
    """None when no deployment matched. A deployment with no events yields empty `events`, which
    `decide` refuses as corrupt; a type outside EventType raises ValueError, handled the same."""
    if not rows:
        return None
    return DeploymentFacts(
        version=rows[0].version,
        commit_sha=rows[0].commit_sha,
        events=tuple(
            StoredEvent(
                id=row.event_id,
                type=EventType(row.type),
                source_url=row.source_url,
                reason=row.reason,
            )
            for row in rows
            if row.event_id is not None
        ),
    )


class PostgresDeploymentStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def record(
        self, target: DeploymentTarget, event: NewEvent, credential_id: uuid.UUID
    ) -> Outcome:
        failure: InvariantFault | StoreUnavailable
        try:
            with self._engine.connect() as connection:
                try:
                    outcome = self._record(connection, target, event, credential_id)
                except BaseException:
                    connection.rollback()
                    raise
                # Commit only a written event. Every other outcome discards the transaction,
                # including a deployment created for an event that was then refused.
                if isinstance(outcome, Accepted):
                    connection.commit()
                else:
                    connection.rollback()
                return outcome
        except InvariantFault, StoreUnavailable:
            raise
        except SQLAlchemyError as error:
            failure = classify_database_error(error)
        except ValueError:
            # decide() on an impossible stored set, or a stored type that is not an event type.
            _log.error("deployment store invariant fault: stored state is impossible")
            failure = InvariantFault()
        # Raised outside the except blocks, so neither __cause__ nor __context__ holds the driver
        # error, whose statement and bound values must not travel onward.
        raise failure

    def _record(
        self,
        connection: Connection,
        target: DeploymentTarget,
        event: NewEvent,
        credential_id: uuid.UUID,
    ) -> Outcome:
        identity = {
            "service_id": target.service_id,
            "environment_id": target.environment_id,
            "deployment_key": target.deployment_key,
        }
        rows = list(connection.execute(_READ, identity))
        facts = _facts(rows)
        deployment_id: object = rows[0].deployment_id if rows else None
        created = False
        if facts is None and event.type is not EventType.REVERTED:
            inserted = connection.execute(
                _INSERT_DEPLOYMENT,
                {**identity, "version": event.version, "commit_sha": event.commit_sha},
            ).one_or_none()
            if inserted is not None:
                created, deployment_id = True, inserted.id
            else:
                # Lost the race for the identity. A new statement sees the committed winner.
                rows = list(connection.execute(_READ, identity))
                facts = _facts(rows)
                if facts is None:
                    raise InvariantFault  # A conflict with a row that cannot be read.
                deployment_id = rows[0].deployment_id

        # A deployment this transaction just created has no stored state to compare with.
        decision = decide(event, None if created else facts)
        if not isinstance(decision, Accept):
            return decision

        written = connection.execute(
            _INSERT_EVENT,
            {
                "deployment_id": deployment_id,
                "type": event.type.value,
                "source_url": event.source_url,
                "reason": event.reason,
                "credential_id": credential_id,
            },
        ).one_or_none()
        if written is not None:
            return Accepted(event_id=written.id, seq=written.seq, received_at=written.received_at)

        # A concurrent writer committed a conflicting event between our read and our insert.
        # Nothing could conflict with a deployment this transaction created.
        if created:
            raise InvariantFault
        facts = _facts(list(connection.execute(_READ, identity)))
        later = decide(event, facts)
        if isinstance(later, Accept):
            raise InvariantFault  # Nothing explains the conflict.
        return later
