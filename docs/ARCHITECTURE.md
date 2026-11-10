# ShipTrace — Architecture

Status: **Draft for review**. Requirements live in [PROJECT_SPEC.md](PROJECT_SPEC.md);
decisions and rejected alternatives live in [adr/](adr/README.md).

## 1. System view

```text
 GitHub Actions ──HTTPS + ingest credential──┐
 Engineers (browser) ──HTTPS + session───────┤
 Operators / scripts ──HTTPS + admin cred.───┤
                                             ▼
                              ┌─────────────────────────┐
                              │  ShipTrace (one process │      OTLP (traces, metrics)
                              │  per container)         ├────► collector (optional)
                              │  FastAPI on Uvicorn     │
                              │  JSON logs to stdout    ├────► platform log sink
                              └───────────┬─────────────┘
                                          │ bounded pool, TLS in cloud
                                          ▼
                              ┌─────────────────────────┐
                              │ PostgreSQL 18           │
                              │ append-only event log   │
                              └─────────────────────────┘
```

One deployable, one database. Horizontal scale means more containers, not more processes per
container. No queue, cache or background worker: ingest is a single short transaction.

## 2. Layers and dependency rules

```text
api ─────────► application ─────► domain
persistence ─► application ─────► domain   (implements ports)
bootstrap wires everything, including logging and telemetry setup
```

| Layer | Holds | Must not import |
|---|---|---|
| `domain` | Event types, status derivation, ingestion decisions, metric formulas. Pure and clock-free. | Everything except stdlib |
| `application` | Use cases, transaction boundaries, ports (`typing.Protocol`), scope checks | FastAPI, SQLAlchemy, `api`, `persistence` |
| `persistence` | SQLAlchemy models, repositories, session handling | `api`, FastAPI |
| `api` | Routers, Pydantic schemas, auth dependency, middleware, dashboard, error mapping | `persistence` |
| `bootstrap` | Settings, app factory, lifespan, CLI | Is imported only by entry points |

Enforced by `import-linter` contracts in `scripts/verify.sh`, and in CI from P5, so a violation
fails the build. The pre-commit hook does not run them: import-linter imports modules from its
working directory, and a commit runs outside the sandbox (V66). Ports exist only
where they pay for themselves: fast unit tests of use cases without a database.

## 3. Data model

```text
services(id, slug UNIQUE, created_at)
environments(id, slug UNIQUE, created_at)

deployments(                                   -- immutable identity row
  id uuid PK DEFAULT uuidv7(),
  service_id FK RESTRICT, environment_id FK RESTRICT,
  deployment_key, version, commit_sha,
  created_at DEFAULT now(),
  UNIQUE (service_id, environment_id, deployment_key))

deployment_events(                             -- append-only
  seq bigint GENERATED ALWAYS AS IDENTITY PK,
  id uuid UNIQUE DEFAULT uuidv7(),
  deployment_id FK RESTRICT,
  type CHECK (type IN (...)),
  source_url, reason,
  credential_id FK RESTRICT,                   -- who reported it
  received_at timestamptz DEFAULT now(),
  UNIQUE (deployment_id, type))
UNIQUE (deployment_id) WHERE type IN ('succeeded','failed','cancelled')   -- terminal slot

api_credentials(id, name, scope, service_id NULL, environment_id NULL,   -- both set iff ingest
  secret_sha256 UNIQUE, display_prefix, expires_at, revoked_at, last_used_at, created_at,
  CHECK scope/binding consistency)

dashboard_users(id, username UNIQUE, password_hash, disabled_at, created_at)

dashboard_sessions(id, token_sha256 UNIQUE, user_id FK,
  created_at, last_seen_at, expires_at, revoked_at)
```

Indexes follow the read paths: `deployments (service_id, environment_id, id DESC)`,
`(environment_id, id DESC)` and `(service_id, id DESC)` for history, and `deployment_events
(received_at)` for metrics. "Latest" joins a pair's deployments to their `succeeded` events,
which the unique index on `(deployment_id, type)` serves. Copying service and environment onto
events would be faster, and is held back until P2 measurements show the need. History pages by `id` (UUIDv7, time-ordered) as a keyset cursor.
A report committed late may be missed while paging; a reload shows it.

### Runtime role grants

| Table | `shiptrace_app` may |
|---|---|
| `deployments`, `deployment_events` | `SELECT, INSERT` |
| `services`, `environments` | `SELECT`, and `INSERT (slug)` only, so ids and timestamps come from the database (migration `0002`) |
| `api_credentials` | `SELECT`; `INSERT` of the issuing columns only (not `id`, `created_at`, `revoked_at`, `last_used_at`); `UPDATE (revoked_at, last_used_at)` only. A guard trigger refuses admin scope and any timestamp other than database time (migration `0003`, ADR-0012). Admin credentials come from the bootstrap CLI under the migrator role |
| `dashboard_users` | `SELECT` only: accounts are managed by the CLI under the migrator role |
| `dashboard_sessions` | `SELECT, INSERT`; `UPDATE (last_seen_at, revoked_at)` only |
| `alembic_version` | `SELECT` |

No `DELETE` anywhere. Roles and passwords are created outside Alembic by an environment
bootstrap step, because `CREATE ROLE` needs privileges the migrator should not hold and RDS differs
from local PostgreSQL. Migrations only grant to roles that already exist.

### Append-only, in two independent layers

1. **Privilege**: the runtime role `shiptrace_app` has only `SELECT, INSERT` on `deployments`
   and `deployment_events`. The owner role `shiptrace_migrator` is used only by migrations.
2. **Trigger**: `BEFORE UPDATE OR DELETE` row triggers and a `BEFORE TRUNCATE` statement
   trigger raise an exception, which also stops an owner-role mistake.

### Why status is derived, not stored

A stored status needs mutation, and that re-creates ordering races the event log just
removed. Reads aggregate a few rows per deployment over indexed columns. If the p95 target in
the spec is missed with measured data, a rebuildable projection is the fallback, not the start.

## 4. Key flows

**Ingest** (`POST /deployment-events`), in one `READ COMMITTED` transaction:

1. Middleware assigns the correlation ID and enforces the body limit.
2. Check the per-IP failed-auth limit, then hash the bearer token and look up an active
   credential. Check scope; apply the credential's rate limit.
3. Validate the body. Compare its service and environment slugs to the credential's binding
   *before* resolving them, so the response cannot reveal whether a target exists (R11).
4. For `reverted`: read the deployment; if absent, reject (R9). Never create one. For other types:
   `INSERT ... ON CONFLICT DO NOTHING` the deployment, then read it in a separate statement.
5. Compare immutable attributes (R5); check the `reverted` preconditions (R9, R10).
6. `INSERT ... ON CONFLICT DO NOTHING` the event, with **no conflict target**, so that both unique
   indexes act as arbiters. Naming one would turn the other into a `unique_violation`.
7. If no row was inserted, read the events in a **separate statement**, which takes a new snapshot
   and so sees the winner, and classify as duplicate or conflict.

Every rejection rolls back. If the wait for a concurrent writer exceeds `lock_timeout`, the
response is a retryable `503` with `Retry-After`.

**Concurrency uses constraints, not locks.** `ON CONFLICT` makes a second writer wait for the
first to commit, so the two unique indexes decide every race. `SELECT ... FOR UPDATE` was
rejected because PostgreSQL requires `UPDATE` privilege for it, and the runtime role must not
have that privilege on these tables. R9 is safe without a lock: `reverted` is accepted only
after `succeeded` is visible, and committed events never change.

**Shutdown.** ECS deregisters a task from the load balancer (`DEACTIVATING`) *before* sending
`SIGTERM` (`STOPPING`), then sends `SIGKILL` after `stopTimeout` (default 30 s, maximum 120 s).
Uvicorn runs with `--timeout-graceful-shutdown 20`, because its default of `None` waits
indefinitely. The FastAPI lifespan shutdown then disposes the pool and flushes telemetry, capped at 3 s so an
unreachable collector cannot reach the kill window. Compose sets `stop_grace_period: 30s`, since
its default is 10 s.

## 5. Reliability settings

- Sync SQLAlchemy `QueuePool`: size 5, overflow 5, timeout 3 s, `pool_pre_ping`, 30-minute
  recycle. Connections set `statement_timeout`, `lock_timeout` and
  `idle_in_transaction_session_timeout`.
- Exhausted pool returns `503` with `Retry-After`. That is deliberate load shedding, since
  FastAPI's threadpool (40) is larger than the pool.
- Capacity rule: `maximum tasks during a rollout × 10 + 2` must stay below `max_connections`.
- Migrations run as a separate one-shot step before rollout, never at app startup, where
  several tasks would race. Schema changes follow expand/contract so the previous version keeps
  working during a rolling deploy. Rollback past a contract migration is not supported: see
  ADR-0011.
- `/healthz` never touches dependencies; restarting the app does not repair a database.

## 6. Security architecture

Full analysis: [security/THREAT_MODEL.md](security/THREAT_MODEL.md) and
[security/ASVS_ASSESSMENT.md](security/ASVS_ASSESSMENT.md).

- Credentials: 256-bit random opaque tokens prefixed `st1_`; only the SHA-256 digest is stored.
- Authorization: deny by default, in an application-layer use-case check, not only in routing.
- Dashboard: named accounts separate from API tokens, Argon2id, server-side sessions, `__Host-` cookie, `SameSite=Strict`, Origin check on POST,
  strict CSP with no inline script.
- Client IP comes from `X-Forwarded-For` only when the peer is a configured trusted proxy.
- `/readyz` reveals status only, and caches its result for 1 s so unauthenticated calls cannot
  drive database load.

## 7. Observability

| Signal | Mechanism | Rule |
|---|---|---|
| Logs | structlog JSON on stdout | Allowlisted fields only; includes `correlation_id`, `trace_id`, `credential_id` |
| Traces | OpenTelemetry SDK, OTLP/HTTP | FastAPI and SQLAlchemy instrumentation; no bind values in spans |
| Metrics | OpenTelemetry SDK, OTLP/HTTP | Labels limited to route template, method, status class, event type, outcome |
| Health | `/healthz`, `/readyz` | No detail in responses |

Service and environment slugs are not metric labels: they are registered data, and their
cardinality is not ours to bound. Those questions go to the API or logs. Telemetry is optional
and failure-isolated: an unreachable collector must never affect a request.

## 8. Repository layout

```text
shiptrace/
├── CLAUDE.md                     Agent instructions
├── README.md
├── pyproject.toml, uv.lock       Dependencies, tool config, import contracts (P0)
├── compose.yaml                  PostgreSQL (P0), full stack (P4)
├── Dockerfile                    (P4)
├── deploy/postgres/              Role bootstrap, run once by a superuser (P0)
├── src/shiptrace/
│   ├── domain/                   Pure rules
│   ├── application/              Use cases and ports
│   ├── persistence/              SQLAlchemy, repositories, migrations/ (shipped with the package,
│   │                             because /readyz needs the revision list at runtime)
│   ├── api/                      Routers, schemas, middleware, dashboard/
│   └── bootstrap/                Settings, app factory, logging/telemetry setup, CLI
├── tests/
│   ├── unit/                     No I/O
│   ├── integration/              Testcontainers PostgreSQL
│   ├── contract/                 OpenAPI drift and schema-driven API checks
│   ├── migration/                Upgrade, downgrade, drift
│   └── smoke/                    Built container against Compose
├── scripts/                      verify.sh, smoke.sh, git hooks and repository checks
├── examples/github-actions/      CI integration example (P3)
├── infra/terraform/              Plan only, after approval (P7)
├── docs/                         Spec, architecture, ADRs, security, runbooks/, api/
├── .github/                      Workflows, actions.lock (P5)
└── .claude/                      Settings, hooks, rules, skills, reviewer agents
```

Directories appear only in the phase that fills them.

## 9. Cloud target (planned, nothing provisioned)

ALB with ACM TLS → ECS Fargate tasks in private subnets → RDS PostgreSQL 18, with ECR, Secrets
Manager, CloudWatch and GitHub Actions OIDC. Full design, sizing and verified cost estimates
are Phase 7 deliverables and need approval first.

Known input from research: Fargate `stopTimeout` defaults to 30 s and caps at 120 s; RDS lists
PostgreSQL 18.6 as generally available. Open question for that phase: which health path the
ALB uses. `/readyz` gates traffic well during rollout, but during a database outage it could
mark every task unhealthy and make ECS replace them, with no benefit.
