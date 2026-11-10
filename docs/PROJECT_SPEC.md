# ShipTrace — Project Specification (MVP)

Status: **Draft for review** · Owner: Zakaria Ait Ali · Last updated: 2026-11-01

ShipTrace records what was deployed, where, and whether it worked. CI/CD systems send
deployment events; people read history, the latest good version, and two basic delivery
metrics through an API and a small dashboard.

## 1. Users

| Actor | Authenticates with | Can do |
|---|---|---|
| CI/CD pipeline | `ingest` credential bound to exactly one service and one environment | Record events for that service only |
| Engineer (browser) | Named dashboard account and password, never an API token | View everything; change nothing |
| Script reading the API | `read` credential | View everything; change nothing |
| Operator | `admin` credential | Register services/environments; issue `read` and `ingest` credentials; list and revoke credentials |

Dashboard accounts are created by an operator through the CLI and have no roles. There is no
self-service registration and no organizations. See §9.

## 2. Domain vocabulary

- **Service**: a deployable thing, identified by a slug (`payments-api`).
- **Environment**: a global deployment target identified by a slug (`staging`, `production`).
  Any service may deploy to any registered environment.
- **Deployment**: one attempt to roll one version of one service into one environment.
  - `id`: server-assigned UUIDv7. Stable forever.
  - `deployment_key`: client-chosen, unique within (service, environment). For GitHub
    Actions: `gha-<run_id>-<run_attempt>`. A re-run is a new attempt, so a new deployment.
- **Event**: an immutable fact about a deployment, of a type below.

## 3. Event and state model

| Event type | Meaning |
|---|---|
| `started` | Rollout began |
| `succeeded` | Rollout finished and the pipeline considers it healthy |
| `failed` | Rollout did not complete successfully |
| `cancelled` | Rollout was deliberately stopped; says nothing about quality |
| `reverted` | A deployment that previously succeeded was later judged bad and undone |

**Deployment status** is a pure function of its stored events, never a stored column:

| Events present | Status |
|---|---|
| only `started` | `in_progress` |
| `succeeded` | `succeeded` |
| `failed` | `failed` |
| `cancelled` | `cancelled` |
| `succeeded` + `reverted` | `reverted` |

`started` never changes a terminal status, so `started` and a terminal event may arrive in
either order. `reverted` is the exception: it is rejected until `succeeded` is committed (R9),
so a client that sees `revert_requires_success` must retry. With that retry, the final status
is independent of arrival order.

### Ingestion rules

The natural idempotency key is **(service, environment, deployment_key, type)**.
A deployment holds at most one event of each type and at most one of
`succeeded | failed | cancelled` (the terminal slot). The database enforces both.

| # | Situation | Result |
|---|---|---|
| R1 | First event for a new deployment, any type except `reverted` | `201`; deployment created |
| R2 | New event type, compatible with existing events | `201` |
| R3 | Same type, identical content (duplicate or replay) | `200`, original event returned, `duplicate: true`, nothing written |
| R4 | Same type, different `reason` or `source_url` | `409 event_conflict` |
| R5 | `version` or `commit_sha` differs from the deployment's | `409 deployment_attribute_conflict` |
| R6 | Terminal event when a different terminal event exists | `409 terminal_conflict`; first committed wins |
| R7 | `started` after a terminal event (out of order) | `201`; status unchanged |
| R8 | Terminal event with no `started` (lost or late) | `201`; valid per R1/R2 |
| R9 | `reverted` when the deployment does not exist or has no terminal event yet | `409 revert_requires_success`; retryable; no deployment is created |
| R10 | `reverted` when the deployment is `failed` or `cancelled` | `409 revert_not_applicable`; not retryable |
| R11 | Service or environment differs from the credential's binding, whether or not it exists | `403`, identical in both cases; nothing written |

**Precedence.** When more than one row could apply, the first step below that applies decides:

1. R11, from the credential and the body's slugs alone, before anything is looked up.
2. The deployment does not exist: R9 for `reverted`, otherwise R1.
3. R5: a `version` or `commit_sha` that differs from the deployment's, even for a replay.
4. A `reverted` event is already stored: R3 or R4. Otherwise a new `reverted` is R9 when the
   deployment has no terminal event, R10 when its terminal event is `failed` or `cancelled`, and
   accepted when it is `succeeded`.
5. An event of the same type is already stored: R3 or R4.
6. A different terminal event is stored: R6.
7. Otherwise accepted: R2, with R7 and R8 as the cases that need no check.

Identical content (R3) means the same `reason` and `source_url`, where an absent value equals only
an absent value. `version` and `commit_sha` are compared under R5, not R3.

Every rejection rolls back its transaction, so a rejected event can never leave a deployment
row behind. Rejected events are logged and counted, not stored. The event log holds only
accepted facts.

### Timestamps

The server assigns `received_at`. **Clients cannot supply any timestamp.** All ordering and
windows use server values. This costs accuracy under delayed delivery (§7) and removes
clock-skew and backdating as attack surface.

### Latest successful deployment

For a (service, environment): the deployment with `succeeded` and no `reverted`, having the
highest `succeeded` event sequence number.

## 4. Metrics

Computed per environment, over a rolling window of `window_days` (1–90, default 30). Optional
service filter. The window is half-open, `[now - window_days, now)`. An outcome belongs to the
window containing its terminal event's `received_at`, wherever its `reverted` event falls.

- **Deployment frequency** = count of `succeeded` terminal events ÷ `window_days`.
  Later-reverted deployments still count: they were deployed.
- **Change failure rate** = (`failed` + later `reverted`) ÷ (`succeeded` + `failed`).
  `null`, not `0`, when the denominator is zero. Response also includes the raw counts.

**A failed change** in ShipTrace is a deployment whose rollout failed, or which succeeded and
was later reverted. `cancelled` and `in_progress` deployments are excluded from both sides.

## 5. API surface

All JSON under `/api/v1`; errors are `application/problem+json` (RFC 9457) with a stable
`code`. Lists use opaque cursor pagination with a maximum page size of 100.

| Method and path | Scope | Purpose |
|---|---|---|
| `POST /services`, `POST /environments` | admin | Register |
| `GET /services`, `GET /environments` | read, admin | List |
| `POST /deployment-events` | ingest | Record an event |
| `GET /deployments` | read, admin | History, newest first; filter by service, environment, and status (status requires both of the others) |
| `GET /deployments/{id}` | read, admin | One deployment with its events |
| `GET /services/{s}/environments/{e}/latest` | read, admin | Latest successful |
| `GET /metrics` | read, admin | Frequency and failure rate |
| `POST /credentials`, `GET /credentials`, `POST /credentials/{id}/revoke` | admin | Lifecycle; secret shown once at creation |

Unversioned: `GET /healthz` (process alive, no dependencies), `GET /readyz` (database
reachable, and schema not older than this build; a newer schema is ready, because expand/contract
keeps the previous release working), dashboard pages. `/docs` and `/openapi.json`
are disabled in production; the schema is committed at `docs/api/openapi.json`.

Event body (all fields are length- and pattern-validated; unknown fields rejected):

```json
{
  "service": "payments-api",
  "environment": "production",
  "deployment_key": "gha-12345678-1",
  "type": "succeeded",
  "version": "1.4.2",
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "source_url": "https://github.com/acme/payments/actions/runs/12345678",
  "reason": null
}
```

`service`, `environment`, `deployment_key`, `type`, `version` and `commit_sha` are required.
`source_url` and `reason` are optional. `reason` is rendered escaped and never logged;
`source_url` is display-only and ShipTrace never fetches it. Field rules are under Input formats.

### Input formats

Approved by the owner on 2026-11-08; the event fields on 2026-11-10. Values are matched exactly and
never normalized: an uppercase slug is rejected, not lowercased. Every value is ASCII except
`reason`.

| Field | Rule |
|---|---|
| Service and environment slug | 1–63 characters of `a-z`, `0-9` and `-`; starts and ends with a letter or digit; no `--` |
| Credential name | 1–64 characters of `A-Z`, `a-z`, `0-9`, space, `.`, `_` and `-`; starts and ends with a letter or digit; not unique |
| Page size `limit` | 1–100, default 50; the cursor is opaque |
| `deployment_key` | Required. `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; case-sensitive |
| `version` | Required. `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}` |
| `commit_sha` | Required. Exactly 40 or 64 lowercase hexadecimal characters |
| `source_url` | Optional. At most 2048 characters; the rules below |
| `reason` | Optional. 1–500 Unicode code points, counted after JSON parsing. LF and TAB are allowed. Other control characters (C0 and C1), NUL, lone surrogates and the bidirectional override and isolate characters U+202A–U+202E and U+2066–U+2069 are rejected |

Event fields are strings only: a number, boolean or other type is `422`, never coerced. An empty
string is `422` for every field. A required field that is omitted or `null` is `422`. An optional
field that is omitted or `null` is absent, and the two are the same.

`source_url` is display-only and is never fetched. It is checked in this order:

1. Every character is in the RFC 3986 set: `A-Z a-z 0-9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; = %`.
   So there is no whitespace, control character, non-ASCII character or backslash. An
   international host name must be Punycode (`xn--`), and other non-ASCII text percent-encoded.
2. It starts with lowercase `https://` and is split with `urllib.parse.urlsplit`; the checks
   below then run on the parts.
3. A host is required. A host made only of digits and dots must be accepted by
   `ipaddress.IPv4Address`, so `999.1.1.1` is rejected. Any other DNS name has labels of 1–63
   characters from `A-Za-z0-9-`, none starting or ending with a hyphen, at most 253 characters in
   all, and no trailing dot. An IPv6 literal is in brackets, is accepted by
   `ipaddress.IPv6Address`, and has no zone identifier.
4. There is no user information (`@` in the authority). A port is optional: 1–65535, digits only.
5. Every `%` is followed by two hexadecimal digits, and the escape is not a control octet
   (`%00`–`%1F`, `%7F`). Escapes are never decoded.
6. Path, query and fragment are kept exactly as sent: nothing is trimmed, decoded or reordered. A
   second `#` is rejected.

### Registry bodies

`POST /services` and `POST /environments` take `{"slug": "<slug>"}` and nothing else, and answer
`201` with `{"id": "<uuid>", "slug": "<slug>", "created_at": "<RFC 3339>"}`; the database assigns
`id` and `created_at`. The lists answer `200` with `{"items": [...], "next_cursor": "<opaque>"}`,
ordered by slug in byte order; `next_cursor` is `null` on the last page. A cursor is `422` unless
it is in the exact form the server issues and names a position in the list it is sent to, so a
services cursor is refused by `/environments`. Cursors are not signed: a client that builds one
can only start a list at a slug of its choosing, which reveals nothing more than the list itself.

### Credential issuance

Approved by the owner on 2026-11-08; enforced by the database (migration `0003`, ADR-0012).

- `POST /credentials` issues `read` and `ingest` credentials only. Admin credentials come only from
  the bootstrap CLI under the migrator role.
- `expires_in_days` is optional, an integer from 1 to 365. Omitted means no expiry.
- Expiry is counted in elapsed 24-hour days from the database's time at issuance, whatever the
  time zone or daylight-saving changes.

Issuance body, approved by the owner on 2026-11-10. `POST /credentials` takes these fields and
nothing else; an unknown field is `422`:

```json
{
  "name": "ci payments",
  "scope": "ingest",
  "service": "payments-api",
  "environment": "production",
  "expires_in_days": 90
}
```

- `name` follows the credential name rule; names are not unique.
- `scope` is `read` or `ingest`; any other value, `admin` included, is `422`.
- An `ingest` credential requires both `service` and `environment`, as slugs of registered
  entries; a `read` credential must not carry either. An unregistered slug is `422`
  `validation_failed` naming that field, never its value.
- `service`, `environment` and `expires_in_days` may be omitted or `null` where allowed.

It answers `201` with `Cache-Control: no-store` and `{"id", "name", "scope", "service",
"environment", "display_prefix", "created_at", "expires_at", "token"}`; an unbound or absent value
is `null`. The database assigns `id`, `created_at` and `expires_at`. `token` appears in this
response only: the service stores its SHA-256 digest and the metadata above, never the token.

### Credential listing and revocation

Approved by the owner with CP8 and implemented at `e03637c`; enforced by the same database guard
(migration `0003`, ADR-0012). Both routes are admin only.

Credential object, used by both routes. It holds metadata only: never a token, a digest or any
part of a token beyond the public `display_prefix`:

```json
{
  "id": "<uuid>",
  "name": "ci payments",
  "scope": "ingest",
  "service": "payments-api",
  "environment": "production",
  "display_prefix": "st1_AbCd",
  "created_at": "<RFC 3339>",
  "expires_at": "<RFC 3339 or null>",
  "revoked_at": "<RFC 3339 or null>",
  "last_used_at": "<RFC 3339 or null>"
}
```

- `GET /credentials` takes `limit` and `cursor` (see Input formats) and nothing else. It answers
  `200` with `{"items": [<credential>, ...], "next_cursor": "<opaque>"}`, ordered by `id`
  ascending (UUIDv7, so oldest first, and unique, so a walk never repeats or skips a row);
  `next_cursor` is `null` on the last page. Revoked and expired credentials are listed, since the
  list is the operator's audit view. A cursor is `422` unless it is in the exact form the server
  issues and names a position in this list.
- `POST /credentials/{id}/revoke` takes no body; a non-empty one is `422` `validation_failed`
  (location `body`, rule `body_not_allowed`, never its content) and nothing is revoked. It sets `revoked_at` to the
  database's time and answers `200` with the credential object. Revoking an already revoked
  credential also answers `200` with the object as stored: `revoked_at` keeps its first value and
  the row is not written again. An `id` that names no credential is `404` `not_found`; an `id`
  that is not a UUID is `422` `validation_failed`. Any scope may be revoked, an admin's own
  included, and so may an expired credential. Clients never supply a timestamp.
- Revocation takes effect on the next authenticated request (AC11): authentication reads the
  stored `revoked_at` on every request, with no cache.

### Errors

Every error is `application/problem+json` with `type` `urn:shiptrace:problem:<code>`, `title`,
`status`, `detail` and `code`. `title` and `detail` are fixed per code. No response contains a
credential, a request value, an internal exception or a stack trace. Mandatory headers stay, such
as `WWW-Authenticate` on `401` and `Retry-After` on `503`.

| Code | Status | When |
|---|---|---|
| `unauthenticated` | 401 | Credential missing, malformed, unknown, revoked or expired |
| `forbidden` | 403 | Valid credential without the required scope |
| `not_found` | 404 | Unknown route or resource |
| `method_not_allowed` | 405 | Known route, other method |
| `already_exists` | 409 | A service or environment with that slug is already registered |
| `validation_failed` | 422 | Body, query or cursor invalid; adds `errors` with location and rule, never values |
| `internal_error` | 500 | Unexpected failure |
| `unavailable` | 503 | Database unreachable or pool exhausted |

Ingestion adds the codes of §3.

## 6. Non-functional limits (defaults, all configurable)

| Limit | Value |
|---|---|
| Request body | 16 KiB |
| Ingest rate, per credential | 60/min, burst 20 |
| Read rate, per credential | 300/min |
| Failed authentication, per client IP | 30/min |
| Database statement / lock / connect timeout | 5 s / 2 s / 3 s |
| Pool per process | 5 + 5 overflow, 3 s wait, then `503` with `Retry-After` |
| Graceful shutdown budget | 20 s, inside a 30 s kill window |
| Dashboard session | 8 h absolute, 30 min inactivity |
| Target latency at MVP scale (local, 100k events) | ingest p95 < 100 ms; latest p95 < 100 ms |

## 7. Known limitations of derived data

Documented here and repeated in the API docs, because numbers without caveats mislead.

1. **ShipTrace knows what pipelines report.** A deployment that bypasses CI is invisible.
2. **Change failure rate is a proxy**, not DORA's metric. It has no incident data, so a bad
   change that nobody reverts counts as a success, and a failed rollout that never served
   traffic counts as a failure. Raw counts are exposed so readers can recompute.
3. **Rates are retroactive.** A `reverted` event changes the failure rate of the window that
   holds the original success, so past values can change.
4. **Delayed delivery misorders.** Time means received time. If report A arrives after report
   B though A finished first, A appears latest. "Latest successful" means *latest reported*,
   not *what is running now*.
5. **Lost terminal events** leave a deployment `in_progress` forever. They count in neither
   metric. There is no timeout.
6. **Small samples.** Three deployments and one failure is 33%. Consumers should read counts.
7. **Re-runs are separate attempts**, so a flaky pipeline raises the failure rate.
8. **Frequency is not "changes shipped"**: one deployment may hold many commits.

## 8. Acceptance criteria

Each criterion is met only by an automated test or recorded procedure that can fail.

**Ingestion**
- AC1 Every row of the §3 rules table has an integration test against real PostgreSQL.
- AC2 50 concurrent identical submissions produce exactly one event and one `201`, the rest `200`
  (run with rate limits raised, so the test measures idempotency).
- AC3 Concurrent `succeeded` and `failed` for one deployment produce exactly one terminal event.
- AC4 Property test: any permutation of a valid event set, with R9 rejections retried until
  accepted, gives the same final status and never leaves a deployment without events.
- AC5 The application database role cannot `UPDATE`, `DELETE` or `TRUNCATE` events, and a
  trigger rejects those operations for the owner role too.

**Security**
- AC6 Missing, malformed, expired, revoked and wrong-scope credentials are each rejected, on
  every protected route, by a test generated from the route table so new routes are covered.
- AC7 An `ingest` credential cannot write to another service or environment, and the response
  does not reveal whether that target exists.
- AC8 Oversized bodies get `413` without the body being buffered in full, with and without `Content-Length`.
- AC9 Rate limits return `429` with `Retry-After`.
- AC10 A secret-sentinel test proves tokens, `Authorization` and `reason` reach no log line or error body.
- AC11 Credential secrets are stored only as SHA-256 digests; revocation takes effect on the next request.

**Read side**
- AC12 Latest-successful ignores failed, cancelled and reverted deployments, tested with concurrent histories.
- AC13 Metrics match a hand-computed fixture, including empty window (`null`) and window boundaries.
- AC14 The dashboard shows services, environments, history, latest and metrics; it requires a
  session, emits a strict CSP, and renders hostile `reason` text inert.
- AC24 Sessions: API tokens cannot sign in and session cookies cannot call the JSON API; passwords
  are stored only as Argon2id hashes; disabled accounts cannot sign in; the token changes on login; cookie flags
  are present; POST without a matching Origin is refused; inactivity and absolute timeouts work;
  logout ends the session server-side.

**Operations**
- AC15 Migrations pass upgrade from empty, downgrade round trip and model drift checks.
- AC16 `/readyz` goes `503` when PostgreSQL stops or the schema is older than the build, stays
  `200` for a newer schema, and recovers without restart; `/healthz` stays `200`, even with the
  threadpool exhausted. Revision files are never pruned, because an unknown revision means newer.
- AC17 On `SIGTERM`, an in-flight request completes and the process exits within budget.
- AC18 Logs are one JSON object per line carrying a correlation ID that matches the response header and trace.
- AC19 Backup and restore is run for real, with row counts and event-log integrity verified.
- AC25 Runbooks cover credential rotation with overlap, recovery from a lost admin credential,
  dashboard account lifecycle and troubleshooting; rotation and the database-down steps are executed as written.

**Delivery**
- AC20 The container runs as non-root and passes smoke tests against Compose PostgreSQL.
- AC21 CI runs all gates with minimal permissions and locked actions; a deliberately broken
  change fails it.
- AC22 A release produces an image digest, SBOM and provenance that verify with `gh attestation verify`.
- AC23 The example workflow passes actionlint, and its reporting script records a real deployment
  against a running local instance. A run from a hosted GitHub runner needs a reachable deployment,
  so that evidence waits until one exists. A rejected report (`409`) surfaces as a visible warning.

## 9. Out of scope

Advanced RBAC, self-service accounts, SSO, MFA, organizations and tenancy; notifications and webhooks;
integrations beyond GitHub Actions; lead time and restore-time metrics; incident correlation;
service or environment deletion and renaming; event editing; retention and pruning; charts
beyond simple tables and counts; multi-region. Any of these requires a spec change first.
