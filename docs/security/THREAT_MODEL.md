# ShipTrace — Threat Model

Status: **Design-time, revisited at the P1 S2 closeout**. The settings, database roles, health
endpoints, bearer authentication, credential storage, the registry, and credential issuance,
listing, revocation and usage tracking now exist (verification log V105 to V161). Most controls
below are still not implemented, and T28 to T31 were added for S2. "Verification" names the
evidence that must exist before a control may be claimed: where a row cites no evidence, the
control is not claimed. Revisit at every phase boundary.

Method: STRIDE over the trust boundaries below, scoped to a small internal tool.

## 1. What needs protecting

| Asset | Why it matters |
|---|---|
| Event-log integrity | The product's only value is trustworthy history; a forged success misleads people during an incident |
| Credentials and sessions | Grant write access or read access |
| Deployment metadata | Reveals service names, versions, commit SHAs and release cadence, which helps attackers target unpatched versions |
| Availability | Lower than integrity. An outage must not break customer pipelines (§5) |
| CI/CD and supply chain | A compromised build ships attacker code with valid provenance |

## 2. Attackers considered

- **A1 Internet attacker**, unauthenticated, reaching the public endpoint.
- **A2 Malicious or compromised workflow** holding a valid `ingest` credential. Most likely.
- **A3 Read-only insider** with a `read` credential.
- **A4 Supply-chain attacker** through a dependency, action or base image.
- **A5 AI agent error or prompt injection** during development.

Out of scope: a compromised AWS account, a malicious operator, and physical or hypervisor attacks.
A *stolen* admin token is in scope (T27).

## 3. Trust boundaries

```text
 Internet ─[B1]─ Load balancer/TLS ─[B2]─ App ─[B3]─ PostgreSQL
 GitHub runner ─[B1]                       └─[B4]─ Collector / log sink
 Dev machine + agent ─[B5]─ Repository ─[B6]─ CI ─[B7]─ Registry ─[B8]─ Runtime
```

## 4. Threats

| ID | Threat (STRIDE) | Actor | Mitigation | Verification | Residual |
|---|---|---|---|---|---|
| T1 | Forged events using a guessed token (S) | A1 | 256-bit CSPRNG tokens; constant lookup on digest | AC6 | Negligible |
| T2 | Stolen `ingest` token used outside its pipeline (S) | A2 | Mandatory service and environment binding, optional expiry, fast revocation, `credential_id` on each event, rotation overlap | AC7, AC11 | **Medium**: holder can forge events for its bound service until revoked. Short-lived OIDC would remove this; see ADR-0005 |
| T3 | Token leaked through logs, errors or traces (I) | A3 | Allowlist logging, no bind values in spans, sentinel test; `st1_` prefix so scanners can match | AC10 | Low |
| T4 | Database dump exposes usable tokens (I) | A3 | Digest-only storage; a 256-bit secret cannot be brute-forced offline | AC11 | Low |
| T5 | Replay of a captured request (S, R) | A1, A2 | TLS is the real control, since a captured request contains the bearer token. The idempotency key limits accidental and network replays: an identical accepted event is a no-op, permanently. A captured `reverted` rejected by R9 could still land if replayed after success | AC1, AC2 | Low |
| T6 | Tampering with or erasing history (T) | A2, A3 | No update API, restricted role, triggers, parameterized SQL | AC5 | Low; the owner role or a superuser can still disable triggers, so database access stays restricted |
| T7 | Cross-service write, or broken object-level authorization (E) | A2 | Binding check in the application layer; generated route tests | AC6, AC7 | Low |
| T8 | Repudiation: "we never reported that" (R) | A2 | Event stores credential; auth and lifecycle events logged | AC18 | Low; shared credentials identify a pipeline, not a person |
| T9 | Memory exhaustion by large or endless bodies (D) | A1 | Streaming body limit before parsing; Uvicorn has no body cap of its own | AC8 | Low |
| T10 | Flooding of authenticated or failed-auth requests (D) | A1, A2 | Per-credential and per-IP limits; concurrency limit; pool timeout sheds load | AC9 | **Medium**: limits are per process, and distributed floods need an edge control (ADR-0007) |
| T11 | Metric pollution by mass fake failures (T, D) | A2 | Binding limits blast radius; rate limit; credential attribution. Events are immutable, so clean-up is a known gap | Manual procedure | **Medium**: no event retraction in MVP; accepted |
| T12 | XSS through `reason`, `version` or `source_url` (T) | A2 | Jinja autoescape, `https`-only URLs, strict CSP, no inline script | AC14 | Low |
| T13 | SQL injection (T, I) | A1, A2 | SQLAlchemy bound parameters only; Ruff `S` rules | Lint, integration tests | Low |
| T14 | Session theft or fixation; CSRF on login/logout; password guessing (S) | A1 | API tokens cannot sign in. Argon2id, sign-in rate limit, server-side sessions, regenerated on login, `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict`, Origin check | AC24 | Low |
| T15 | Spoofed client IP evades limits (S) | A1 | Trust `X-Forwarded-For` only from configured proxy addresses | Integration test | Low |
| T16 | Information leak through errors or docs (I) | A1 | Generic errors with correlation ID; docs disabled in production; `404` for unknown routes | AC10, contract tests | Low |
| T17 | Log injection (T) | A2 | JSON encoding; client text never logged | AC10 | Low |
| T18 | SSRF (T) | A2 | The server fetches nothing from user input, and `source_url` is only displayed | Review | None by design |
| T19 | Database credential exposure (I, E) | A4 | Secrets Manager, least-privilege runtime role, no secrets in image or logs | Image scan, IAM review (P7) | Low for exposure; the runtime role has credential write grants since migration `0003`, so see T28 for what exposure now allows |
| T20 | Malicious dependency (T, E) | A4 | Hashed `uv.lock`, `pip-audit`, Dependabot review, SBOM, no install-time network in runtime image | CI gates | **Medium**: pinning freezes a bad version as faithfully as a good one |
| T21 | Compromised action or tag-moving attack (T) | A4 | `actions.lock` for transitive pins, minimal `permissions`, zizmor | AC21 | Low to medium; a lockfile pins, but does not vet |
| T22 | Unverified or swapped image in production (T) | A4 | Digest-only promotion, provenance and SBOM attestations verified before deploy | AC22 | Low |
| T23 | Agent reads secrets, pushes, or runs destructive commands (T, I, E) | A5 | Permission rules, hooks that block on their own errors, read-only reviewers. Text-matching guards are guardrails, not a boundary | Hook test suite | **Medium**, staying Medium after the sandbox patch: approved full runs still execute agent-edited code; see ADR-0010 |
| T24 | Prompt injection through fetched docs, dependencies or issues (T) | A5 | No auto-installed plugins, no MCP servers, review of third-party content, human gate on outward actions | Config check | Medium; inherent to agent use |
| T25 | Key squatting: a stolen token pre-posts `failed` for a predictable future `gha-<run_id>-<attempt>` key, so the real `succeeded` is refused forever (T, D) | A2 | Binding limits scope; `409` is logged and counted; the example surfaces it as a warning | AC23 | **Medium**: that deployment's history stays wrong; accepted |
| T26 | Rollback steering: forged `reverted` events walk "latest" back to an old, vulnerable version, and people redeploy it (T) | A2 | Mandatory environment binding, so a staging token cannot touch production; attribution; dashboard shows `reverted` with its reporter | AC7 | **Medium**: a production token can still do this until revoked |
| T27 | Stolen `admin` token (E) | A1, A3 | Tokens never enter a browser, because the dashboard has its own accounts; lifecycle events logged (**not yet: see T30**); recovery revokes the token *and* everything it issued (**not yet possible to enumerate: see T30**) | AC24, AC25 | Medium: full control until noticed |
| T28 | A compromised runtime database credential, or SQL injection in the runtime, abuses the credential write grants added by migration `0003` (E, T, D) | A1, A2 | ADR-0012 Option A: `INSERT` on seven columns and `UPDATE (revoked_at, last_used_at)` only; a guard trigger refuses admin issuance, any expiry but `NULL` or `now()` plus 1 to 365 whole days, a `revoked_at` or `last_used_at` other than exactly `now()`, and a backwards `last_used_at`; the role owns neither the table nor the function, so it cannot disable the guard; no `DELETE` or `TRUNCATE` | S2 integration tests (V152, V156, V160): exact privilege matrix, guard refusals, upserts and `MERGE` meeting the guard, every attempt to disable, drop or replace the guard refused, 0003 round trip. The guard's behavior under a superuser or the migrator is out of scope | **Medium**, accepted: the holder can still issue read and ingest credentials for any registered binding, revoke any credential (admin ones included, a denial of service the bootstrap CLI repairs), and mark credentials used now. It cannot issue admin credentials, change scope or binding, delete rows, or forward-date any timestamp; it can backdate only inside a transaction it holds open. Option B (`SECURITY DEFINER` functions) is the strengthening path and needs a new ADR before the first production deployment |
| T29 | Lock contention on a credential row delays or fails authenticated requests through the usage write (D) | A2, A3 | Fresh credentials cause no write: staleness is decided in the lookup by database time, and the write happens at most once per 5 minutes per credential. The usage write is a filtered `UPDATE` in its own transaction with `SET LOCAL lock_timeout = '100ms'`, best effort: a timeout, error or lost commit is rolled back and logged without detail, and authentication still succeeds. An unknown token never reaches the write | V160: boundary tests, a real row lock held past the timeout, a deterministic two-connection race, 8 parallel first uses, HTTP unchanged on failure, `lock_timeout` back to 0 on the pooled connection | Low. The extra delay is bounded by 100 ms plus a round trip, and only for a stale credential whose row is locked. Two gaps, below: the fixed 100 ms exceeds a configured `db_lock_timeout_ms` lower than 100 (the setting allows 1 ms and up), and a permanently failing usage write (for example a missing grant) logs one warning per stale request and alerts nothing |
| T30 | No attribution of credential issuance or revocation (R) | A1, A3 | None yet. ADR-0012 defers audit columns; application logs are the only planned source, and none exist for these actions | Not evidenced: `src` has one logger, which reports only a failed usage write. AC18 and AC25 are P3 | **Medium**: after a stolen admin token, the system cannot say which credentials it issued or revoked, so T27's "revoke everything it issued" cannot be carried out from the data. Fix before release: log an allowlisted line (action, acting credential id, target id) on issue and revoke, or add audit columns |
| T31 | An admin credential revoked after authentication but before its insert still issues one credential in that request (E) | A2 | Revocation is read on every request with no cache (AC11); the window is one request | V150: confirmed by reading, accepted. A re-check inside the issuing transaction would change the authentication model for every route | Low: bounded to the single in-flight request |

## 5. Failure-mode decision: reporting must not break deploys

If ShipTrace is down, a customer deployment must still proceed. The example workflow uses
bounded retries and `continue-on-error`, so an outage means a **gap in history, not a failed
deploy**. This trades completeness for availability of the system people care about more.

## 6. Accepted risks for MVP (provisional; reassess before release)

1. T2: stolen ingest tokens stay valid until noticed and revoked.
2. T10: per-process rate limiting only.
3. T11: no way to retract fraudulent events.
4. Dashboard accounts have no MFA (ASVS 6.3.3).
5. T25: a squatted deployment key permanently blocks the true result for that deployment.
6. T26: a production-bound token can forge rollbacks until revoked.
7. ADR-0011: `/readyz` cannot detect a rollback past a contract migration. No such migration exists,
   and none is allowed until the fix lands; older images stay exposed even then.
8. T23: the guards and sandbox are active, but an approved full run still executes agent-edited
   code outside the sandbox, and signatures cannot be verified inside it. `onFailure: block` on a
   hook timeout has never been triggered.
9. T28 (ADR-0012): the runtime role can issue read and ingest credentials for any registered
   binding, revoke any credential and mark credentials used. Reconsider Option B before the first
   production deployment.
10. T30: issuance and revocation are not attributable to an admin credential. Not acceptable for
    release without a log line or audit columns; recorded here so it is not forgotten.
