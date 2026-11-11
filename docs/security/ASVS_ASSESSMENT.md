# ASVS 5.0 Assessment

Target: **Level 2** for chapters in scope. Baseline: requirement text read from the
`OWASP/ASVS` repository, `5.0/en/`, on 2026-11-01 (345 requirements in 17 chapters).

**Current status: scoping. Only a skeleton exists, and no requirement is "Pass" yet.** Status
moves to `Pass` only with linked evidence (test, config or scan output). The final assessment
is a Phase 6 deliverable.

Legend: `Planned` will be verified · `N/A` feature absent, by design · `Risk` accepted gap.

## Chapter applicability

| Chapter | Applies? | Note |
|---|---|---|
| V1 Encoding and Sanitization | Yes | SQL, HTML output, logs |
| V2 Validation and Business Logic | Yes | Spec rules, ordering, limits |
| V3 Web Frontend Security | Yes | Dashboard only |
| V4 API and Web Service | Yes | |
| V5 File Handling | No | No uploads or files |
| V6 Authentication | Yes | Machine tokens plus named dashboard accounts, so V6.2 applies |
| V7 Session Management | Yes | Dashboard sessions |
| V8 Authorization | Yes | Three scopes plus binding |
| V9 Self-contained Tokens | No | Opaque tokens; no JWT |
| V10 OAuth and OIDC | No | Deferred with ADR-0005 |
| V11 Cryptography | Partly | Digests and CSPRNG only; no app-level encryption |
| V12 Secure Communication | Yes | TLS terminates at the load balancer; database TLS in cloud |
| V13 Configuration | Yes | |
| V14 Data Protection | Yes | |
| V15 Secure Coding and Architecture | Yes | Dependencies, resource limits |
| V16 Logging and Error Handling | Yes | |
| V17 WebRTC | No | |

## Requirements in focus

| Req | Level | Topic | Plan | Status |
|---|---|---|---|---|
| 1.2.1 | L1 | Contextual output encoding | Jinja autoescape; hostile-text test | Planned |
| 1.2.4 | L1 | Parameterized queries | SQLAlchemy binds; Ruff `S608` | Planned |
| 1.3.6 | L2 | SSRF | No outbound fetch from input | N/A |
| 1.3.7 | L2 | Template injection | Templates are static files | Planned |
| 2.1.1–2.1.3 | L1–L2 | Documented validation and limits | PROJECT_SPEC §3, §5, §6 | Planned |
| 2.2.1–2.2.3 | L1–L2 | Server-side and combined validation | Pydantic, domain rules | Planned |
| 2.3.1 | L1 | Sequential flow | Status table; R9 | Planned |
| 2.3.3 | L2 | Transactions | One transaction per use case | Planned |
| 2.4.1 | L2 | Anti-automation | Rate limits | Planned |
| 3.3.1–3.3.4 | L1–L2 | Cookie attributes | `__Host-`, Secure, SameSite, HttpOnly | Planned |
| 3.4.1, 3.4.3–3.4.6 | L1–L2 | Security headers | HSTS, CSP, nosniff, Referrer-Policy, `frame-ancestors` | Planned |
| 3.5.1, 3.5.3 | L1 | CSRF and safe methods | Origin check; POST for changes | Planned |
| 4.1.1 | L1 | Correct Content-Type | Contract tests | Planned |
| 4.1.3 | L2 | Intermediary headers | Trusted-proxy config | Planned |
| 6.2.1–6.2.9 | L1–L2 | Password policy | Minimum 15, no composition rules, paste allowed, `type=password` | Planned |
| 6.2.12 | L2 | Breached-password check | No outbound lookup; CLI-issued passwords only | Risk |
| 6.3.1 | L1 | Brute-force controls | Failed-auth and sign-in limits | Planned |
| 6.3.2 | L1 | No default accounts | Bootstrap CLI generates the first credential | Planned |
| 6.3.3 | L2 | MFA for access | Not in the MVP; read-only UI | Risk |
| 6.3.4 | L2 | Documented auth pathways | Bearer and session only; both tested | Planned |
| 7.1.1, 7.3.1, 7.3.2 | L2 | Session timeouts | 30 min inactivity, 8 h absolute | Planned |
| 7.2.1–7.2.4 | L1 | Session token handling | Server-side, CSPRNG, new on login | Planned |
| 7.5.2 | L2 | View and end sessions | Disabling an account ends its sessions; no per-session UI | Risk |
| 8.1.1, 8.2.1, 8.2.2, 8.3.1 | L1 | Function and data authorization | Scope table; generated negative tests | Planned |
| 8.4.1 | L2 | Tenancy controls | Single tenant | N/A |
| 11.4.1, 11.4.3 | L1–L2 | Approved hashes | SHA-256 | Planned |
| 11.4.2 | L2 | Password storage | Argon2id for dashboard passwords; API tokens use SHA-256 because of their entropy (ADR-0005) | Planned |
| 12.1.1, 12.2.1, 12.2.2 | L1 | TLS at the edge | ALB policy, ACM | Planned (P7) |
| 13.2.2, 13.2.3 | L2 | Backend least privilege, no defaults | Separate database roles | Planned |
| 13.3.1, 13.3.2 | L2 | Secrets management | Secrets Manager | Planned (P7) |
| 13.4.1–13.4.5 | L1–L2 | Hardening | No `.git` in image; docs off in production; debug off | Planned |
| 14.2.1 | L1 | Secrets not in URLs | Bearer header; form POST | Planned |
| 14.3.2 | L2 | Anti-caching | `Cache-Control: no-store` on authenticated pages | Planned |
| 15.1.1, 15.2.1 | L1 | Dependency remediation timeframes | Critical 7 d, High 30 d, others next release | Planned |
| 15.1.2 | L2 | SBOM | Release attestation | Planned |
| 15.1.3, 15.2.2 | L2 | Resource-heavy functions | Bounded `window_days`, page size and timeouts | Planned |
| 15.3.1, 15.3.3 | L1–L2 | Field limits, mass assignment | Explicit schemas, `extra="forbid"` | Planned |
| 15.3.4 | L2 | Original client IP | Trusted-proxy config | Planned |
| 16.1.1, 16.2.1–16.2.5 | L2 | Log inventory and metadata | Runbook; structured UTC logs | Planned |
| 16.3.1–16.3.4 | L2 | Security events | Auth, authorization, credential lifecycle. S2 gap: issuance and revocation log nothing yet (THREAT_MODEL T30) | Planned |
| 16.4.1 | L2 | Log injection | JSON encoding | Planned |
| 16.5.1–16.5.3 | L2 | Safe errors, fail closed | Generic problem documents; deny when auth lookup fails | Planned |

## S2 evidence index (credential write model, ADR-0012)

Added at the P1 S2 closeout. It links existing evidence to the rows above and **does not change
any status**: every row stays `Planned`, because a row passes only in the final assessment (P6),
against its full requirement text, and several rows below depend on controls that are not built
yet. Evidence IDs are in [VERIFICATION_LOG.md](../engineering/VERIFICATION_LOG.md).

| Rows | What S2 evidence exists | What is still missing before `Pass` |
|---|---|---|
| 1.2.4 | Credential SQL uses bound parameters or fixed text; the guard is exercised by upserts and `MERGE` (V146, V156) | Ruff `S608` result recorded for the whole code base |
| 2.3.3 | One transaction per use case for issuance and revocation; usage write in its own best-effort transaction (V152, V156, V160) | Same evidence for ingestion (P1 S3) |
| 6.3.2 | Admin credentials come only from the bootstrap CLI; the API and the runtime role cannot issue them (V152, V146) | A recorded clean-install walk-through of the CLI |
| 8.1.1, 8.2.1, 8.2.2, 8.3.1 | Scope table and route-generated negative tests cover the credential routes; admin-only issuance, listing and revocation (V152, V156) | Binding enforcement on ingest routes (S3, AC7) |
| 11.4.1, 11.4.3 | Tokens stored only as SHA-256 digests; a scan of every column of every table finds no token (V152) | Final assessment |
| 13.2.2, 13.2.3 | Runtime role limited to seven insert columns and `UPDATE (revoked_at, last_used_at)`; exact privilege matrix and guard tests (V146, V160) | Accepted residual risk T28; Option B review before production; production role setup (P7) |
| 14.2.1, 14.3.2 | Token appears only in the `201` body, with `Cache-Control: no-store`; no token or digest in listings, errors or logs (V152, V156) | Sentinel test across all log output (AC10, P3) |
| 16.3.1–16.3.4 | None for credential lifecycle | Logging of issuance and revocation (T30); AC18 |
| 16.5.1–16.5.3 | Authentication lookup failure answers `503` rather than allowing access; a failed usage write never changes the response (V160) | Review of all routes at the final assessment |
| AC11 | Digest-only storage and revocation on the next request, with no cache (V156) | None known for S2 |

## S4 to S6 evidence index (ingestion, P1 security gate)

Added at the P1 security gate, after the S3 to S6 reviews (V257 to V265). Like the S2 index it
**changes no status**: every row stays `Planned`, because a row passes only in the final
assessment (P6), against its full requirement text. Where a control is not built, the row says so
and names the phase that builds it. It supersedes the S2 index only where it says "ingestion".

| Rows | What S4 to S6 evidence exists | What is still missing before `Pass` |
|---|---|---|
| 1.2.4 | The event store uses bound parameters and fixed statement text. A unit test checks its SQL for `UPDATE`, `DELETE`, `FOR UPDATE`, literals and a conflict target (V216, V219). Ruff `S` rules run in `verify.sh` (V247) | The Ruff `S608` result recorded for the whole code base |
| 2.1.1–2.1.3 | Field rules are documented (spec §3, §5) and enforced in the use case (V227, V228) | **No request body size limit (AC8, P3).** The documented 16 KiB limit does not exist |
| 2.2.1–2.2.3 | Server-side validation in `ingest_event` before the store: every problem at once, no coercion, no unknown field, no client timestamp (V228). Ingestion validates by hand and not with Pydantic, because the body is read after authentication (V245) | Final assessment; the plan wording "Pydantic" does not describe ingestion |
| 2.3.1, 2.3.3 | Status is derived from events. One store call is one transaction that commits only an accepted event and rolls back otherwise, including a deployment created for a refused first event (V216, V222). AC2: 50 concurrent identical submissions give one `201` and 49 `200` (V251). AC4: every valid order converges with R9 retried, and competing terminals follow the first committed (V252) | Final assessment |
| 2.4.1 | **None.** No rate limit exists (AC9, P3) | AC9 |
| 4.1.1 | Responses are `application/json` or `application/problem+json` (V243, V247) | Contract tests (P2) and the committed OpenAPI schema, which does not describe this route's request body (V260) |
| 8.1.1, 8.2.1, 8.2.2, 8.3.1 | Ingest scope only, then the principal's binding, then R11, before any store call; the target and credential id come from the principal (V227, V228, V235, V247, V251). Expired and revoked tokens, and a token revoked after use, on this route: V261 (tests written, awaiting the owner's run) | Final assessment |
| 13.2.2, 13.2.3 | Migration 0004 grants, the trigger functions' ownership, privileges and `search_path`, and the runtime role's lack of `CREATE`, `TEMP` and `TRIGGER` (V203, V221, V239) | Production role setup (P7); T32 |
| 15.3.1, 15.3.3 | Unknown fields are refused (`unknown_field`); the client supplies no timestamp (V228) | Body limit (AC8) |
| 15.1.3, 15.2.2 | Statement, lock and connect timeouts and a bounded pool exist (ARCHITECTURE §5) | **No body limit and no rate limit** (AC8, AC9) |
| 16.2.1–16.2.5, 16.3.1–16.3.4, 16.4.1 | `src` has five fixed-text log lines. Nothing logs a rejection, an authentication failure or a credential lifecycle action. Secret-sentinel checks exist at the application level; the engine hides bind parameters (V261) | **Structured logging and a real-process sentinel (AC10, AC18, P3);** T30 |
| 16.5.1–16.5.3 | Problem documents have fixed text and no value (V243). Store faults are sanitized and non-retryable, with no cause or context (V219) | Review of all routes at the final assessment |
| 6.3.1 | **None for ingestion.** Failed-authentication limits do not exist; any well-formed token costs a database lookup (T10) | AC9 |
