# ADR-0005: Opaque scoped tokens stored as SHA-256 digests; OIDC deferred

Status: Accepted by the owner on 2026-11-08, for P1 S1. The runtime credential-write model
(issuance, revocation and `last_used_at` by the runtime role) is reviewed separately before S2;
until then the runtime role may only read `api_credentials` · Date: 2026-11-01

**Context.** Ingestion needs authenticated, scoped machine credentials with rotation and
revocation. Human sign-in is separate (ADR-0006).

**Decision.**
- Tokens: `st1_` + 256 bits from `secrets`, shown once. Stored as SHA-256; looked up by digest.
- One scope per credential: `ingest` (bound to exactly one service and one environment), `read`,
  or `admin`. Binding is checked in the application layer. Mandatory environment binding is
  simpler than optional binding, and it stops a staging token forging production history (T26).
- Rotation is overlap: issue a new credential, update the pipeline, revoke the old one.
- The first admin credential comes from a bootstrap CLI, so no default credential exists. The same
  CLI is the recovery path for a lost admin credential.

**Why SHA-256 rather than Argon2.** Slow hashing defends low-entropy human passwords. A 256-bit
random secret cannot be guessed offline, and a slow KDF on every API call would become a CPU
denial-of-service target. Lookup by digest also avoids comparing secrets in application code.

**Rejected.**
- *JWTs*: revocation needs server state anyway, and they add algorithm and key-management risk.
- *HMAC with a server-side pepper*: little gain at this entropy and one more secret to rotate.
- *Argon2*: see above.

**Deferred, and the strongest alternative: GitHub Actions OIDC.** Pipelines could present a
short-lived, signed token with no stored secret. That removes stored-secret theft from T2, though
a compromised workflow could still mint tokens. It adds JWKS
fetching, claim-to-service mapping and an outbound dependency, so it is a candidate immediately
after MVP. The credential check sits behind one application port so this can be added.

**Consequences.** Long-lived secrets exist in GitHub, mitigated by binding, expiry and
revocation. `last_used_at` writes are throttled to once per 5 minutes per credential.
