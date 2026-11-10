# ADR-0012: Credential write model

Status: Accepted by the owner on 2026-11-10 · Date: 2026-11-08

**Context.** S2 issues read and ingest credentials over HTTP, revokes credentials and records
`last_used_at` (ADR-0005). Until now the runtime role `shiptrace_app` could only `SELECT` from
`api_credentials`; admin credentials come from the bootstrap CLI under `shiptrace_migrator`. The
runtime role must gain some write access, without letting it mint admin credentials, change what a
credential may do, or set timestamps of its choosing.

**Options.**

| Option | What the runtime role gets | Assessment |
|---|---|---|
| A. Column grants plus a guard trigger | `INSERT` on the issuing columns, `UPDATE (revoked_at, last_used_at)`; a `BEFORE INSERT OR UPDATE` trigger checks values | **Chosen.** Plain SQL from the application, rules enforced in the database for every role but the migrator |
| B. `SECURITY DEFINER` functions | `EXECUTE` on `issue_credential`, `revoke_credential`, `touch_credential`; no table writes | Narrower surface, but more PL/pgSQL with owner rights, where a mistake (search path, argument checks) grants the owner's power. Kept as a strengthening path |
| C. Plain table grants, rules only in application code | `INSERT, UPDATE` on the table | Rejected: one SQL injection or a stolen runtime password mints admin credentials |

**Decision (Option A, migration `0003`).**

1. `GRANT INSERT (name, scope, service_id, environment_id, secret_sha256, display_prefix,
   expires_at)`. `id` and `created_at` always take their defaults.
2. `GRANT UPDATE (revoked_at, last_used_at)` only. Scope, binding, name, digest, prefix and expiry
   are never updatable by the runtime role. No `DELETE` or `TRUNCATE`.
3. The trigger `api_credentials_guard`, for every role except `shiptrace_migrator`:
   - refuses `scope = 'admin'` on insert (SQLSTATE 42501);
   - accepts `expires_at` only as `NULL` or `now()` plus 1 to 365 whole days of 24 hours, measured
     in absolute seconds so a daylight-saving change cannot alter the length (23514). The API
     therefore computes it in SQL as `now() + make_interval(hours => 24 * d)`;
   - lets `revoked_at` change only from `NULL` to exactly `now()`, once (23514);
   - lets `last_used_at` change only to exactly `now()`, never to `NULL` or backwards (23514).
4. The function runs with the caller's rights, not `SECURITY DEFINER`, and pins `search_path` to
   `pg_catalog, pg_temp`, so an object the caller creates is never consulted. The runtime role
   owns neither the table nor the function, so it cannot disable, drop or replace either.
5. The migrator is exempt, because it owns the table, runs the bootstrap CLI, and needs to create
   fixtures such as already-expired credentials in tests.

**Consequences.**

- `now()` is the transaction start time. The application must issue, revoke and touch in a
  transaction that starts when the request is served, which is already the rule (one transaction
  per use case).
- Revoke and touch must be filtered updates, so a lost race updates no row instead of failing:
  `SET revoked_at = now() WHERE id = :id AND revoked_at IS NULL`, and
  `SET last_used_at = now() WHERE id = :id AND (last_used_at IS NULL OR last_used_at < now() -
  interval '5 minutes')`, which is also ADR-0005's throttle. Under READ COMMITTED the filter is
  re-checked against the row a concurrent writer committed. An unfiltered write that loses the
  race is refused by the guard (23514) and would fail the whole request. CP8 and CP9 test this with
  two connections.
- Revocation is idempotent at the API: revoking an already revoked credential succeeds without an
  update.
- The migration is expand-only: the S1 build never writes these columns and keeps working.

**Residual risk.** A compromised runtime database credential (or SQL injection in the runtime) can
still issue read and ingest credentials for any service and environment, revoke any credential,
including admin ones, and mark credentials as used now. It cannot issue admin credentials, change
scope or binding, delete rows, or forward-date any timestamp. It can backdate only within the
transaction it holds open: `now()` is that transaction's start, so a session that waits before
revoking or touching records the earlier time. `idle_in_transaction_session_timeout` is set by the
client and so does not bound this. The effect is limited to audit accuracy: a revocation counts
whatever its time, `last_used_at` still never moves back, and an earlier `now()` only shortens an
expiry. Revoking every admin credential is a denial of service that the bootstrap CLI repairs.

**Not decided here.**

- Audit columns (who issued or revoked a credential) are deferred. Until they exist, the database
  cannot attribute an issuance or a revocation to an admin credential; only application logs can.
- Before the first production deployment, reconsider Option B: moving the three writes into
  `SECURITY DEFINER` functions with fixed arguments would remove the runtime role's table writes
  entirely. That needs a new ADR superseding this one.
