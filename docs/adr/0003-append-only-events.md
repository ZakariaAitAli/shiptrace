# ADR-0003: Append-only events, natural idempotency key, server time only

Status: Proposed · Date: 2026-11-01

**Context.** CI retries requests, networks reorder them, and history must be trustworthy.

**Decision.**
1. `deployments` and `deployment_events` are insert-only, enforced by role privileges *and*
   triggers.
2. The idempotency key is natural: (service, environment, deployment_key, event type). A
   deployment holds at most one event per type and one terminal event, enforced by unique
   indexes.
3. `received_at` is server-assigned. The API has no client timestamp field.
4. Conflicts are resolved by constraints and target-less `ON CONFLICT DO NOTHING`; first commit
   wins. Every rejection rolls back, and a rejected `reverted` never creates a deployment.
5. Rejected events are logged and counted, not stored.

**Why.** Because each type occurs once, the key already exists in the data: clients need no
extra ID to generate and persist across retries. Replays stay no-ops forever since nothing is
pruned, so no time window is needed. Removing client timestamps removes skew and backdating.

**Rejected.**
- *Client-generated event UUID*: a client bug minting a new ID on retry would create
  duplicates; here that is impossible.
- *`Idempotency-Key` header with TTL*: extra storage and an expiry after which replays succeed.
- *`SELECT ... FOR UPDATE`*: requires `UPDATE` privilege, which the runtime role must not have.
  Advisory locks work but are unnecessary, since the indexes decide every race.
- *Storing rejected events*: a compromised credential could fill the log with junk.
- *Client timestamps for ordering*: better fidelity, but trusts unauthenticated clocks.

**Consequences.** New event types with repeat semantics (such as `progress`) would need a new
key design. Delayed delivery misorders "latest" (spec §7). Fraudulent events cannot be
retracted in the MVP (threat T11).
