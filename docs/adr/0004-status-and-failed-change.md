# ADR-0004: Derived status and the definition of a failed change

Status: Proposed · Date: 2026-11-01

**Context.** The brief requires a definition of failed change and honest metric limits.

**Decision.**
- Status is computed from events at read time; nothing stores it.
- `reverted` is valid only after a committed `succeeded`.
- A **failed change** is a `failed` rollout, or a `succeeded` deployment later `reverted`.
- `cancelled` and `in_progress` are excluded from rates.
- Change failure rate is `null` when its denominator is zero, and raw counts are always returned.

**Why.** A stored status field would be mutable state derived from an immutable log, inviting
the races the log removes. Counting failed rollouts is broader than DORA, which measures
production impact, but ShipTrace has no incident data and cannot see impact. Exposing the counts
keeps the choice transparent. `null` stops "no data" being read as "no failures".

**Rejected.** *Projection table*: premature; kept as a fallback if measured reads miss target.
*Counting only reverts*: hides broken pipelines. *An `incident` event*: out of scope.

**Consequences.** Metrics can change retroactively when a `reverted` arrives. Lost terminal
events leave deployments `in_progress` indefinitely (spec §7).
