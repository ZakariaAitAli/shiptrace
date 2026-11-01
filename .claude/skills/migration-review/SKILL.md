---
name: migration-review
description: Reviews and verifies an Alembic migration or schema change for safety and reversibility. Use whenever files under migrations/ or persistence models change.
disable-model-invocation: true
---

Review migration: $ARGUMENTS (default: migrations changed on this branch)

1. Delegate to the `migration-reviewer` agent.
2. Run migration tests: upgrade from empty, downgrade round trip, and model drift check.
3. Verify the previous release's tests pass against the new schema when the change is expand-only.
4. Verify the runtime role still cannot `UPDATE`, `DELETE` or `TRUNCATE` append-only tables.
5. Report lock risk, rollback path and the deployment order.
