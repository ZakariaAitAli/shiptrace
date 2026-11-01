---
paths:
  - "src/shiptrace/persistence/**"
  - "migrations/**"
---

# Persistence rules

- One transaction per use case; the application layer owns the boundary.
- Bound parameters only. Never build SQL from strings containing input.
- Races are settled by constraints and `ON CONFLICT`. Do not use `FOR UPDATE` on append-only
  tables: it needs an `UPDATE` privilege the runtime role must not have.
- Never edit an applied migration. Each new one needs a working `downgrade`, or a stated reason.
- Follow expand/contract, so the previous release keeps working on the new schema.
- Every migration: add explicit grants, and set `lock_timeout` for operations on large tables.
- Use `/migration-review` for any schema change.
