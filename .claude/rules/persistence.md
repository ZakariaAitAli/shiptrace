---
paths:
  - "src/shiptrace/persistence/**"
  - "migrations/**"
---

# Persistence rules

- The application layer orchestrates, authorizes and makes domain decisions; it holds no database
  transaction. Each store's port method is one atomic PostgreSQL transaction, owned by the store,
  which commits only what the use case's decision allows (docs/ARCHITECTURE.md §2).
- Bound parameters only. Never build SQL from strings containing input.
- Races are settled by constraints and `ON CONFLICT`. Do not use `FOR UPDATE` on append-only
  tables: it needs an `UPDATE` privilege the runtime role must not have.
- Never edit an applied migration or delete a revision file: `/readyz` reads an unknown revision
  as newer. Each new one needs a working `downgrade`, or a stated reason.
- Follow expand/contract, so the previous release keeps working on the new schema. Contract
  migrations are forbidden until ADR-0011 step 2 lands.
- Every migration: add explicit grants, and set `lock_timeout` for operations on large tables.
- Use `/migration-review` for any schema change.
