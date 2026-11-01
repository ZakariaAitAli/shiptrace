# ADR-0002: Python 3.14, PostgreSQL 18, sync SQLAlchemy with psycopg

Status: Proposed · Date: 2026-11-01

**Context.** Versions must be supported and proven compatible. Workload is low-volume short
transactions.

**Decision.**
- **Python 3.14**: supported to 2030-10. 3.15 shipped 2026-10-09 and is left for ecosystem
  wheels to catch up. Tested: the full stack resolves, installs from wheels only and imports
  on 3.14.10.
- **PostgreSQL 18**: supported to 2030-11, native `uuidv7()` (run locally on 18.6), and RDS
  lists it as generally available.
- **SQLAlchemy 2.1 + psycopg 3, synchronous**, with plain `def` routes on FastAPI's threadpool.
- **One Uvicorn process per container**: replicas handle scale. No Gunicorn.

**Why sync.** Every request is one database transaction with no fan-out, so async buys nothing.
Sync gives simpler stack traces, session lifetimes and tests, and avoids a class of bugs where a
blocking call stalls the event loop. Threads and the bounded pool cap concurrency on purpose.

**Rejected.** *asyncpg/async SQLAlchemy*: complexity without a throughput need. *psycopg_pool*:
SQLAlchemy already has a tested pool, and two pools blur ownership. *Python 3.15*: too new.

**Consequences.** Throughput is capped per process, which suits the MVP. Revisit only with
measurements showing thread-pool saturation.
