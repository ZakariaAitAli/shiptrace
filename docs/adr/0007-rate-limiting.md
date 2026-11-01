# ADR-0007: In-process rate limiting, with edge limits as a later layer

Status: Proposed · Date: 2026-11-01

**Context.** Abuse protection must fit the threat model: credentialed pipelines and an
internet-exposed endpoint, in a small system with no cache.

**Decision.** An in-process token bucket keyed by credential ID, plus a limit on failed
authentication by client IP, in bounded memory. Replicas each hold their own state, so the
effective limit is `limit × tasks`. Uvicorn `--limit-concurrency` and the pool timeout are the
backstop. AWS WAF is evaluated in Phase 7 as the answer to distributed floods.

**Why.** The aim is containing buggy or compromised pipelines, not exact quotas. In-process
limiting adds no dependency. The per-IP check runs before the credential lookup, so random tokens
are limited without database load, and it keeps working during an outage. The per-credential
bucket needs a successful lookup, so it does not.

**Rejected.** *Redis*: new infrastructure for an inexact goal. *PostgreSQL counters*: turns
every request into a write, so an attack creates database load. *Edge only*: the limit is not
aware of credentials, and it does not exist locally.

**Consequences.** Limits reset on restart and scale with replicas. Accepted risk (T10).
