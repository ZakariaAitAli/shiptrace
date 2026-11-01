# Architecture Decision Records

Short records of decisions that are costly to reverse. Status values: `Proposed`, `Accepted`,
`Superseded by NNNN`. All are `Proposed` until the foundation review. An accepted ADR is not
edited; a later ADR supersedes it.

| ADR | Decision |
|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith with enforced import boundaries |
| [0002](0002-runtime-and-data-access.md) | Python 3.14, PostgreSQL 18, sync SQLAlchemy with psycopg |
| [0003](0003-append-only-events.md) | Append-only events, natural idempotency key, server time only |
| [0004](0004-status-and-failed-change.md) | Derived status and the definition of a failed change |
| [0005](0005-api-credentials.md) | Opaque scoped tokens stored as SHA-256 digests; OIDC deferred |
| [0006](0006-dashboard.md) | Server-rendered dashboard with separate named accounts |
| [0007](0007-rate-limiting.md) | In-process rate limiting, with edge limits as a later layer |
| [0008](0008-observability.md) | structlog on stdout, OpenTelemetry for traces and metrics |
| [0009](0009-supply-chain.md) | Locked builds, `actions.lock`, digest promotion, attestations |
| [0010](0010-claude-code-configuration.md) | Minimal Claude Code config; enforcement over instruction |
| [0011](0011-schema-compatibility-readiness.md) | Readiness and schema compatibility |
