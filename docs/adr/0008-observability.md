# ADR-0008: structlog on stdout, OpenTelemetry for traces and metrics

Status: Proposed · Date: 2026-11-01

**Context.** The brief requires structured logs with correlation IDs, plus metrics and traces,
without high-cardinality labels or sensitive data.

**Decision.** JSON logs to stdout through structlog, with allowlisted fields. OpenTelemetry SDK
for traces and metrics, exported over OTLP/HTTP to a collector when configured, and disabled
otherwise. A validated inbound `X-Request-ID` is honoured, or one is generated; it is returned
in the response and joined to `trace_id` in logs.

**Why.** stdout is the container contract and works unchanged with CloudWatch. One telemetry
pipeline for traces and metrics means one exporter to run. OTel log export is not needed
because stdout already delivers logs.

**Rejected.** *`prometheus-client` with `/metrics`*: a second metrics system, plus another
endpoint to protect, and Fargate has no scraper by default. *OTel logs SDK*: unnecessary
coupling; its Python maturity was not confirmed.

**Consequences.** OTel instrumentation packages are pre-1.0 (`0.66b2`), so they are pinned
exactly and used thinly. Metrics in AWS need a collector sidecar, whose cost and CPU are sized in
Phase 7. Without a collector, logs remain the fallback signal.
