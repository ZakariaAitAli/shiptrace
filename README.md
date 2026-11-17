# ShipTrace

A small deployment tracking service: CI/CD pipelines report deployments, and people see history,
the latest good version, deployment frequency and change failure rate.

**Status: early development, not production ready.** Working today: admin bootstrap CLI, service
and environment registration, credential issuance and revocation, deployment event ingestion, and
deployment history and detail over the JSON API. Not built yet: latest-successful, metrics, the
dashboard, rate and body limits, a container image and CI.

Run the checks with `scripts/verify.sh` (needs `uv` and Docker). Install the commit hook once with
`scripts/install_git_hooks.sh`.

Start with [the spec](docs/PROJECT_SPEC.md), [the architecture](docs/ARCHITECTURE.md) and
[the plan](docs/IMPLEMENTATION_PLAN.md). Decisions are in [docs/adr](docs/adr/README.md).
