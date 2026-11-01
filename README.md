# ShipTrace

A small deployment tracking service: CI/CD pipelines report deployments, and people see history,
the latest good version, deployment frequency and change failure rate.

**Status: early development. Only a health-checked skeleton exists; it is not production ready.**

Run the checks with `scripts/verify.sh` (needs `uv` and Docker). Install the commit hook once with
`scripts/install_git_hooks.sh`.

Start with [the spec](docs/PROJECT_SPEC.md), [the architecture](docs/ARCHITECTURE.md) and
[the plan](docs/IMPLEMENTATION_PLAN.md). Decisions are in [docs/adr](docs/adr/README.md).
