# Toolchain

Versions checked on 2026-11-01 against PyPI, endoflife.date and vendor docs. The lockfile becomes
the authority in P0; this records the starting point and why.

## Host (Ubuntu 26.04 on WSL2, x86_64)

| Tool | Status |
|---|---|
| Docker 29.6.2 (Docker Desktop), Compose 5.3.1 | Working |
| Terraform 1.15.9, AWS CLI 2.35.21 | Installed; not used until P7 |
| gh 2.46.0 | Authenticated; old, and may need upgrading for `gh actions-lock` and `gh attestation` |
| git 2.53.0, jq 1.8.1, node 22, actionlint 1.7.9, Python 3.14.4 | Present |
| Claude Code 2.1.316 | Present; `onFailure` hook option needs ≥ 2.1.295 |
| bubblewrap | Present |
| uv 0.13.6 | Installed from the GitHub release, SHA-256 verified. Managed Python 3.14.10 |
| socat | Installed by the owner |
| **Missing** | `make`, `psql`, `shellcheck`, `hadolint`; system Python has no `ensurepip` |

Consequences: project commands are shell scripts rather than a Makefile. `psql` runs through the
container. Scanners run in CI or through `uv tool`, and are not assumed on the host.

## Selected versions

| Component | Version | Note |
|---|---|---|
| Python | 3.14 (image 3.14.10) | Security support to 2030-10 |
| PostgreSQL | 18 (18.6) | Support to 2030-11; on RDS |
| uv | 0.13.6 | |
| FastAPI / Starlette | 0.162.0 / 1.10.0 | |
| Pydantic | 2.14.2 | |
| SQLAlchemy | 2.1.6 | Requires Python ≥ 3.11 |
| Alembic | 1.20.1 | |
| psycopg (binary) | 3.3.6 | No system libpq needed |
| Uvicorn | 0.54.0 | Set `timeout_graceful_shutdown`; default `None`. Exits 143 on SIGTERM by design: it re-raises the signal after shutting down |
| structlog, Jinja2 | Arrive with P3, P2 | |
| OpenTelemetry SDK | 1.45.2 | Instrumentation `0.66b2`, pinned exactly |
| pytest / pytest-cov | 9.2.0 / 7.1.0 | |
| Testcontainers | 4.15.0 | Import from `testcontainers.community.postgres`; the old path is deprecated |
| httpx2 | 2.16.0 | Required by Starlette's test client; `httpx` is deprecated there. Declared in Starlette's metadata; source `pydantic/httpx2` |
| Hypothesis, Schemathesis | Arrive with P1, P2 | Dependencies are added when first used |
| Ruff / mypy | 0.17.3 / 2.4.1 | |
| import-linter | 2.15 | Layer contracts |
| gitleaks | 8.30.1, image by digest | `.gitleaks.toml` allows only the `gha-<run>-<attempt>` format |
| pip-audit / zizmor | Arrive with P5 | |

Compatibility proof: `docs/engineering/VERIFICATION_LOG.md`, entry V3. Not proven yet: runtime
behaviour of these versions together, which P0 and P1 tests will show.

## Base image digests (2026-11-01)

| Image | Digest |
|---|---|
| `python:3.14-slim-trixie` | `sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8` |
| `postgres:18.6-trixie` | `sha256:3a4264520e121176619f54ff867d12774bc81e95e7b84db58d63bccdb6144b81` |
| `postgres:18-alpine` | `sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5` |

Local Compose and tests use the Debian Postgres image, matching RDS's glibc collation behaviour
more closely than Alpine's musl.
