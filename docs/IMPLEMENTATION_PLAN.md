# ShipTrace — Implementation Plan

Each phase is a vertical slice, ends with a human review, and is complete only when its gate
passes with recorded evidence in [VERIFICATION_LOG.md](engineering/VERIFICATION_LOG.md).

**Every phase gate also includes:** `scripts/verify.sh` green; `security-reviewer` and the
relevant reviewers run with confirmed findings fixed; the threat model and ASVS table updated;
unresolved risks written down. New behavior starts with a failing test.

| Phase | Delivers | Measurable gate | Spec ACs |
|---|---|---|---|
| **P0 Walking skeleton** | `pyproject.toml`, `uv.lock`, package layout, import contracts, settings, `/healthz`, `/readyz`, role bootstrap script, Alembic baseline, Compose PostgreSQL, full `verify.sh`, git pre-commit hook | Clean clone → `verify.sh` green in one command; a deliberate layer violation fails import-linter; a deliberate type error fails mypy; `/readyz` flips with PostgreSQL state | AC16, AC15 (upgrade from empty) |
| **P1 Secure ingestion** | Domain rules, credentials, bootstrap CLI, service/environment registration, `POST /deployment-events`, error format, migration test suite | All 11 rules tested; concurrency and permutation tests pass; generated negative auth tests cover every route; domain branch coverage ≥ 95% | AC1–AC7, AC11, AC15 (complete) |
| **P2 Read side and dashboard** | History, latest, metrics, sessions, dashboard pages with CSP and security headers, committed OpenAPI, API guide with metric limitations, schema-driven contract tests | Metrics equal the fixture; p95 targets measured on 100k events; hostile-input rendering test passes | AC12–AC14, AC24 |
| **P3 Hardening and operability** | Body limit, rate limits, remaining headers, trusted proxy, JSON logs, OTel, graceful shutdown, GitHub Actions example, rotation and troubleshooting runbooks | Secret-sentinel test passes; correlation works across log, header and trace; `SIGTERM` test passes within budget; reporting script records to a local instance; runbooks executed | AC8–AC10, AC17, AC18, AC23, AC25 |
| **P4 Container** | Dockerfile, full Compose stack, smoke tests, distroless spike | Non-root verified at runtime; image size recorded; two clean builds compared and result recorded honestly | AC20 |
| **P5 CI/CD and supply chain** | CI and release workflows, `actions.lock`, scanners, SBOM, provenance, digest promotion, Dependabot, branch protection guide | A broken commit of each gate type fails CI; `gh attestation verify` passes on a real image; zizmor clean | AC21, AC22 |
| **P6 Recovery and assessment** | Backup/restore runbook, tested restore, final ASVS assessment, risk register | Restore drill recorded with measured RTO, row counts and log integrity; no ASVS item in scope without evidence or accepted risk | AC19 |
| **P7 Cloud plan** *(approval required first)* | Terraform, network and IAM design, WAF evaluation, rollback design, sizing, cost estimate from current AWS pricing | `terraform validate`, `tflint`, policy scan and a reviewed plan. **No apply, no spend, no credentials touched without explicit approval** | — |

## P0.1 skeleton to green: done

Evidence is in the verification log, entries V14 to V28.

1. Owner decisions applied.
2. `uv` installed from a checksum-verified release.
3. Tests first: `tests/unit` for settings validation, and `tests/integration` for every `/readyz`
   case in AC16, including older and newer schemas.
4. `pyproject.toml` with `requires-python = ">=3.14,<3.15"`, `uv.lock`, Ruff, strict mypy,
   pytest and import contracts.
5. App factory, `/healthz`, `/readyz`; a role bootstrap script; Alembic with a first migration that applies grants.
6. Extend `scripts/verify.sh` to run all gates.

## P0.2 close the P0 gate: implemented, one owner step left

Pre-commit hook, repeatable smoke script, gate-violation proof and readiness review are done. See
the verification log, entries V29 to V38.

**Open:** the owner inspects and applies `docs/engineering/proposals/guard-update-v3.patch`. P0 is
not complete until then, because enforcement of the signing policy and the sandbox depend on it.

## Standing obligation

Before the first contract migration, in whichever phase needs one: deliver ADR-0011 step 2. Until
then contract migrations are forbidden.

## Owner decisions needed

| # | Decision | Recommendation | Why it matters |
|---|---|---|---|
| D1 | Repository visibility | **Decided: public**, once approved to publish | Artifact attestations need public repos below Enterprise Cloud; without this, AC22 needs a different provenance design |
| D2 | Default branch | **Done: `main`** | Repository metadata expects `main`; `master` has no commits yet, so it is free now |
| D3 | First commit of the foundation | **Done, signed** | Worktrees and hook protection for tracked migrations need history |
| D4 | Enable OS sandbox | Apply guard patch v3, which holds the proven config | Turns the agent guardrails into a real boundary |
| D5 | Accepted MVP risks (six) | **Provisionally accepted**; reassess before release | None may be marked mitigated without evidence |
| D6 | Dashboard accounts (ADR-0006) | Approve before P2 | Replaces the rejected token sign-in |
| D8 | Commit email | Decide before any push | `zakaria-aitali@outlook.com` is in every commit, and in `scripts/check_history.py`, and becomes public with the repository |
| D7 | `gh` version | Run `! gh attestation --help`, and upgrade before P5 if it fails | AC22 needs that command, and local gh is 2.46.0. The guard correctly stopped me checking |
