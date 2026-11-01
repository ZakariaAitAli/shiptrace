# Verification Log

What was actually run, and what happened. Newest phase last. If it is not here, it was not verified.

## Foundation phase, 2026-11-01

| ID | Check | Outcome |
|---|---|---|
| V1 | Tool inventory across 30 tools; `docker info`, `gh auth status`, `uv python list` | See TOOLCHAIN.md. Docker works; `uv`, `socat` and others are missing |
| V2 | `docker run postgres:18-alpine`, then `select version(); select uuidv7();` | PostgreSQL 18.6; `uuidv7()` returned a value |
| V3 | In `python:3.14-slim-trixie@sha256:cd89c30e…` (Python 3.14.10): `uv pip compile` wheels only, `uv pip install`, `uv pip check`, import of core packages | 100 packages resolved and installed; "All installed packages are compatible"; imports OK; psycopg `binary` implementation. Runtime integration is **not** proven |
| V4 | `docker buildx imagetools inspect` on three images | Digests in TOOLCHAIN.md |
| V5 | `python3 -I .claude/hooks/tests/test_hooks.py` | First run **failed**: a real defect, `readonly_bash.py` treated `&&` as a background `&`. Fixed the regex; 12 tests pass (over 140 command and path cases as subtests) |
| V6 | Nine hand-made mutations of the hooks, run on a scratch copy | 9 of 9 caught by the test suite, on the guards as first written. **Not repeated after the review rewrite**, because the guard now protects its own files. Repeat in P0 with owner approval |
| V7 | All skill, rule and agent frontmatter loaded with PyYAML | All 13 files parse |
| V8 | Headless `claude -p --model haiku`: asked to run `git push origin HEAD` | Project hook blocked it in a real session. No remote exists, so a miss would have been harmless |
| V9 | Headless: `security-reviewer` asked to use Write, `touch`, and `git status` | No Write tool; `touch` blocked by the agent hook; `git status` worked. Filesystem confirmed: no probe files |

### Independent review and correction

Two read-only reviewers with no knowledge of the author's reasoning reviewed the design and the
guards. Every finding below was checked against the text; review notes were not taken on trust.

| ID | Check | Outcome |
|---|---|---|
| V10 | Architecture review: 23 findings | 22 fixed in the documents. One declined: the P4 distroless spike stays, because the brief requires a minimal runtime image |
| V11 | Security review: 9 design and 9 guard findings | Design findings fixed. New threats T25, T26 and T27. `ingest` environment binding became mandatory |
| V12 | Added 49 failing subtests for the reported guard bypasses, seen red, then fixed the guards | 13 tests pass. This also shows the earlier suite's green result gave false comfort on shell structure |

The PostgreSQL behaviour in the ingest flow (`ON CONFLICT` arbitration, snapshot of the read-back)
was reasoned by the reviewer and author. It is **not tested yet**; P1 concurrency tests must prove it.

| V13 | Guard active on the author's own session | Blocked real commands four times, including two false positives on prose in heredocs and one read-only `gh` query. Recorded as known limitations |

### Not verified at foundation close

- `format_python.py` behaviour when it runs Ruff: only its no-op path was tested. Needs P0.
- Permission `deny` rules in isolation: V8 proved the hook, which fires first. They were not
  separately exercised.
- `onFailure: "block"` when a hook times out: never triggered. Guards now also catch their own
  errors and exit 2, which is tested with malformed input.
- `gh actions-lock` on this machine, including with gh 2.46.0.
- Sandbox configuration in the evaluation doc: never run; `socat` is missing.
- Project agents in *this* session: they load at session start, so the foundation review used
  the built-in read-only `Plan` agent with the same briefs.
- Any application behaviour: none exists.
- AWS prices: only Fargate rates were read from the AWS pricing page (us-east-1 x86
  ~$0.0405/vCPU-h and ~$0.0044/GB-h). A full estimate is deferred to P7.

## P0.1 and pre-implementation checks, 2026-11-01

| ID | Check | Outcome |
|---|---|---|
| V14 | gitleaks 8.30.1 by digest, no network, over working tree and staged content, with a planted-secret control | One finding, a false positive on the spec's `gha-` example. Narrow allowlist added; a non-`gha` value in the same field is still caught. Tree and staged content clean. Machine-path scan clean |
| V15 | Sandbox probes from a separate headless session | Blocked: writes outside the project, `.claude/hooks`, `.claude/settings.json`, `.git/hooks`, direct network, unlisted host, Docker socket. Allowed: project writes, listed host through the proxy. Credential directories appear empty on tmpfs (canary 0 of 1, `.ssh` 0 of 5) |
| V16 | Everyday commands inside the sandbox | git, uv, ruff, mypy, lint-imports, unit tests and hook tests all work. `scripts/verify.sh` passes through its exclusion |
| V17 | Guard mutation re-run on the rewritten hooks, on a scratch copy | 39 of 39 killed |
| V18 | 74 legitimate commands against the guard | 13 false positives, mostly read-only `gh`. 10 fixed in the patch. 3 remain, all fail safe: `.env` mentioned in a grep or commit message |
| V19 | Guard patch v1, on a copy. **Superseded by V34**; v1 must not be applied | 29 new subtests failed first, then passed; 13 of 13 new mutants killed; `git apply --check` passes. **Not applied**: guards change only with the owner |
| V20 | Test-first: suite run before implementation | Collection failed, as expected |
| V21 | Sentinel test | **Found a real defect**: `hide_input_in_errors` leaves the password in `ValidationError.errors()`. URL refusals now raise an exception Pydantic does not wrap. This fix was **incomplete**; see V25 |
| V22 | `scripts/verify.sh` | Exit 0. 68 tests on real PostgreSQL 18.6, strict mypy on 27 files, 3 of 3 import contracts. Branch coverage 95%; `bootstrap/migrate.py` shows 0% there and is exercised by V24 instead |
| V23 | 30 injected defects across code, SQL, layers and types | First run 27 of 30: three tests were too weak. Tests added; second run 30 of 30 |
| V24 | Real processes: Compose PostgreSQL, `shiptrace-migrate`, Uvicorn, curl | `/readyz` 503 before migration, 200 after, 503 within 13 ms of a database stop, 200 after restart with no app restart; `/healthz` 200 throughout. SIGTERM exit 143 in 169 ms, idle. No password in app output |

Incident: `ruff format .` reformatted protected `.claude/hooks/readonly_bash.py` through a route the
guard cannot see. Line wrapping only, confirmed by diff, and committed in that form. `.claude` is now
excluded from Ruff.

### Not verified

- AC17: an in-flight request surviving SIGTERM. V24 was idle. Belongs to P3.
- `onFailure: "block"` on a hook timeout.
- `/readyz` under real pool exhaustion.
- Production `sslmode=verify-full` against a real TLS server: only the setting check is tested.
- Bootstrap script on RDS: only tested on the Docker image.
- `gh actions-lock` and `gh attestation` with local gh 2.46.0.

### Independent review of P0.1

Project agents `security-reviewer` and `migration-reviewer` reviewed the committed slice. Findings
were reproduced first; see the phase report commit for the fixes.

| ID | Check | Outcome |
|---|---|---|
| V25 | Reproduction before fixing | A password misread as a port appeared in plain `str(error)`, the text a startup crash prints. A failed timeout check leaked through `errors()`. `?user=shiptrace_admin` was accepted. All confirmed against the committed code |
| V26 | New tests seen failing, then fixes | 8 failed and one module failed to import before the fixes. Role check is now exact, URL query is an allowlist, migrator URL is validated, `/healthz` is async, a busy readiness probe fails closed |

| V27 | Repeat after fixes | 93 tests pass. Defect injection repeated with 16 new mutants: 42 of 42 caught. Real-process run repeated with identical results. A built wheel contains the migrations, now a gate |

| V28 | Clean clone | **Failed once**: 9 errors from a flaky fixture I wrote. A port chosen on the Linux side can be refused by Docker Desktop on Windows; about 1 run in 6. Fixture now retries on that error only. 26 consecutive integration runs then passed, and no containers were left behind |

Not verified from this review: `transaction_per_migration` behaviour (no test can show it with one
migration); `tcp_user_timeout` under a real network blackhole, since Docker's proxy acknowledges
locally; log suppression in the bootstrap script; bootstrap script on RDS.

## P0.2, 2026-11-01

Commands below were run on the final commit unless stated. See the section at the end for its hash.

| ID | Check | Outcome |
|---|---|---|
| V29 | Review of guard patch v1 | Rejected by its own author, then by review: `--help` as a flag value, abbreviated git options, identity through the environment, and an excluded `git commit` running agent-editable hooks |
| V30 | Sandbox experiments in throwaway clones | Refuses to start without `socat` (exit 1). Signing fails inside. An edited excluded script escaped and wrote to `$HOME`. Relative `denyWrite` does nothing through `--settings`, works in project settings |
| V31 | Pre-commit hook, test first | Tests failed first. It then blocked three of my own commits; two were bugs in the hook itself, now fixed with tests. Review found Ruff could echo a staged secret; fixed, and tested |
| V32 | Smoke script | First version **would have exited 0 on failure**, because a trap overwrote the status, and leaked a `sleep`. Both fixed. Review found it reintroduced the port race and allowed Compose override files. Both fixed |
| V33 | Independent P0 gate review | Three project reviewers. Verdict at that commit: **not passed**. All confirmed findings fixed or recorded here |
| V34 | Guard patch v3, on a copy | 82 new subtests failed first, then passed; 18 of 18 mutants killed. **Not applied to the repository** |
| V35 | v3 as real project settings in a throwaway clone | Blocked: `scripts/*`, new files in `scripts/`, Compose files including overrides, `pyproject.toml`, `uv.lock`, `.venv`, `.git/config`, `.gitleaks.toml`, and renaming `scripts/`. `.env` unreadable. `src/` writable. Fast gates pass inside the sandbox. Edited `verify.sh` and `git commit` both need approval, and neither ran |

Corrections to earlier claims. The first `check_gates.py` result, 21 of 21, is withdrawn: it accepted
any non-zero exit, and one violation failed before reaching the step it claimed to test. V27's
"42 of 42" stands as recorded, but those mutants were checked by test failure only.

### Final P0.2 evidence, at commit c578267

| ID | Check | Outcome |
|---|---|---|
| V36 | `scripts/check_gates.py`: full-gate baseline, then 24 violations, each needing exit 1 and a named marker | Baseline exit 0. 24 of 24 caught. The stricter check first reported 6 misses: 3 wrong markers, and 3 that exposed a real pre-commit crash on non-UTF-8 content, now fixed with a test |
| V37 | Forced smoke failures: broken migration, readiness never recovering, app crash, outage reported ready, broken bootstrap SQL, total timeout, signal mid-run, missing Docker | Each gave the expected exit code (1, 130 or 2) and left 0 containers and 0 volumes |
| V38 | Fresh `git clone`, `uv sync --locked`, `scripts/verify.sh`; smoke 5 times; integration 10 times | Exit 0. 97 tests, 95% coverage, mypy clean on 28 files, 3 of 3 contracts. Smoke 5 of 5. Integration 10 of 10. Nothing left behind |

Guard patch v3 is `1865b1f0550403ae…` by SHA-256, and `git apply --check` passes at this commit.

### Not verified at P0.2

- Guard patch v3 in the real repository: it is not applied.
- `allowUnsandboxedCommands: false`: not forced, because the model declined to try.
- `onFailure: "block"` on a hook timeout, and whether hooks themselves run outside the sandbox.
- An in-flight request during SIGTERM (AC17, P3).
- `transaction_per_migration`, real pool exhaustion, and a real network blackhole.
- Workflow lockfile and attestation tooling with local gh 2.46.0.
