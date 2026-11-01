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
| V33 | Independent P0 gate review | Three project reviewers. Verdict at that commit: **not passed**. Findings itemized under V33 below |
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
| V38 | Fresh `git clone`, `uv sync --locked`, `scripts/verify.sh`; smoke 5 times; integration 10 times | Exit 0. 97 tests, 95% coverage, mypy clean on 28 files, 3 of 3 contracts. Smoke 5 of 5. Integration 10 of 10. Nothing left behind. Superseded by the one-command run below |

Guard patch v3 was later revised; the final hash is below.

### Not verified at P0.2

- Guard patch v3 in the real repository: it is not applied.
- `allowUnsandboxedCommands: false`: not forced, because the model declined to try.
- `onFailure: "block"` on a hook timeout, and whether hooks themselves run outside the sandbox.
- An in-flight request during SIGTERM (AC17, P3).
- `transaction_per_migration`, real pool exhaustion, and a real network blackhole.
- Workflow lockfile and attestation tooling with local gh 2.46.0.

### V33 findings and dispositions

| Finding | Disposition |
|---|---|
| Guard: case-sensitive keys, `GIT_CONFIG_KEY_0`, separated assignments, `--no-gpg-sign` on merge and friends | Fixed in patch v3 |
| `autoAllowBashIfSandboxed` weakens prompts; `.env` and other credential files readable | Fixed in v3 by deny lists; setting kept |
| `compose.override.yaml` bypass | Fixed: `COMPOSE_FILE` in smoke, protected in v3 |
| `.venv` writable and run outside the sandbox | Fixed in v3 |
| Only named files protected; hook shebangs lack `-I` | Fixed: all of `scripts/` in v3; shebangs changed |
| `check_history` accepted any key | Fixed: key ID and author pinned |
| Ruff could echo a staged secret | Fixed, tested |
| `.git/config` writable; path traversal in file guard | Fixed in v3 |
| Quoted paths, binary files, deleted lockfile in pre-commit | Fixed, tested |
| Smoke: truncated log, unchecked grep, second interrupt, port race | Fixed |
| `#` lines hid attribution in commit messages | Fixed, tested |
| `check_gates` accepted any non-zero exit; outage case failed early | Fixed with markers and a full baseline |
| `known` revisions untested; Layers contract unproven | Fixed, tested |
| `lockfile`, `boundaries` and missing `uv` untested | Fixed, tested or proven by `check_gates` |
| Lifespan not run in a wiring test; sleep used to synchronize; tautological test | Fixed |
| Stale documents | Fixed |
| Secret pattern lists duplicated in two files | Accepted: hooks are protected, so sharing would couple them |
| `check_gates.py` has no doc reference | Fixed: named in this log and the plan |
| `SMOKE_*` overrides unused | Kept: the timeout override is how the timeout path is tested |
| `conftest` retry matches only Docker Desktop text | Accepted for this machine; revisit in P5 for CI |

### Final re-judgement of P0

The final review found `.importlinter` could override `pyproject.toml`. Confirmed, then fixed by
naming the config, with a new `check_gates` case. It also found clustered `-aSKEY`, `sandbox`
removal passing `check_repo`, and unverified `.git/commondir`. Outcomes:

- `.importlinter`: reproduced (`Contracts: 0 kept`, exit 0, violation unnoticed), then fixed.
- Clustered `-aSKEY`: fixed in patch v3, with a test and a mutant.
- `sandbox` removal: `check_repo.py` still passes it, because the block does not exist until the
  owner applies v3. Open: require it in the commit that applies v3.
- `.git/commondir`: the probe did not create it. Adding it to `denyWrite` was tried and **broke git in the sandbox**,
  because the sandbox mounts a placeholder over a path that does not exist. Removed. It stays a
  residual risk, controlled by approving each `git commit`.

Patch v3 after these changes: 83 new subtests failed first then passed, 19 of 19 mutants killed,
and the live clone test was repeated.

### Final evidence, at commit 353210c

| ID | Check | Outcome |
|---|---|---|
| V39 | `git clone`, then only `scripts/verify.sh`, with no prior sync | Exit 0. 97 tests, 95% coverage, mypy clean on 28 files, 3 of 3 contracts |
| V40 | Smoke 3 times from that clone | 3 of 3. 0 containers and 0 volumes left |
| V41 | `scripts/check_gates.py` with a full-gate baseline | Baseline exit 0. 25 of 25 caught, each with exit 1 and its marker |

Guard patch v3 is `8998d3024aaa3753…` by SHA-256, and `git apply --check` passes. It is not applied.
Only log text changed after this evidence. No independent review ran after the last fixes.

## After guard patch v3 was applied by the owner, 2026-11-01

Commit `a0ee681` holds the applied guards and removes the obsolete proposal.

| ID | Check | Outcome |
|---|---|---|
| V42 | Applied files against the reviewed patch | Patch hash `8998d3024aaa3753…` from `git show`, and it reverses cleanly, so the applied change is the reviewed one |
| V43 | Live probes from the real session sandbox | 16 protected write targets blocked, including `.git/hooks`, `$HOME` and `/etc`. `src/` and `$TMPDIR` writable. `.ssh`, `.aws`, `.config/gh` and `.gnupg` show 0 entries. PyPI reachable; example.com, github.com and a direct socket blocked. Docker unreachable. `git status` works |
| V44 | Opt-out parameter on a harmless command | Refused by the auto-mode classifier before reaching the sandbox, so the setting itself was not observed working. The session's configuration states it is disabled |
| V45 | `scripts/verify.sh` through its exclusion, main checkout | Exit 0 by final output: 97 tests, 95% coverage, smoke passed |
| V46 | Commit through the `git commit` exclusion | Hooks ran. Correct identity and key ID, no attribution. Status `E` inside the sandbox, so the owner must confirm a good signature |
| V47 | Guard refused an edit to `scripts/check_repo.py` | Correct by design, and a flaw in it: the owner's requested change could not be made. Supplied as an owner patch; 11 of 11 rule removals caught in a throwaway clone |

## External P0 gate, run by the owner

Run by the owner outside the sandbox, on the pushed commit `b7ceec8`. Results below are as the owner
reported them; Claude Code did not run or observe this execution.

| ID | Check | Outcome |
|---|---|---|
| V48 | `scripts/p0_gate.sh`: clean clone, then `scripts/verify.sh` | Checkout clean. Exit 0. 97 passed, 95% coverage, mypy clean on 28 files, 3 of 3 contracts, history OK |
| V49 | Smoke, three times; `scripts/check_gates.py` | Smoke 3 of 3. Baseline exit 0. 33 violations, 0 missed, exit 0 |
| V50 | Every commit reachable from HEAD must be `G` | 42 commits, none unverified. Gate exit 0, `P0 GATE: ALL STEPS PASSED`. Supersedes V39 to V41, and closes the signature check left open by V46 |

## Final independent reviews, at `be3957c`

Architecture review: BLOCKED only because no security review was recorded; no code blocker. Security
review: **FAIL**, two blockers. Both were confirmed before any fix.

| ID | Finding | Disposition |
|---|---|---|
| V51 | Blocker: hooks run outside the sandbox (documented) yet `format_python.py` and `guard_files.py` trust the payload `cwd`, so a nested project's tools could run unapproved | Confirmed with a contained probe: `uv` targeted the nested `.venv`. No escape was performed. Fixed in the owner patch |
| V52 | Blocker: exclusions match text only, so an approved `git commit` or `scripts/verify.sh` from a nested directory would run what lives there. `.git/commondir` is writable and unmounted | Confirmed by reading `guard_bash.py` and mount info. This corrects the earlier "controlled by approving each commit" claim. Fixed in the owner patch |
| V53 | Symlink past file guard; `.venv` and `.gitleaks.toml` unguarded for edit tools; Read deny gaps; `rm -rf ./.git`; `git checkout .`; `++` lines unscanned; `T` type change on migrations; stray tool configs outrank `pyproject.toml`; broad integration marker | Fixed in the owner patch |
| V54 | Stale documents, hook tier missing from ADR-0010, "fail-closed" overclaim, merge claim in `CLAUDE.md` | Fixed in this commit |
| V55 | Not changed: `.env.*` Read deny (would also block `.env.example`), `rg --hostname-bin` (sandbox-contained), spurious 503 during an overlapping refresh (deliberate), duplicated image digest, Alembic CLI fallback, stdlib-only domain check (with first domain code), frozen growth of `guard_bash.py` | Recorded; none blocks P0 |

Owner patch built in a throwaway clone: 15 hook subtests and 1 pre-commit test failed first; all pass;
`scripts/verify.sh --fast` passes there. 9 of 11 mutants killed; the 2 survivors are the two layers
of the `format_python.py` fix, each covering the other, and removing both together fails the tests.
The Docker gates have not run on this patch, so V48 to V50 no longer describe the final state.

## Final fixes applied by the owner

| ID | Check | Outcome |
|---|---|---|
| V56 | Owner patch `p0-final-fixes` against the reviewed copy | Working diff byte-identical, 10 files. Committed as `b6fefee` |
| V57 | Live location test, session really in `src/`, each command harmless if the guard failed | `git commit --dry-run`, `scripts/verify.sh` and `scripts/smoke.sh` refused; `git status` allowed. A Python write at the root was formatted through the protected `.venv`; a write from `src/` was left unformatted. The `.git/commondir` refusal and a nested project's own `.venv` are unit-tested only |
| V58 | `scripts/verify.sh --fast` after `b6fefee` | **Failed**: a regression from that patch. The `uv.toml` deny entry mounts a placeholder that `uv` fails to read, in the real project only, so the clone test missed it |
| V59 | Owner patch `uv-no-config` against the reviewed copy | Working diff byte-identical, 2 files. Sets `UV_NO_CONFIG=1`, and `check_repo.py` requires it. Removing it is caught |
| V60 | `scripts/verify.sh --fast` after restart, no manually set variables | Exit 0 at `16457ff`, with the setting inherited from project settings: 76 unit tests, mypy clean on 28 files, 3 of 3 contracts. Docker gates did not run |

V48 to V50 describe `b7ceec8`. The external gate must run again on the final commit.
