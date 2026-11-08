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

## External P0 gate on the final code, run by the owner

Run by the owner outside the sandbox on `1822839`, then pushed. Results are as the owner reported
them; Claude Code did not run or observe this execution.

| ID | Check | Outcome |
|---|---|---|
| V61 | `scripts/p0_gate.sh`: clean checkout and clone, `scripts/verify.sh` | 97 tests passed, 95% coverage, 3 of 3 architecture contracts |
| V62 | Smoke three times; `scripts/check_gates.py` | Smoke 3 of 3. 34 of 34 deliberate violations detected |
| V63 | Every commit reachable from HEAD must be `G` | 47 of 47 valid. `P0 GATE: ALL STEPS PASSED`, exit 0. Supersedes V48 to V50, and closes the signature gap in V46 for the commits since then |

## Focused final security review, at `c8b5769`

Verdict: **FAIL**. High findings H1 and H2 were each partly resolved. `format_python.py` is closed,
and `.git/config` is protected. Three new blockers were confirmed by contained execution in
`$TMPDIR`; no escape from the sandbox was performed.

| ID | Finding | Confirmed by | Disposition |
|---|---|---|---|
| V64 | `guard_files.py` runs `git ls-files` outside the sandbox, and a planted `.git/commondir` can supply `core.fsmonitor` | Planted fsmonitor ran in a throwaway repo | Owner patch deletes that check. `pre_commit.py` still blocks applied migration edits |
| V65 | Claude Code strips wrappers such as `nohup`, `timeout` and `NO_COLOR=1` before matching exclusions, but `LEAVES_SANDBOX` was anchored | 6 of 6 wrapped forms passed from a nested directory | Owner patch removes the anchor |
| V66 | `pre_commit.py` runs `lint-imports` from the root, which imports modules from its working directory | Planted module ran | Owner patch deletes that check. `scripts/verify.sh` still runs it |
| V67 | Time-of-check gap: a background sandboxed process can plant `.git/commondir` during an approval prompt | Reasoned, not executed | Open, for the owner. Only moving `git commit` out of the agent's hands closes it |

V61 to V63 describe `1822839`, and do not cover these fixes.

## Remediation of V64 to V67, prepared in a disposable clone

Run by Claude Code in a scratch clone of `6f79ff4`, never in the live repository. The guards refuse
writes to any `.claude/hooks/` path, so the proposed hooks were edited in a copy outside `.claude`
and are delivered as an owner patch. Nothing here describes the applied state.

| ID | Check | Outcome |
|---|---|---|
| V68 | State of `6f79ff4` | V64 to V66 unfixed in code. In the sandbox, opening `.git/HEAD` for write succeeds although mount info lists `.git` read-only; `.git/hooks` returns `EROFS`. So `.git/commondir` can be planted |
| V69 | Reproductions before any fix | A planted `commondir` ran its fsmonitor on `git status`. `check_location()` allowed 7 of 7 wrapped forms from `src/`. An untracked root `typing_extensions.py` ran during `pre_commit.py`, because import-linter puts its directory first on `sys.path` |
| V70 | New tests against the unchanged code | Hook tests: 58 failing tests and subtests, covering V64, every wrapped, rewritten and redirected form, substitutions, a missing `cwd` and `commondir`. Pre-commit: the planted-module test failed. Plain forms passed throughout |
| V71 | Same tests after the fixes | Hook tests 28 of 28, pre-commit 23 of 23 |
| V72 | Mutants of the new location check | 10 of 10 killed |
| V73 | `scripts/verify.sh --fast` in the clone, with the original hooks in place | Exit 0: 76 unit tests, mypy clean on 28 files, 3 of 3 contracts, pre-commit 23, hooks 22. Docker gates did not run |
| V74 | V67 protections, emulated in throwaway repositories | An empty or `/dev/null` `commondir`, which is what a `denyWrite` placeholder would be, makes every git command fail, so that protection is rejected. Pinning `GIT_COMMON_DIR` to the real `.git` stopped the planted fsmonitor. A read-only `.git` kept status, diff and ls-files working, and refused add and stash. The real harness was not tested: `bwrap` cannot nest here |

Correction to V67: a planted `commondir` affects any git command run outside the sandbox, including
the owner's own, so moving commits to the owner does not close it alone. V71 to V74 are the agent's
own runs. The owner patch, a live sandbox test and the external gate remain.

## V67 design: read-only `.git` and a single commit script, prepared in the same clone

| ID | Check | Outcome |
|---|---|---|
| V75 | Real harness, by observation in the live session | A `.git` read-only mount exists, but under the root mount, and the project's writable bind is mounted over it, so it has no effect. Directories in `denyWrite`, such as `scripts` and `.venv`, are mounted under the project bind and refuse writes. This suggests a `.git` entry would hold; it is not a test of one |
| V76 | Real harness, direct test | **Not run by the agent.** Nested `bwrap` is refused inside the sandbox, and the CLI has no command that runs one command in its sandbox. A probe for the owner exists; its dry run in a writable clone reported every metadata write as a failure, so it can fail |
| V77 | New guard tests for `scripts/commit.py` and redirections, against the V64 to V66 guard | 13 failures, including `scripts/verify.sh >> ~/.bashrc`: a redirection runs in the shell outside the sandbox |
| V78 | `scripts/test_commit.py` before `scripts/commit.py` existed | 11 errors |
| V79 | All tests after the change | Hooks 28, commit 11, pre-commit 23, commit messages 3, history 7, history checks OK, Ruff and formatting clean, mypy clean on 28 files, 3 of 3 contracts, 76 unit tests. `check_repo.py` accepts the candidate settings and rejects the current ones |
| V80 | Mutants | Guard: 12 of 12 killed. `commit.py`: 9 of 10. The survivor is the repository pin behind the `commondir` refusal; with the refusal removed, a planted hook did not run with the pin and did run without it |
| V81 | `check_repo.py` against weakened candidate settings | Each refused: no `.git` in `denyWrite`, `git commit` excluded again, `commit.py` auto-allowed, its `ask` rule removed |

`scripts/verify.sh --fast` as a single run with the candidate settings and new hooks in place needs
the owner's patch; its steps ran separately in V79.

## V64 to V67 patch applied to the live working tree, uncommitted

V82 is as the owner reported it; Claude Code did not observe that run. V83 to V88 ran in this
session, on `6f79ff4` with the patch applied by the owner.

| ID | Check | Outcome |
|---|---|---|
| V82 | Owner's disposable-clone probe in the real sandbox | Claude Code 2.1.318, git 2.53.0: 30 checks passed, 0 failed; `.git` writes refused, git reads working, fast verification passed |
| V83 | Working tree against patch `c1e7b238…` | Reverse apply succeeds, so every hunk and both new files match. 13 modified and 2 new files; modified files are byte-identical to the reviewed copies |
| V84 | Active sandbox | `.git` mounted read-only under the project mount. Write-open of `.git/HEAD`, `index`, `description`, `touch` and `mkdir` refused. git add, update-ref, branch and `config --local` refused, no ref created. status, diff, log, rev-parse, show, branch list, blame and ls-files return 0 |
| V85 | Hook tests, run directly | 28 of 28 |
| V86 | `scripts/verify.sh --fast` | Exit 0: repository and history checks OK; commit messages 3, history 7, pre-commit 23, commit script 11, hooks 28; Ruff, formatting and mypy clean; 3 of 3 contracts; 76 unit tests |
| V87 | Live location check | Shell in `src/`: a harmless trigger was refused as outside the root. Shell at the root: allowed, and `--show-prefix` printed nothing, so it ran there. The guard's view matched the real directory in each pair; a `cd` applied one call late |
| V88 | Defect found | `EXCLUDED_SCRIPT` is unanchored, so `pre_commit.py`, `test_commit.py` and `test_pre_commit.py` count as excluded scripts, and commands naming them are refused unless plain. Fails closed; no security effect. Fix before committing |

The signed path through `scripts/commit.py` has not run live; the first approved commit tests it.

## V88 fix: anchor the excluded-script names, prepared outside `.claude`

The guards protect `.claude/hooks/`, so the fix was made in a scratch copy and is an owner patch.

| ID | Check | Outcome |
|---|---|---|
| V89 | New tests against the current guard | 16 failures: 8 harmless mentions of `pre_commit.py`, `test_commit.py` and `test_pre_commit.py`, each from a nested directory and the root. The new test that excluded scripts stay protected by any path already passed |
| V90 | New tests against the corrected guard | 30 of 30. The unchanged previous test file also passes against it, 28 of 28 |
| V91 | Mutants of the corrected guard | 16 of 16 killed: 5 on the new pattern, including reverting it, and the 11 earlier mutants, each with at least as many failures as in V80 |

## Final pre-commit validation, live working tree on `6f79ff4`

| ID | Check | Outcome |
|---|---|---|
| V92 | Contents | V88 patch reverse-applies; three hook files byte-identical to the corrected copies; the other 12 files match the approved V64 to V67 patch; this log only gains lines. 13 modified and 2 new files, nothing else |
| V93 | Gates | Hooks 30 of 30. `scripts/verify.sh --fast` exit 0: commit messages 3, history 7, pre-commit 23, commit script 11, hooks 30, Ruff, formatting and mypy clean, 3 of 3 contracts, 76 unit tests. `git diff --check` clean |
| V94 | Protections live | 11 of 11 guard payloads for this project as expected, including the commit script refused from `src/`, with `nohup`, a substitution, a redirection or `cd`, and allowed plainly at the root. No process call in `guard_files.py`; no import-linter in the pre-commit hook. `.git` write refused, `git add` refused, `git status` works. Commands naming `pre_commit.py` and `test_pre_commit.py` now run |
| V95 | Commit path readiness | Script executable, `/usr/bin/python3` 3.14.4, `commit-msg` and `pre-commit` hooks installed. The signing key's state cannot be seen from the sandbox |

## External P0 gate at `bf9f754`, and the stale negative test

V96 is as the owner reported it; Claude Code did not observe that run. V97 to V101 ran in this
session, in a scratch clone of `bf9f754`; `scripts/` is protected, so the fix is an owner patch.

| ID | Check | Outcome |
|---|---|---|
| V96 | Owner's `scripts/p0_gate.sh` at `bf9f754` | **Failed.** `scripts/verify.sh` 97 tests, 95% coverage; smoke 3 of 3; contracts 3 of 3; 53 of 53 signatures good; violations 32 of 33, `MISSED exit=0 exclusion auto-allowed` |
| V97 | Root cause | The violation still adds `Bash(git commit *)` to `allow`. Since `22f44ed` that is no longer a sandbox exclusion, so `check_repo.py`, which flags an `allow` rule equal to an exclusion, rightly passes it. The V67 patch changed the exclusion without updating the violation; V81 used its own settings mutations, not `check_gates.py`. Reproduced alone as the gate runs it: `MISSED exit=0`, `repository checks: OK` |
| V98 | New `scripts/test_check_gates.py` against `bf9f754` | 2 failures, both the stale violation: not caught, and its added rule `Bash(git commit *)` is not a current exclusion. The baseline and every other `check_repo.py` violation passed |
| V99 | After the fix, which now adds `Bash(scripts/commit.py *)` | 3 of 3 |
| V100 | Mutants | 3 of 3 killed: the auto-allow rule removed from `check_repo.py`; an unrelated error that contains the expected marker, caught by the baseline test; the fix reverted |
| V101 | Gate steps in the clone | Repository and history checks OK; commit messages 3, history 7, pre-commit 23, commit script 11, gate violations 3, hooks 30; lockfile current; 61 files formatted; Ruff and mypy clean; 3 of 3 contracts; 76 unit tests. `check_gates.py` needs Docker, so the owner runs it |

## P0 acceptance at `05763a9`, run by the owner

Run by the owner outside the sandbox on `05763a9`, the fix for V96. Results are as the owner
reported them; Claude Code did not run or observe this execution.

| ID | Check | Outcome |
|---|---|---|
| V102 | `scripts/p0_gate.sh` at `05763a9` | **Passed**, exit 0. `scripts/verify.sh`: 97 tests, 95% coverage, 3 of 3 contracts. Smoke 3 of 3. Violations 33 of 33 detected, 0 missed. 54 of 54 commits GPG-verified. Supersedes V96 |

P0 is accepted by the owner at `05763a9`. P1 starts from that commit.

## P1 S1 CP1: credential tokens, scopes and name rules

Run in this session on `02f2ad0` with CP1 uncommitted. Pure domain and application code; no
database change.

| ID | Check | Outcome |
|---|---|---|
| V103 | New unit tests before any implementation | All three files failed to import: `shiptrace.domain.credentials`, `shiptrace.domain.names` and `shiptrace.application.credentials` did not exist |
| V104 | Same tests after the implementation | 93 passed. Line and branch coverage of the new modules 100% |
| V105 | Security review, CP1 only | One Low finding, reproduced: `is_allowed(Scope.ADMIN, "register")` returned True, because `StrEnum` members hash and compare as strings. A new test failed for `register` and `view_registry`, then passed after an `Action` type check. No other finding |
| V106 | Test review, CP1 only | Three findings, each reproduced as a surviving mutant: slugs of length 2 rejected; name ends allowing `_` and names unable to start with a digit; base64 with `-` and `_` swapped. Fixed by adding `qa`, `1st deploy`, `_ci`, `ci_`, `.ci`, `ci-` and two alphabet vectors |
| V107 | Mutants | 22 of 22 killed, including the four that had survived |
| V108 | Accepted, not tested | A non-cryptographic generator such as `random.randbytes` passes the tests, but Ruff S311 rejects it in `scripts/verify.sh`; checked on a scratch file |
