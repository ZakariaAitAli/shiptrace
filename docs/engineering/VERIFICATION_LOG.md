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

## P1 S1 CP2: migration 0002 and least-privilege grants

Run in this session on `3f6277e` with CP2 uncommitted, against PostgreSQL 18.6 through
`scripts/verify.sh`, each run approved by the owner.

| ID | Check | Outcome |
|---|---|---|
| V109 | New integration tests before the migration existed | About 92 new tests failed, with `42P01` (undefined table) or no row; existing tests passed. SQLSTATE checks kept a missing table from passing as a privilege refusal |
| V110 | Same tests with migration `0002` | `scripts/verify.sh` passed: 282 tests, 96.07% coverage, smoke passed |
| V111 | Migration review, `0002` only | No critical, high or medium finding. Low: credential-name tests had no forbidden character in the middle and no names with space, `.` or `_`; reproduced by reasoning, then fixed with four middle-character cases and four valid names checked against the domain rule. Low: ARCHITECTURE §3 listed the old broader runtime grants; corrected |
| V112 | The reviewer's mutant, middle character class replaced by `.` | Killed: exactly the four new middle-character cases failed, 286 passed. The pattern was then restored |
| V113 | Final `scripts/verify.sh` | Passed: 290 tests, 96.07% coverage, smoke passed |

## P1 S1 CP3: bearer authentication, credential lookup and problem responses

Run in this session on `49377be` with CP3 uncommitted. Docker-backed runs went through
`scripts/verify.sh`, each approved by the owner. No production route is protected yet; tests attach
probe routes.

| ID | Check | Outcome |
|---|---|---|
| V114 | New unit tests before the implementation | All three new files failed to import: `shiptrace.api.auth` and `shiptrace.application.access` did not exist |
| V115 | Unit tests after the implementation | 223 passed. 16 of 16 mutants killed, covering header parsing, the format check before lookup, unknown credentials, skipped authorization, missing `WWW-Authenticate` and `Retry-After`, an outage reported as 401, echoed input or keys, an incomplete `Allow`, a 500 echoing its exception, the media type and the type URN |
| V116 | First `scripts/verify.sh` | Passed: 359 tests, 97.41% coverage, new modules 100%, smoke passed |
| V117 | Docker mutants of the lookup | Revocation ignored: 4 tests failed. SQL error chained to `StoreUnavailable`: 1 failed. Restored byte for byte |
| V118 | Accepted, not tested | Inclusive expiry (`>=`) survived: a lookup in a later transaction cannot share the writer's `now()`, so the same-microsecond boundary is unobservable through the store |
| V119 | Test review, CP3 only | Medium: database time is not proven against the application's clock, because both share a host; enforced by the query and review, not by a test, since freezing the clock needs a new dependency. Low: pool exhaustion untested; added. Low: fixed title, detail and exact members checked only for 401; now checked for every code, with the texts written in the test. A test that could not fail, the `Principal` repr check, was removed |
| V120 | Security review, CP3 only | No leak of token, digest, header, SQL or request value. Low, reproduced: an invalid UTF-8 body made FastAPI raise HTTP 400, answered as 500 even for anonymous callers. A new test failed for both, then passed with 400 mapped to `validation_failed` |
| V121 | Accepted | A body that is not JSON is answered with 422 before authentication, because FastAPI parses it before dependencies run. It names no value. Such requests will not count toward the failed-authentication limit (T10, P3). Server-side tracebacks on 500 are for P3 logging |
| V122 | Docker mutant, `except OperationalError` instead of `SQLAlchemyError` | Killed by the new pool-exhaustion test alone, 360 passed. Restored byte for byte |
| V123 | Final checks | 18 of 18 unit mutants killed, including detail passthrough and an added `instance` member. `scripts/verify.sh` passed: 361 tests, 97.43% coverage, smoke passed |
| V124 | Database time, owner decision: option A | Accepted with its limit: the integration tests cannot tell database time from application time. Confirmed by reading: the only expiry rule is `expires_at > now()` in the lookup's SQL, which returns no timestamp. A static guard, `tests/unit/test_auth_clock.py`, fails if a module on the authentication path imports `datetime`, `time` or `calendar`, or if the lookup brings `expires_at` or `revoked_at` into Python. The test review's mutant, comparing `expires_at` with `datetime.now(UTC)` in Python, failed both assertions; the file was restored byte for byte. No dependency added |

## P1 S1 CP4: admin credential bootstrap CLI

Run in this session on `28081ed` with CP4 uncommitted. The owner applied the one-line
`pyproject.toml` entry point and ran `uv sync --frozen`; `uv lock --check` passed with it in a
scratch copy first. Docker-backed runs went through `scripts/verify.sh`, each approved by the owner.

| ID | Check | Outcome |
|---|---|---|
| V125 | New unit tests before the implementation | Failed to import: `create_admin_credential`, `CredentialNotStored` and `shiptrace.bootstrap.cli` did not exist. The console-entry test stayed red until the owner's patch |
| V126 | Unit mutants | 14 of 14 killed: name unchecked or lowercased, token stored instead of digest, token in repr, constant token, token also on stderr or printed twice, `--token` or `--scope` accepted, CLI name check skipped, a fresh id instead of the database's, and wrong exit codes for refused configuration, a failed write and a wrong role |
| V127 | Security review, CP4 only | No token leak. Low: a commit whose acknowledgement is lost was reported as "not stored"; now "may not have been stored", naming the display prefix. Low: a closed stdout gave exit 0 with the token lost, and a broken pipe a traceback; now a missing stream is refused before anything is created, and an unwritable token is reported by id with exit 5. Each fix was red first. Noted: the configuration message, now corrected; T27's recovery path also revokes, which is AC25 in P3; no role can create a schema that shadows `api_credentials`, because the database grants only `CONNECT` |
| V128 | Test review, CP4 only | High: a same-name credential could revoke or delete the first unnoticed. Medium: no integrity error reached the writer in tests; names only tested as `ops`; the token scan looked only for verbatim text. Low: the wrong-role branch and the returned id were untested. All fixed in tests |
| V129 | Docker mutants of the writer | All killed by their own tests, 399 passed: the role check bypassed; the catch narrowed to `OperationalError` and `ProgrammingError`, where the duplicate digest then raised an `IntegrityError` carrying the `INSERT` and the bound digest; and a same-name rotation revoking the earlier credential. Restored byte for byte |
| V130 | Final `scripts/verify.sh` | Passed: 402 tests, 97.62% coverage, smoke passed. Covers, against PostgreSQL 18: the CLI as a process, stdout holding exactly the token, the stored row, a scan of every column of every table for the token, its hex and its base64 forms, a same-name second credential leaving the first unchanged and both authenticating as admin through CP3, the runtime-role URL refused with nothing written, the role check and the database's own refusal, a duplicate digest with no detail, and an unreachable database |

## P1 S1 CP5: service and environment registry API

Run in this session on `930dfac` with CP5 uncommitted. Docker-backed runs went through
`scripts/verify.sh`, each approved by the owner. No database grant changed.

| ID | Check | Outcome |
|---|---|---|
| V131 | New unit tests before the implementation | All three new files failed to import: `shiptrace.application.registry` did not exist |
| V132 | Defect found in CP3 code | FastAPI 0.162 keeps included routers as lazy wrappers, so `allowed_methods()` sent an empty `Allow` on a 405 for any included route; CP3's test used routes added to the app directly. A new test failed with `{''}`, then passed after probing each method through `matches()`. The route-table test had also found no routes, and its guard failed rather than passing empty |
| V133 | Unit mutants | 20 of 22 killed: authorization skipped in either use case, ingest allowed to list, slug unchecked, a duplicate returning quietly, limits 0 and 101, no look-ahead row, an off-by-one next position, unchecked positions, cursor prefix, slug and round trip unchecked, a plain-slug cursor, 200 for register, default page 49, extra body fields, the rule name, the 409 code, and an `Allow` from matched routes only. Two survivors are equivalent: the cursor length cap, since a valid cursor is at most 88 characters, and ignoring the kind on decode, since the round trip re-encodes with the requested kind |
| V134 | Docker mutants, first run | All killed, 517 passed: `ON CONFLICT` removed (duplicate, concurrency and end-to-end tests), `slug >= :after`, ordering by `created_at`, and error chaining |
| V135 | Security review, CP5 only | No critical, high or medium finding. Low: AC6 read routes from the OpenAPI schema, so a protected route excluded from the schema would be unseen; now enumerated from the real route table, cross-checked with the schema, and a hidden unprotected route was shown to fail it. Low: the spec said a cursor the server did not issue is 422, which unsigned cursors cannot enforce; reworded, and cursors now carry their list's kind and must round-trip exactly, so non-canonical base64 is refused |
| V136 | Test review, CP5 only | Medium: the barrier race opened connections after the barrier, so inserts might not overlap; the pool is now warmed first, and a deterministic test holds an uncommitted winner and waits for the second writer to block. Medium: the database pagination test survived a missing `LIMIT`; it now checks every page size. Medium: the cursor kind, as in V135. Low: the 409 body is now checked exactly and never echoes the slug. Low: every pagination loop is bounded, so an ignored cursor fails instead of hanging |
| V137 | Docker mutants, second run | A check-then-insert insert and a missing `LIMIT` were killed by exactly their own tests, 529 passed. An earlier run had wrongly failed the deterministic race for both kinds: the migrator cannot see another role's wait state, so the observer is now the superuser, and the second writer is always joined |
| V138 | Final `scripts/verify.sh` | Passed: 532 tests, 98.19% coverage, every CP5 module 100%, smoke passed |

## P1 S2 CP6: runtime credential writes (migration 0003, ADR-0012)

Run in this session on `d36b78c` with CP6 uncommitted. Docker-backed runs went through
`scripts/verify.sh`, each approved by the owner. Mutants were applied to the uncommitted migration
and restored byte for byte from a backup, confirmed with `cmp`.

| ID | Check | Outcome |
|---|---|---|
| V139 | New tests before migration 0003 | The new privilege, transition and round-trip tests failed: the runtime role still had no `INSERT` or `UPDATE`, and no guard existed. The tests that try to disable, drop or replace the guard passed, as they should with nothing to bypass |
| V140 | First green `scripts/verify.sh` | Passed: 579 tests, 98.19% coverage, smoke passed. An earlier draft checked expiry with calendar days, which a daylight-saving zone turns into 23 or 25 hours; the guard now checks absolute seconds and the acceptance test runs under UTC and Europe/Paris |
| V141 | Docker mutants, run A | 6 failed, 574 passed; each killed by its own test: the admin rule disabled (three tests, including CP4's database refusal), the upper bound 366, the whole-day check removed (`+1 day 1 second`), and revocation allowed twice |
| V142 | Docker mutants, run B | 5 failed, 575 passed: revocation time unchecked killed all three `test_revocation_time_cannot_be_chosen` cases; usage time unchecked and usage allowed to move back, applied together, killed `test_usage_time_is_database_time` and `test_usage_time_never_goes_back`. Applied together, so this run does not show each usage test failing for its own rule alone |
| V143 | Migration review, CP6 only | No critical or high finding. Medium: a revoke or touch that loses a race is refused (23514) rather than ignored, since `now()` is the transaction start; ADR-0012 now requires filtered updates, which CP8 and CP9 test with two connections. Medium: the admin and expiry rules were owner decisions not yet in `PROJECT_SPEC.md`; the owner approved a spec clarification in CP6 (§5, credential issuance). Low: the ADR said no timestamp can be backdated, but an open transaction can; reworded as residual risk. Low: the docstring implied the guard checks server columns on insert; reworded, since grants cover them. Low: the round trip checked only the `INSERT` grant on downgrade; now every `UPDATE` grant too. Low: refusals were matched by SQLSTATE only; now by the guard's own message, with infinite expiries, upserts, `MERGE` and a combined update added |
| V144 | `scripts/verify.sh --fast` after the review fixes and the spec clarification | Passed: 362 unit tests; repository, history, hook, format, lint, type and import gates |
| V145 | Docker mutant, run C, against the review's new tests | The admin rule disabled, and the revocation-time and usage-time checks removed, together: 12 failed, 575 passed. All five new write-path cases failed (two upserts, `MERGE` update, `MERGE` insert, the combined update), with the earlier admin, revocation-time and usage-time tests. `test_usage_time_never_goes_back` passed, as it should, since the backwards check stayed. A first run of this mutant showed the `MERGE` insert reusing an existing digest, so it failed on a unique violation (23505) rather than for want of a refusal; it now uses a fresh digest. Limits: the mutants were applied together, so no single new case is shown failing for one rule alone, and the infinite-expiry cases were not mutated, being covered by the run A expiry mutants' rules. Restored byte for byte, confirmed with `cmp` |
| V146 | Final `scripts/verify.sh` | Passed: 587 tests, 98.19% coverage, smoke passed. Covers against PostgreSQL 18: read and ingest issuance by the runtime role, admin refused for it and still allowed for the migrator, server columns not insertable, expiry accepted only as 1, 30 or 365 whole 24-hour days under UTC and Europe/Paris and refused otherwise (including infinities), revocation once at database time, usage at database time and never backwards, scope, binding and identity not updatable, upserts and `MERGE` meeting the guard, every attempt to disable, drop or replace the guard refused, the guard function's owner, rights and `search_path`, the exact column privilege matrix, and a 0003 round trip removing every grant it added |

## P1 S2 CP7: credential issuance API

Run in this session on `b5348a9` with CP7 uncommitted. Docker-backed runs went through
`scripts/verify.sh`, each approved by the owner. No migration or grant changed.

| ID | Check | Outcome |
|---|---|---|
| V147 | New unit tests before the implementation | Both new unit files failed to import: `FieldProblem`, `IssuanceRejected` and `NewCredential` did not exist |
| V148 | Static guard met during the change | `test_lookup_returns_no_timestamp_to_compare` failed once the issuer, which returns `expires_at` for the 201, lived in `persistence/credentials.py`. The guard was kept; the issuer moved to `persistence/issuance.py`, so the authentication lookup still brings no expiry into Python |
| V149 | First full `scripts/verify.sh` | 2 failed, 673 passed: the time-zone expiry test under Europe/Paris and America/Santiago. A test defect: Python subtracts datetimes sharing a `tzinfo` as wall-clock time, so a correct 182-day expiry across a daylight-saving change measured one hour short. The stored values were correct, and the guard had accepted them. The test now compares absolute timestamps |
| V150 | Security review, CP7 only | No critical, high or medium finding. Low: `IssuedResponse` showed the token in its repr; confirmed, a failing test added, then fixed with `Field(repr=False)`. Low: an admin credential revoked after authentication but before the insert can still issue in that request; confirmed by reading, not fixed: AC11 makes revocation effective on the next request, no revoke route exists before CP8, and a re-check inside the issuing transaction would change CP3's model for every route. Recorded as a remaining risk |
| V151 | Unit mutants | 6 of 6 killed: use-case authorization removed, admin made issuable, the token stored instead of its digest, `Cache-Control: no-store` dropped, the read-binding rule removed, and lax `expires_in_days` parsing. Restored byte for byte, confirmed with `cmp` |
| V152 | Final `scripts/verify.sh` | Passed: 676 tests, 98.51% coverage, every CP7 module 100%, smoke passed. Covers against PostgreSQL 18: read and ingest issuance as the runtime role with only the digest and metadata stored, a scan of every column of every table for the token in five encodings, the issued token authenticating through CP3 with its own scope, expiry of 1, 30 and 365 days as exact 24-hour multiples of database time and 1, 182 and 365 days under UTC, Europe/Paris and America/Santiago, field-specific 422 for unregistered slugs with no echo and nothing written, admin, bad binding, out-of-range expiry and client timestamps refused with nothing written, expired and revoked admins refused, duplicate names, the issuer refused by the database when given admin scope, and an unreachable database |

## P1 S2 CP8: credential listing and revocation

Run in this session on `a4788ad` with CP8 uncommitted. Docker-backed runs went through
`scripts/verify.sh`. No migration or grant changed.

| ID | Check | Outcome |
|---|---|---|
| V153 | New unit tests before the implementation | `tests/unit/test_credential_admin_api.py` failed at collection: `shiptrace.application.credential_admin` did not exist |
| V154 | `scripts/verify.sh --fast` after the implementation | Passed: 474 unit tests; repository, history, hook, format, lint, type and import gates |
| V155 | Mutant: `AND revoked_at IS NULL` removed from the revoke `UPDATE`, full `scripts/verify.sh` | 3 failed, 733 passed: the repeat-revoke, already-revoked and concurrent-loser tests. The guard refused the unfiltered write (23514), which the API reported as 503. Restored; the final run below is on the restored code. Only this one mutant was run |
| V156 | Final `scripts/verify.sh` | Passed: 736 tests, 97.92% coverage, smoke passed. New against PostgreSQL 18: admin-only listing and revocation; no token or digest in any response; revoked and expired rows listed; a page walk in id order without gaps or repeats; a services cursor refused; revocation at database time; a revoked token refused on the next request (AC11); a repeat revoke returning 200 with the row's `xmin` unchanged; 404 for an unknown id and 422 for a malformed one; an admin revoking itself; an expired credential revoked; a two-connection race where the loser waits and returns the winner's time; the same race unfiltered refused by the guard; the runtime role's `UPDATE` columns still exactly `revoked_at` and `last_used_at`. Not covered: the `StoreUnavailable` paths in `persistence/lifecycle.py` |
| V157 | Owner correction: revoke rejects a non-empty body, then full `scripts/verify.sh` | The ignore-a-body unit test became `test_revoke_rejects_a_body_without_echoing_it` (three bodies: JSON with a timestamp, `{}`, raw text): 422 `validation_failed`, `errors` exactly `body` / `body_not_allowed`, no submitted value in the response, nothing revoked, and a bodyless retry then succeeds. The route-auth test sends no body to the revoke route. Written together with the fix, so it was not seen failing first. Passed: 738 tests, 97.93% coverage, smoke passed. The body check runs after authentication, so a missing or wrong credential still gets 401 or 403. `docs/api/openapi.json` does not exist yet, so no schema file changed. No further mutants were run |

## P1 S2 CP9: credential usage tracking

Run in this session on `e03637c` with CP9 uncommitted. Docker-backed runs went through
`scripts/verify.sh`. No migration, grant or contract changed.

| ID | Check | Outcome |
|---|---|---|
| V158 | Targeted integration run with bare `pytest` | Not possible: the sandbox cannot reach the Docker socket (`PermissionError: Operation not permitted`). Nothing was claimed from it; the Docker-backed evidence is V160 |
| V159 | `scripts/verify.sh --fast` before the lock-timeout change | Passed: 484 unit tests; repository, history, hook, format, lint, type and import gates |
| V160 | Final `scripts/verify.sh` with the 100 ms transaction-local lock timeout | Passed: 770 tests, 97.97% coverage (`persistence/credentials.py` 100%), smoke passed. New against PostgreSQL 18: first use recorded at database time; repeat use inside the window writes nothing; age boundary at 1, 299, 301 and 86400 seconds; no UPDATE statement for a fresh credential; expired, revoked and unknown credentials never marked used; a credential revoked between lookup and touch not marked used; the two-connection race (the loser waits on the row lock, authenticates, stores the winner's time, no timeout logged); a row lock held past 100 ms (the toucher returns while the lock is still held, authentication succeeds, nothing is stored, one log line with no SQL, identifier or SQLSTATE); `lock_timeout` back to 0 on the pooled connection after both a timeout and a success; 8 parallel first uses behind a barrier; HTTP status and body unchanged when the usage write fails |
| V161 | Limits | No mutant was run for CP9, so the timeout test was not seen failing against broken code. It is built so that removing `SET LOCAL` leaves the toucher blocked until `join`'s 30 s limit, failing `finished_while_locked`. The race test asserts the wait ended by commit through the absence of the timeout's log line, so a host stalled past 100 ms during the observer loop could fail it. Both timing-sensitive tests ran once, in V160 |

## P1 S2 closeout: acceptance gate and security review

Run in this session on `ac811ee`. Documentation changes only after V162 and V163.

| ID | Check | Outcome |
|---|---|---|
| V162 | S2 acceptance gate: `scripts/verify.sh --fast` and one full `scripts/verify.sh` | Passed: 488 unit tests in the fast gate; 770 tests, 97.97% coverage, smoke passed in the full gate. Migration head `0003` (parent `0002`); lockfile current; tracked tree clean. Signatures could not be checked inside the sandbox: `%G?` shows `E` for all commits, while `scripts/commit.py` printed `Good signature` for the CP9 commits. Not confirmed as `G` |
| V163 | One focused security review, CP6 to CP9 together (`security-reviewer`, read-only) | No critical or high finding, no blocker. By reading the code: the grants, guard trigger, `search_path`, ownership, `ON CONFLICT`, `MERGE` and `COPY` coverage, no token or digest in any response, listing or log, no cache on revocation, `SET LOCAL` scoped to the usage transaction and not leaking to the pool, one row lock per path so no deadlock, and a valid token causing at most one write per credential per 5 minutes. Limits: the reviewer did not read `tests/` or this log, ran nothing, and could not read `compose.override.yaml`, so its statements are not test evidence |
| V164 | Findings of V163, each checked against the code by the author | Confirmed, none fixed (the owner scoped the closeout to documentation). Medium: issuance and revocation are not logged and not attributable, so THREAT_MODEL T27's "revoke everything it issued" cannot be done from the data; recorded as T30 and accepted risk 10, to be fixed before release. Low: THREAT_MODEL T19 was stale after `0003`; updated, with T28. Low: if the usage grant is ever missing, every stale request logs a warning and nothing alerts (T29). Low: `SET LOCAL lock_timeout = '100ms'` is longer than a configured `db_lock_timeout_ms` below 100 (the setting allows 1 ms and up; the default is 2000 ms) (T29) |
| V165 | Documentation closeout | `THREAT_MODEL.md`: status line, T19 residual, T27 notes, new T28 to T31, accepted risks 9 and 10. `ASVS_ASSESSMENT.md`: an S2 evidence index and a note on 16.3; no status changed, every row stays `Planned`. `PROJECT_SPEC.md`: the stale "Proposed for owner approval with CP8" now says approved with CP8 and implemented at `e03637c`. `python3 -I scripts/check_repo.py` passed. The full suite was not rerun, since only documents changed after V162 |

## P1 S3 CP10: event types and derived status

Run in this session on `87f6e91`, with CP10 committed as `bffb2cf`. Pure domain change: no
migration, grant, route or dependency changed.

| ID | Check | Outcome |
|---|---|---|
| V166 | Test-first implementation | `tests/unit/test_deployment_status.py` was written first and failed at collection with `ModuleNotFoundError` for `shiptrace.domain.deployments`. `EventType`, `Status`, `TERMINAL` and `derive_status` were then added, and the new file passed (52 tests) |
| V167 | Coverage of event sets | 9 valid sets (`started` alone; each terminal alone and after `started`; `succeeded` + `reverted`, with and without `started`) and 14 impossible sets (empty; repeated type; two or three terminal types; `reverted` alone, after `started`, or after `failed` or `cancelled`), each tried in every order. Valid sets give one status in every order; impossible sets raise `ValueError` in every order. Also checked: the enum values, `TERMINAL`, a one-shot iterator, and a plain string refused as an event type |
| V168 | Two targeted mutants | Removing the check that `reverted` requires `succeeded` failed 10 tests. Removing the more-than-one-terminal check failed 11. Both were reverted and the file confirmed identical with `diff`. No broader mutation run was made |
| V169 | `scripts/verify.sh --fast` | Passed: 540 unit tests; repository, history, commit-rule, hook, lockfile, format, lint, type and import-boundary gates (3 contracts kept) |
| V170 | Limits | No Docker-backed test, security reviewer or full `scripts/verify.sh` was run, which is intended for a pure-domain checkpoint. Hypothesis is not a locked dependency, so order independence is shown by exhaustive permutation of small sets, not generated histories. Rules R1 to R11 are not yet implemented; the decision function starts at CP12 |

## P1 S3 CP11 prerequisite: field formats, rule precedence and ADR acceptance

Documentation only, run in this session on `0b6a049`. Committed as `45e50ac` (spec) and `81c0378`
(ADR-0003 and ADR-0004).

| ID | Check | Outcome |
|---|---|---|
| V171 | `python3 -I scripts/check_repo.py` after the spec and ADR edits, and again after the IPv4 correction | Passed both times (`repository checks: OK`) |
| V172 | Scope and limits | The owner approved the final event field formats, the R1 to R11 precedence order and the acceptance of ADR-0003 (terminal types named) and ADR-0004 on 2026-11-10. No code, test or validator changed, and no test suite, Docker run or reviewer was run. `source_url` validation and the precedence order are specified but not yet implemented or tested |

## P1 S3 CP11: event field validators

Run in this session on `0b523b2`, with CP11 committed as `f8e8c0c`. Pure domain change in
`domain/event_fields.py`; standard library only; no migration, route or dependency changed.

| ID | Check | Outcome |
|---|---|---|
| V173 | Test-first implementation | `tests/unit/test_event_fields.py` was written first and failed at collection with `ModuleNotFoundError` for `shiptrace.domain.event_fields`. With the module added, all tests passed on the first run, so the evidence that they can fail is V174, not a red run on the logic |
| V174 | Targeted mutants | 20 one-line mutants of the validators (digest case, length bounds, reason controls and bidi range, second `#`, IPv6 zone, IPv4 check, port bounds, encoded controls, malformed escapes, host length, scheme, URL length and character set, version pattern, `any` to `all`). 19 were caught. The survivor removes the explicit `@` (userinfo) check. It is redundant, since any `@` in the authority already fails the host, port or bracket checks, and the owner chose to keep the explicit check for clarity. No broader mutation run was made |
| V175 | Owner decisions recorded as tests or kept | DEL (U+007F) rejected in `reason`; numeric-looking hosts must be valid IPv4 (`999.1.1.1`, `1.2.3`, `123` rejected); a port with leading zeros is accepted when its value is 1 to 65535 (`https://ci.example.com:0080/` added as a test); U+2028, U+2029, U+200E and U+200F stay allowed in `reason` |
| V176 | `uv run --frozen pytest tests/unit/test_event_fields.py -q`, then `scripts/verify.sh --fast` | Passed: 301 tests in the new file; 841 unit tests in the fast gate; repository, history, hook, lockfile, format, lint, type and import-boundary gates (3 contracts kept) |
| V177 | Limits | Docker-backed tests, security reviewers and the full `scripts/verify.sh` were intentionally omitted for a pure-domain checkpoint. The validators are not yet wired to any route or store, so no HTTP or database behavior is claimed. The allowance for U+2028, U+200E and U+200F is pinned by a test; U+2029 is not |

## P1 S3 CP12: deployment decision rules R1 to R10

Run in this session on `fbed5a5`, with CP12 committed as `e65a715`. Pure domain change in
`domain/deployments.py`: `NewEvent`, `StoredEvent`, `DeploymentFacts`, `Accept`, `Duplicate`,
`Reject`, `RejectReason` and `decide`. No migration, route or dependency changed, and R11 is not
part of it.

| ID | Check | Outcome |
|---|---|---|
| V178 | Test-first implementation | `tests/unit/test_deployment_decision.py` was written first and failed at collection with `ImportError: cannot import name 'Accept'`. After the implementation, the new file and the CP10 status tests passed together (209 tests). A missing `dataclass` import, removed by the formatter hook after a first partial edit, was restored before that run |
| V179 | Independently specified matrix | A hand-written table of the expected outcome for each of the 9 valid stored event sets against each of the 5 incoming types (45 cases), with identical content so only the rules decide. A guard test checks that the table covers every valid set. The table was written from the spec's precedence order, not from the code |
| V180 | Other coverage | Per rule R1 to R10, including R7 leaving derived status unchanged; R3 returning the stored event object itself and not mutating its input; R4 with absent against present content and exact-case comparison; R5 for every event type and ahead of R3, R4, R6, R9 and R10; a replay of the stored terminal event as R3 or R4 and not R6; a `reverted` replay as R3 or R4 and not R9 or R10; stable rejection codes; frozen value types; independence from stored-event order; 10 corrupt stored sets against all 5 incoming types raising `ValueError`, including before an attribute conflict |
| V181 | Retryability | Fixed by the owner: only `revert_requires_success` is retryable; `event_conflict`, `deployment_attribute_conflict`, `terminal_conflict` and `revert_not_applicable` are not. The flag is a domain classification only. No HTTP `Retry-After` is derived from it; that mapping belongs to S5 |
| V182 | Targeted mutants | 13 one-line mutants of `decide` and `RejectReason`: the R5 check (both parts, and `or` to `and`), the R4 comparison (each half), the identity of the returned original, R10, R9 with a deployment, R9 with none, R6, the retryable flag, the corruption check, same-type replay of `reverted`, and a frozen `Reject`. All 13 were caught. No broader mutation run was made |
| V183 | `scripts/verify.sh --fast` | Passed: 998 unit tests (841 before CP12, 157 new); repository, history, hook, lockfile, format, lint, type and import-boundary gates (3 contracts kept) |
| V184 | Limits | Docker-backed tests, security reviewers and the full `scripts/verify.sh` were intentionally omitted for a pure-domain checkpoint. `decide` is not wired to any route or store. It trusts format-checked input, and it raises on corrupt stored data instead of returning a decision; how S4 and S5 handle that is not yet decided |

## P1 S3 CP13: credential binding (R11) and domain histories

Run in this session on `13aabf3`. Pure domain and test change: `binding_matches` in
`domain/deployments.py`, two new test files. No migration, route or dependency change.

| ID | Check | Outcome |
|---|---|---|
| V185 | Test-first implementation | `tests/unit/test_deployment_binding.py` and `tests/unit/test_deployment_histories.py` were written first. The binding file failed at collection with `ImportError: cannot import name 'binding_matches'`. After `binding_matches` was added, both files passed (191 tests). The histories file exercises `decide` and `derive_status`, which already existed, so it did not fail before the change; its ability to fail is shown by V187 |
| V186 | R11 | `binding_matches(bound_service, bound_environment, service, environment)` is an exact comparison of both pairs and returns a `bool`. Tests cover another service, another environment, both, swapped values, case, prefix and extension, whitespace and newline, empty strings, a look-alike character and NFC against NFD. A test pins the four-slug parameter list, so the function cannot take a deployment or a registry and its answer cannot depend on the target existing. The binding as ids on `Principal` and how S4 or S5 supplies bound slugs are not decided here |
| V187 | Histories | Exhaustive, no sampling and no Hypothesis (not in `uv.lock`). Each of the 9 valid event sets in every order, with `revert_requires_success` retried until nothing changes: the same status, each event stored exactly once, no deployment without events, and a rejected first `reverted` creating no deployment. Fifty identical submissions give one write and 49 duplicates. A replay of any stored event returns that stored object and writes nothing. All 24 orders of started plus the three terminals store only the first terminal and reject the others with `terminal_conflict`; the final statuses are deliberately not equal across orders. All 120 orders of those four plus `reverted` follow the first terminal: `reverted` when it is `succeeded`, otherwise `revert_not_applicable`. A `reverted` before its success is accepted on retry and ends `reverted`; after a failure it stays `revert_not_applicable` on every retry. Rejections repeat and change nothing. A corrupt stored set makes `decide` raise for every incoming type |
| V188 | Targeted mutants | 11 mutants against the two new files plus 2 corrected re-runs. Caught: `and` to `or` in R11, dropping either pair, case folding, `retryable` forced false, R6 removed, replay returning `Accept`, a `reverted` creating a deployment, the R9 no-terminal branch removed, and (after V187's corruption test was changed to call `decide` directly) the corruption check removed. Two first survived: one was a mutation of `derive_status` and not of `decide`, covered by the CP10 file; the other was the corruption check, which the earlier test hid because the test store re-validated afterwards. The real R10 branch of `decide`, removed, is caught by both the CP12 file and the new histories file |
| V189 | Correction to V182 | V182 lists an R10 mutant as caught. The pattern used (`if terminal != [EventType.SUCCEEDED]:`) matched `derive_status` first, so that mutant changed `derive_status` and not R10 in `decide`. It was caught by the corruption tests, as recorded. The R10 branch in `decide` was first mutated in V188, and is caught. The CP12 claim of 13 of 13 caught is otherwise unchanged, but one of the 13 did not test what V182 says |
| V190 | Domain branch coverage | `uv run --frozen pytest tests/unit -q --cov=shiptrace.domain --cov-branch --cov-report=term-missing`: 1189 passed; `shiptrace.domain` 209 statements, 68 branches, 0 missed, 100%. Each module (`credentials`, `deployments`, `event_fields`, `names`) is 100%. This is from unit tests alone and meets the 95% P1 gate for the domain; the whole-package figure is still taken by the full `scripts/verify.sh`, which was not run |
| V191 | `scripts/verify.sh --fast` | A first run stopped at mypy (an unannotated `log` in the histories helper); fixed, rerun. Passed: 1189 unit tests (998 before CP13, 191 new); repository, history, hook, lockfile, format, lint, type and import-boundary gates (3 contracts kept) |
| V192 | Limits | No Docker-backed test, security reviewer or full `scripts/verify.sh` was run. The histories use an in-test store that writes on `Accept`; they model S4, they do not test it. Concurrency (AC2, AC3), the database indexes, the HTTP mapping and the ordering of R11 before any lookup remain for S4 to S6. Open for S4 and S5: `Principal` holds `service_id` and `environment_id`, but `binding_matches` compares slugs and ARCHITECTURE §4 step 3 requires that comparison before the event's slugs are resolved. The credential lookup must therefore also return the bound service and environment slugs, for example by joining the registry, or R11 would have to resolve the event's slugs first and could reveal whether a target exists (AC7). Not decided or implemented here |
