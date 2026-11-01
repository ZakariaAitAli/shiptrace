# ADR-0010: Minimal Claude Code config; enforcement over instruction

Status: Proposed · Date: 2026-11-01

**Context.** Official docs state that CLAUDE.md is context, not enforced configuration, while
permission rules and hooks are enforced by the client. Evaluation:
[engineering/CLAUDE_CODE_EVALUATION.md](../engineering/CLAUDE_CODE_EVALUATION.md).

**Decision.** Put each rule in the strongest layer that can hold it.

| Layer | Used for |
|---|---|
| Permission `deny` rules | Secrets paths, outward and destructive commands; bypass mode disabled |
| Hooks (`onFailure: block`) | Same rules with command parsing; protected files; secret patterns |
| Tests and CI | Everything that must hold regardless of who wrote the code |
| Agent frontmatter | Reviewers lose edit tools; Bash limited to a read-only allowlist |
| Skills | Repeatable procedures, loaded on demand |
| Path-scoped rules | Conventions for one code area |
| CLAUDE.md | Short facts needed every session |

**Outward actions are denied to the agent, not merely prompted.** Pushing, merging, `aws`, and
`terraform apply` are blocked in hooks. When you approve one, you run it yourself with `! <cmd>`,
which is the plainest possible approval record.

**No plugins or MCP servers now.** Reviewed official plugins were not installed: each adds
per-session cost, and project skills cover the need. No MCP server is needed; `gh` and docs
fetching suffice, and each server widens the injection surface.

**Limits, stated plainly.** Text-based command guards can be evaded by indirection, such as a
written script, or by a tool that rewrites files, as `ruff format .` once did to a hook. They stop
mistakes, and are not a security boundary. The OS sandbox is the stronger control, and is active
through guard patch v3, applied by the owner in `a0ee681`.

**Sandbox design, as applied.**

| Tier | Commands | Runs | Approval |
|---|---|---|---|
| Sandboxed | Everything, including `scripts/verify.sh --fast` | Inside the sandbox | None |
| Excluded | `scripts/verify.sh`, `scripts/smoke.sh`, `git commit` | Outside the sandbox | Each run |

- Docker cannot run in the sandbox, and signing fails there, so these exclusions are needed.
- Every exclusion must be an `ask` rule and must not be an `allow` rule; `check_repo.py` enforces it.
- The sandbox refuses to start when unavailable, and forbids unsandboxed retries.
- `scripts/`, Compose files, `pyproject.toml`, `uv.lock`, `.venv`, `.git/config` and `.gitleaks.toml`
  are read-only to sandboxed commands, and hooks block the edit tools on them. `UV_NO_SYNC` stops
  `uv run` rebuilding `.venv`, while the smoke test's explicit `uv sync` installs only from the
  protected lockfile. Dependency changes become owner actions.

**Practical consequences, observed once active.** `scripts/` being protected means changes to gates
and repository checks are owner patches, even when the owner has asked for them. Docker gates outside
the two named scripts, such as `check_gates.py`, are owner-run. Inside the sandbox, `git status` lists
its `/dev/null` placeholders as untracked, so stage explicit paths and never `git add -A`. Signatures
read `E` there, because `~/.gnupg` is hidden, so a good signature can only be confirmed outside it.

**What remains.** Approval is the only control over the full run. `scripts/verify.sh` runs `src/`
and `tests/`, which the agent can edit, with full access, so approving it means trusting that code.
The stronger answer is running integration tests in a container with no Docker socket and no home
directory, and that is left for the owner to schedule. `autoAllowBashIfSandboxed` stays on, so
sandboxed commands run unprompted; that is acceptable only because of the deny lists above.

**Rejected.** *Long CLAUDE.md*: docs target under 200 lines, and adherence falls as it grows.
*Stop hook running the suite*: slow, and it re-runs on every
turn; the `verify-slice` skill does this at the right moment instead.
