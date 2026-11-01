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
written script. They stop mistakes, and are not a security boundary. A real boundary needs the
OS sandbox, which needs `socat` on this machine, and cannot wrap Docker.

**Rejected.** *Long CLAUDE.md*: docs target under 200 lines, and adherence falls as it grows.
*`sandbox.failIfUnavailable` committed now*: would stop Claude Code from starting until the
missing package is installed. *Stop hook running the suite*: slow, and it re-runs on every
turn; the `verify-slice` skill does this at the right moment instead.
