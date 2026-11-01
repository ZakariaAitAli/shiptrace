# Claude Code Capability Evaluation

Reviewed 2026-11-01 for Claude Code 2.1.316 against code.claude.com/docs, agentskills.io and the
`anthropics/claude-plugins-official` repository. Decisions are recorded in ADR-0010.

| Capability | Documented behaviour that matters | Decision |
|---|---|---|
| **CLAUDE.md** | Context, not enforcement; target under 200 lines | Short facts only |
| **Path-scoped rules** | `paths:` frontmatter; loaded when a matching file is read or edited | Four rules, for domain, persistence/migrations, API and tests |
| **Agent Skills** | `SKILL.md`; `name` must match the directory; description ≤ 1024 by spec; `disable-model-invocation`, `context: fork`, `agent` | Five skills. Side-effect-free procedures only |
| **Subagents** | `tools`, `disallowedTools`, frontmatter `hooks`, `maxTurns`; can nest unless `Agent` is removed | Four reviewers: no edit tools, no `Agent`, read-only Bash hook |
| **Hooks** | `PreToolUse` deny blocks a call; non-2 exit codes **fail open** unless `onFailure: "block"`; docs recommend permissions for hard rules because `if` is best-effort | Three hooks; guards fail closed, with no reliance on `if` |
| **Permissions** | Deny, then ask, then allow; deny applies to subcommands, substitutions and subshells | Deny list for secrets and outward actions; `disableBypassPermissionsMode` |
| **Sandboxing** | bubblewrap and socat on Linux/WSL2; Docker is incompatible and must be excluded; reads default wide open, including `~/.ssh` | Recommended once `socat` is installed. Not committed yet: see below |
| **Worktrees** | `--worktree`, `isolation: worktree`; need a first commit; `${CLAUDE_PROJECT_DIR}` does not follow into a worktree, while `cwd` does | Use for parallel implementation later; hooks read `cwd` from input |
| **Plugins** | Run as you, add per-session cost, marketplace does not vet behaviour | None installed |
| **MCP** | Adds tools and injection surface | None. `gh` CLI and doc fetching suffice |

## Plugin review (read only, none installed)

| Plugin | Origin | What executes | Decision |
|---|---|---|---|
| `pyright-lsp` | Anthropic | Config only (2 files); spawns locally installed `pyright-langserver` | Optional later. mypy stays the gate, so two type checkers would disagree without benefit. Candidate if code navigation becomes a real need |
| `security-guidance` | Anthropic | Hooks on session start, every prompt, edits and commits; **creates a venv and pip-installs the Agent SDK on session start**; LLM review on Stop | Decline: broad hook footprint, runtime install and usage cost. `security-reviewer` runs at milestones |
| `claude-security` | Anthropic | 46 files, multi-agent scanner | Decline for now; reconsider for the P6 assessment after full review |
| `pr-review-toolkit` | Anthropic | Markdown agents and a command | Decline: overlaps project reviewers, which are tailored to this spec |
| `hookify` | Anthropic | Python rule engine | Decline: hooks here are small, tested and in the repository |

`anthropics/skills` was considered for its authoring guidance only. No third-party skill is used;
project skills are original, small and reviewable.

Connected claude.ai services (Gmail, Calendar, Drive) are unrelated to this project and are not
used. Consider disabling them for this project.

## Known guard limitations

- The hook scans the whole command text, including heredoc bodies. Prose that mentions a blocked
  command can be refused. It fails safe; write such text with the Write tool.
- `grep -r` over the repository reads secrets without a prompt, because `Read` deny rules do not
  cover Bash. Only the sandbox's `denyRead` closes this.
- Scripts written to disk and then run are out of reach, by design.

## Sandbox setup (owner step)

`bwrap` is installed and `kernel.apparmor_restrict_unprivileged_userns` does not exist on this
kernel, so the AppArmor issue does not apply. Only `socat` is missing:

```bash
sudo apt-get install socat
```

Then add to `.claude/settings.local.json`, and move to `settings.json` once proven:

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "excludedCommands": ["docker compose *", "docker ps *", "docker logs *"],
    "filesystem": { "denyRead": ["~/.ssh", "~/.aws", "~/.config/gh", "~/.claude/.credentials.json"] }
  }
}
```

Testcontainers needs the Docker socket, which is incompatible with this sandbox, so integration
tests must run through an excluded command. Excluded commands have full access, and an agent
that can write a Compose file can use it to escape. That residual risk stays documented.

`allowUnsandboxedCommands: false` also removes the retry path around the sandbox, so test this
in a separate session first.

## Sources

- https://code.claude.com/docs/en/memory
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/sub-agents
- https://code.claude.com/docs/en/hooks
- https://code.claude.com/docs/en/permissions
- https://code.claude.com/docs/en/sandboxing
- https://code.claude.com/docs/en/plugins/overview
- https://code.claude.com/docs/en/worktrees
- https://agentskills.io/specification
- https://github.com/anthropics/claude-plugins-official
