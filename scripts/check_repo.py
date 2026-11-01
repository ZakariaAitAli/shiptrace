#!/usr/bin/env python3
"""Deterministic repository checks: Claude config contract and documentation integrity."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAUDE = ROOT / ".claude"
EDIT_TOOLS = {"Write", "Edit", "NotebookEdit", "Agent"}
REQUIRED_GATES = (
    "scripts/check_repo.py",
    "scripts/check_history.py",
    "scripts/test_commit_msg.py",
    "scripts/test_check_history.py",
    "scripts/test_pre_commit.py",
    ".claude/hooks/tests/test_hooks.py",
    "uv lock --check",
    "ruff format --check",
    "ruff check",
    "uv run --frozen mypy",
    "lint-imports",
    "uv build --wheel",
    "pytest --cov",
    "--cov-fail-under",
    "scripts/smoke.sh",
)
errors: list[str] = []


def frontmatter(path: Path) -> dict[str, str]:
    """Reads top-level `key: value` pairs. Enough for this repo; stdlib has no YAML parser."""
    text = path.read_text()
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        errors.append(f"{path}: missing frontmatter")
        return {}
    pairs = re.findall(r"^([A-Za-z-]+):[ ]?(.*)$", match[1], re.MULTILINE)
    return dict(pairs)


def check_skills() -> None:
    skills = sorted((CLAUDE / "skills").glob("*/SKILL.md"))
    if len(skills) != 5:
        errors.append(f"expected 5 skills, found {len(skills)}")
    for path in skills:
        meta = frontmatter(path)
        directory = path.parent.name
        if meta.get("name") != directory:
            errors.append(f"{path}: name must equal directory {directory}")
        if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", directory) or len(directory) > 64:
            errors.append(f"{path}: invalid skill name")
        if not 1 <= len(meta.get("description", "")) <= 1024:
            errors.append(f"{path}: description must be 1-1024 characters")
        if len(path.read_text().splitlines()) >= 500:
            errors.append(f"{path}: must stay under 500 lines")


def check_agents() -> None:
    agents = sorted((CLAUDE / "agents").glob("*.md"))
    if len(agents) != 4:
        errors.append(f"expected 4 agents, found {len(agents)}")
    for path in agents:
        text = path.read_text()
        meta = frontmatter(path)
        tools = {t.strip() for t in meta.get("tools", "").split(",")}
        disallowed = {t.strip() for t in meta.get("disallowedTools", "").split(",")}
        if tools & EDIT_TOOLS:
            errors.append(f"{path}: reviewers must not have edit or agent tools")
        if not disallowed >= EDIT_TOOLS:
            errors.append(f"{path}: disallowedTools must list {sorted(EDIT_TOOLS)}")
        if "readonly_bash.py" not in text or "onFailure: block" not in text:
            errors.append(f"{path}: must use the read-only Bash hook, failing closed")


def check_settings() -> None:
    settings = json.loads((CLAUDE / "settings.json").read_text())
    permissions = settings["permissions"]
    if permissions.get("disableBypassPermissionsMode") != "disable":
        errors.append("settings.json: bypass mode must be disabled")
    guards = settings["hooks"]["PreToolUse"]
    for group in guards:
        for hook in group["hooks"]:
            script = re.search(r"\.claude/hooks/(\w+\.py)", hook["command"])
            if not script or not (CLAUDE / "hooks" / script[1]).exists():
                errors.append(f"settings.json: missing hook script in {hook['command']}")
            if hook.get("onFailure") != "block":
                errors.append(f"settings.json: guard must fail closed: {hook['command']}")
    sandbox = settings.get("sandbox")
    if sandbox and not (
        sandbox.get("enabled") is True
        and sandbox.get("failIfUnavailable") is True
        and sandbox.get("allowUnsandboxedCommands") is False
    ):
        errors.append("settings.json: sandbox must fail closed and forbid unsandboxed retries")
    excluded = {f"Bash({command})" for command in (sandbox or {}).get("excludedCommands", [])}
    if not excluded <= set(permissions.get("ask", [])):
        errors.append("settings.json: every sandbox exclusion must need approval per run")
    if excluded & set(permissions.get("allow", [])):
        errors.append("settings.json: a sandbox exclusion must not be auto-allowed")


def check_verify_script() -> None:
    script = (ROOT / "scripts/verify.sh").read_text()
    for gate in REQUIRED_GATES:
        if gate not in script:
            errors.append(f"scripts/verify.sh is missing a gate: {gate}")


def check_documents() -> None:
    if (lines := len((ROOT / "CLAUDE.md").read_text().splitlines())) >= 200:
        errors.append(f"CLAUDE.md has {lines} lines; keep it under 200")
    documents = [ROOT / "README.md", ROOT / "CLAUDE.md", *(ROOT / "docs").rglob("*.md")]
    for path in documents:
        for target in re.findall(r"\]\((?!https?://|#)([^)#\s]+)", path.read_text()):
            if not (path.parent / target).exists():
                errors.append(f"{path.relative_to(ROOT)}: broken link {target}")
    index = (ROOT / "docs/adr/README.md").read_text()
    for adr in (ROOT / "docs/adr").glob("[0-9]*.md"):
        if adr.name not in index:
            errors.append(f"{adr.name}: missing from ADR index")
        if not re.search(r"^Status: ", adr.read_text(), re.MULTILINE):
            errors.append(f"{adr.name}: missing Status line")
    assessment = (ROOT / "docs/security/ASVS_ASSESSMENT.md").read_text()
    for row in re.findall(r"^\|.*\| Pass \|$", assessment, re.MULTILINE):
        if "](" not in row:
            errors.append(f"ASVS row claims Pass without linked evidence: {row[:50]}")


def main() -> int:
    for check in (check_skills, check_agents, check_settings, check_verify_script, check_documents):
        check()
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    print("repository checks: " + ("FAILED" if errors else "OK"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
