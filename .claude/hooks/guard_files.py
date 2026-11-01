#!/usr/bin/env python3
"""PreToolUse guard for file edits: protected paths, applied migrations, and secret content."""

import json
import os
import re
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

# Names and globs matched against the file name; generated files must come from their tools.
PROTECTED_NAMES = {
    ".env": "secrets file",
    "uv.lock": "generated: use `uv add` or `uv lock`",
    "actions.lock": "generated: use `gh actions-lock`",
}
PROTECTED_GLOBS = {
    ".env.*": "secrets file",
    "*.pem": "key material",
    "*.key": "key material",
    "*.tfstate*": "Terraform state",
    "*.tfvars": "may hold secrets",
}
ALLOWED_NAMES = {".env.example"}
# Run or read by commands outside the sandbox, so they change only with the owner.
TRUSTED_EXECUTED = re.compile(
    r"^(scripts/.+|compose[\w.-]*\.ya?ml|pyproject\.toml|\.git/.+)$"
)

SECRET_PATTERNS = {
    "AWS access key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub token": r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b",
    "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "ShipTrace token": r"\bst1_[A-Za-z0-9_-]{40,}\b",
    "credentialed database URL": r"postgres(ql)?(\+\w+)?://[^:\s/@]+:(?!\{|\$|<|change)[^@\s]+@",
}


def is_tracked_migration(path: Path, cwd: str) -> bool:
    if "migrations/versions" not in path.as_posix() or path.suffix != ".py":
        return False
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(path)],
        cwd=cwd,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def path_problem(raw_path: str, cwd: str) -> str | None:
    if not raw_path:
        return None
    root = Path(os.path.abspath(cwd))
    path = Path(os.path.normpath(root / raw_path))  # So x/../ cannot hide a protected path.
    name = PurePosixPath(path.as_posix()).name
    if name in ALLOWED_NAMES:
        return None
    if name in PROTECTED_NAMES:
        return f"{name}: {PROTECTED_NAMES[name]}"
    for pattern, why in PROTECTED_GLOBS.items():
        if fnmatch(name, pattern):
            return f"{name}: {why}"
    if re.search(r"(^|/)\.claude/(hooks/|settings(\.local)?\.json$)", path.as_posix()):
        return f"{name}: agent guardrails change only with the owner, who edits them directly"
    if path.is_relative_to(root) and TRUSTED_EXECUTED.search(path.relative_to(root).as_posix()):
        return f"{name}: runs outside the sandbox, so it changes only with the owner"
    if is_tracked_migration(path, cwd):
        return f"{name}: applied migrations are immutable, add a new one"
    return None


def content_problem(tool_input: dict) -> str | None:
    text = "\n".join(
        str(tool_input.get(key, "")) for key in ("content", "new_string", "new_source")
    )
    for label, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            return f"content looks like a {label}"
    return None


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        tool_input = payload.get("tool_input", {})
        raw_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        problem = path_problem(raw_path, payload.get("cwd", ".")) or content_problem(tool_input)
    except Exception as error:  # noqa: BLE001 - a broken guard must block, never allow.
        problem = f"guard error ({type(error).__name__})"
    if problem:
        print(f"Blocked by .claude/hooks/guard_files.py: {problem}.", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
