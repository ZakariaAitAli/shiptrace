#!/usr/bin/env python3
"""PostToolUse hook: format and lint an edited Python file.

Hooks run outside the sandbox, so this must never run anything the sandbox can write. It uses only
the project's own protected .venv, and never trusts the payload's working directory.
"""

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    payload = json.load(sys.stdin)
    raw_path = payload.get("tool_input", {}).get("file_path", "")
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project or not raw_path.endswith(".py") or ".claude/" in raw_path:
        return
    root = Path(project).resolve()
    cwd = Path(payload.get("cwd", ".")).resolve()
    ruff = root / ".venv/bin/ruff"
    if cwd != root or not (root / raw_path).resolve().is_relative_to(root) or not ruff.exists():
        return
    for args in (["format", raw_path], ["check", "--fix", raw_path]):
        result = subprocess.run(
            [str(ruff), *args, "--config", str(root / "pyproject.toml")],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            print(result.stdout[-2000:] + result.stderr[-1000:], file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    main()
