#!/usr/bin/env python3
"""PostToolUse hook: format and lint an edited Python file. No-op until P0 adds pyproject.toml."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> None:
    payload = json.load(sys.stdin)
    raw_path = payload.get("tool_input", {}).get("file_path", "")
    cwd = Path(payload.get("cwd", "."))
    if not raw_path.endswith(".py") or ".claude/" in raw_path:
        return
    if not (cwd / raw_path).resolve().is_relative_to(cwd.resolve()):
        return
    if not (cwd / "pyproject.toml").exists() or shutil.which("uv") is None:
        return
    for args in (["format", raw_path], ["check", "--fix", raw_path]):
        result = subprocess.run(
            ["uv", "run", "--frozen", "ruff", *args],
            cwd=cwd,
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
