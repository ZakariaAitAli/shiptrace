#!/usr/bin/env python3
"""Every commit must follow the commit standards and must carry a signature."""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from commit_msg import problems

FIELD, RECORD = "\x1f", "\x1e"
# G good; U good but untrusted key; E cannot be checked here, because the key is not available.
# Anything else means no signature or a bad one.
SIGNED = {"G", "U", "E"}


def violations(log: str) -> list[str]:
    found = []
    for record in filter(str.strip, log.split(RECORD)):
        commit, signature, message = record.strip().split(FIELD, 2)
        if signature not in SIGNED:
            found.append(f"{commit[:7]}: signature status {signature}")
        found.extend(f"{commit[:7]}: {problem}" for problem in problems(message))
    return found


def main() -> int:
    log = subprocess.run(
        ["git", "log", f"--format=%H{FIELD}%G?{FIELD}%B{RECORD}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    found = violations(log)
    for violation in found:
        print(f"history: {violation}", file=sys.stderr)
    print(f"history checks: {'FAILED' if found else 'OK'}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
