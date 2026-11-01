#!/usr/bin/env python3
"""Every commit must follow the commit standards and carry the owner's signature."""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from commit_msg import problems

FIELD, RECORD = "\x1f", "\x1e"
# G good; U good but untrusted key; E the public key is not available here to verify with.
# Anything else means no signature or a bad one. E is accepted only for the owner's key ID, so a
# clone without the public key still checks who signed, but cannot prove it.
SIGNED = {"G", "U", "E"}
OWNER_KEY_ID = "9656DC342415CDB2"
OWNER_EMAIL = "zakaria-aitali@outlook.com"


def violations(log: str) -> list[str]:
    found = []
    for record in filter(str.strip, log.split(RECORD)):
        commit, signature, key, email, message = record.strip().split(FIELD, 4)
        if signature not in SIGNED:
            found.append(f"{commit[:7]}: signature status {signature}")
        if key != OWNER_KEY_ID:
            found.append(f"{commit[:7]}: signed by key {key or 'none'}")
        if email != OWNER_EMAIL:
            found.append(f"{commit[:7]}: unexpected author")
        found.extend(f"{commit[:7]}: {problem}" for problem in problems(message))
    return found


def main() -> int:
    log = subprocess.run(
        ["git", "log", f"--format=%H{FIELD}%G?{FIELD}%GK{FIELD}%ae{FIELD}%B{RECORD}"],
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
