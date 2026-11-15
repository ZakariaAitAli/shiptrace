#!/usr/bin/env python3
"""Every commit must follow the commit standards and carry the owner's signature.

Signing-key rotation (ADR-0013). History is split at ROTATION_BOUNDARY:

* Commits reachable from the boundary (the historical set) were signed with the retired key.
  Its public key could not be recovered, so Git reports `E` for them and the signature cannot be
  checked. `E` is accepted only for that set and only when the claimed key ID is RETIRED_KEY_ID.
  `E` does NOT prove the commit was signed by that key: it records which key the commit claims.
* Every other commit must verify as exactly `G` and must be signed by the key whose complete
  fingerprint is CURRENT_KEY_FINGERPRINT. The retired key can never authorize a new commit.
* The check fails closed if the boundary is missing, is not an ancestor of HEAD, or the
  repository is shallow, because the historical set cannot then be established.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from commit_msg import problems

# `git log -z` ends each record with NUL and the format below separates fields with NUL. Git refuses
# NUL in a commit message and in an identity, so no commit can forge a field or a record. The old
# 0x1e and 0x1f separators were accepted by Git inside messages and emails, so a crafted commit
# could split its own record.
SEP = "\0"
LOG_FORMAT = "%x00".join(("%H", "%G?", "%GK", "%GF", "%ae", "%B"))
OWNER_EMAIL = "zakaria-aitali@outlook.com"

# Retired on 2026-11-12. Its public key is unavailable, so only the claimed key ID can be checked.
RETIRED_KEY_ID = "9656DC342415CDB2"
# The last commit signed with the retired key. Never move this: it fixes what the retired key may
# vouch for. A later rotation adds its own boundary instead of changing this one.
ROTATION_BOUNDARY = "e436568b582c0d3b43825c1bb8bb424db97b8e31"
# The key that signs every commit after the boundary, as the full 40-hex fingerprint of the
# signing key (`%GF`). A 64-bit key ID is not accepted: it can be forged.
CURRENT_KEY_FINGERPRINT = "0C8D2B652F6D7010116DE44AEFF6790D7412A56C"

# For the historical set only. G good; U good but untrusted key; E the public key is not available
# to verify with. Anything else means no signature or a bad one.
HISTORICAL_STATUSES = {"G", "U", "E"}
# After the boundary a signature must verify, so only G.
CURRENT_STATUSES = {"G"}
FIELDS = 6


def run(args: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        # Replace refs and grafts must not change which commits, parents or messages are checked.
        ["git", "--no-replace-objects", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
    )


def violations(log: str, historical: frozenset[str]) -> list[str]:
    """Checks `git log` output. `historical` holds the full hashes reachable from the boundary."""
    tokens = log.split(SEP)
    if tokens and tokens[-1] == "":
        tokens.pop()  # the terminator of the last record
    if len(tokens) % FIELDS:
        return [f"unreadable git log: {len(tokens)} fields is not a multiple of {FIELDS}"]
    found = []
    for start in range(0, len(tokens), FIELDS):
        commit, signature, key, fingerprint, email, message = tokens[start : start + FIELDS]
        short = commit[:7]
        if commit in historical:
            if signature not in HISTORICAL_STATUSES:
                found.append(f"{short}: signature status {signature}")
            if key != RETIRED_KEY_ID:
                found.append(f"{short}: signed by key {key or 'none'}")
        else:
            if signature not in CURRENT_STATUSES:
                found.append(f"{short}: signature status {signature}")
            if key == RETIRED_KEY_ID:
                found.append(f"{short}: retired key {key} used after the rotation boundary")
            elif fingerprint != CURRENT_KEY_FINGERPRINT:
                found.append(f"{short}: signed by fingerprint {fingerprint or 'none'}")
        if email != OWNER_EMAIL:
            found.append(f"{short}: unexpected author")
        found.extend(f"{short}: {problem}" for problem in problems(message))
    return found


def boundary_problems(boundary: str, cwd: Path | None = None) -> tuple[list[str], frozenset[str]]:
    """Problems with the rotation boundary, and the historical set. Empty set if any problem."""
    shallow = run(["rev-parse", "--is-shallow-repository"], cwd)
    if shallow.returncode != 0 or shallow.stdout.strip() != "false":
        return ["repository is shallow or unreadable: the historical set cannot be established"], (
            frozenset()
        )
    exists = run(["cat-file", "-e", f"{boundary}^{{commit}}"], cwd)
    if exists.returncode != 0:
        return [f"rotation boundary {boundary[:12]} is not a commit in this repository"], (
            frozenset()
        )
    ancestor = run(["merge-base", "--is-ancestor", boundary, "HEAD"], cwd)
    if ancestor.returncode != 0:
        return [f"rotation boundary {boundary[:12]} is not an ancestor of HEAD"], frozenset()
    reachable = run(["rev-list", boundary], cwd)
    if reachable.returncode != 0 or not reachable.stdout.split():
        return [f"cannot list the history of rotation boundary {boundary[:12]}"], frozenset()
    return [], frozenset(reachable.stdout.split())


def history_violations(boundary: str = ROTATION_BOUNDARY, cwd: Path | None = None) -> list[str]:
    found, historical = boundary_problems(boundary, cwd)
    if found:
        return found
    log = run(["log", "-z", f"--format={LOG_FORMAT}"], cwd)
    if log.returncode != 0:
        return [f"git log failed with exit status {log.returncode}"]
    return violations(log.stdout, historical)


def main() -> int:
    found = history_violations()
    for violation in found:
        print(f"history: {violation}", file=sys.stderr)
    print(f"history checks: {'FAILED' if found else 'OK'}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
