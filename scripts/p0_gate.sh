#!/usr/bin/env bash
# Owner-run P0 evidence. Docker cannot run inside the sandbox, so run this with `! scripts/p0_gate.sh`.
# Clean clone, one command, no prior sync; repeated smoke; then every gate's deliberate violation.
set -uo pipefail
unset UV_NO_SYNC UV_CACHE_DIR # A clean clone has no environment to reuse.
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
status=0

echo "HEAD $(git -C "$repo" rev-parse --short HEAD), dirty files: $(git -C "$repo" status --short | grep -vc '^??')"
git clone -q "$repo" "$work/clone"
cd "$work/clone" || exit 1

echo "==> clean clone: scripts/verify.sh"
scripts/verify.sh >"$work/verify.txt" 2>&1
code=$?
echo "exit=$code"
grep -E '^(==> ALL|[0-9]+ passed|TOTAL|Success|Contracts:|history checks)' "$work/verify.txt"
((code == 0)) || { tail -30 "$work/verify.txt"; status=1; }

echo "==> smoke, three times"
passed=0
for _ in 1 2 3; do scripts/smoke.sh >/dev/null 2>&1 && passed=$((passed + 1)); done
echo "passed $passed of 3"
((passed == 3)) || status=1

echo "==> gates fail for the right reason"
cd "$repo" || exit 1
python3 -I scripts/check_gates.py >"$work/gates.txt" 2>&1
code=$?
echo "exit=$code"
grep -E '^(baseline|MISSED|violations)' "$work/gates.txt"
((code == 0)) || status=1

echo "==> signatures"
git log '--format=%G?' | sort | uniq -c
git log -1 --show-signature --format=%h 2>&1 | grep -E 'Good signature|BAD|Can.t check' || status=1
exit "$status"
