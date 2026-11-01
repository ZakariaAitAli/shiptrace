#!/usr/bin/env bash
# Owner-run P0 evidence. Docker cannot run inside the sandbox, so run this with `! scripts/p0_gate.sh`.
# Clean clone, one command, no prior sync; repeated smoke; then every gate's deliberate violation.
# Exits 0 only if every step passed. A failed step does not stop later steps, so one run shows
# everything that is wrong.
set -uo pipefail
unset UV_NO_SYNC UV_CACHE_DIR # A clean clone has no environment to reuse.
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
status=0

fail() {
  echo "FAILED: $*"
  status=1
}

# The evidence must describe exactly what is committed.
if ! dirty=$(git -C "$repo" status --porcelain --untracked-files=all); then
  echo "FAILED: could not read the checkout"
  exit 1
fi
if [[ -n $dirty ]]; then
  echo "FAILED: the checkout has uncommitted or untracked changes:"
  echo "$dirty"
  exit 1
fi
echo "HEAD $(git -C "$repo" rev-parse --short HEAD), checkout clean"

git clone -q "$repo" "$work/clone" || { echo "FAILED: git clone"; exit 1; }
cd "$work/clone" || { echo "FAILED: cannot enter the clone"; exit 1; }

echo "==> clean clone: scripts/verify.sh"
scripts/verify.sh >"$work/verify.txt" 2>&1
code=$?
echo "exit=$code"
grep -E '^(==> ALL|[0-9]+ passed|TOTAL|Success|Contracts:|history checks)' "$work/verify.txt"
((code == 0)) || { tail -30 "$work/verify.txt"; fail "scripts/verify.sh"; }

echo "==> smoke, three times"
passed=0
for run in 1 2 3; do
  if scripts/smoke.sh >"$work/smoke.txt" 2>&1; then
    passed=$((passed + 1))
  else
    echo "smoke run $run failed:"
    tail -30 "$work/smoke.txt"
  fi
done
echo "passed $passed of 3"
((passed == 3)) || fail "smoke"

echo "==> gates fail for the right reason"
cd "$repo" || { echo "FAILED: cannot enter the repository"; exit 1; }
python3 -I scripts/check_gates.py >"$work/gates.txt" 2>&1
code=$?
echo "exit=$code"
grep -E '^(baseline|violations)' "$work/gates.txt"
((code == 0)) || { tail -40 "$work/gates.txt"; fail "scripts/check_gates.py"; }

echo "==> signatures: every commit reachable from HEAD must be G"
if signatures=$(git log '--format=%G? %h'); then
  total=$(grep -c . <<<"$signatures")
  unverified=$(grep -v '^G ' <<<"$signatures")
  echo "commits=$total"
  ((total > 0)) || fail "no commits were read"
  [[ -z $unverified ]] || { echo "$unverified"; fail "commits without a good signature"; }
else
  fail "could not read signatures"
fi

if ((status == 0)); then
  echo "P0 GATE: ALL STEPS PASSED"
else
  echo "P0 GATE: FAILED"
fi
exit "$status"
