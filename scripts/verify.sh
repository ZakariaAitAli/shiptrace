#!/usr/bin/env bash
# Runs the quality gates. Any failure stops the script with a non-zero exit.
#   scripts/verify.sh         every gate; needs Docker
#   scripts/verify.sh --fast  gates that need no Docker, so they can run inside the sandbox
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode=${1:-full}
case $mode in
  full | --fast) ;;
  *) echo "usage: scripts/verify.sh [--fast]" >&2; exit 2 ;;
esac

echo "==> repository and Claude config checks"
python3 -I scripts/check_repo.py

echo "==> commit history"
python3 -I scripts/check_history.py

echo "==> commit and pre-commit rules"
python3 -I scripts/test_commit_msg.py
python3 -I scripts/test_check_history.py
python3 -I scripts/test_pre_commit.py

echo "==> hook tests"
python3 -I .claude/hooks/tests/test_hooks.py

echo "==> lockfile is current"
uv lock --check

echo "==> formatting"
uv run --frozen ruff format --check .

echo "==> lint and static security rules"
uv run --frozen ruff check .

echo "==> types"
uv run --frozen mypy

echo "==> import boundaries"
uv run --frozen lint-imports --config pyproject.toml

echo "==> built wheel ships the migrations"
wheel_dir=$(mktemp -d)
trap 'rm -r "$wheel_dir"' EXIT
uv build --wheel --quiet --out-dir "$wheel_dir"
python3 -I -m zipfile -l "$wheel_dir"/*.whl | grep -q 'persistence/migrations/script.py.mako'
python3 -I -m zipfile -l "$wheel_dir"/*.whl | grep -q 'persistence/migrations/versions/0001_'

if [[ $mode == --fast ]]; then
  echo "==> unit tests"
  uv run --frozen pytest tests/unit -q
  echo "==> FAST GATES PASSED (no integration or smoke tests ran)"
  exit 0
fi

echo "==> tests with coverage (real PostgreSQL)"
uv run --frozen pytest --cov --cov-branch --cov-report=term-missing --cov-fail-under=90 -q

echo "==> real-process smoke test"
scripts/smoke.sh

echo "==> ALL GATES PASSED"
