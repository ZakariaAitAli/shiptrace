#!/usr/bin/env bash
# Runs every quality gate. Any failure stops the script with a non-zero exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> repository and Claude config checks"
python3 -I scripts/check_repo.py

echo "==> commit message rules"
python3 -I scripts/test_commit_msg.py

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
uv run --frozen lint-imports

echo "==> tests with coverage (real PostgreSQL)"
uv run --frozen pytest --cov --cov-branch --cov-report=term-missing --cov-fail-under=90 -q

echo "==> built wheel ships the migrations"
wheel_dir=$(mktemp -d)
trap 'rm -r "$wheel_dir"' EXIT
uv build --wheel --quiet --out-dir "$wheel_dir"
python3 -I -m zipfile -l "$wheel_dir"/*.whl | grep -q 'persistence/migrations/script.py.mako'
python3 -I -m zipfile -l "$wheel_dir"/*.whl | grep -q 'persistence/migrations/versions/0001_'

echo "==> ALL GATES PASSED"
