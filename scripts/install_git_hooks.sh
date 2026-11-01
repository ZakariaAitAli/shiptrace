#!/usr/bin/env bash
# Installs repository git hooks into this clone. Safe to run repeatedly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
ln -sf ../../scripts/commit_msg.py .git/hooks/commit-msg
ln -sf ../../scripts/pre_commit.py .git/hooks/pre-commit
chmod +x scripts/commit_msg.py scripts/pre_commit.py
echo "installed commit-msg and pre-commit hooks"
