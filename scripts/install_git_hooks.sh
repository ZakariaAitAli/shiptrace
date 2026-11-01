#!/usr/bin/env bash
# Installs repository git hooks into this clone. Safe to run repeatedly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
ln -sf ../../scripts/commit_msg.py .git/hooks/commit-msg
chmod +x scripts/commit_msg.py
echo "installed commit-msg hook"
