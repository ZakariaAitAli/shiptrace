#!/usr/bin/env python3
"""Tests for the pre-commit hook. Each runs the real script in a throwaway repository."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "pre_commit.py"
MIGRATION = "src/shiptrace/persistence/migrations/versions/0001_x.py"
CLEAN_PYTHON = 'VALUE = "clean"\n'
UNFORMATTED_PYTHON = "VALUE   =   'messy'\n"
LINT_FAILURE_PYTHON = "import os\n"


class Repo:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        shutil.copy(ROOT / "pyproject.toml", self.path)

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.path, check=True, capture_output=True)

    def write(self, name: str, content: str) -> None:
        target = self.path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def stage(self, name: str, content: str) -> None:
        self.write(name, content)
        self.git("add", "-f", name)

    def snapshot_tree(self) -> None:
        """Records history without creating a real commit, so nothing needs signing."""
        tree = subprocess.run(
            ["git", "write-tree"], cwd=self.path, check=True, capture_output=True, text=True
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "commit-tree", tree, "-m", "base"],
            cwd=self.path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.git("update-ref", "HEAD", commit)

    def run_hook(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(HOOK)],
            cwd=self.path,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )


class PreCommit(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repo = Repo(directory.name)

    def assert_blocked(self, phrase: str) -> None:
        result = self.repo.run_hook()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(phrase, result.stdout + result.stderr)

    def assert_allowed(self) -> None:
        result = self.repo.run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_clean_python_passes(self) -> None:
        self.repo.stage("a.py", CLEAN_PYTHON)
        self.assert_allowed()

    def test_nothing_staged_passes(self) -> None:
        self.assert_allowed()

    def test_unformatted_python_is_blocked(self) -> None:
        self.repo.stage("a.py", UNFORMATTED_PYTHON)
        self.assert_blocked("ruff format")

    def test_lint_failure_is_blocked(self) -> None:
        self.repo.stage("a.py", LINT_FAILURE_PYTHON)
        self.assert_blocked("ruff check")

    def test_staged_content_is_checked_not_the_working_tree(self) -> None:
        self.repo.stage("a.py", UNFORMATTED_PYTHON)
        self.repo.write("a.py", CLEAN_PYTHON)
        self.assert_blocked("ruff format")

    def test_per_file_rules_from_pyproject_still_apply(self) -> None:
        """Partial executable paths are allowed under scripts/ and refused elsewhere."""
        source = 'import subprocess\n\nsubprocess.run(["git", "status"], check=True)\n'
        self.repo.stage("scripts/tool.py", source)
        self.assert_allowed()
        self.repo.stage("src/tool.py", source)
        self.assert_blocked("ruff check")

    def test_working_tree_mess_does_not_block_clean_staged_content(self) -> None:
        self.repo.stage("a.py", CLEAN_PYTHON)
        self.repo.write("a.py", UNFORMATTED_PYTHON)
        self.assert_allowed()

    def test_forbidden_paths_are_blocked(self) -> None:
        for name in (".env", ".env.production", "certs/a.pem", "a.key", "prod.tfstate", "x.tfvars"):
            with self.subTest(name=name):
                self.repo.git("read-tree", "--empty")
                self.repo.stage(name, "x\n")
                self.assert_blocked("must not be committed")

    def test_env_example_is_allowed(self) -> None:
        self.repo.stage(".env.example", "A=\n")
        self.assert_allowed()

    def test_secrets_in_added_lines_are_blocked(self) -> None:
        # Built by concatenation so this file holds no realistic secret.
        secrets = [
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "ghp_" + "a" * 36,
            "-----BEGIN RSA " + "PRIVATE KEY-----",
            "st1_" + "b" * 43,
            "postgresql://app:" + "hunter2@db/shiptrace",
        ]
        for secret in secrets:
            with self.subTest(secret=secret[:10]):
                self.repo.git("read-tree", "--empty")
                self.repo.stage("notes.txt", f"value {secret}\n")
                self.assert_blocked("looks like a secret")

    def test_secret_value_is_not_echoed(self) -> None:
        secret = "ghp_" + "c" * 36
        self.repo.stage("notes.txt", f"{secret}\n")
        result = self.repo.run_hook()
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_placeholder_urls_are_allowed(self) -> None:
        self.repo.stage("notes.txt", "postgresql://app:<password>@db/shiptrace\n")
        self.assert_allowed()

    def test_new_migration_is_allowed(self) -> None:
        self.repo.stage(MIGRATION, CLEAN_PYTHON)
        self.assert_allowed()

    def test_applied_migration_cannot_change(self) -> None:
        self.repo.stage(MIGRATION, CLEAN_PYTHON)
        self.repo.snapshot_tree()
        self.repo.stage(MIGRATION, 'VALUE = "changed"\n')
        self.assert_blocked("applied migration")

    def test_applied_migration_cannot_be_deleted(self) -> None:
        self.repo.stage(MIGRATION, CLEAN_PYTHON)
        self.repo.snapshot_tree()
        self.repo.git("rm", "-q", "--cached", MIGRATION)
        self.assert_blocked("applied migration")

    def test_installed_hook_stops_a_real_commit(self) -> None:
        self.repo.stage(".env", "x\n")
        hooks = self.repo.path / ".git" / "hooks"
        (hooks / "pre-commit").symlink_to(HOOK)
        result = subprocess.run(
            ["git", "commit", "-m", "chore(test): must not land"],
            cwd=self.repo.path,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        log = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", "HEAD"],
            cwd=self.repo.path,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(log.returncode, 0, "a commit landed")


if __name__ == "__main__":
    unittest.main(verbosity=1)
