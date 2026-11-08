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

    def test_ruff_output_does_not_echo_a_secret(self) -> None:
        secret = "ghp_" + "d" * 36
        self.repo.stage("a.py", f"VALUE   =   '{secret}'\n")
        result = self.repo.run_hook()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_unusual_file_names_are_still_checked(self) -> None:
        self.repo.stage("caf\u00e9.pem", "x\n")
        self.assert_blocked("must not be committed")

    def test_secret_in_a_binary_looking_file_is_blocked(self) -> None:
        secret = "ghp_" + "e" * 36
        target = self.repo.path / "blob.bin"
        target.write_bytes(b"\x00\xe2\xff" + secret.encode() + b"\n")
        self.repo.git("add", "-f", "blob.bin")
        self.assert_blocked("looks like a secret")

    def test_deleting_the_lockfile_is_blocked(self) -> None:
        self.repo.stage("uv.lock", "version = 1\n")
        self.repo.snapshot_tree()
        self.repo.git("rm", "-q", "--cached", "uv.lock")
        (self.repo.path / "uv.lock").unlink()
        self.assert_blocked("uv.lock")

    def test_missing_uv_blocks_instead_of_skipping_checks(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(HOOK)],
            cwd=self.repo.path,
            env={"PATH": str(Path(sys.executable).parent.parent / "nonexistent")},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("uv", result.stderr)

    def test_added_line_that_looks_like_a_header_is_scanned(self) -> None:
        secret = "ghp_" + "f" * 36
        self.repo.stage("notes.txt", f"++ b/{secret}\n")
        self.assert_blocked("looks like a secret")

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

    def test_never_imports_code_from_the_working_tree(self) -> None:
        """V66: a commit runs outside the sandbox, so no tool may import an untracked root module.

        import-linter puts its working directory first on sys.path and later imports
        typing_extensions, so a planted copy at the root would run.
        """
        marker = self.repo.path / "planted-ran"
        self.repo.write("typing_extensions.py", f"open({str(marker)!r}, 'w').close()\n")
        self.repo.stage("src/shiptrace/a.py", CLEAN_PYTHON)
        self.repo.run_hook()
        self.assertFalse(marker.exists())

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
        self.assertIn("must not be committed", result.stderr)
        log = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", "HEAD"],
            cwd=self.repo.path,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(log.returncode, 0, "a commit landed")


if __name__ == "__main__":
    unittest.main(verbosity=1)
