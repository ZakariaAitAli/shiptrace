#!/usr/bin/env python3
"""Tests for scripts/commit.py. Each copies the script into a throwaway repository.

A fake gpg.program lets git sign without the owner's key. It cannot verify, so a successful run
here ends with the script's "signature did not verify" exit, which is itself under test.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "commit.py"
FAKE_GPG = """#!/bin/sh
cat > /dev/null
echo "[GNUPG:] SIG_CREATED D 1 8 00 0 0 0" >&2
printf -- '-----BEGIN PGP SIGNATURE-----\\n\\nfake\\n-----END PGP SIGNATURE-----\\n'
"""
NOT_VERIFIED = 3


class Workspace:
    def __init__(self, directory: str, signing: str = "true") -> None:
        base = Path(directory)
        self.home = base / "home"
        self.root = base / "project"
        self.home.mkdir()
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy(SCRIPT, self.root / "scripts/commit.py")
        gpg = self.home / "fake-gpg"
        gpg.write_text(FAKE_GPG)
        gpg.chmod(0o755)
        # Stands in for the owner's ~/.gitconfig, which sandboxed code cannot write.
        (self.home / ".gitconfig").write_text(
            "[user]\n\tname = Test\n\temail = test@example.invalid\n"
            f"[commit]\n\tgpgsign = {signing}\n[gpg]\n\tprogram = {gpg}\n"
        )
        self.git("init", "-q")

    def env(self, **extra: str) -> dict[str, str]:
        return {"HOME": str(self.home), "PATH": os.environ["PATH"], **extra}

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            env=self.env(),
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def write(self, name: str, content: str = "x\n") -> None:
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def hook(self, name: str, body: str) -> None:
        hook = self.root / ".git/hooks" / name
        hook.write_text(f"#!/bin/sh\n{body}\n")
        hook.chmod(0o755)

    def commit(
        self, *args: str, cwd: Path | None = None, **env: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts/commit.py"), *args],
            cwd=cwd or self.root,
            env=self.env(**env),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def has_commit(self) -> bool:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=self.root, capture_output=True
        )
        return result.returncode == 0


class Commit(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.ws = Workspace(directory.name)

    def test_commits_only_the_named_paths_and_signs(self) -> None:
        self.ws.write("a.py")
        self.ws.write("b.py")
        result = self.ws.commit("chore(test): add a", "a.py")
        self.assertEqual(result.returncode, NOT_VERIFIED, result.stderr)
        self.assertEqual(self.ws.git("ls-tree", "--name-only", "HEAD").split(), ["a.py"])
        self.assertIn("gpgsig", self.ws.git("cat-file", "commit", "HEAD"))
        self.assertIn("did not verify", result.stderr)

    def test_message_is_data(self) -> None:
        marker = self.base / "ran"
        message = f"--amend $(touch {marker}) `touch {marker}`"
        self.ws.write("a.py")
        self.ws.commit(message, "a.py")
        self.assertEqual(self.ws.git("log", "-1", "--format=%B").strip(), message)
        self.assertFalse(marker.exists())

    def test_refuses_when_signing_is_off(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        unsigned = Workspace(directory.name, signing="false")
        unsigned.write("a.py")
        result = unsigned.commit("chore(test): add a", "a.py")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(unsigned.has_commit())

    def test_refuses_a_planted_commondir(self) -> None:
        marker = self.base / "ran"
        common = self.base / "common"
        subprocess.run(["git", "init", "-q", "--bare", str(common)], check=True)
        hook = common / "hooks/pre-commit"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o755)
        (self.ws.root / ".git/commondir").write_text(f"{common}\n")
        self.ws.write("a.py")
        result = self.ws.commit("chore(test): add a", "a.py")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("commondir", result.stderr)
        self.assertFalse(marker.exists())

    def test_hostile_environment_is_ignored(self) -> None:
        marker = self.base / "ran"
        elsewhere = self.base / "elsewhere"
        subprocess.run(["git", "init", "-q", str(elsewhere)], check=True)
        planted = self.ws.root / "bin"
        planted.mkdir()
        for tool in ("git", "gpg", "uv", "python3", "pre-commit"):
            (planted / tool).write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
            (planted / tool).chmod(0o755)
        self.ws.write("a.py")
        result = self.ws.commit(
            "chore(test): add a",
            "a.py",
            PATH=f"{planted}:{os.environ['PATH']}",
            GIT_DIR=str(elsewhere / ".git"),
            GIT_WORK_TREE=str(elsewhere),
            GIT_INDEX_FILE=str(self.base / "index"),
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="core.fsmonitor",
            GIT_CONFIG_VALUE_0=f"touch {marker}",
            GIT_CONFIG_PARAMETERS=f"'core.hooksPath'='{planted}'",
            GIT_EXEC_PATH=str(planted),
        )
        self.assertEqual(result.returncode, NOT_VERIFIED, result.stderr)
        self.assertFalse(marker.exists())
        self.assertTrue(self.ws.has_commit())

    def test_runs_from_a_nested_directory_on_the_project_repository(self) -> None:
        nested = self.ws.root / "tests/x"
        nested.mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=nested, check=True)
        self.ws.write("a.py")
        result = self.ws.commit("chore(test): add a", "a.py", cwd=nested)
        self.assertEqual(result.returncode, NOT_VERIFIED, result.stderr)
        self.assertTrue(self.ws.has_commit())

    def test_hooks_run_and_can_block(self) -> None:
        marker = self.base / "hook-ran"
        self.ws.hook("pre-commit", f"touch {marker}\nexit 1")
        self.ws.write("a.py")
        result = self.ws.commit("chore(test): add a", "a.py")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(marker.exists())
        self.assertFalse(self.ws.has_commit())

    def test_a_path_cannot_become_an_option(self) -> None:
        marker = self.base / "hook-ran"
        self.ws.hook("pre-commit", f"touch {marker}\nexit 1")
        self.ws.write("--no-verify")
        result = self.ws.commit("chore(test): add a", "--no-verify")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(marker.exists(), "the hook must still run")
        self.assertFalse(self.ws.has_commit())

    def test_unrelated_staged_changes_refuse(self) -> None:
        self.ws.write("a.py")
        self.ws.write("other.py")
        self.ws.git("add", "other.py")
        result = self.ws.commit("chore(test): add a", "a.py")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("other.py", result.stderr)
        self.assertFalse(self.ws.has_commit())

    def test_retry_after_a_blocked_commit(self) -> None:
        self.ws.hook("pre-commit", "exit 1")
        self.ws.write("a.py")
        self.assertEqual(self.ws.commit("chore(test): add a", "a.py").returncode, 1)
        (self.ws.root / ".git/hooks/pre-commit").unlink()
        result = self.ws.commit("chore(test): add a", "a.py")
        self.assertEqual(result.returncode, NOT_VERIFIED, result.stderr)

    def test_needs_a_message_and_a_path(self) -> None:
        for args in ((), ("chore(test): add a",), ("", "a.py")):
            with self.subTest(args=args):
                self.assertEqual(self.ws.commit(*args).returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
