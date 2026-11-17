#!/usr/bin/env python3
"""Fast checks on scripts/check_gates.py: its check_repo.py violations still break something.

check_gates.py needs Docker and runs only at phase gates, so a violation that went stale, such as
one naming a sandbox exclusion that no longer exists, would otherwise surface only there.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_gates  # noqa: E402

REPO_VIOLATIONS = [v for v in check_gates.VIOLATIONS if v.gate == check_gates.CHECK_REPO]


def working_copy(directory: str, root: Path = ROOT) -> Path:
    """Copies the candidate state: tracked files as they are in the working tree, plus new files.

    New files that Git does not ignore count, or a change that adds a file and links to it from a
    tracked one would fail here only until it is committed. Ignored files, `.git` and symlinks
    are left out, as in a fresh clone.
    """
    copy = Path(directory, "copy")
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for name in filter(None, listed.split("\0")):
        source = root / name
        if source.is_file() and not source.is_symlink():
            (copy / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, copy / name)
    return copy


class WorkingCopy(unittest.TestCase):
    """The copy must be the candidate state: tracked, modified, new and nothing Git ignores."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name, "root")
        self.root.mkdir()
        self.git("init", "-q")
        (self.root / ".gitignore").write_text("ignored.txt\nbuild/\n")
        (self.root / "kept.txt").write_text("committed\n")
        (self.root / "gone.txt").write_text("deleted later\n")
        self.git("add", ".gitignore", "kept.txt", "gone.txt")

    def git(self, *args: str) -> None:
        env = {
            "PATH": os.environ["PATH"],
            "HOME": self._tmp.name,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
        subprocess.run(
            ["git", *args],
            cwd=self.root,
            env=env,
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )

    def copy(self) -> Path:
        directory = tempfile.mkdtemp(dir=self._tmp.name)
        return working_copy(directory, self.root)

    def test_includes_untracked_files_that_are_not_ignored(self) -> None:
        (self.root / "docs").mkdir()
        (self.root / "docs/new.md").write_text("new\n")
        self.assertEqual((self.copy() / "docs/new.md").read_text(), "new\n")

    def test_includes_uncommitted_edits_to_tracked_files(self) -> None:
        (self.root / "kept.txt").write_text("edited\n")
        self.assertEqual((self.copy() / "kept.txt").read_text(), "edited\n")

    def test_excludes_ignored_files_and_directories(self) -> None:
        (self.root / "ignored.txt").write_text("x\n")
        (self.root / "build").mkdir()
        (self.root / "build/out.bin").write_text("x\n")
        copy = self.copy()
        self.assertFalse((copy / "ignored.txt").exists())
        self.assertFalse((copy / "build").exists())

    def test_skips_a_tracked_file_deleted_in_the_working_tree(self) -> None:
        (self.root / "gone.txt").unlink()
        copy = self.copy()
        self.assertFalse((copy / "gone.txt").exists())
        self.assertTrue((copy / "kept.txt").exists())

    def test_never_copies_git_metadata_or_symlinks(self) -> None:
        (self.root / "link.txt").symlink_to("kept.txt")
        copy = self.copy()
        self.assertFalse((copy / ".git").exists())
        self.assertFalse((copy / "link.txt").exists())


class RepositoryViolations(unittest.TestCase):
    def check_repo(self, breaks: check_gates.Breaks | None) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            copy = working_copy(directory)
            if breaks:
                breaks(copy)
            return check_gates.run(check_gates.CHECK_REPO, copy)

    def test_unmodified_repository_passes(self) -> None:
        """Without this, a violation could look caught because of an unrelated error."""
        code, output = self.check_repo(None)
        self.assertEqual(code, 0, output)
        self.assertNotIn("ERROR", output)

    def test_every_violation_is_caught_for_its_own_reason(self) -> None:
        self.assertTrue(REPO_VIOLATIONS)
        for violation in REPO_VIOLATIONS:
            with self.subTest(violation=violation.label):
                code, output = self.check_repo(violation.breaks)
                self.assertEqual(code, 1, output)
                self.assertIn(violation.marker, output)

    def test_auto_allow_violation_names_a_current_exclusion(self) -> None:
        """Allowing a command that is not excluded is harmless, so it would prove nothing."""
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        before = set(settings["permissions"]["allow"])
        violation = next(v for v in REPO_VIOLATIONS if v.label == "exclusion auto-allowed")
        with tempfile.TemporaryDirectory() as directory:
            copy = working_copy(directory)
            violation.breaks(copy)
            after = json.loads((copy / ".claude/settings.json").read_text())
        added = set(after["permissions"]["allow"]) - before
        excluded = {f"Bash({command})" for command in settings["sandbox"]["excludedCommands"]}
        self.assertTrue(added)
        self.assertLessEqual(added, excluded)


if __name__ == "__main__":
    unittest.main(verbosity=1)
