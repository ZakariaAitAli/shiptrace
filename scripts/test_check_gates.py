#!/usr/bin/env python3
"""Fast checks on scripts/check_gates.py: its check_repo.py violations still break something.

check_gates.py needs Docker and runs only at phase gates, so a violation that went stale, such as
one naming a sandbox exclusion that no longer exists, would otherwise surface only there.
"""

import json
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


def working_copy(directory: str) -> Path:
    """Copies the tracked files as they are in the working tree, so uncommitted changes count."""
    copy = Path(directory, "copy")
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    for name in filter(None, listed.split("\0")):
        source = ROOT / name
        if source.is_file() and not source.is_symlink():
            (copy / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, copy / name)
    return copy


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
