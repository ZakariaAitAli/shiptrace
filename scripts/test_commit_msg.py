#!/usr/bin/env python3
"""Tests for the commit-msg hook, run by scripts/verify.sh."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from commit_msg import problems


class CommitMessages(unittest.TestCase):
    def test_owner_examples_pass(self) -> None:
        for message in [
            "chore(repo): initialize project structure",
            "feat(api): add deployment ingestion endpoint",
            "fix(db): prevent duplicate deployment events",
            "test(api): cover invalid authentication tokens",
            "ci(github): add automated quality checks",
            "docs(adr): document event storage strategy",
            "security(auth): restrict token permissions",
            "build(deps): add uv project\n\nBody text explaining why.\n",
            "# git comment\nperf(db): add index for latest lookup\n",
        ]:
            with self.subTest(message=message):
                self.assertEqual(problems(message), [])

    def test_rejected(self) -> None:
        for message in [
            "",
            "# only a comment",
            "add thing",
            "Feat(api): add x",
            "feat(API): add x",
            "feature(api): add x",
            "style(api): add x",
            "feat(api):add x",
            "feat(api): ",
            "fix(db): updates",
            "chore(repo): WIP",
            "feat(api): added endpoint",
            "feat(api): adding endpoint",
            "feat(api): add endpoint.",
            "feat(api): " + "x" * 70,
            "feat(api): add x\nno blank line",
            "feat(api): add x\n\nCo-Authored-By: Claude <x@y.z>",
            "feat(api): add x\n\nco-authored-by: ChatGPT <x@y.z>",
            "feat(api): add x\n\nGenerated with Claude Code",
            "feat(api): add x\n\nThis was AI-assisted.",
            "feat(api): add x\n\nCo-Authored-By: Someone <noreply@anthropic.com>",
            "feat(api): add x\n\n# Co-Authored-By: Claude <x@y.z>",
            "feat(api): add x\n\n# Generated with Claude Code",
        ]:
            with self.subTest(message=message):
                self.assertNotEqual(problems(message), [])

    def test_human_coauthor_is_allowed(self) -> None:
        message = "feat(api): add x\n\nCo-authored-by: Sam Doe <sam@example.com>"
        self.assertEqual(problems(message), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
