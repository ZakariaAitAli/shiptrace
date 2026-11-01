#!/usr/bin/env python3
"""Tests for the commit history check."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from check_history import FIELD, OWNER_EMAIL, OWNER_KEY_ID, RECORD, violations

GOOD = "chore(repo): add a thing\n"


def log(*entries: tuple[str, str], key: str = OWNER_KEY_ID, email: str = OWNER_EMAIL) -> str:
    return "".join(
        f"abcdef1{FIELD}{sig}{FIELD}{key}{FIELD}{email}{FIELD}{body}{RECORD}\n"
        for sig, body in entries
    )


class History(unittest.TestCase):
    def test_signed_conforming_history_passes(self) -> None:
        self.assertEqual(violations(log(("G", GOOD), ("U", GOOD), ("E", GOOD))), [])

    def test_unsigned_commit_fails(self) -> None:
        self.assertEqual(len(violations(log(("G", GOOD), ("N", GOOD)))), 1)

    def test_bad_signature_fails(self) -> None:
        for status in ("B", "X", "Y", "R"):
            with self.subTest(status=status):
                self.assertTrue(violations(log((status, GOOD))))

    def test_signature_from_another_key_fails(self) -> None:
        for status in ("G", "E"):
            with self.subTest(status=status):
                self.assertTrue(violations(log((status, GOOD), key="0123456789ABCDEF")))

    def test_another_author_fails(self) -> None:
        self.assertTrue(violations(log(("G", GOOD), email="someone@example.com")))

    def test_nonconforming_message_fails(self) -> None:
        self.assertTrue(violations(log(("G", "updates\n"))))

    def test_ai_trailer_fails(self) -> None:
        message = "chore(repo): add a thing\n\nCo-Authored-By: Claude <x@y.z>\n"
        self.assertTrue(violations(log(("G", message))))


if __name__ == "__main__":
    unittest.main(verbosity=1)
