#!/usr/bin/env python3
"""Tests for the commit history check and its signing-key rotation policy (ADR-0013)."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from check_history import (
    CURRENT_KEY_FINGERPRINT,
    OWNER_EMAIL,
    RETIRED_KEY_ID,
    ROTATION_BOUNDARY,
    SEP,
    boundary_problems,
    history_violations,
    violations,
)

GOOD = "chore(repo): add a thing\n"
# The values the owner approved, written out a second time so that editing the constants in
# check_history.py alone cannot pass these tests.
APPROVED_RETIRED_KEY_ID = "9656DC342415CDB2"
APPROVED_BOUNDARY = "e436568b582c0d3b43825c1bb8bb424db97b8e31"
APPROVED_FINGERPRINT = "0C8D2B652F6D7010116DE44AEFF6790D7412A56C"
OLD = "a" * 40  # a commit inside the historical set
NEW = "b" * 40  # a commit after the rotation boundary
LEGACY = frozenset({OLD})
ALL_STATUSES = "GUEXYRBNTQ"  # every `%G?` letter Git can print, plus a few it does not
NOT_G = [s for s in ALL_STATUSES if s != "G"]


def entry(
    commit: str,
    sig: str,
    *,
    key: str,
    fingerprint: str = "",
    email: str = OWNER_EMAIL,
    body: str = GOOD,
) -> str:
    return SEP.join((commit, sig, key, fingerprint, email, body)) + SEP


def old(sig: str = "E", *, key: str = RETIRED_KEY_ID, **rest: str) -> str:
    return entry(OLD, sig, key=key, **rest)


def new(
    sig: str = "G",
    *,
    key: str = CURRENT_KEY_FINGERPRINT[-16:],
    fingerprint: str = CURRENT_KEY_FINGERPRINT,
    **rest: str,
) -> str:
    return entry(NEW, sig, key=key, fingerprint=fingerprint, **rest)


class Policy(unittest.TestCase):
    def test_pinned_values_are_the_approved_ones(self) -> None:
        self.assertEqual(RETIRED_KEY_ID, APPROVED_RETIRED_KEY_ID)
        self.assertEqual(ROTATION_BOUNDARY, APPROVED_BOUNDARY)
        self.assertEqual(CURRENT_KEY_FINGERPRINT, APPROVED_FINGERPRINT)


class Historical(unittest.TestCase):
    def test_retired_key_with_unverifiable_signature_passes(self) -> None:
        self.assertEqual(violations(old("E"), LEGACY), [])

    def test_retired_key_with_a_verified_signature_passes(self) -> None:
        # Should the retired public key ever be recovered, `G` and `U` become possible.
        for status in ("G", "U"):
            with self.subTest(status=status):
                self.assertEqual(violations(old(status), LEGACY), [])

    def test_unexpected_key_fails_for_every_accepted_status(self) -> None:
        for status in ("G", "U", "E"):
            with self.subTest(status=status):
                self.assertTrue(violations(old(status, key="0123456789ABCDEF"), LEGACY))

    def test_current_key_on_a_historical_commit_fails(self) -> None:
        self.assertTrue(violations(old("G", key=CURRENT_KEY_FINGERPRINT[-16:]), LEGACY))

    def test_missing_key_fails(self) -> None:
        self.assertTrue(violations(old("E", key=""), LEGACY))

    def test_unsigned_bad_or_unknown_status_fails(self) -> None:
        for status in "NBXYRTQ":
            with self.subTest(status=status):
                self.assertTrue(violations(old(status), LEGACY))

    def test_another_author_fails(self) -> None:
        self.assertTrue(violations(old(email="someone@example.com"), LEGACY))

    def test_nonconforming_message_fails(self) -> None:
        self.assertTrue(violations(old(body="updates\n"), LEGACY))

    def test_ai_trailer_fails(self) -> None:
        message = "chore(repo): add a thing\n\nCo-Authored-By: Claude <x@y.z>\n"
        self.assertTrue(violations(old(body=message), LEGACY))


class AfterRotation(unittest.TestCase):
    def test_exact_current_fingerprint_with_good_signature_passes(self) -> None:
        self.assertEqual(violations(new(), LEGACY), [])

    def test_history_in_both_ranges_passes(self) -> None:
        self.assertEqual(violations(old("E") + new(), LEGACY), [])

    def test_every_other_status_fails_even_with_the_right_fingerprint(self) -> None:
        for status in NOT_G:
            with self.subTest(status=status):
                self.assertTrue(violations(new(status), LEGACY))

    def test_unsigned_commit_names_the_status(self) -> None:
        # check_gates.py looks for this text to prove the gate catches an unsigned commit.
        found = violations(new("N", key="", fingerprint=""), LEGACY)
        self.assertIn(f"{NEW[:7]}: signature status N", found)

    def test_a_different_fingerprint_fails(self) -> None:
        other = "0123456789ABCDEF0123456789ABCDEF01234567"
        self.assertTrue(violations(new(fingerprint=other), LEGACY))

    def test_a_fingerprint_that_differs_by_one_character_fails(self) -> None:
        flipped = CURRENT_KEY_FINGERPRINT[:-1] + "B"
        self.assertNotEqual(flipped, CURRENT_KEY_FINGERPRINT)
        self.assertTrue(violations(new(fingerprint=flipped), LEGACY))

    def test_matching_key_id_without_a_fingerprint_fails(self) -> None:
        self.assertTrue(violations(new(fingerprint=""), LEGACY))

    def test_matching_suffix_only_fails(self) -> None:
        # A 64-bit key ID can be forged; only the complete fingerprint counts.
        forged = "F" * 24 + CURRENT_KEY_FINGERPRINT[-16:]
        self.assertEqual(len(forged), 40)
        self.assertTrue(violations(new(fingerprint=forged), LEGACY))

    def test_lowercase_fingerprint_fails(self) -> None:
        self.assertTrue(violations(new(fingerprint=CURRENT_KEY_FINGERPRINT.lower()), LEGACY))

    def test_retired_key_fails_after_the_boundary(self) -> None:
        for status in ("G", "U", "E"):
            with self.subTest(status=status):
                found = violations(new(status, key=RETIRED_KEY_ID, fingerprint=""), LEGACY)
                self.assertTrue(any("retired key" in line for line in found), found)

    def test_retired_key_cannot_borrow_the_current_fingerprint(self) -> None:
        self.assertTrue(violations(new(key=RETIRED_KEY_ID), LEGACY))

    def test_empty_historical_set_treats_every_commit_as_new(self) -> None:
        self.assertTrue(violations(old("E"), frozenset()))

    def test_another_author_fails(self) -> None:
        self.assertTrue(violations(new(email="someone@example.com"), LEGACY))

    def test_nonconforming_message_fails(self) -> None:
        self.assertTrue(violations(new(body="updates\n"), LEGACY))

    def test_ai_trailer_fails(self) -> None:
        message = "chore(repo): add a thing\n\nCo-Authored-By: Claude <x@y.z>\n"
        self.assertTrue(violations(new(body=message), LEGACY))


class Malformed(unittest.TestCase):
    def test_a_record_with_too_few_fields_fails(self) -> None:
        self.assertTrue(violations(SEP.join((NEW, "G", "ABCDEF")) + SEP, LEGACY))

    def test_a_record_with_too_many_fields_fails(self) -> None:
        self.assertTrue(violations(new() + SEP.join((NEW, "G")) + SEP, LEGACY))

    def test_empty_log_is_not_a_pass_for_a_partial_record(self) -> None:
        self.assertTrue(violations(new()[:-1] + "x", LEGACY))

    def test_old_style_delimiters_in_a_message_cannot_forge_a_record(self) -> None:
        # Git accepts 0x1e and 0x1f in a message. They are ordinary text, not separators.
        trailer = "Co-Authored-By: Claude <x@y.z>\n"
        for control in ("\x1e", "\x1f"):
            with self.subTest(control=hex(ord(control))):
                body = f"chore(repo): add a thing\n{control}{trailer}"
                self.assertTrue(violations(new(body=body), LEGACY))

    def test_a_forged_historical_record_inside_a_message_cannot_hide_text(self) -> None:
        forged = "\x1e".join(
            (OLD, "E", RETIRED_KEY_ID, "Co-Authored-By: Claude", OWNER_EMAIL, GOOD)
        )
        self.assertTrue(violations(new(body=f"chore(repo): ok\n{forged}"), LEGACY))

    def test_a_field_separator_in_the_author_email_fails(self) -> None:
        self.assertTrue(violations(new(email=f"{OWNER_EMAIL}\x1fchore(repo): ok"), LEGACY))


def git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": OWNER_EMAIL,
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": OWNER_EMAIL,
    }
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,  # `git mktree` reads stdin until it closes
        timeout=60,
    ).stdout.strip()


def commit(cwd: Path, parent: str | None, message: str) -> str:
    """An unsigned commit with the same tree; `commit-tree` needs no signing setup."""
    tree = git(cwd, "mktree")
    parents = ["-p", parent] if parent else []
    return git(cwd, "commit-tree", tree, *parents, "-m", message)


class Boundary(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        self.first = commit(self.repo, None, "chore(repo): one")
        self.boundary = commit(self.repo, self.first, "chore(repo): two")
        self.tip = commit(self.repo, self.boundary, "chore(repo): three")
        git(self.repo, "update-ref", "HEAD", self.tip)

    def test_reachable_boundary_yields_exactly_its_ancestors(self) -> None:
        problems, legacy = boundary_problems(self.boundary, self.repo)
        self.assertEqual(problems, [])
        self.assertEqual(legacy, frozenset({self.first, self.boundary}))
        self.assertNotIn(self.tip, legacy)

    def test_boundary_at_head_is_allowed(self) -> None:
        problems, legacy = boundary_problems(self.tip, self.repo)
        self.assertEqual(problems, [])
        self.assertIn(self.tip, legacy)

    def test_absent_boundary_fails_closed(self) -> None:
        problems, legacy = boundary_problems("c" * 40, self.repo)
        self.assertTrue(problems)
        self.assertEqual(legacy, frozenset())

    def test_boundary_that_is_not_an_ancestor_of_head_fails(self) -> None:
        side = commit(self.repo, self.first, "chore(repo): side")
        problems, _ = boundary_problems(side, self.repo)
        self.assertTrue(any("ancestor" in line for line in problems), problems)

    def test_a_tree_object_is_not_a_boundary(self) -> None:
        tree = git(self.repo, "rev-parse", f"{self.tip}^{{tree}}")
        problems, _ = boundary_problems(tree, self.repo)
        self.assertTrue(problems)

    def test_shallow_clone_fails_closed(self) -> None:
        shallow = Path(self._tmp.name) / "shallow"
        git(self.repo, "clone", "-q", "--depth", "1", f"file://{self.repo}", str(shallow))
        git(shallow, "rev-parse", "HEAD")  # the clone worked
        problems, legacy = boundary_problems(self.boundary, shallow)
        self.assertTrue(any("shallow" in line for line in problems), problems)
        self.assertEqual(legacy, frozenset())

    def test_history_check_reports_unsigned_commits_in_both_ranges(self) -> None:
        found = history_violations(self.boundary, self.repo)
        for sha in (self.first, self.boundary, self.tip):
            self.assertTrue(any(line.startswith(sha[:7]) for line in found), (sha, found))

    def test_history_check_stops_when_the_boundary_is_absent(self) -> None:
        found = history_violations("c" * 40, self.repo)
        self.assertTrue(found)
        self.assertFalse(any("signature status" in line for line in found), found)

    def test_a_good_signature_status_from_git_is_not_faked_by_a_trailer(self) -> None:
        trailer = commit(self.repo, self.tip, "chore(repo): four\n\nSigned-off-by: x <x@y.z>")
        git(self.repo, "update-ref", "HEAD", trailer)
        found = history_violations(self.boundary, self.repo)
        self.assertTrue(any(line.startswith(trailer[:7]) for line in found), found)

    def test_a_replace_ref_cannot_change_what_the_check_sees(self) -> None:
        bad = commit(self.repo, self.tip, "updates")
        clean = commit(self.repo, self.tip, "chore(repo): four")
        git(self.repo, "update-ref", "HEAD", bad)
        git(self.repo, "replace", bad, clean)
        found = history_violations(self.boundary, self.repo)
        self.assertTrue(any(line.startswith(bad[:7]) for line in found), found)

    def test_a_replace_ref_cannot_move_the_boundary(self) -> None:
        new = commit(self.repo, self.tip, "chore(repo): four")
        git(self.repo, "update-ref", "HEAD", new)
        # Without `--no-replace-objects`, this makes `new` look like an ancestor of the boundary.
        forged = commit(self.repo, new, "chore(repo): forged")
        git(self.repo, "replace", "--force", self.boundary, forged)
        problems, legacy = boundary_problems(self.boundary, self.repo)
        self.assertEqual(problems, [])
        self.assertNotIn(new, legacy)

    def test_a_control_character_in_a_real_commit_is_still_just_text(self) -> None:
        trailer = "Co-Authored-By: Claude <x@y.z>"
        body = f"chore(repo): four\n\x1e{trailer}"
        tip = commit(self.repo, self.tip, body)
        git(self.repo, "update-ref", "HEAD", tip)
        found = history_violations(self.boundary, self.repo)
        self.assertTrue(any(line.startswith(tip[:7]) and "AI" in line for line in found), found)


if __name__ == "__main__":
    unittest.main(verbosity=1)
