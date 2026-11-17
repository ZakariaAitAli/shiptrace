# ADR-0013: Signing-key rotation and the historical verification limit

Status: Accepted on 2026-11-15 · Date: 2026-11-15

**Context.** `scripts/check_history.py` pinned one signing key ID, `9656DC342415CDB2`, and accepted
signature status `E` ("the public key is not available here") for it. A replacement signing key was
created on 2026-11-12 after a workstation reinstall. The four commits made on 2026-11-14 carry
good signatures from it, so Git reports `G`, but the gate rejected them because the pin named only
the old key.

The retired key was reportedly created in the previous Windows WSL environment;
its origin cannot be independently confirmed from repository evidence. Its public half could not be recovered on 2026-11-15. It is not
published on the configured GitHub account, not on `keys.openpgp.org` or `keyserver.ubuntu.com`, and
not in any of the eight Restic snapshots of the new machine (the earliest, from 2026-11-12 22:45
UTC, holds a keyring with the new key only). So the 115 historical commits cannot be verified, and
no fingerprint for the retired key is known: only the 64-bit key ID the commits claim.

**Options.**

| Option | Assessment |
|---|---|
| A. Add the new key to a flat allow-list | Rejected: the retired key could then sign new commits for ever, and `E` stays acceptable for both |
| B. Re-sign the four commits with the retired key | Rejected: the retired secret key is not available, history would be rewritten, and it forces a retired key back into use |
| C. Split history at a fixed boundary: retired key only before it, new key only after it | **Chosen** |

**Decision (Option C).**

1. **The boundary is commit `e436568b582c0d3b43825c1bb8bb424db97b8e31`**, the last commit signed with
   the retired key. The historical set is every commit reachable from it: **115 commits**, fixed at
   the time of this decision.
2. **Historical set.** The claimed key ID must be `9656DC342415CDB2`. Status `G`, `U` or `E` is
   accepted. Status `E` is the expected result today. It is accepted for these commits only, and
   only for this key ID. If the retired public key is ever recovered, `E` becomes `G` with no policy
   change.
3. **Every other commit.** The status must be exactly `G`, and the fingerprint of the signing key
   (`%GF`, 40 hex digits, upper case, compared exactly) must be
   `0C8D2B652F6D7010116DE44AEFF6790D7412A56C`. Statuses `E`, `U`, `N`, `B`, `X`, `Y`, `R` and any
   other all fail. The retired key ID on a commit after the boundary is reported as its own
   violation.
4. **Unchanged for both ranges:** the author email (D8 in the implementation plan) and the
   Conventional Commits rules, including the ban on AI attribution.
5. **The check fails closed.** It fails if the boundary is not a commit in the repository, is not
   an ancestor of `HEAD`, or the repository is shallow, because the historical set cannot then be
   established. It also fails on a log it cannot parse. Git output is read as NUL-delimited
   fields, because Git accepts the control characters `0x1e` and `0x1f` inside commit messages and
   author emails, and a crafted commit could otherwise split its own record. Git runs with
   `--no-replace-objects`, so a local replace ref cannot change which commits or messages are
   checked.
6. **History is not rewritten.** All existing commits and signatures stay as they are.

**Trust model.**

- The anchor for new commits is a complete fingerprint, not a key ID. A 64-bit ID can be forged; a
  160-bit fingerprint cannot, in practice. Git must also verify the signature (`G`), which needs the
  public key in the verifying keyring and a key that is neither expired nor revoked.
- The anchor for the retired key is weaker, and this ADR says so. **Status `E` does not prove that
  a commit was signed by `9656DC342415CDB2`.** It proves only that the commit's signature claims
  that key ID. Anyone who could write a commit before the boundary could have made that claim. The
  boundary limits the damage: the claim is honored for the 115 commits that already existed when
  the rotation was decided, and for no commit created afterwards. This exception is accepted
  because the retired public key is unavailable.
- **The old and the new identity cannot be cryptographically linked.** The retired key cannot sign
  a statement endorsing the new one, and no earlier artifact does. The link rests on this ADR, on
  the recorded rotation decision, and on the new key being listed on the configured GitHub account (fingerprint
  `0C8D2B65…A56C` was listed there on 2026-11-15). The same author email is on both ranges, but an
  email address proves nothing.
- The gate cannot detect a retired key that was compromised before the rotation.

**Consequences.**

- Verifying new commits needs the current public key in the verifying keyring. A clone or CI job
  without it sees `E` for new commits and fails. Any future CI must import
  `0C8D2B652F6D7010116DE44AEFF6790D7412A56C` (for example from the configured GitHub account’s public key list) and
  check the fingerprint after importing.
- A commit signed by a subkey of the new key reports the subkey's fingerprint in `%GF` and fails.
  This is deliberate; accepting a subkey takes a new ADR.
- A shallow clone fails the check. Verify on a full clone.
- The retired key's public half, should it turn up, does not change the boundary or the
  fingerprint rules. Record its full fingerprint in a superseding ADR and pin it, so the 115 commits
  are verified instead of trusted.

**Procedure for the next rotation.** Never edit this ADR or move its boundary.

1. Before retiring a key, export its **public** key (`gpg --armor --export <fingerprint>`) and keep
   it in a place that outlives the machine, such as the repository and the configured GitHub account.
   This ADR exists because that was not done.
2. Create the new key and publish its public half on the configured GitHub account. Record its
   complete 40-hex fingerprint. Where possible, have the retiring key certify the new one, so that
   a cryptographic link exists.
3. Make the last commit signed with the outgoing key. Its hash is the new boundary.
4. Write a new ADR that supersedes this one. It names the new boundary, the outgoing key's complete
   fingerprint and the incoming key's complete fingerprint.
5. Change `scripts/check_history.py` from one boundary to an ordered list of ranges, each with its
   key. Keep this ADR's boundary and key as the first range, unchanged. A commit belongs to the
   earliest range whose boundary reaches it, and an outgoing key may not sign anything after its
   own boundary. Add tests for each new rule before changing the code.
6. Sign the commit that makes this change with the **incoming** key, then run
   `python3 -I scripts/check_history.py` and `scripts/verify.sh` on a full clone.

**Verification.** `scripts/test_check_history.py` covers both ranges, every signature status, the
exact-fingerprint rule, the retired key after the boundary, a missing, non-ancestor, tree-object
and shallow boundary, the author and message rules, and the real hash, key ID and fingerprint
pins. The results are in `docs/engineering/VERIFICATION_LOG.md`.
