---
name: verify-slice
description: Runs ShipTrace quality gates and maps results to acceptance criteria before work is called done. Use after implementing a change and before reporting completion.
---

Verify the current work: $ARGUMENTS

1. Run `scripts/verify.sh` and read the full output. Do not summarize from memory.
2. Run any slice-specific checks the gates do not cover.
3. For each new significant test, confirm it can fail: break the target code briefly, run the
   test, restore the code. Record what you broke.
4. Map every acceptance criterion in scope to its evidence. A criterion without executed evidence
   is `not verified`, whatever the code looks like.
5. Check `git status` and `git diff` for stray changes, debugging leftovers and secrets.
6. Append to `docs/engineering/VERIFICATION_LOG.md`: date, commands, outcomes, unresolved risks.
7. Report plainly, including failures and anything skipped.
