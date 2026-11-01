---
name: security-audit
description: Runs an independent read-only security review of ShipTrace at a phase gate or on a sensitive change, then triages findings. Use for milestones and for changes to auth, input handling, sessions, logging, secrets or CI.
disable-model-invocation: true
---

Audit: $ARGUMENTS (default: all changes since the last phase gate)

1. Delegate to the `security-reviewer` agent with the exact scope. Do not pass your own conclusions.
2. For changed tests, also delegate to `test-reviewer`.
3. Reproduce each finding yourself: confirmed, or rejected with a reason. Do not fix silently, or
   dismiss a finding without evidence.
4. Fix confirmed issues, each with a regression test that fails first.
5. Update `docs/security/THREAT_MODEL.md` and `docs/security/ASVS_ASSESSMENT.md`. Move an item to
   `Pass` only with linked evidence.
6. Report findings, dispositions and residual risks.
