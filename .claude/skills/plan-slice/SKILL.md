---
name: plan-slice
description: Plans one small vertical slice of ShipTrace with acceptance criteria and tests first. Use before starting a feature, a phase step or any change spanning more than one layer.
---

Plan the slice: $ARGUMENTS

1. Read the relevant parts of `docs/PROJECT_SPEC.md`, `docs/IMPLEMENTATION_PLAN.md` and any ADR
   the slice touches. Inspect the current code; do not assume.
2. If the slice needs behavior outside the spec, stop and raise it.
3. Produce a concise plan:
   - **Outcome**, in one sentence
   - **Acceptance criteria**: spec AC or rule IDs, and any new ones, each checkable
   - **Tests to write first**, by layer, each with the defect it would catch
   - **Files** to change, by layer
   - **Risks**: security, data, concurrency, rollback
   - **Out of this slice**
4. Keep it reviewable in one sitting. If it is not, split it.
5. Present the plan. Do not start implementing until it is accepted, unless already told to.
