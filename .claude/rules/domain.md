---
paths:
  - "src/shiptrace/domain/**"
  - "tests/unit/**"
---

# Domain rules

- Stdlib only. No clock, randomness, I/O, logging or framework imports.
- Time and IDs come in as arguments.
- Each ingestion rule R1–R11 in `docs/PROJECT_SPEC.md` maps to named tests. Changing behavior
  means changing the spec first.
- Status derivation must stay order-independent; keep the Hypothesis permutation test.
