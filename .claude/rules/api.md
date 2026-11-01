---
paths:
  - "src/shiptrace/api/**"
  - "docs/api/**"
---

# API rules

- Every route declares its required scope. There is no public route except health checks, login
  and static dashboard assets. New routes are picked up by generated negative auth tests.
- Authorization is enforced in the application layer too, including service/environment binding.
- Pydantic models use `extra="forbid"` and bounded lengths.
- Errors are RFC 9457 problem documents with a stable `code`. Never echo internals.
- Log allowlisted fields only. Never log tokens, `Authorization`, cookies, `reason` or bodies.
- Do not add a metric label unless its values are a small fixed set.
- Update `docs/api/openapi.json` with any contract change.
