---
paths:
  - "tests/**"
---

# Testing rules

- Integration tests use real PostgreSQL through Testcontainers. Do not mock the database, and do
  not use SQLite.
- Assert observable behavior: status, body, resulting rows. Avoid asserting that mocks were called.
- Each test must be able to fail for a real defect. For subtle tests, break the code briefly and
  confirm it fails.
- Concurrency tests use real connections and a barrier, with a timeout, and no sleeps as
  synchronization.
- Test credentials are generated at runtime. Do not commit realistic token strings.
