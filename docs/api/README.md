# API schema snapshot

`openapi.json` is exported from the actual application without connecting to PostgreSQL or
loading runtime credentials. Regenerate it with:

```bash
uv run --frozen python -m shiptrace.bootstrap.openapi > docs/api/openapi.json
```

`tests/unit/test_openapi_contract.py` detects drift, requires bearer authentication metadata on
protected operations, and checks latest-successful's RFC 9457 error declarations.

This is a partial contract artifact, not completion of P2/AC24. The manually parsed ingestion
body is absent, and older routes still show FastAPI's default JSON validation-error metadata
instead of their actual problem documents. Latest-successful explicitly declares its actual
401/403/422/500/503 problem responses; the remaining operations need equivalent treatment and
schema-driven wire tests before the snapshot can be described as a complete API contract.
