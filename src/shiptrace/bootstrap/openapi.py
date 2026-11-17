"""Export the API contract without a database connection or runtime credentials.

Run with `uv run --frozen python -m shiptrace.bootstrap.openapi` from the repository root.
The composition root creates a lazy engine; building OpenAPI does not open it or start lifespan.
"""

import json
from typing import Any

from shiptrace.bootstrap.app import create_app
from shiptrace.bootstrap.settings import Settings


def schema() -> dict[str, Any]:
    settings = Settings.model_validate(
        {
            "environment": "test",
            "database_url": "postgresql+psycopg://shiptrace_app@127.0.0.1/openapi_only",
        }
    )
    return create_app(settings).openapi()


if __name__ == "__main__":
    print(json.dumps(schema(), indent=2, sort_keys=True))
