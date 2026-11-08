"""Services and environments in PostgreSQL, through the runtime role's SELECT and INSERT (slug).

Every statement is written out literally per table; nothing is built from strings. Races are
settled by the unique index on slug: ON CONFLICT DO NOTHING makes a second writer wait for the
first and then insert nothing. Ids and timestamps come from the database defaults.
"""

from dataclasses import dataclass

from sqlalchemy import TextClause, text
from sqlalchemy.engine import Engine, Row
from sqlalchemy.exc import SQLAlchemyError

from shiptrace.application.access import StoreUnavailable
from shiptrace.application.registry import Kind, RegistryEntry


@dataclass(frozen=True)
class _Statements:
    insert: TextClause
    first_page: TextClause
    next_page: TextClause


_SQL = {
    Kind.SERVICES: _Statements(
        insert=text(
            "INSERT INTO services (slug) VALUES (:slug) "
            "ON CONFLICT (slug) DO NOTHING RETURNING id, slug, created_at"
        ),
        first_page=text("SELECT id, slug, created_at FROM services ORDER BY slug LIMIT :limit"),
        next_page=text(
            "SELECT id, slug, created_at FROM services WHERE slug > :after "
            "ORDER BY slug LIMIT :limit"
        ),
    ),
    Kind.ENVIRONMENTS: _Statements(
        insert=text(
            "INSERT INTO environments (slug) VALUES (:slug) "
            "ON CONFLICT (slug) DO NOTHING RETURNING id, slug, created_at"
        ),
        first_page=text("SELECT id, slug, created_at FROM environments ORDER BY slug LIMIT :limit"),
        next_page=text(
            "SELECT id, slug, created_at FROM environments WHERE slug > :after "
            "ORDER BY slug LIMIT :limit"
        ),
    ),
}


def _entry(row: Row[tuple[object, ...]]) -> RegistryEntry:
    return RegistryEntry(id=row.id, slug=row.slug, created_at=row.created_at)


class PostgresRegistry:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def add(self, kind: Kind, slug: str) -> RegistryEntry | None:
        try:
            with self._engine.begin() as connection:
                row = connection.execute(_SQL[kind].insert, {"slug": slug}).one_or_none()
        except SQLAlchemyError:
            raise StoreUnavailable from None  # Never the statement or the bound slug.
        return None if row is None else _entry(row)

    def list_after(self, kind: Kind, after: str | None, limit: int) -> list[RegistryEntry]:
        params: dict[str, object] = {"limit": limit}
        statement = _SQL[kind].first_page
        if after is not None:
            statement, params["after"] = _SQL[kind].next_page, after
        try:
            with self._engine.connect() as connection:
                rows = connection.execute(statement, params).all()
        except SQLAlchemyError:
            raise StoreUnavailable from None
        return [_entry(row) for row in rows]
