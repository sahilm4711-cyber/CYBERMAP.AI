"""Dialect-aware column types.

PostgreSQL is the production database; SQLite is the local-dev fallback
(no server in this environment). These types compile to the rich
Postgres type when the engine dialect is ``postgresql`` and to a plain
SQLite-compatible type otherwise, so the same models and the same
migration work on both.
"""

from sqlalchemy import JSON, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import TypeDecorator

# JSONB on Postgres (DATABASE.md), plain JSON on SQLite.
JSONB = JSON().with_variant(postgresql.JSONB, "postgresql")

# INET on Postgres (DATABASE.md), plain string on SQLite.
INET = postgresql.INET().with_variant(String(45), "sqlite")


class EmbeddingVector(TypeDecorator):
    """Embedding column: ``vector(1536)`` on Postgres, JSON on SQLite.

    DATABASE.md §2.20 / §3: pgvector on Postgres, JSON fallback on
    SQLite with cosine similarity computed in Python. The pgvector
    import is lazy so the package is only required when the dialect
    is actually PostgreSQL (it is a runtime dependency in
    ``requirements.txt`` for the Docker/Postgres deployment).
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from pgvector.sqlalchemy import Vector

            return Vector(1536)
        return JSON()
