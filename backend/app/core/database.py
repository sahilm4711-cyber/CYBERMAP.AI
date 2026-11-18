"""Database engine and session handling (SQLAlchemy).

Phase 2: only the engine/session plumbing exists. Real ORM models and
Alembic migrations arrive in Phase 3 (see ``docs/DATABASE.md`` for the
planned schema). The default URL is a local SQLite file so the API can
run without a database server; Docker Compose wires PostgreSQL +
pgvector instead.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings

connect_args = {}
if settings.database_url.startswith("sqlite"):
    # SQLite needs this flag for use with FastAPI's threaded server.
    connect_args = {"check_same_thread": False}

engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

if settings.database_url.startswith("sqlite"):
    # SQLite does not enforce foreign keys unless asked — turn them on
    # so ON DELETE CASCADE / FK integrity behave like PostgreSQL.
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a database session, then closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
