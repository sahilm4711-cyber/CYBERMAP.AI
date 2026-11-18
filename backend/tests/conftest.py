"""Shared test fixtures (Phase 3).

Every test gets a FRESH temp SQLite database — never the dev
``cybermap.db``. Tables are created with ``Base.metadata.create_all``
and the roles + data_sources are seeded, exactly as the migration
does for real databases. The app's ``get_db`` dependency is
overridden to use the temp database.

The existing Phase 2 health tests keep working unchanged: they use
the same ``client`` fixture and never touch the database.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import create_app
from app.services.seed import seed_roles_and_sources

import app.models  # noqa: F401  (registers all models on Base.metadata)


@pytest.fixture()
def app_with_db(tmp_path):
    """(app, SessionFactory) bound to a fresh temp SQLite file."""
    db_path = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False
    )
    seed_roles_and_sources(TestingSession())

    app = create_app()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield app, TestingSession
    engine.dispose()


@pytest.fixture()
def client(app_with_db) -> TestClient:
    """A TestClient bound to the temp-DB app (fresh cookies per test)."""
    app, _ = app_with_db
    return TestClient(app)


@pytest.fixture()
def db_session(app_with_db):
    """A raw SQLAlchemy session on the same temp DB (for model-level setup)."""
    _, TestingSession = app_with_db
    db = TestingSession()
    yield db
    db.close()


def register_user(client: TestClient, username: str, password: str = "correct-horse-battery") -> dict:
    """Register a user via the API; returns the response JSON."""
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def login_user(client: TestClient, username: str, password: str = "correct-horse-battery") -> dict:
    """Log a user in via the API (sets the session cookie on ``client``)."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()
