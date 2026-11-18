"""Tests for the root and health endpoints (Phase 2 foundation).

These are the only endpoints that exist in Phase 2. They must answer
without a database, because ingestion and models arrive in Phases 3-4.
"""

from fastapi.testclient import TestClient


def test_root_returns_service_info(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "cybermap-ai"
    assert body["version"] == "0.1.0"
    assert body["health"] == "/health"
    assert body["docs"] == "/docs"


def test_health_endpoint_ok(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "cybermap-ai"
    assert body["version"] == "0.1.0"
    assert body["environment"] == "development"
    assert "timestamp" in body
    # Phase 9: the database field is a real check now — the temp DB
    # answers SELECT 1, so it reports "ok" (the Phase 2 placeholder
    # "not_configured" is gone).
    assert body["database"] == "ok"
    assert body["ai_mode"] == "fallback"


def test_api_v1_health_reports_database_ok(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["database"] == "ok"


def test_health_reports_error_when_database_unreachable(
    app_with_db,
) -> None:
    """Point the app at an unreachable DB file: the service still
    answers 200 (it is up) but reports ``database: "error"``."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import get_db

    app, _ = app_with_db
    bad_engine = create_engine(
        "sqlite:////nonexistent-dir-xyz/health.db",
        connect_args={"check_same_thread": False},
    )
    BadSession = sessionmaker(
        bind=bad_engine, autoflush=False, expire_on_commit=False
    )

    def bad_get_db():
        db = BadSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = bad_get_db
    bad_client = TestClient(app)
    resp = bad_client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["database"] == "error"
    assert body["status"] == "ok"
    bad_engine.dispose()


def test_api_v1_health_matches_root_health(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "cybermap-ai"
    assert body["ai_mode"] == "fallback"


def test_unknown_route_returns_404(client: TestClient) -> None:
    resp = client.get("/api/v1/definitely-not-a-route")
    assert resp.status_code == 404


def test_vulnerabilities_requires_auth(client: TestClient) -> None:
    # Phase 5 built this route; unauthenticated callers get 401, not 404.
    resp = client.get("/api/v1/vulnerabilities")
    assert resp.status_code == 401
