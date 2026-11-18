"""Ingestion API tests (Phase 4).

The ingestion router is NOT registered in ``app.main`` (the
coordinator owns that), so these tests include it on the test app
directly — exactly what the coordinator will do in ``main.py``.
Sync runs use monkeypatched fetchers, so no live HTTP happens.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import ingestion as ingestion_api
from app.ingestion import run as run_module
from app.models import Role, User
from tests.conftest import login_user, register_user
from tests.ingestion_fixtures import NVD_FULL_RECORD


@pytest.fixture()
def ingestion_client(app_with_db):
    """TestClient with the ingestion router included."""
    app, _ = app_with_db
    app.include_router(ingestion_api.router)
    return TestClient(app)


def _make_admin(client: TestClient, db_session: Session, username: str = "admin"):
    register_user(client, username)
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    user = db_session.query(User).filter(User.username == username).first()
    user.role_id = admin_role.id
    db_session.commit()
    login_user(client, username)
    return user


def test_status_requires_auth(ingestion_client: TestClient):
    resp = ingestion_client.get("/api/v1/ingestion/status")
    assert resp.status_code == 401


def test_status_lists_all_sources_for_logged_in_user(
    ingestion_client: TestClient, db_session: Session,
):
    register_user(ingestion_client, "alice")
    login_user(ingestion_client, "alice")
    resp = ingestion_client.get("/api/v1/ingestion/status")
    assert resp.status_code == 200
    sources = {row["source"] for row in resp.json()}
    assert sources == {"nvd", "cisa-kev", "epss", "mitre-attack", "mitre-cwe"}
    assert all(row["last_job"] is None for row in resp.json())


def test_jobs_requires_auth_and_lists_history(
    ingestion_client: TestClient, db_session: Session, monkeypatch,
):
    resp = ingestion_client.get("/api/v1/ingestion/jobs")
    assert resp.status_code == 401
    _make_admin(ingestion_client, db_session)
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [NVD_FULL_RECORD]
    )
    sync = ingestion_client.post("/api/v1/ingestion/sync/nvd")
    assert sync.status_code == 200
    jobs = ingestion_client.get("/api/v1/ingestion/jobs")
    assert jobs.status_code == 200
    assert len(jobs.json()) == 1
    assert jobs.json()[0]["source"] == "nvd"
    assert jobs.json()[0]["records_created"] == 1


def test_sync_non_admin_gets_403(
    ingestion_client: TestClient, db_session: Session,
):
    register_user(ingestion_client, "alice")
    login_user(ingestion_client, "alice")
    resp = ingestion_client.post("/api/v1/ingestion/sync/nvd")
    assert resp.status_code == 403


def test_sync_unauthenticated_gets_401(ingestion_client: TestClient):
    resp = ingestion_client.post("/api/v1/ingestion/sync/nvd")
    assert resp.status_code == 401


def test_sync_admin_triggers_mocked_run_and_returns_summary(
    ingestion_client: TestClient, db_session: Session, monkeypatch,
):
    _make_admin(ingestion_client, db_session)
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [NVD_FULL_RECORD]
    )
    resp = ingestion_client.post("/api/v1/ingestion/sync/nvd?limit=10")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "nvd"
    assert body["status"] == "success"
    assert body["records_fetched"] == 1
    assert body["records_created"] == 1
    assert body["job_id"] is not None


def test_sync_second_immediate_trigger_gets_429(
    ingestion_client: TestClient, db_session: Session, monkeypatch,
):
    _make_admin(ingestion_client, db_session)
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [NVD_FULL_RECORD]
    )
    first = ingestion_client.post("/api/v1/ingestion/sync/nvd")
    assert first.status_code == 200
    second = ingestion_client.post("/api/v1/ingestion/sync/nvd")
    assert second.status_code == 429


def test_sync_unknown_source_gets_404(
    ingestion_client: TestClient, db_session: Session,
):
    _make_admin(ingestion_client, db_session)
    resp = ingestion_client.post("/api/v1/ingestion/sync/bogus")
    assert resp.status_code == 404
