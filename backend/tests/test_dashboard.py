"""Dashboard API tests (Phase 5).

The dashboard router is NOT registered in ``app.main`` (the
coordinator owns that), so these tests include it on the test app
directly — exactly what the coordinator will do in ``main.py``.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import dashboard as dashboard_api
from tests.phase5_helpers import authed_client, seed_phase5_data


@pytest.fixture()
def dashboard_client(app_with_db):
    app, _ = app_with_db
    app.include_router(dashboard_api.router)
    return TestClient(app)


@pytest.fixture()
def seeded(db_session: Session):
    return seed_phase5_data(db_session)


def test_summary_requires_auth(dashboard_client: TestClient):
    assert dashboard_client.get("/api/v1/dashboard/summary").status_code == 401
    assert dashboard_client.get("/api/v1/dashboard/trends").status_code == 401


def test_summary_counts_match_seeded_data(
    dashboard_client: TestClient, seeded
):
    authed_client(dashboard_client)
    resp = dashboard_client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_cves"] == 6
    assert body["critical"] == 1
    assert body["high"] == 2
    assert body["medium"] == 1
    assert body["low"] == 1
    assert body["none_severity"] == 1
    assert body["unknown_severity"] == 0
    assert body["kev_count"] == 2
    assert body["high_epss_count"] == 2  # 0.9 and 0.75
    assert body["last_sync_at"] is not None
    assert {s["name"] for s in body["sources"]} == {
        "nvd",
        "cisa-kev",
        "epss",
        "mitre-attack",
        "mitre-cwe",
    }
    nvd = next(s for s in body["sources"] if s["name"] == "nvd")
    assert nvd["last_sync_status"] == "success"
    # Newest first: 2024-04-01, 2024-03-01, 2024-02-05, ...
    recent = body["recently_published"]
    assert len(recent) == 6
    assert recent[0]["cve_id"] == "CVE-2024-0005"
    assert recent[-1]["cve_id"] == "CVE-2023-9999"


def test_summary_date_range_changes_counts(
    dashboard_client: TestClient, seeded
):
    authed_client(dashboard_client)
    full = dashboard_client.get("/api/v1/dashboard/summary").json()
    ranged = dashboard_client.get(
        "/api/v1/dashboard/summary?from=2024-02-01&to=2024-03-31"
    ).json()
    assert full["total_cves"] == 6
    # Published Feb–Mar 2024: CVE-2024-0002, CVE-2024-0003 only.
    assert ranged["total_cves"] == 2
    assert ranged["critical"] == 0
    assert ranged["high"] == 1
    assert ranged["medium"] == 1
    assert ranged["low"] == 0
    assert [r["cve_id"] for r in ranged["recently_published"]] == [
        "CVE-2024-0003",
        "CVE-2024-0002",
    ]
    # Range-independent facts stay put.
    assert ranged["kev_count"] == 2
    assert ranged["high_epss_count"] == 2


def test_summary_empty_db_reports_zero_not_fake_data(
    dashboard_client: TestClient,
):
    authed_client(dashboard_client)
    body = dashboard_client.get("/api/v1/dashboard/summary").json()
    assert body["total_cves"] == 0
    assert body["kev_count"] == 0
    assert body["recently_published"] == []
    assert body["last_sync_at"] is None
    assert all(s["last_sync_status"] == "never" for s in body["sources"])


def test_trends_publications_severity_cwe_kev_epss(
    dashboard_client: TestClient, seeded
):
    authed_client(dashboard_client)
    resp = dashboard_client.get(
        "/api/v1/dashboard/trends?from=2023-06-01&to=2024-04-01"
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["range_from"] == "2023-06-01"
    assert body["range_to"] == "2024-04-01"
    per_day = {row["date"]: row["count"] for row in body["publications_per_day"]}
    assert per_day["2024-01-10"] == 1
    assert per_day["2024-01-20"] == 1
    assert per_day["2023-06-01"] == 1
    assert per_day["2024-01-11"] == 0
    assert sum(per_day.values()) == 6
    dist = body["severity_distribution"]
    assert dist["CRITICAL"] == 1
    assert dist["HIGH"] == 2
    assert dist["MEDIUM"] == 1
    assert dist["LOW"] == 1
    assert dist["NONE"] == 1
    cwe = {row["cwe_id"]: row["count"] for row in body["cwe_distribution"]}
    assert cwe["CWE-79"] == 2  # CVE-2024-0001, CVE-2024-0003
    assert cwe["CWE-20"] == 2  # CVE-2024-0004, CVE-2023-9999
    assert cwe["CWE-89"] == 1
    kev = {row["date"]: row["count"] for row in body["kev_additions_per_day"]}
    assert kev["2024-01-15"] == 1
    assert kev["2024-01-25"] == 1
    assert sum(kev.values()) == 2
    buckets = body["epss_buckets"]
    assert buckets["0-0.1"] == 2  # 0.05, 0.01
    assert buckets["0.1-0.3"] == 0
    assert buckets["0.3-0.5"] == 0
    assert buckets["0.5-0.7"] == 1  # 0.5
    assert buckets["0.7-1.0"] == 2  # 0.9, 0.75


def test_trends_default_range_is_30_days(
    dashboard_client: TestClient, seeded
):
    authed_client(dashboard_client)
    body = dashboard_client.get("/api/v1/dashboard/trends").json()
    assert len(body["publications_per_day"]) == 30
    assert len(body["kev_additions_per_day"]) == 30
