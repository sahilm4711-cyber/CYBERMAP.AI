"""Threat-intelligence API tests (Phase 5).

Router included directly on the test app (coordinator owns
``app.main``), same pattern as the Phase 4/6 API tests.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import intelligence as intel_api
from tests.phase5_helpers import authed_client, seed_phase5_data


@pytest.fixture()
def intel_client(app_with_db):
    app, _ = app_with_db
    app.include_router(intel_api.router)
    return TestClient(app)


@pytest.fixture()
def seeded(db_session: Session):
    return seed_phase5_data(db_session)


def test_all_endpoints_require_auth(intel_client: TestClient):
    for path in (
        "/api/v1/intelligence/kev",
        "/api/v1/intelligence/epss-ranking",
        "/api/v1/intelligence/timeline",
        "/api/v1/intelligence/metrics-explained",
    ):
        assert intel_client.get(path).status_code == 401


def test_kev_newest_first_and_paginated(
    intel_client: TestClient, seeded
):
    authed_client(intel_client)
    body = intel_client.get("/api/v1/intelligence/kev").json()
    assert body["total"] == 2
    assert body["pages"] == 1
    # Newest date_added first: 2024-01-25 before 2024-01-15.
    assert body["items"][0]["cve_id"] == "CVE-2024-0004"
    assert body["items"][0]["due_date"] == "2024-02-15"
    assert body["items"][0]["is_indexed"] is True
    assert body["items"][1]["cve_id"] == "CVE-2024-0001"
    page2 = intel_client.get("/api/v1/intelligence/kev?per_page=1&page=2").json()
    assert page2["total"] == 2
    assert page2["pages"] == 2
    assert page2["items"][0]["cve_id"] == "CVE-2024-0001"


def test_epss_ranking_descending(intel_client: TestClient, seeded):
    authed_client(intel_client)
    body = intel_client.get("/api/v1/intelligence/epss-ranking").json()
    assert body["total"] == 5
    scores = [item["epss_score"] for item in body["items"]]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == 0.9
    assert body["items"][0]["cve_id"] == "CVE-2024-0001"
    assert body["items"][1]["cve_id"] == "CVE-2023-9999"
    assert body["items"][1]["epss_score"] == 0.75
    assert body["items"][-1]["epss_score"] == 0.01


def test_timeline_merges_event_types(intel_client: TestClient, seeded):
    authed_client(intel_client)
    body = intel_client.get("/api/v1/intelligence/timeline").json()
    events = body["events"]
    assert len(events) <= 50
    types = {e["type"] for e in events}
    assert types == {"cve", "kev", "ingestion"}
    dates = [e["date"] for e in events]
    assert dates == sorted(dates, reverse=True)
    cve_events = [e for e in events if e["type"] == "cve"]
    assert cve_events[0]["cve_id"] == "CVE-2024-0005"
    kev_events = [e for e in events if e["type"] == "kev"]
    assert kev_events[0]["cve_id"] == "CVE-2024-0004"
    job_events = [e for e in events if e["type"] == "ingestion"]
    assert job_events[0]["source"] == "nvd"
    assert job_events[0]["status"] == "success"


def test_metrics_explained_three_distinct_definitions(
    intel_client: TestClient, seeded
):
    authed_client(intel_client)
    body = intel_client.get("/api/v1/intelligence/metrics-explained").json()
    assert len(body["metrics"]) == 3
    names = [m["name"] for m in body["metrics"]]
    assert names[0] == "CVSS"
    assert names[1] == "EPSS"
    assert "KEV" in names[2]
    # The three definitions must be genuinely different text.
    definitions = {m["what_it_measures"] for m in body["metrics"]}
    assert len(definitions) == 3
    assert "severe" in body["metrics"][0]["what_it_measures"].lower()
    assert "probability" in body["metrics"][1]["what_it_measures"].lower()
    assert "exploited" in body["metrics"][2]["what_it_measures"].lower()
    # Explicitly not interchangeable.
    assert "not interchangeable" in body["note"].lower()
    for metric in body["metrics"]:
        assert metric["limitations"], metric["name"]
        assert metric["what_it_does_not_mean"], metric["name"]
