"""Vulnerability explorer API tests (Phase 5).

Router included directly on the test app (coordinator owns
``app.main``), same pattern as the Phase 4/6 API tests.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import vulnerabilities as vuln_api
from tests.phase5_helpers import authed_client, seed_phase5_data


@pytest.fixture()
def vuln_client(app_with_db):
    app, _ = app_with_db
    app.include_router(vuln_api.router)
    return TestClient(app)


@pytest.fixture()
def seeded(db_session: Session):
    return seed_phase5_data(db_session)


def _ids(body: dict) -> list[str]:
    return [item["cve_id"] for item in body["items"]]


def test_list_requires_auth(vuln_client: TestClient):
    assert vuln_client.get("/api/v1/vulnerabilities").status_code == 401


def test_search_by_cve_id_and_description_word(
    vuln_client: TestClient, seeded
):
    authed_client(vuln_client)
    by_id = vuln_client.get("/api/v1/vulnerabilities?q=CVE-2024-0001").json()
    assert _ids(by_id) == ["CVE-2024-0001"]
    by_word = vuln_client.get("/api/v1/vulnerabilities?q=widget").json()
    assert _ids(by_word) == ["CVE-2024-0001"]
    # Case-insensitive: description word in upper case.
    by_upper = vuln_client.get("/api/v1/vulnerabilities?q=WIDGET").json()
    assert _ids(by_upper) == ["CVE-2024-0001"]
    by_title = vuln_client.get("/api/v1/vulnerabilities?q=Buffer").json()
    assert _ids(by_title) == ["CVE-2023-9999"]
    assert vuln_client.get("/api/v1/vulnerabilities?q=zzz-no-match").json()["total"] == 0


def test_filters_narrow_correctly(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    base = "/api/v1/vulnerabilities"
    assert _ids(vuln_client.get(f"{base}?severity=HIGH").json()) == [
        "CVE-2024-0002",
        "CVE-2023-9999",
    ]
    assert _ids(
        vuln_client.get(f"{base}?severity=HIGH&severity=CRITICAL").json()
    ) == ["CVE-2024-0002", "CVE-2024-0001", "CVE-2023-9999"]
    assert _ids(vuln_client.get(f"{base}?cwe=CWE-79").json()) == [
        "CVE-2024-0003",
        "CVE-2024-0001",
    ]
    assert _ids(vuln_client.get(f"{base}?min_cvss=9").json()) == [
        "CVE-2024-0001"
    ]
    assert _ids(vuln_client.get(f"{base}?max_cvss=3").json()) == [
        "CVE-2024-0005",
        "CVE-2024-0004",
    ]
    assert _ids(vuln_client.get(f"{base}?min_epss=0.7").json()) == [
        "CVE-2024-0001",
        "CVE-2023-9999",
    ]
    assert _ids(vuln_client.get(f"{base}?max_epss=0.1").json()) == [
        "CVE-2024-0003",
        "CVE-2024-0004",
    ]
    assert _ids(vuln_client.get(f"{base}?vendor=acme").json()) == [
        "CVE-2024-0002",
        "CVE-2024-0001",
    ]
    assert _ids(vuln_client.get(f"{base}?product=widget").json()) == [
        "CVE-2024-0001"
    ]
    assert _ids(vuln_client.get(f"{base}?published_from=2024-02-01&published_to=2024-03-31").json()) == [
        "CVE-2024-0003",
        "CVE-2024-0002",
    ]


def test_kev_only_excludes_non_kev(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    body = vuln_client.get("/api/v1/vulnerabilities?kev_only=true").json()
    assert body["total"] == 2
    assert set(_ids(body)) == {"CVE-2024-0001", "CVE-2024-0004"}
    assert all(item["is_kev"] for item in body["items"])
    plain = vuln_client.get("/api/v1/vulnerabilities").json()
    assert plain["total"] == 6
    assert any(not item["is_kev"] for item in plain["items"])


def test_sorting_orders_correctly(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    base = "/api/v1/vulnerabilities"
    newest = _ids(vuln_client.get(f"{base}?sort=newest").json())
    assert newest == [
        "CVE-2024-0005",
        "CVE-2024-0003",
        "CVE-2024-0002",
        "CVE-2024-0004",
        "CVE-2024-0001",
        "CVE-2023-9999",
    ]
    assert _ids(vuln_client.get(f"{base}?sort=oldest").json()) == list(
        reversed(newest)
    )
    assert _ids(vuln_client.get(f"{base}?sort=cvss").json()) == [
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2023-9999",
        "CVE-2024-0003",
        "CVE-2024-0004",
        "CVE-2024-0005",
    ]
    assert _ids(vuln_client.get(f"{base}?sort=epss").json()) == [
        "CVE-2024-0001",
        "CVE-2023-9999",
        "CVE-2024-0002",
        "CVE-2024-0003",
        "CVE-2024-0004",
        "CVE-2024-0005",
    ]
    # Risk = EPSS desc, then CVSS desc (same order here).
    assert _ids(vuln_client.get(f"{base}?sort=risk").json()) == [
        "CVE-2024-0001",
        "CVE-2023-9999",
        "CVE-2024-0002",
        "CVE-2024-0003",
        "CVE-2024-0004",
        "CVE-2024-0005",
    ]
    assert _ids(vuln_client.get(f"{base}?sort=severity").json()) == [
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2023-9999",
        "CVE-2024-0003",
        "CVE-2024-0004",
        "CVE-2024-0005",
    ]


def test_pagination_totals_and_pages(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    page1 = vuln_client.get("/api/v1/vulnerabilities?per_page=2&page=1").json()
    assert page1["total"] == 6
    assert page1["page"] == 1
    assert page1["per_page"] == 2
    assert page1["pages"] == 3
    assert len(page1["items"]) == 2
    page3 = vuln_client.get("/api/v1/vulnerabilities?per_page=2&page=3").json()
    assert len(page3["items"]) == 2
    assert _ids(page1) != _ids(page3)
    assert vuln_client.get("/api/v1/vulnerabilities?per_page=101").status_code == 422


def test_detail_full_fields(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    resp = vuln_client.get("/api/v1/vulnerabilities/CVE-2024-0001")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cve_id"] == "CVE-2024-0001"
    assert body["severity"] == "CRITICAL"
    assert body["cvss_score"] == 9.8
    assert body["cvss_vector"].startswith("CVSS:3.1/")
    assert [c["cwe_id"] for c in body["cwes"]] == ["CWE-79"]
    assert body["affected_products"][0]["vendor"] == "acme"
    assert body["affected_products"][0]["product"] == "widget"
    assert body["epss"]["epss_score"] == 0.9
    assert body["epss"]["percentile"] == 0.99
    assert body["kev"]["due_date"] == "2024-02-01"
    assert body["kev"]["ransomware_use"] == "Known"
    assert body["remediation"] == "Apply the vendor patch immediately."
    assert body["references"][0]["url"] == "https://example.com/advisory-0001"
    # Related: CVE-2024-0003 shares CWE-79.
    assert [r["cve_id"] for r in body["related"]] == ["CVE-2024-0003"]


def test_detail_missing_epss_kev_shown_as_unavailable(
    vuln_client: TestClient, seeded
):
    authed_client(vuln_client)
    body = vuln_client.get("/api/v1/vulnerabilities/CVE-2024-0005").json()
    assert body["epss"] is None
    assert body["kev"] is None
    assert body["remediation"] is None
    assert body["cwes"] == []
    assert body["related"] == []


def test_detail_404_for_unknown_cve(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    assert (
        vuln_client.get("/api/v1/vulnerabilities/CVE-1999-0001").status_code
        == 404
    )
    assert (
        vuln_client.get("/api/v1/vulnerabilities/CVE-1999-0001/related").status_code
        == 404
    )


def test_related_endpoint(vuln_client: TestClient, seeded):
    authed_client(vuln_client)
    body = vuln_client.get("/api/v1/vulnerabilities/CVE-2024-0003/related").json()
    assert [r["cve_id"] for r in body] == ["CVE-2024-0001"]
    # CVE with no CWE has no related CVEs.
    assert (
        vuln_client.get("/api/v1/vulnerabilities/CVE-2024-0005/related").json()
        == []
    )
