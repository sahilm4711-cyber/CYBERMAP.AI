"""Research workspace API tests (Phase 8).

The research router is NOT registered in ``app/main.py``
(coordinator registers routers), so these tests include it on the
test app explicitly — the same router object the coordinator will
register. Isolation: user B must get 404 (not 403) for user A's
collections, notes and analyses, and must not list A's items.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import research as research_router
from app.models import (
    AttackTechnique,
    CweEntry,
    ResearchNote,
    SavedAnalysis,
    User,
    Vulnerability,
)
from tests.conftest import login_user, register_user


@pytest.fixture()
def research_client(app_with_db):
    app, _ = app_with_db
    app.include_router(research_router.router)
    return TestClient(app)


@pytest.fixture()
def client_b(app_with_db):
    app, _ = app_with_db
    app.include_router(research_router.router)
    client = TestClient(app)
    register_user(client, "bob")
    login_user(client, "bob")
    return client


@pytest.fixture()
def user_a(research_client):
    register_user(research_client, "alice")
    login_user(research_client, "alice")
    return "alice"


def _seed_entities(db_session: Session):
    vuln = Vulnerability(
        cve_id="CVE-2024-11111",
        description="A test injection flaw in the demo parser.",
        cvss_score=9.8,
        severity="CRITICAL",
        source="nvd",
    )
    vuln2 = Vulnerability(
        cve_id="CVE-2024-22222",
        description="A test cross-site scripting flaw.",
        cvss_score=6.1,
        severity="MEDIUM",
        source="nvd",
    )
    cwe = CweEntry(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command",
        description="SQL injection.",
        source="mitre-cwe",
    )
    tech = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        description="Adversaries abuse PowerShell.",
        tactic="Execution",
        source="mitre-attack",
    )
    db_session.add_all([vuln, vuln2, cwe, tech])
    db_session.commit()
    return vuln, vuln2, cwe, tech


def _make_collection(client: TestClient, name="Alice research"):
    resp = client.post(
        "/api/v1/research/collections",
        json={"name": name, "description": "private"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_note(client: TestClient, **overrides):
    payload = {"title": "A note", "body": "findings", "tags": ["web"]}
    payload.update(overrides)
    resp = client.post("/api/v1/research/notes", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ------------------------------------------------------------------
# Collections
# ------------------------------------------------------------------


def test_create_and_list_collections_own_only(
    research_client, client_b, user_a
):
    mine = _make_collection(research_client)
    assert mine["name"] == "Alice research"
    assert mine["item_count"] == 0
    resp = research_client.get("/api/v1/research/collections")
    assert resp.status_code == 200
    assert [c["id"] for c in resp.json()["items"]] == [mine["id"]]
    # Bob's list is empty: he cannot list Alice's collections.
    resp = client_b.get("/api/v1/research/collections")
    assert resp.status_code == 200
    assert resp.json()["items"] == []
    assert resp.json()["total"] == 0


def test_other_user_cannot_get_patch_delete_collection(
    research_client, client_b, user_a
):
    mine = _make_collection(research_client)
    url = f"/api/v1/research/collections/{mine['id']}"
    assert client_b.get(url).status_code == 404
    assert client_b.patch(url, json={"name": "stolen"}).status_code == 404
    assert client_b.delete(url).status_code == 404
    # Alice's collection is untouched.
    assert research_client.get(url).status_code == 200


def test_update_and_delete_own_collection(research_client, user_a):
    mine = _make_collection(research_client)
    url = f"/api/v1/research/collections/{mine['id']}"
    resp = research_client.patch(url, json={"name": "Renamed"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    assert research_client.delete(url).status_code == 204
    assert research_client.get(url).status_code == 404


# ------------------------------------------------------------------
# Collection items
# ------------------------------------------------------------------


def test_add_item_and_duplicate_is_idempotent_200(
    research_client, user_a, db_session
):
    vuln, _, _, _ = _seed_entities(db_session)
    mine = _make_collection(research_client)
    url = f"/api/v1/research/collections/{mine['id']}/items"
    payload = {"item_type": "vulnerability", "item_id": str(vuln.id)}
    first = research_client.post(url, json=payload)
    assert first.status_code == 201, first.text
    assert first.json()["label"] == "CVE-2024-11111"
    second = research_client.post(url, json=payload)
    assert second.status_code == 200, second.text
    assert second.json()["id"] == first.json()["id"]
    items = research_client.get(url).json()
    assert items["total"] == 1


def test_add_item_to_nonexistent_entity_is_404(
    research_client, user_a, db_session
):
    _seed_entities(db_session)
    mine = _make_collection(research_client)
    url = f"/api/v1/research/collections/{mine['id']}/items"
    resp = research_client.post(
        url,
        json={"item_type": "vulnerability", "item_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404


def test_other_user_cannot_list_or_remove_items(
    research_client, client_b, user_a, db_session
):
    vuln, _, cwe, _ = _seed_entities(db_session)
    mine = _make_collection(research_client)
    base = f"/api/v1/research/collections/{mine['id']}"
    research_client.post(
        f"{base}/items",
        json={"item_type": "vulnerability", "item_id": str(vuln.id)},
    )
    research_client.post(
        f"{base}/items",
        json={"item_type": "cwe", "item_id": str(cwe.id)},
    )
    assert client_b.get(f"{base}/items").status_code == 404
    assert (
        client_b.delete(
            f"{base}/items/{vuln.id}?item_type=vulnerability"
        ).status_code
        == 404
    )
    # Alice still has both items.
    assert research_client.get(f"{base}/items").json()["total"] == 2


def test_remove_item(research_client, user_a, db_session):
    vuln, _, _, _ = _seed_entities(db_session)
    mine = _make_collection(research_client)
    base = f"/api/v1/research/collections/{mine['id']}"
    research_client.post(
        f"{base}/items",
        json={"item_type": "vulnerability", "item_id": str(vuln.id)},
    )
    resp = research_client.delete(
        f"{base}/items/{vuln.id}?item_type=vulnerability"
    )
    assert resp.status_code == 204
    assert research_client.get(f"{base}/items").json()["total"] == 0


# ------------------------------------------------------------------
# Bookmarks (a "Bookmarks" collection per user)
# ------------------------------------------------------------------


def test_bookmarks_isolated_per_user(
    research_client, client_b, user_a, db_session
):
    vuln, _, _, _ = _seed_entities(db_session)
    resp = research_client.post(
        "/api/v1/research/bookmarks",
        json={"item_type": "vulnerability", "item_id": str(vuln.id)},
    )
    assert resp.status_code in (200, 201), resp.text
    assert resp.json()["label"] == "CVE-2024-11111"
    # Bob has no bookmarks and cannot see Alice's.
    assert client_b.get("/api/v1/research/bookmarks").json()["total"] == 0
    mine = research_client.get("/api/v1/research/bookmarks").json()
    assert mine["total"] == 1
    # Duplicate bookmark is idempotent.
    again = research_client.post(
        "/api/v1/research/bookmarks",
        json={"item_type": "vulnerability", "item_id": str(vuln.id)},
    )
    assert again.status_code == 200
    # Remove it.
    resp = research_client.delete(
        f"/api/v1/research/bookmarks/vulnerability/{vuln.id}"
    )
    assert resp.status_code == 204
    assert (
        research_client.get("/api/v1/research/bookmarks").json()["total"]
        == 0
    )


# ------------------------------------------------------------------
# Notes
# ------------------------------------------------------------------


def test_notes_crud_and_isolation(
    research_client, client_b, user_a, db_session
):
    vuln, _, _, _ = _seed_entities(db_session)
    mine = _make_collection(research_client)
    note = _make_note(
        research_client,
        collection_id=mine["id"],
        vulnerability_id=str(vuln.id),
        tags=["web", "status"],
    )
    url = f"/api/v1/research/notes/{note['id']}"
    assert client_b.get(url).status_code == 404
    assert client_b.patch(url, json={"body": "stolen"}).status_code == 404
    assert client_b.delete(url).status_code == 404
    # Filters: by tag and by collection.
    listed = research_client.get("/api/v1/research/notes?tag=web").json()
    assert listed["total"] == 1
    listed = research_client.get(
        f"/api/v1/research/notes?collection_id={mine['id']}"
    ).json()
    assert listed["total"] == 1
    assert (
        research_client.get("/api/v1/research/notes?tag=other").json()[
            "total"
        ]
        == 0
    )
    # Bob's list is empty.
    assert client_b.get("/api/v1/research/notes").json()["total"] == 0
    # Update + delete by owner.
    resp = research_client.patch(url, json={"body": "updated"})
    assert resp.status_code == 200
    assert resp.json()["body"] == "updated"
    assert research_client.delete(url).status_code == 204


def test_note_linking_to_others_collection_is_404(
    research_client, client_b, user_a
):
    # Bob creates a collection; Alice linking a note to it is 404.
    b_collection = _make_collection(client_b, "Bob research")
    resp = research_client.post(
        "/api/v1/research/notes",
        json={
            "body": "sneaky",
            "collection_id": b_collection["id"],
        },
    )
    assert resp.status_code == 404


# ------------------------------------------------------------------
# Saved analyses
# ------------------------------------------------------------------


def _seed_analysis(db_session: Session, username: str):
    user = db_session.query(User).filter(User.username == username).first()
    vuln = Vulnerability(
        cve_id="CVE-2024-33333",
        description="Seeded for saved-analysis tests.",
        severity="HIGH",
        source="nvd",
    )
    db_session.add(vuln)
    db_session.commit()
    analysis = SavedAnalysis(
        user_id=user.id,
        vulnerability_id=vuln.id,
        analysis_type="simple",
        content={"executive_summary": "test"},
        ai_mode="fallback",
        model=None,
    )
    db_session.add(analysis)
    db_session.commit()
    return analysis, vuln


def test_saved_analyses_isolated(
    research_client, client_b, user_a, db_session
):
    analysis, vuln = _seed_analysis(db_session, "alice")
    url = f"/api/v1/research/analyses/{analysis.id}"
    assert client_b.get(url).status_code == 404
    assert client_b.delete(url).status_code == 404
    assert client_b.get("/api/v1/research/analyses").json()["total"] == 0
    mine = research_client.get("/api/v1/research/analyses").json()
    assert mine["total"] == 1
    assert mine["items"][0]["cve_id"] == "CVE-2024-33333"
    assert mine["items"][0]["analysis_type"] == "simple"
    # Filter by vulnerability.
    filtered = research_client.get(
        f"/api/v1/research/analyses?vulnerability_id={vuln.id}"
    ).json()
    assert filtered["total"] == 1
    assert research_client.delete(url).status_code == 204


# ------------------------------------------------------------------
# Compare
# ------------------------------------------------------------------


def test_compare_validation_and_unknown_cve(
    research_client, user_a, db_session
):
    vuln, vuln2, _, _ = _seed_entities(db_session)
    # 1 CVE -> 422.
    resp = research_client.post(
        "/api/v1/research/compare", json={"cve_ids": ["CVE-2024-11111"]}
    )
    assert resp.status_code == 422
    # 6 CVEs -> 422.
    resp = research_client.post(
        "/api/v1/research/compare",
        json={"cve_ids": [f"CVE-2024-0000{i}" for i in range(6)]},
    )
    assert resp.status_code == 422
    # Unknown CVE -> 404.
    resp = research_client.post(
        "/api/v1/research/compare",
        json={"cve_ids": ["CVE-2024-11111", "CVE-1999-99999"]},
    )
    assert resp.status_code == 404
    # Valid pair returns side-by-side rows.
    resp = research_client.post(
        "/api/v1/research/compare",
        json={"cve_ids": ["CVE-2024-11111", "CVE-2024-22222"]},
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()["comparisons"]
    assert len(rows) == 2
    assert rows[0]["cve_id"] == "CVE-2024-11111"
    assert rows[0]["cvss_score"] == 9.8
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[1]["cvss_score"] == 6.1


# ------------------------------------------------------------------
# Export + investigation status
# ------------------------------------------------------------------


def test_export_json_contains_only_owners_data(
    research_client, client_b, user_a, db_session
):
    vuln, _, _, _ = _seed_entities(db_session)
    mine = _make_collection(research_client)
    base = f"/api/v1/research/collections/{mine['id']}"
    research_client.post(
        f"{base}/items",
        json={"item_type": "vulnerability", "item_id": str(vuln.id)},
    )
    _make_note(research_client, collection_id=mine["id"], body="secret")
    # Bob cannot export Alice's collection at all.
    assert client_b.get(f"{base}/export?format=json").status_code == 404
    assert client_b.get(f"{base}/export?format=csv").status_code == 404
    resp = research_client.get(f"{base}/export?format=json")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    data = resp.json()
    assert data["collection"]["name"] == "Alice research"
    assert len(data["items"]) == 1
    assert data["items"][0]["label"] == "CVE-2024-11111"
    assert len(data["notes"]) == 1
    assert data["notes"][0]["body"] == "secret"
    # CSV: header + one row.
    resp = research_client.get(f"{base}/export?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.strip().splitlines()
    assert lines[0] == "collection,item_type,item_id,label,added_at"
    assert len(lines) == 2
    assert "CVE-2024-11111" in lines[1]


def test_investigation_status_via_notes(
    research_client, user_a, db_session
):
    _seed_entities(db_session)
    mine = _make_collection(research_client)
    url = f"/api/v1/research/collections/{mine['id']}/status"
    assert research_client.get(url).json()["status"] == "not_started"
    _make_note(
        research_client,
        collection_id=mine["id"],
        title="investigating",
        body="looking into it",
        tags=["status"],
    )
    status_resp = research_client.get(url).json()
    assert status_resp["status"] == "investigating"
    assert status_resp["note_id"] is not None


def test_unauthenticated_is_401(research_client):
    assert research_client.get("/api/v1/research/collections").status_code == 401
    assert research_client.get("/api/v1/research/notes").status_code == 401
