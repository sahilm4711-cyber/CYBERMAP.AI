"""Learning center API tests (Phase 8).

The learning router is NOT registered in ``app/main.py``
(coordinator registers routers), so these tests include it on the
test app explicitly — the same router object the coordinator will
register.
"""

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import learning as learning_router
from app.models import CweEntry, Vulnerability, VulnerabilityRelationship
from tests.conftest import login_user, register_user


@pytest.fixture()
def learning_client(app_with_db):
    app, _ = app_with_db
    app.include_router(learning_router.router)
    return TestClient(app)


@pytest.fixture()
def user_a(learning_client):
    register_user(learning_client, "alice")
    login_user(learning_client, "alice")
    return "alice"


def test_topics_list(learning_client, user_a):
    resp = learning_client.get("/api/v1/learning/topics")
    assert resp.status_code == 200, resp.text
    topics = resp.json()["topics"]
    slugs = [t["slug"] for t in topics]
    assert "owasp_top_10" in slugs
    assert "secure_coding" in slugs
    assert "remediation" in slugs
    assert len(topics) == 9
    assert all(t["title"] for t in topics)


def test_topic_detail_has_levels_and_knowledge_check(
    learning_client, user_a
):
    resp = learning_client.get("/api/v1/learning/topics/owasp_top_10")
    assert resp.status_code == 200, resp.text
    topic = resp.json()
    assert set(topic["levels"]) == {
        "beginner",
        "intermediate",
        "advanced",
    }
    assert len(topic["key_points"]) >= 5
    assert topic["defensive_examples"]
    assert topic["related_cwe_ids"]
    # Knowledge check: 4 options, valid answer index, explanation.
    assert topic["knowledge_check"]
    for question in topic["knowledge_check"]:
        assert len(question["options"]) == 4
        assert 0 <= question["answer_index"] < 4
        assert question["explanation"]
    # Fresh DB has no relationships: related records resolve honestly empty.
    assert topic["related_real_records"] == []


def test_related_real_records_resolve(
    learning_client, user_a, db_session
):
    cwe = CweEntry(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="SQL injection weakness.",
        source="mitre-cwe",
    )
    vuln = Vulnerability(
        cve_id="CVE-2024-11111",
        description="A test injection flaw.",
        severity="CRITICAL",
        cvss_score=9.8,
        source="nvd",
    )
    db_session.add_all([cwe, vuln])
    db_session.commit()
    db_session.add(
        VulnerabilityRelationship(
            from_type="vulnerability",
            from_id=vuln.id,
            to_type="cwe",
            to_id=cwe.id,
            relationship="HAS_WEAKNESS",
            source="nvd",
        )
    )
    db_session.commit()
    resp = learning_client.get("/api/v1/learning/topics/secure_coding")
    assert resp.status_code == 200
    related = resp.json()["related_real_records"]
    assert len(related) == 1
    assert related[0]["cve_id"] == "CVE-2024-11111"
    assert related[0]["related_cwe_id"] == "CWE-89"


def test_unknown_topic_is_404(learning_client, user_a):
    resp = learning_client.get("/api/v1/learning/topics/nope")
    assert resp.status_code == 404


def test_learning_requires_auth(learning_client):
    assert learning_client.get("/api/v1/learning/topics").status_code == 401
    assert (
        learning_client.get("/api/v1/learning/topics/owasp_top_10").status_code
        == 401
    )


def test_all_topics_are_well_formed(learning_client, user_a):
    resp = learning_client.get("/api/v1/learning/topics")
    for entry in resp.json()["topics"]:
        detail = learning_client.get(
            f"/api/v1/learning/topics/{entry['slug']}"
        )
        assert detail.status_code == 200, entry["slug"]
        topic = detail.json()
        assert topic["title"]
        assert all(topic["levels"][lvl] for lvl in
                   ("beginner", "intermediate", "advanced"))
        assert topic["knowledge_check"]
        for question in topic["knowledge_check"]:
            assert len(question["options"]) == 4
