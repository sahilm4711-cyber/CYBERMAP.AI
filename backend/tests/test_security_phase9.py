"""Phase 9 security tests — each test proves a checklist item in
``docs/SECURITY.md`` against the real implementation.

Coverage:
- login rate limiting (10 failed / 15 min / identifier, 429, reset
  on success, per-identifier isolation)
- common-password denylist on register and password change
- Origin/Referer CSRF check on state-changing requests
- IDOR: cross-user access to collections, notes, analyses and
  conversations returns 404
- graph responses contain public intel only (no private research data)
- no sensitive data in responses (password_hash, session tokens,
  API keys) and no tracebacks in 500 bodies
- ingestion sync accepts only allow-listed source names (admin-only)
- AI analyse limit counts saved analyses, not conversations
- ingestion 5-minute sync guard (via a recent finished job row)
- login issues a fresh token every time (no session fixation)

The prompt-injection and RAG-delimiter checks live in the Phase 6
files (``test_ai_rag.py::test_grounded_prompt_wraps_context_in_delimiters``
and ``test_ai_chat_api.py::test_chat_injection_chunk_never_obeyed``)
and are re-run as part of the full suite.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.main import create_app
from app.models import (
    DataSource,
    IngestionJob,
    Role,
    User,
    Vulnerability,
)
from app.security.rate_limit import reset_login_rate_limits
from tests.conftest import login_user, register_user


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_login_rate_limits()
    yield
    reset_login_rate_limits()


def _seed_vuln(db_session: Session, cve_id="CVE-2024-44444") -> Vulnerability:
    vuln = Vulnerability(
        cve_id=cve_id,
        description="A buffer overflow in the parser lets attackers crash the service.",
        cvss_score=7.5,
        severity="HIGH",
        source="nvd",
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )
    db_session.add(vuln)
    db_session.commit()
    return vuln


def _make_admin(client: TestClient, db_session: Session, username: str = "admin"):
    register_user(client, username)
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    user = db_session.query(User).filter(User.username == username).first()
    user.role_id = admin_role.id
    db_session.commit()
    login_user(client, username)
    return user


def _second_client(app_with_db, username: str) -> TestClient:
    """A second logged-in client (a different user) on the same app."""
    app, _ = app_with_db
    other = TestClient(app)
    register_user(other, username)
    login_user(other, username)
    return other


# ------------------------------------------------------------------
# Login rate limiting
# ------------------------------------------------------------------


def test_login_rate_limit_blocks_after_10_failures(client: TestClient):
    register_user(client, "alice")
    for _ in range(10):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "wrong-password"},
        )
        assert resp.status_code == 401
    # 11th attempt — even with the RIGHT password — is 429.
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert resp.status_code == 429
    # A different identifier is not blocked by alice's failures.
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "ghost", "password": "whatever-password"},
    )
    assert resp.status_code == 401


def test_successful_login_resets_failure_counter(client: TestClient):
    register_user(client, "alice")
    for _ in range(9):
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"username": "alice", "password": "wrong-password"},
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={
                "username": "alice",
                "password": "correct-horse-battery",
            },
        ).status_code
        == 200
    )
    # Counter cleared by the success: 5 more failures are still 401.
    for _ in range(5):
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"username": "alice", "password": "wrong-password"},
            ).status_code
            == 401
        )


def test_login_issues_fresh_token_each_time(client: TestClient):
    """No session fixation: a token planted before login is replaced,
    and every login mints a different token."""
    register_user(client, "alice")

    def _token_from_response(resp) -> str:
        header = resp.headers.get("set-cookie", "")
        assert header.startswith(f"{settings.session_cookie_name}=")
        return header.split(";", 1)[0].split("=", 1)[1]

    # Attacker plants a cookie value before the victim logs in.
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
        headers={
            "Cookie": f"{settings.session_cookie_name}=attacker-planted-token"
        },
    )
    assert resp.status_code == 200
    token_a = _token_from_response(resp)
    assert token_a != "attacker-planted-token"
    # A second login mints a different token again.
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert resp.status_code == 200
    token_b = _token_from_response(resp)
    assert token_b != token_a


# ------------------------------------------------------------------
# Weak / common passwords
# ------------------------------------------------------------------


def test_common_passwords_rejected_on_register(client: TestClient):
    for i, weak in enumerate(("password", "password123", "12345678", "qwerty123")):
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": f"weakuser-{i}",
                "email": f"weakuser-{i}@example.com",
                "password": weak,
            },
        )
        assert resp.status_code == 422, weak
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "strong",
            "email": "strong@example.com",
            "password": "correct-horse-battery-staple",
        },
    )
    assert resp.status_code == 201


def test_common_password_rejected_on_change(client: TestClient):
    register_user(client, "alice")
    login_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": "correct-horse-battery",
            "new_password": "password123",
        },
    )
    assert resp.status_code == 422
    resp = client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": "correct-horse-battery",
            "new_password": "a-fresh-strong-passphrase",
        },
    )
    assert resp.status_code == 200


# ------------------------------------------------------------------
# CSRF: Origin / Referer check
# ------------------------------------------------------------------

EVIL = "https://evil.example"
GOOD = "http://localhost:3000"


def test_cross_origin_login_post_blocked(client: TestClient):
    register_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
        headers={"Origin": EVIL},
    )
    assert resp.status_code == 403
    # Same-origin POST passes the check (wrong password -> 401).
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "wrong-password"},
        headers={"Origin": GOOD},
    )
    assert resp.status_code == 401


def test_cross_origin_referer_post_blocked(client: TestClient):
    register_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
        headers={"Referer": f"{EVIL}/phishing-page"},
    )
    assert resp.status_code == 403
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "wrong-password"},
        headers={"Referer": f"{GOOD}/login"},
    )
    assert resp.status_code == 401


def test_safe_methods_unaffected_by_origin(client: TestClient):
    # GETs never get a 403 from the Origin check (401 = auth, as usual).
    resp = client.get(
        "/api/v1/auth/me", headers={"Origin": EVIL}
    )
    assert resp.status_code == 401


def test_cross_origin_research_post_blocked(
    client: TestClient, app_with_db
):
    register_user(client, "alice")
    login_user(client, "alice")
    resp = client.post(
        "/api/v1/research/collections",
        json={"name": "x"},
        headers={"Origin": EVIL},
    )
    assert resp.status_code == 403
    resp = client.post(
        "/api/v1/research/collections", json={"name": "x"}
    )
    assert resp.status_code == 201


# ------------------------------------------------------------------
# IDOR: cross-user object access
# ------------------------------------------------------------------


def test_idor_other_users_objects_return_404(
    client: TestClient, app_with_db, db_session: Session
):
    _seed_vuln(db_session)
    register_user(client, "alice")
    login_user(client, "alice")

    coll = client.post(
        "/api/v1/research/collections", json={"name": "alice-private"}
    ).json()
    note = client.post(
        "/api/v1/research/notes",
        json={
            "title": "alice secret note",
            "body": "alice private findings",
            "collection_id": coll["id"],
        },
    ).json()
    analysis = client.post(
        "/api/v1/ai/analyze",
        json={"cve_id": "CVE-2024-44444", "analysis_type": "simple"},
    ).json()
    # The analyse call saved a SavedAnalysis row; fetch its id via list.
    saved = client.get("/api/v1/research/analyses").json()["items"]
    assert len(saved) == 1
    analysis_id = saved[0]["id"]
    assert analysis["cve_id"] == "CVE-2024-44444"
    chat = client.post(
        "/api/v1/ai/chat",
        json={"question": "Tell me about CVE-2024-44444."},
    ).json()
    conv_id = chat["conversation_id"]

    bob = _second_client(app_with_db, "bob")
    for url in (
        f"/api/v1/research/collections/{coll['id']}",
        f"/api/v1/research/notes/{note['id']}",
        f"/api/v1/research/analyses/{analysis_id}",
        f"/api/v1/ai/conversations/{conv_id}",
    ):
        assert bob.get(url).status_code == 404, url
    for url in (
        f"/api/v1/research/collections/{coll['id']}",
        f"/api/v1/research/notes/{note['id']}",
        f"/api/v1/research/analyses/{analysis_id}",
        f"/api/v1/ai/conversations/{conv_id}",
    ):
        assert bob.delete(url).status_code == 404, url
    # And alice can still see her own objects.
    assert (
        client.get(f"/api/v1/research/collections/{coll['id']}").status_code
        == 200
    )


# ------------------------------------------------------------------
# Graph: public intel only, no private research leakage
# ------------------------------------------------------------------


def test_graph_node_exposes_no_private_data(
    client: TestClient, app_with_db, db_session: Session
):
    _seed_vuln(db_session)
    register_user(client, "alice")
    login_user(client, "alice")
    coll = client.post(
        "/api/v1/research/collections", json={"name": "alice-secret-collection"}
    ).json()
    client.post(
        "/api/v1/research/notes",
        json={
            "title": "alice-secret-note",
            "body": "alice-private-findings-xyz",
            "collection_id": coll["id"],
        },
    )
    bob = _second_client(app_with_db, "bob")
    resp = bob.get("/api/v1/graph/node/vulnerability/CVE-2024-44444")
    assert resp.status_code == 200
    body = resp.json()
    blob = resp.text
    assert "password_hash" not in blob
    assert "alice-secret-collection" not in blob
    assert "alice-secret-note" not in blob
    assert "alice-private-findings-xyz" not in blob
    # Only the public intel fields are present.
    assert set(body["fields"].keys()) <= {
        "cve_id",
        "description",
        "severity",
        "cvss_score",
        "cvss_version",
        "cvss_vector",
        "published_at",
        "source",
        "source_url",
    }


# ------------------------------------------------------------------
# Sensitive data exposure / error handling
# ------------------------------------------------------------------


def test_no_sensitive_fields_in_auth_and_docs(client: TestClient):
    register_user(client, "alice")
    login_user(client, "alice")
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert "password_hash" not in me.text
    assert "session_token" not in me.text
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    assert "password_hash" not in openapi.text
    assert "session_token" not in openapi.text
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "password_hash" not in docs.text


def test_500_response_contains_no_traceback():
    """FastAPI's default handler returns a generic 500 body."""
    app = create_app()

    @app.get("/_boom")
    def _boom():
        raise RuntimeError("secret-internal-detail")

    test_client = TestClient(app, raise_server_exceptions=False)
    resp = test_client.get("/_boom")
    assert resp.status_code == 500
    assert "Traceback" not in resp.text
    assert "secret-internal-detail" not in resp.text
    assert "RuntimeError" not in resp.text


# ------------------------------------------------------------------
# SSRF / ingestion allow-list
# ------------------------------------------------------------------


def test_ingestion_sync_rejects_arbitrary_source(
    client: TestClient, db_session: Session
):
    _make_admin(client, db_session, "admin")
    for bad in ("bogus", "NVD", "nvd;rm", "evil-feed"):
        resp = client.post(f"/api/v1/ingestion/sync/{bad}")
        assert resp.status_code == 404, bad


def test_ingestion_sync_guard_blocks_second_run_within_5_minutes(
    client: TestClient, db_session: Session
):
    """A finished job < 5 min ago blocks a new sync with 429."""
    _make_admin(client, db_session, "admin")
    source = (
        db_session.query(DataSource)
        .filter(DataSource.name == "nvd")
        .first()
    )
    assert source is not None
    now = datetime.now(timezone.utc)
    db_session.add(
        IngestionJob(
            source_id=source.id,
            started_at=now - timedelta(minutes=1),
            finished_at=now - timedelta(seconds=30),
            status="success",
            records_fetched=1,
            records_created=1,
            triggered_by="scheduler",
        )
    )
    db_session.commit()
    resp = client.post("/api/v1/ingestion/sync/nvd")
    assert resp.status_code == 429


# ------------------------------------------------------------------
# AI analyse limit counts saved analyses, not conversations
# ------------------------------------------------------------------


def test_ai_analyze_limit_not_bypassed_by_new_conversation(
    client: TestClient, db_session: Session
):
    _seed_vuln(db_session)
    register_user(client, "alice")
    login_user(client, "alice")
    for _ in range(10):
        resp = client.post(
            "/api/v1/ai/analyze",
            json={"cve_id": "CVE-2024-44444", "analysis_type": "simple"},
        )
        assert resp.status_code == 200, resp.text
    # 11th analysis is rate-limited...
    assert (
        client.post(
            "/api/v1/ai/analyze",
            json={"cve_id": "CVE-2024-44444", "analysis_type": "simple"},
        ).status_code
        == 429
    )
    # ...and opening a brand-new conversation does not reset it.
    chat = client.post(
        "/api/v1/ai/chat",
        json={"question": "Tell me about CVE-2024-44444."},
    )
    assert chat.status_code == 200
    assert (
        client.post(
            "/api/v1/ai/analyze",
            json={"cve_id": "CVE-2024-44444", "analysis_type": "simple"},
        ).status_code
        == 429
    )
