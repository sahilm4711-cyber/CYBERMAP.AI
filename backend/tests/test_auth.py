"""Auth tests (Phase 3).

Covers: registration, duplicates, weak passwords, login + HTTP-only
cookie, wrong password, logout revocation, protected routes, expired
and revoked sessions, password change revoking other sessions, and
audit logging. No test data ever touches the dev database — the
``client`` fixture uses a fresh temp SQLite DB per test.
"""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import AuditLog, User, UserSession
from app.services import auth_service
from tests.conftest import login_user, register_user


def test_register_success_creates_user_role(client: TestClient, db_session: Session):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "correct-horse-battery",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.com"
    # Registration always creates role "user" — never admin.
    assert body["role"] == "user"
    assert body["is_active"] is True
    # No password (plain or hashed) is ever returned.
    assert "password" not in body
    assert "password_hash" not in body

    user = db_session.query(User).filter(User.username == "alice").first()
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert user.password_hash != "correct-horse-battery"
    assert user.created_at is not None and user.updated_at is not None


def test_register_duplicate_username_rejected(client: TestClient):
    register_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "alice",
            "email": "alice2@example.com",
            "password": "correct-horse-battery",
        },
    )
    assert resp.status_code == 409


def test_register_duplicate_email_rejected(client: TestClient):
    register_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "alice2",
            "email": "alice@example.com",
            "password": "correct-horse-battery",
        },
    )
    assert resp.status_code == 409


def test_register_weak_password_rejected(client: TestClient):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "short",
        },
    )
    assert resp.status_code == 422


def test_login_success_sets_http_only_cookie(client: TestClient, db_session: Session):
    register_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert settings.session_cookie_name in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()
    # The DB stores only the hash — the raw token is never in the DB.
    raw_token = client.cookies.get(settings.session_cookie_name)
    assert raw_token is not None
    stored_hashes = [
        row.session_token_hash
        for row in db_session.query(UserSession).all()
    ]
    assert stored_hashes
    assert all(raw_token not in h for h in stored_hashes)


def test_login_wrong_password_401_and_audit_logged(
    client: TestClient, db_session: Session
):
    register_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    assert resp.status_code == 401
    failed = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "auth.login_failed")
        .all()
    )
    assert len(failed) == 1
    # Audit details never contain a password.
    assert "wrong-password" not in str(failed[0].details)


def test_login_unknown_user_401(client: TestClient):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "ghost", "password": "whatever-password"},
    )
    assert resp.status_code == 401


def test_protected_endpoint_401_without_cookie(client: TestClient):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_protected_endpoint_200_with_cookie(client: TestClient):
    register_user(client, "alice")
    login_user(client, "alice")
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"


def test_logout_revokes_session(client: TestClient):
    register_user(client, "alice")
    login_user(client, "alice")
    assert client.get("/api/v1/auth/me").status_code == 200
    resp = client.post("/api/v1/auth/logout")
    assert resp.status_code == 200
    # The same cookie no longer works.
    assert client.get("/api/v1/auth/me").status_code == 401


def test_revoked_session_rejected(
    client: TestClient, db_session: Session
):
    register_user(client, "alice")
    login_user(client, "alice")
    raw_token = client.cookies.get(settings.session_cookie_name)
    assert raw_token is not None
    # Revoke the session directly in the DB (as a password change would).
    session = auth_service.find_session_by_token(db_session, raw_token)
    assert session is not None
    auth_service.revoke_session(db_session, session)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_expired_session_rejected(
    client: TestClient, db_session: Session
):
    register_user(client, "alice")
    login_user(client, "alice")
    raw_token = client.cookies.get(settings.session_cookie_name)
    assert raw_token is not None
    # Back-date the session expiry.
    session = auth_service.find_session_by_token(db_session, raw_token)
    assert session is not None
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_password_change_revokes_other_sessions(
    client: TestClient, app_with_db
):
    register_user(client, "alice")
    login_user(client, "alice")

    # A second session for the same user (e.g. another device).
    app, _ = app_with_db
    other_client = TestClient(app)
    login_user(other_client, "alice")
    assert other_client.get("/api/v1/auth/me").status_code == 200

    resp = client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": "correct-horse-battery",
            "new_password": "new-strong-password",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["sessions_revoked"] == 1
    # The caller's own session still works; the other one is dead.
    assert client.get("/api/v1/auth/me").status_code == 200
    assert other_client.get("/api/v1/auth/me").status_code == 401
    # Old password no longer works; new one does.
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct-horse-battery"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "new-strong-password"},
        ).status_code
        == 200
    )


def test_password_change_wrong_current_password_401(client: TestClient):
    register_user(client, "alice")
    login_user(client, "alice")
    resp = client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": "not-the-password",
            "new_password": "new-strong-password",
        },
    )
    assert resp.status_code == 401


def test_auth_events_are_audited(
    client: TestClient, db_session: Session
):
    register_user(client, "alice")
    login_user(client, "alice")
    client.post("/api/v1/auth/logout")
    actions = [
        row.action
        for row in db_session.query(AuditLog)
        .order_by(AuditLog.created_at)
        .all()
    ]
    assert "auth.register" in actions
    assert "auth.login" in actions
    assert "auth.logout" in actions
