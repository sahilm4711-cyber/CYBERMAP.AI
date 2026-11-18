"""Auth service — register / login / logout / password change.

Rules (Phase 3):
- Registration always creates role ``user``; self-assigning admin is
  impossible through this service.
- Passwords are Argon2id-hashed; plaintext is never stored or logged.
- Login creates a ``user_sessions`` row holding only the SHA-256 hash
  of a random token; the raw token is returned to the caller, which
  puts it in an HTTP-only cookie.
- Logout / password change revoke sessions.
- Every auth event writes an ``audit_logs`` row (no secrets in details).
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import User, UserSession
from app.security.passwords import (
    hash_password,
    needs_rehash,
    verify_password,
)
from app.security.sessions import hash_token, new_token
from app.services.audit import write_audit_log
from app.services.seed import get_role

MIN_PASSWORD_LENGTH = 8

# Most-common passwords (Phase 9). Length alone is not enough: an
# 8+ character password straight from a breach list is guessed
# first. Exact match, case-insensitive. This is a denylist, not a
# complexity rule — a long passphrase the user invents still passes.
COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password123",
        "password1234",
        "12345678",
        "123456789",
        "1234567890",
        "123456789a",
        "qwerty123",
        "qwertyui",
        "qwertyuiop",
        "letmein1",
        "letmein123",
        "admin123",
        "admin1234",
        "welcome1",
        "welcome123",
        "iloveyou1",
        "monkey123",
        "dragon123",
        "football1",
        "sunshine1",
        "master123",
        "changeme",
        "changeme123",
        "aaaaaaaa",
        "00000000",
        "11111111",
    }
)


def _validate_new_password(password: str, username: str | None = None) -> None:
    """Reject too-short, breached-list, or username-equal passwords."""
    if len(password) < max(MIN_PASSWORD_LENGTH, settings.password_min_length):
        raise AuthError(422, "Password must be at least 8 characters")
    if password.lower() in COMMON_PASSWORDS:
        raise AuthError(
            422, "Password is too common — choose a less predictable one"
        )
    if username is not None and password.lower() == username.lower():
        raise AuthError(422, "Password must not be the same as the username")



class AuthError(Exception):
    """Business-rule failure; the router maps it to an HTTP status."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _session_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(
        days=settings.session_expire_days
    )


def register_user(
    db: Session, username: str, email: str, password: str
) -> User:
    """Create a user with role ``user``. Raises AuthError(409) on duplicates."""
    _validate_new_password(password, username)
    existing = (
        db.query(User)
        .filter(or_(User.username == username, User.email == email))
        .first()
    )
    if existing is not None:
        raise AuthError(409, "Username or email already registered")
    role = get_role(db, "user")
    if role is None:
        raise AuthError(
            500, "Role 'user' is not seeded — run the Phase 3 migration"
        )
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role_id=role.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit_log(
        db,
        "auth.register",
        user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        details={"username": username},
    )
    db.commit()
    return user


def authenticate_user(db: Session, identifier: str, password: str) -> User:
    """Find a user by username or email and check the password.

    Raises AuthError(401) for unknown users and wrong passwords alike
    (no user-enumeration signal). Also logs ``auth.login_failed``.
    """
    user = (
        db.query(User)
        .filter(or_(User.username == identifier, User.email == identifier))
        .first()
    )
    if user is None or not verify_password(password, user.password_hash):
        write_audit_log(
            db,
            "auth.login_failed",
            user_id=user.id if user is not None else None,
            entity_type="user",
            entity_id=user.id if user is not None else None,
            details={"username": identifier},
        )
        db.commit()
        raise AuthError(401, "Invalid username or password")
    if not user.is_active:
        raise AuthError(401, "Account is disabled")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


def create_session(
    db: Session,
    user: User,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[UserSession, str]:
    """Create a session row and return ``(session, raw_token)``."""
    raw_token = new_token()
    session = UserSession(
        user_id=user.id,
        session_token_hash=hash_token(raw_token),
        expires_at=_session_expiry(),
        ip_address=ip_address,
        user_agent=user_agent,
    )
    user.last_login_at = datetime.now(timezone.utc)
    db.add(session)
    db.commit()
    db.refresh(session)
    write_audit_log(
        db,
        "auth.login",
        user_id=user.id,
        entity_type="user_session",
        entity_id=session.id,
        details={"username": user.username},
        ip_address=ip_address,
    )
    db.commit()
    return session, raw_token


def revoke_session(db: Session, session: UserSession) -> None:
    """Mark one session revoked (logout)."""
    session.revoked_at = datetime.now(timezone.utc)
    write_audit_log(
        db,
        "auth.logout",
        user_id=session.user_id,
        entity_type="user_session",
        entity_id=session.id,
    )
    db.commit()


def revoke_all_sessions(db: Session, user: User) -> int:
    """Revoke every live session of a user (password change)."""
    now = datetime.now(timezone.utc)
    live = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .all()
    )
    for session in live:
        session.revoked_at = now
    db.commit()
    return len(live)


def change_password(
    db: Session,
    user: User,
    current_password: str,
    new_password: str,
    keep_session_id=None,
) -> int:
    """Change a user's password and revoke all other sessions.

    Returns the number of sessions revoked (excluding the caller's
    current one, when ``keep_session_id`` is given).
    """
    if not verify_password(current_password, user.password_hash):
        raise AuthError(401, "Current password is incorrect")
    _validate_new_password(new_password, user.username)
    user.password_hash = hash_password(new_password)
    now = datetime.now(timezone.utc)
    live = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .all()
    )
    revoked = 0
    for session in live:
        if keep_session_id is not None and session.id == keep_session_id:
            continue
        session.revoked_at = now
        revoked += 1
    write_audit_log(
        db,
        "auth.password_change",
        user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        details={"sessions_revoked": revoked},
    )
    db.commit()
    return revoked


def find_session_by_token(db: Session, raw_token: str) -> UserSession | None:
    """Look up a live session by its raw token (used by tests/tools)."""
    return (
        db.query(UserSession)
        .filter(
            UserSession.session_token_hash == hash_token(raw_token)
        )
        .first()
    )
