"""Auth API — ``/api/v1/auth`` (Phase 3).

- POST /register — creates a ``user``-role account (never admin).
- POST /login — verifies credentials, sets an HTTP-only session cookie.
- POST /logout — revokes the session, clears the cookie.
- GET  /me — the logged-in user (401 without a valid session).
- POST /change-password — verifies the current password, revokes all
  other sessions.
- GET  /admin/ping — admin-only probe (used by the isolation tests;
  real admin endpoints arrive in Phase 4).

The raw session token is only ever sent in the ``Set-Cookie`` header;
the database stores its SHA-256 hash (see ``app.security.sessions``).
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import User, UserSession
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    PasswordChangeRequest,
    PasswordChangeResponse,
    RegisterRequest,
    UserResponse,
)
from app.security.csrf import verify_origin
from app.security.dependencies import get_current_user, require_role
from app.security.rate_limit import (
    clear_failed_logins,
    is_login_blocked,
    record_failed_login,
)
from app.security.sessions import hash_token
from app.services import auth_service
from app.services.auth_service import AuthError

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
    dependencies=[Depends(verify_origin)],
)

_COOKIE_KWARGS = {
    "httponly": True,
    "samesite": settings.session_cookie_samesite,
    "secure": settings.session_cookie_secure,
    "path": "/",
}


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role_name or "user",
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        max_age=int(
            timedelta(days=settings.session_expire_days).total_seconds()
        ),
        **_COOKIE_KWARGS,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name, path="/"
    )


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post(
    "/register", response_model=UserResponse, status_code=201
)
def register(
    payload: RegisterRequest, db: Session = Depends(get_db)
) -> UserResponse:
    """Register a new account. Always role ``user``."""
    try:
        user = auth_service.register_user(
            db, payload.username, payload.email, payload.password
        )
    except AuthError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail
        ) from exc
    return _user_response(user)


@router.post("/login", response_model=UserResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Log in and set the HTTP-only session cookie.

    Failed logins are rate-limited (Phase 9): 10 failures per
    identifier per 15 minutes, then 429. A successful login clears
    the counter. A fresh session token is issued on every login, so
    a token captured before login cannot be fixed onto the session
    (no session fixation).
    """
    identifier = payload.username
    if is_login_blocked(identifier):
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed login attempts — try again in "
                "15 minutes"
            ),
        )
    try:
        user = auth_service.authenticate_user(
            db, payload.username, payload.password
        )
    except AuthError as exc:
        if exc.status_code == 401:
            record_failed_login(identifier)
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail
        ) from exc
    clear_failed_logins(identifier)
    _, raw_token = auth_service.create_session(
        db,
        user,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, raw_token)
    return _user_response(user)


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MessageResponse:
    """Revoke the current session and clear the cookie."""
    raw_token = request.cookies.get(settings.session_cookie_name)
    if raw_token:
        session = (
            db.query(UserSession)
            .filter(
                UserSession.session_token_hash == hash_token(raw_token)
            )
            .first()
        )
        if session is not None and session.user_id == user.id:
            auth_service.revoke_session(db, session)
    _clear_session_cookie(response)
    return MessageResponse(detail="Logged out")


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)) -> UserResponse:
    """Return the currently logged-in user (401 without a session)."""
    return _user_response(user)


@router.post("/change-password", response_model=PasswordChangeResponse)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PasswordChangeResponse:
    """Change password; revokes every other session of this user."""
    raw_token = request.cookies.get(settings.session_cookie_name)
    keep_session_id = None
    if raw_token:
        session = (
            db.query(UserSession)
            .filter(
                UserSession.session_token_hash == hash_token(raw_token)
            )
            .first()
        )
        if session is not None:
            keep_session_id = session.id
    try:
        revoked = auth_service.change_password(
            db,
            user,
            payload.current_password,
            payload.new_password,
            keep_session_id=keep_session_id,
        )
    except AuthError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail
        ) from exc
    return PasswordChangeResponse(
        detail="Password changed", sessions_revoked=revoked
    )


@router.get("/admin/ping", response_model=MessageResponse)
def admin_ping(
    user: User = Depends(require_role("admin")),
) -> MessageResponse:
    """Admin-only probe (Phase 4 admin endpoints build on this guard)."""
    return MessageResponse(detail=f"admin ok: {user.username}")
