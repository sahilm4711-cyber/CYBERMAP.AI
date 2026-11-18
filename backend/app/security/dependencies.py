"""Auth dependencies: load the current user from the session cookie,
and role guards for later phases.

Flow: ``get_current_user`` reads the cookie named in settings, hashes
the token, looks up the ``user_sessions`` row, rejects revoked or
expired sessions, and returns the owning active user — otherwise 401.
"""

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import User, UserSession
from app.security.sessions import hash_token


def get_current_user(
    session_token: str | None = Cookie(
        default=None, alias=settings.session_cookie_name
    ),
    db: Session = Depends(get_db),
) -> User:
    """Return the logged-in user, or raise 401.

    The cookie alias is read from settings at import time; the cookie
    name is ``cybermap_session`` by default.
    """
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    session = (
        db.query(UserSession)
        .filter(
            UserSession.session_token_hash == hash_token(session_token)
        )
        .first()
    )
    if session is None or session.is_revoked or session.is_expired():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or revoked",
        )
    user = db.query(User).filter(User.id == session.user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user


def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Alias kept for readability in routers (same as get_current_user)."""
    return user


def require_role(*role_names: str):
    """Dependency factory: allow only users whose role is in ``role_names``.

    Usage: ``Depends(require_role("admin"))``. A logged-in user with
    the wrong role gets 403; an anonymous caller gets 401 from
    ``get_current_user`` first.
    """

    def _guard(user: User = Depends(get_current_user)) -> User:
        if user.role_name not in role_names:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _guard


# Convenience guard used by admin-only endpoints (Phase 4+).
require_admin = require_role("admin")
