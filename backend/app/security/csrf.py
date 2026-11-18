"""Origin/Referer check for state-changing requests (Phase 9).

The session cookie is ``SameSite=Lax`` (see ``app/core/config.py``),
which already stops a cross-site ``fetch``/XHR from sending the
cookie — but a **top-level navigation POST** (e.g. a hidden form on
an attacker's page that auto-submits to ``/api/v1/auth/logout`` or
``/api/v1/research/collections``) still carries Lax cookies, because
Lax allows cookies on top-level navigations. This dependency closes
that residual hole:

- Safe methods (GET/HEAD/OPTIONS) are untouched.
- For POST/PUT/PATCH/DELETE, when an ``Origin`` header is present it
  must be in the CORS allow-list, otherwise 403.
- When no ``Origin`` is present but a ``Referer`` is, the Referer's
  origin must likewise be in the allow-list.
- Requests with **neither** header (curl, server-to-server calls,
  TestClient) are allowed — the check only ever *rejects* a request
  that positively identifies itself as coming from another origin.

Attach with ``dependencies=[Depends(verify_origin)]`` on a router.
It is applied to every router that has state-changing routes
(auth, ai, research, ingestion, graph). The app factory
(``app/main.py``, coordinator-owned) is where a global middleware
version of this would live; the router-level dependency is the
equivalent enforcement without touching that file.
"""

from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

from app.core.config import settings

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _origin_of(url: str | None) -> str | None:
    """``https://example.com:3000`` part of a URL, lower-cased."""
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def verify_origin(request: Request) -> None:
    """Raise 403 for a cross-origin state-changing request.

    No-op for safe methods and for requests that carry no Origin or
    Referer header.
    """
    if request.method not in UNSAFE_METHODS:
        return
    allowed = {
        origin.strip().lower().rstrip("/")
        for origin in settings.cors_origin_list
    }
    origin = _origin_of(request.headers.get("origin"))
    if origin is not None:
        if origin not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-origin request not allowed",
            )
        return
    referer = _origin_of(request.headers.get("referer"))
    if referer is not None and referer not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-origin request not allowed",
        )
