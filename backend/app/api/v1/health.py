"""Health-check endpoints.

``GET /health`` (plain, for load balancers / Docker healthchecks) and
``GET /api/v1/health`` (versioned API) both return the same payload.

Phase 9: the ``database`` field is a real check now — the endpoint
runs ``SELECT 1`` against the configured database and reports
``"ok"`` when it answers and ``"error"`` when it does not (Phase 2/3
left this as the hardcoded ``"not_configured"``). The service itself
is still reported ``"ok"`` when the database is down: the API
process is up, it just cannot reach its store — callers that need
the database should look at the ``database`` field, not ``status``.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


def _check_database(db: Session) -> str:
    """Run a trivial query; ``"ok"`` if it answers, ``"error"`` if not."""
    try:
        db.execute(text("SELECT 1"))
        return "ok"
    except Exception:
        return "error"


def _build_health(db: Session) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="cybermap-ai",
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        database=_check_database(db),
        ai_mode="provider" if settings.ai_provider else "fallback",
    )


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    """Unversioned health check (Docker / load balancer)."""
    return _build_health(db)


@router.get("/api/v1/health", response_model=HealthResponse)
def api_v1_health(db: Session = Depends(get_db)) -> HealthResponse:
    """Versioned health check."""
    return _build_health(db)
