"""Dashboard API — ``/api/v1/dashboard`` (Phase 5).

NOTE: this router is intentionally NOT registered in ``app.main``
(the Phase 5 coordinator registers routers); tests include it
directly, exactly as the Phase 4/6 routers do.

Both endpoints require auth (any logged-in user). All numbers come
from the database via ``app.services.dashboard_service``.
"""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import User
from app.schemas.dashboard import DashboardSummary, DashboardTrends
from app.security.dependencies import get_current_user
from app.services import dashboard_service

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    from_date: date | None = Query(None, alias="from"),
    to_date: date | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DashboardSummary:
    """Summary counts, recent CVEs and per-source sync status.

    ``?from=YYYY-MM-DD&to=YYYY-MM-DD`` restricts the published
    counts and the recent list to CVEs published in that range.
    """
    return DashboardSummary(
        **dashboard_service.get_summary(db, from_date, to_date)
    )


@router.get("/trends", response_model=DashboardTrends)
def dashboard_trends(
    from_date: date | None = Query(None, alias="from"),
    to_date: date | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DashboardTrends:
    """Per-day publication counts, severity/CWE/KEV/EPSS breakdowns.

    Defaults to the last 30 days when no range is given.
    """
    return DashboardTrends(
        **dashboard_service.get_trends(db, from_date, to_date)
    )
