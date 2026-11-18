"""Threat-intelligence API — ``/api/v1/intelligence`` (Phase 5).

NOTE: this router is intentionally NOT registered in ``app.main``
(the Phase 5 coordinator registers routers); tests include it
directly, exactly as the Phase 4/6 routers do.

All endpoints require auth (any logged-in user).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import User
from app.schemas.intelligence import (
    EpssRankingResponse,
    KevListResponse,
    MetricsExplainedResponse,
    TimelineEvent,
    TimelineResponse,
)
from app.security.dependencies import get_current_user
from app.services import intelligence_service

router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])


@router.get("/kev", response_model=KevListResponse)
def kev_list(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> KevListResponse:
    """Newest CISA KEV additions first, paginated."""
    return KevListResponse(
        **intelligence_service.list_kev(db, page, per_page)
    )


@router.get("/epss-ranking", response_model=EpssRankingResponse)
def epss_ranking(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EpssRankingResponse:
    """Top CVEs by latest EPSS score, descending."""
    return EpssRankingResponse(
        **intelligence_service.epss_ranking(db, page, per_page)
    )


@router.get("/timeline", response_model=TimelineResponse)
def timeline(
    limit: int = Query(50, ge=1, le=50),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TimelineResponse:
    """Recent events merged: newest CVEs, KEV additions, jobs."""
    result = intelligence_service.get_timeline(db, limit)
    return TimelineResponse(
        events=[TimelineEvent(**e) for e in result["events"]]
    )


@router.get("/metrics-explained", response_model=MetricsExplainedResponse)
def metrics_explained(
    user: User = Depends(get_current_user),
) -> MetricsExplainedResponse:
    """Plain-language CVSS vs EPSS vs KEV explainer (static text)."""
    return MetricsExplainedResponse(
        **intelligence_service.get_metrics_explained()
    )
