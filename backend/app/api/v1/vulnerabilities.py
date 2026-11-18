"""Vulnerability explorer API — ``/api/v1/vulnerabilities`` (Phase 5).

NOTE: this router is intentionally NOT registered in ``app.main``
(the Phase 5 coordinator registers routers); tests include it
directly, exactly as the Phase 4/6 routers do.

All endpoints require auth (any logged-in user).
"""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import User
from app.schemas.vulnerabilities import (
    RelatedVulnerabilityItem,
    VulnerabilityDetail,
    VulnerabilityListResponse,
)
from app.security.dependencies import get_current_user
from app.services import vulnerability_service

router = APIRouter(
    prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"]
)

_SORTS = ("newest", "oldest", "severity", "cvss", "epss", "risk")


@router.get("", response_model=VulnerabilityListResponse)
def list_vulnerabilities(
    q: str | None = Query(None),
    severity: list[str] | None = Query(None),
    cwe: str | None = Query(None),
    min_cvss: float | None = Query(None, ge=0.0, le=10.0),
    max_cvss: float | None = Query(None, ge=0.0, le=10.0),
    min_epss: float | None = Query(None, ge=0.0, le=1.0),
    max_epss: float | None = Query(None, ge=0.0, le=1.0),
    vendor: str | None = Query(None),
    product: str | None = Query(None),
    kev_only: bool = Query(False),
    published_from: date | None = Query(None),
    published_to: date | None = Query(None),
    sort: str = Query("newest"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> VulnerabilityListResponse:
    """Search + filter + sort + paginate the indexed CVEs.

    ``q`` matches CVE ID, title or description (case-insensitive).
    ``sort`` is one of ``newest`` | ``oldest`` | ``severity`` |
    ``cvss`` | ``epss`` | ``risk`` (EPSS desc, then CVSS desc).
    """
    if sort not in _SORTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unknown sort: {sort!r}",
        )
    return VulnerabilityListResponse(
        **vulnerability_service.search_vulnerabilities(
            db,
            q=q,
            severity=severity,
            cwe=cwe,
            min_cvss=min_cvss,
            max_cvss=max_cvss,
            min_epss=min_epss,
            max_epss=max_epss,
            vendor=vendor,
            product=product,
            kev_only=kev_only,
            published_from=published_from,
            published_to=published_to,
            sort=sort,
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{cve_id}", response_model=VulnerabilityDetail)
def vulnerability_detail(
    cve_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> VulnerabilityDetail:
    """Full detail for one CVE (404 when unknown)."""
    detail = vulnerability_service.get_vulnerability_detail(
        db, cve_id.upper()
    )
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown CVE: {cve_id!r}",
        )
    return VulnerabilityDetail(**detail)


@router.get(
    "/{cve_id}/related",
    response_model=list[RelatedVulnerabilityItem],
)
def related_vulnerabilities(
    cve_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[RelatedVulnerabilityItem]:
    """CVEs sharing a CWE with ``cve_id`` (up to 5)."""
    detail = vulnerability_service.get_vulnerability_detail(
        db, cve_id.upper()
    )
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown CVE: {cve_id!r}",
        )
    return [
        RelatedVulnerabilityItem(**item) for item in detail["related"]
    ]
