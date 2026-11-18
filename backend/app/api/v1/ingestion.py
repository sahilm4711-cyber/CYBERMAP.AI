"""Ingestion API — ``/api/v1/ingestion`` (Phase 4).

- GET  /status — sync status per source (any logged-in user).
- GET  /jobs — paginated job history (any logged-in user).
- POST /sync/{source} — admin-only bounded sync run. NVD defaults to
  an incremental (last 7 days) run; a full re-ingestion needs an
  explicit ``?full=true`` and is still bounded by ``?days=``.
  Rate-limited to 1 run per source per 5 minutes, enforced with the
  ``ingestion_jobs`` table (no Redis dependency).

NOTE: this router is intentionally NOT registered in ``app.main``
(the Phase 4 coordinator registers routers); tests include it
directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.ingestion.run import SOURCE_ALIASES, run_ingestion
from app.models import DataSource, IngestionJob, User
from app.models.base import as_utc_aware
from app.schemas.ingestion import (
    IngestionJobResponse,
    IngestionSyncResponse,
    SourceStatusResponse,
)
from app.security.csrf import verify_origin
from app.security.dependencies import get_current_user, require_role

router = APIRouter(
    prefix="/api/v1/ingestion",
    tags=["ingestion"],
    dependencies=[Depends(verify_origin)],
)

SYNC_RATE_LIMIT_MINUTES = 5
# Sources the sync endpoint accepts ("mitre" = both MITRE catalogs).
SYNC_SOURCES = ("nvd", "kev", "epss", "mitre", "mitre-attack", "mitre-cwe")


def _sync_source_names(source: str) -> list[str]:
    """Canonical data_sources names covered by a sync ``source``."""
    if source == "mitre":
        return ["mitre-attack", "mitre-cwe"]
    return [SOURCE_ALIASES[source]]


def _job_response(job: IngestionJob, source_name: str) -> IngestionJobResponse:
    return IngestionJobResponse(
        id=job.id,
        source=source_name,
        started_at=job.started_at,
        finished_at=job.finished_at,
        status=job.status,
        records_fetched=job.records_fetched,
        records_created=job.records_created,
        records_updated=job.records_updated,
        records_skipped=job.records_skipped,
        error_message=job.error_message,
        triggered_by=job.triggered_by,
    )


def _latest_job(db: Session, source: DataSource) -> IngestionJob | None:
    return (
        db.query(IngestionJob)
        .filter(IngestionJob.source_id == source.id)
        .order_by(IngestionJob.started_at.desc())
        .first()
    )


def _check_sync_rate_limit(
    db: Session, source: str, now: datetime
) -> None:
    """Raise 429 if a run for ``source`` is running or finished < 5 min ago."""
    for name in _sync_source_names(source):
        data_source = (
            db.query(DataSource).filter(DataSource.name == name).first()
        )
        if data_source is None:
            continue
        job = _latest_job(db, data_source)
        if job is None:
            continue
        if job.status == "running":
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"a sync for {name} is already running",
            )
        finished = as_utc_aware(job.finished_at)
        if finished is not None and now - finished < timedelta(
            minutes=SYNC_RATE_LIMIT_MINUTES
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"a sync for {name} finished less than "
                    f"{SYNC_RATE_LIMIT_MINUTES} minutes ago"
                ),
            )


@router.get("/status", response_model=list[SourceStatusResponse])
def ingestion_status(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[SourceStatusResponse]:
    """Sync status per source, with the latest job's counts."""
    result: list[SourceStatusResponse] = []
    for source in (
        db.query(DataSource).order_by(DataSource.name).all()
    ):
        job = _latest_job(db, source)
        result.append(
            SourceStatusResponse(
                source=source.name,
                display_name=source.display_name,
                is_enabled=source.is_enabled,
                last_sync_at=source.last_sync_at,
                last_sync_status=source.last_sync_status,
                last_job=(
                    _job_response(job, source.name) if job else None
                ),
            )
        )
    return result


@router.get("/jobs", response_model=list[IngestionJobResponse])
def ingestion_jobs(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    source: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[IngestionJobResponse]:
    """Paginated job history, newest first (optionally by source)."""
    query = db.query(IngestionJob).order_by(IngestionJob.started_at.desc())
    if source is not None:
        data_source = (
            db.query(DataSource).filter(DataSource.name == source).first()
        )
        if data_source is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"unknown source: {source!r}",
            )
        query = query.filter(IngestionJob.source_id == data_source.id)
    jobs = query.offset(skip).limit(limit).all()
    source_names = {
        row.id: row.name
        for row in db.query(DataSource).all()
    }
    # Map each job to its source name via a fresh lookup per row is
    # wasteful; the jobs carry source_id — resolve through the map
    # built from the data_sources table above.
    job_source = {
        job.id: source_names.get(job.source_id, "unknown")
        for job in jobs
    }
    return [_job_response(job, job_source[job.id]) for job in jobs]


@router.post(
    "/sync/{source}",
    response_model=IngestionSyncResponse,
    status_code=status.HTTP_200_OK,
)
def trigger_sync(
    source: str,
    days: int = Query(7, ge=1, le=120),
    limit: int | None = Query(None, ge=1),
    full: bool = Query(False),
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
) -> IngestionSyncResponse:
    """Admin-only bounded sync run for one source.

    NVD runs incrementally (last ``days`` days) unless ``full=true``,
    which switches to a published-date fetch over the same bounded
    ``days`` window — an unbounded full re-ingestion is never allowed
    through this endpoint.
    """
    if source not in SYNC_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown source: {source!r}",
        )
    _check_sync_rate_limit(db, source, datetime.now(timezone.utc))
    summary = run_ingestion(
        source,
        db,
        triggered_by=f"admin:{user.username}",
        days=days,
        limit=limit,
        full=full,
    )
    return IngestionSyncResponse(**summary)
