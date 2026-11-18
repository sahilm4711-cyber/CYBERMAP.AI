"""Dashboard statistics — Phase 5.

Every number comes from the database. A source that has never
synced reports ``last_sync_at=None`` and status ``never``; missing
data is never presented as zero risk, it is presented as absent.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import (
    CweEntry,
    DataSource,
    EpssScore,
    KevEntry,
    Vulnerability,
    VulnerabilityRelationship,
)

EPSS_BUCKETS: tuple[tuple[str, float, float], ...] = (
    ("0-0.1", 0.0, 0.1),
    ("0.1-0.3", 0.1, 0.3),
    ("0.3-0.5", 0.3, 0.5),
    ("0.5-0.7", 0.5, 0.7),
    ("0.7-1.0", 0.7, 1.0),
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


def _range_bounds(
    from_date: date | None, to_date: date | None
) -> tuple[datetime | None, datetime | None]:
    """Inclusive date range -> [start-of-from, end-of-to] datetimes.

    Naive UTC bounds: ``published_at`` is stored naive on SQLite
    and tz-aware on Postgres; a naive bound compares cleanly on
    SQLite and is interpreted in the session timezone on Postgres,
    matching the existing codebase's handling.
    """
    start = (
        datetime.combine(from_date, time.min) if from_date else None
    )
    end = (
        datetime.combine(to_date, time.max) if to_date else None
    )
    return start, end


def _published_in_range(
    query, from_date: date | None, to_date: date | None
):
    start, end = _range_bounds(from_date, to_date)
    if start is not None:
        query = query.filter(Vulnerability.published_at >= start)
    if end is not None:
        query = query.filter(Vulnerability.published_at <= end)
    return query


def _latest_epss_by_cve(db: Session) -> dict[str, float]:
    """Latest EPSS score per CVE (one row per CVE, newest model date)."""
    sub = (
        db.query(
            EpssScore.cve_id,
            func.max(EpssScore.model_date).label("max_date"),
        )
        .group_by(EpssScore.cve_id)
        .subquery()
    )
    rows = (
        db.query(EpssScore.cve_id, EpssScore.epss_score)
        .join(
            sub,
            (EpssScore.cve_id == sub.c.cve_id)
            & (EpssScore.model_date == sub.c.max_date),
        )
        .all()
    )
    return {cve_id: float(score) for cve_id, score in rows}


def get_summary(
    db: Session,
    from_date: date | None = None,
    to_date: date | None = None,
) -> dict:
    """Dashboard summary counts + recent CVEs + per-source sync status."""
    base = _published_in_range(
        db.query(Vulnerability), from_date, to_date
    )
    total = base.count()
    severity_counts = {
        sev: base.filter(Vulnerability.severity == sev).count()
        for sev in SEVERITIES
    }
    unknown = base.filter(Vulnerability.severity.is_(None)).count()

    kev_count = (
        db.query(func.count(func.distinct(KevEntry.cve_id))).scalar()
        or 0
    )
    latest_epss = _latest_epss_by_cve(db)
    high_epss = sum(1 for s in latest_epss.values() if s >= 0.7)

    recent = (
        _published_in_range(
            db.query(Vulnerability), from_date, to_date
        )
        .order_by(Vulnerability.published_at.desc())
        .limit(10)
        .all()
    )

    sources = db.query(DataSource).order_by(DataSource.name).all()
    last_syncs = [
        s.last_sync_at for s in sources if s.last_sync_at is not None
    ]
    return {
        "total_cves": total,
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "none_severity": severity_counts["NONE"],
        "unknown_severity": unknown,
        "kev_count": kev_count,
        "high_epss_count": high_epss,
        "recently_published": [
            {
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": (
                    float(v.cvss_score) if v.cvss_score is not None else None
                ),
                "published_at": v.published_at,
            }
            for v in recent
        ],
        "last_sync_at": max(last_syncs) if last_syncs else None,
        "sources": [
            {
                "name": s.name,
                "display_name": s.display_name,
                "last_sync_at": s.last_sync_at,
                "last_sync_status": s.last_sync_status or "never",
                "is_enabled": s.is_enabled,
            }
            for s in sources
        ],
        "range_from": from_date,
        "range_to": to_date,
    }


def get_trends(
    db: Session,
    from_date: date | None = None,
    to_date: date | None = None,
) -> dict:
    """Trend data for the dashboard charts.

    No range given -> last 30 days (inclusive). EPSS buckets count
    each CVE once, by its latest score.
    """
    today = date.today()
    if to_date is None:
        to_date = today
    if from_date is None:
        from_date = to_date - timedelta(days=29)

    start, end = _range_bounds(from_date, to_date)

    # Publications per day (grouped by published date in the DB).
    pub_rows = (
        db.query(
            func.date(Vulnerability.published_at).label("day"),
            func.count(Vulnerability.id).label("count"),
        )
        .filter(Vulnerability.published_at >= start)
        .filter(Vulnerability.published_at <= end)
        .group_by(func.date(Vulnerability.published_at))
        .order_by("day")
        .all()
    )
    per_day: dict[date, int] = {}
    day = from_date
    while day <= to_date:
        per_day[day] = 0
        day += timedelta(days=1)
    for row in pub_rows:
        if row.day is None:
            continue
        day_value = (
            row.day
            if isinstance(row.day, date)
            else date.fromisoformat(str(row.day))
        )
        per_day[day_value] = row.count

    in_range = (
        db.query(Vulnerability)
        .filter(Vulnerability.published_at >= start)
        .filter(Vulnerability.published_at <= end)
    )
    severity_dist: dict[str, int] = {
        sev: in_range.filter(Vulnerability.severity == sev).count()
        for sev in SEVERITIES
    }
    severity_dist["UNKNOWN"] = in_range.filter(
        Vulnerability.severity.is_(None)
    ).count()

    # Top 10 CWE by vulnerability count (HAS_WEAKNESS edges).
    cwe_rows = (
        db.query(
            CweEntry.cwe_id,
            CweEntry.name,
            func.count(
                func.distinct(VulnerabilityRelationship.from_id)
            ).label("count"),
        )
        .join(
            VulnerabilityRelationship,
            VulnerabilityRelationship.to_id == CweEntry.id,
        )
        .join(
            Vulnerability,
            Vulnerability.id == VulnerabilityRelationship.from_id,
        )
        .filter(
            VulnerabilityRelationship.from_type == "vulnerability",
            VulnerabilityRelationship.to_type == "cwe",
            VulnerabilityRelationship.relationship == "HAS_WEAKNESS",
            Vulnerability.published_at >= start,
            Vulnerability.published_at <= end,
        )
        .group_by(CweEntry.cwe_id, CweEntry.name)
        .order_by(func.count(func.distinct(VulnerabilityRelationship.from_id)).desc())
        .limit(10)
        .all()
    )

    # KEV additions per day (by date_added).
    kev_rows = (
        db.query(
            KevEntry.date_added,
            func.count(KevEntry.id).label("count"),
        )
        .filter(KevEntry.date_added.is_not(None))
        .filter(KevEntry.date_added >= from_date)
        .filter(KevEntry.date_added <= to_date)
        .group_by(KevEntry.date_added)
        .order_by(KevEntry.date_added)
        .all()
    )
    kev_per_day: dict[date, int] = {}
    day = from_date
    while day <= to_date:
        kev_per_day[day] = 0
        day += timedelta(days=1)
    for row in kev_rows:
        kev_per_day[row.date_added] = row.count

    # EPSS distribution buckets (latest score per CVE).
    buckets = {label: 0 for label, _, _ in EPSS_BUCKETS}
    for score in _latest_epss_by_cve(db).values():
        for label, low, high in EPSS_BUCKETS:
            if low <= score < high or (
                label == "0.7-1.0" and score == 1.0
            ):
                buckets[label] += 1
                break

    return {
        "range_from": from_date,
        "range_to": to_date,
        "publications_per_day": [
            {"date": d, "count": c} for d, c in per_day.items()
        ],
        "severity_distribution": severity_dist,
        "cwe_distribution": [
            {"cwe_id": r.cwe_id, "name": r.name, "count": r.count}
            for r in cwe_rows
        ],
        "kev_additions_per_day": [
            {"date": d, "count": c} for d, c in kev_per_day.items()
        ],
        "epss_buckets": buckets,
    }
