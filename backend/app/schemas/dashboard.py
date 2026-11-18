"""Pydantic schemas for the Phase 5 dashboard API.

All statistics come from the database (see
``app.services.dashboard_service``). Nothing here fabricates a
number: when a source has never synced, ``last_sync_at`` is null
and the sync status reports ``never``.
"""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class SourceSyncStatus(BaseModel):
    """Sync status of one upstream source (DATABASE.md §2.12)."""

    name: str
    display_name: str | None
    last_sync_at: datetime | None
    last_sync_status: str | None
    is_enabled: bool


class RecentCve(BaseModel):
    """One row of the dashboard's recently-published table."""

    cve_id: str
    title: str | None
    severity: str | None
    cvss_score: float | None
    published_at: datetime | None


class DashboardSummary(BaseModel):
    """GET /api/v1/dashboard/summary.

    ``total_cves`` and the severity counts honour the ``?from`` /
    ``?to`` range when given (they count CVEs *published* in the
    range); without a range they cover all indexed CVEs. ``kev_count``
    (distinct CVEs in the KEV feed) and ``high_epss_count`` (distinct
    CVEs whose latest EPSS score is >= 0.7) are range-independent:
    they describe current known exploitation, not publication.
    """

    total_cves: int
    critical: int
    high: int
    medium: int
    low: int
    none_severity: int
    unknown_severity: int
    kev_count: int
    high_epss_count: int
    recently_published: list[RecentCve]
    last_sync_at: datetime | None
    sources: list[SourceSyncStatus]
    range_from: date | None = None
    range_to: date | None = None


class DailyCount(BaseModel):
    date: date
    count: int


class CweDistributionItem(BaseModel):
    cwe_id: str
    name: str | None
    count: int


class KevDailyCount(BaseModel):
    date: date
    count: int


class DashboardTrends(BaseModel):
    """GET /api/v1/dashboard/trends.

    Defaults to the last 30 days when no ``?from`` / ``?to`` range
    is given. EPSS buckets count each CVE once, by its *latest*
    EPSS score.
    """

    range_from: date
    range_to: date
    publications_per_day: list[DailyCount]
    severity_distribution: dict[str, int]
    cwe_distribution: list[CweDistributionItem]
    kev_additions_per_day: list[KevDailyCount]
    epss_buckets: dict[str, int]
