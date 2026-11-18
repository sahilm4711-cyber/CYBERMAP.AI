"""Pydantic schemas for the Phase 5 threat-intelligence API."""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class KevListItem(BaseModel):
    cve_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: date | None
    due_date: date | None
    short_description: str | None
    required_action: str | None
    ransomware_use: str | None
    is_indexed: bool


class KevListResponse(BaseModel):
    items: list[KevListItem]
    total: int
    page: int
    per_page: int
    pages: int


class EpssRankingItem(BaseModel):
    cve_id: str
    title: str | None
    severity: str | None
    cvss_score: float | None
    epss_score: float
    percentile: float
    model_date: date


class EpssRankingResponse(BaseModel):
    items: list[EpssRankingItem]
    total: int
    page: int
    per_page: int
    pages: int


class TimelineEvent(BaseModel):
    """One merged timeline event.

    ``type`` is ``cve`` (a CVE was published), ``kev`` (a CVE was
    added to CISA KEV) or ``ingestion`` (an ingestion job ran).
    """

    type: str
    date: datetime | None
    label: str
    cve_id: str | None = None
    source: str | None = None
    status: str | None = None


class TimelineResponse(BaseModel):
    events: list[TimelineEvent]


class MetricExplanation(BaseModel):
    name: str
    what_it_measures: str
    scale: str
    what_high_means: str
    what_it_does_not_mean: str
    limitations: list[str]


class MetricsExplainedResponse(BaseModel):
    """CVSS vs EPSS vs KEV, in plain language.

    The three are explicitly NOT interchangeable: severity, the
    probability of exploitation, and confirmed exploitation are
    three different facts about a vulnerability.
    """

    note: str
    metrics: list[MetricExplanation]
