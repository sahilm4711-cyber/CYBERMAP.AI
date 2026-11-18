"""Pydantic schemas for the Phase 5 vulnerability explorer API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class VulnerabilityListItem(BaseModel):
    cve_id: str
    title: str | None
    severity: str | None
    cvss_score: float | None
    cvss_version: str | None
    epss_score: float | None
    epss_percentile: float | None
    is_kev: bool
    cwe_ids: list[str]
    published_at: datetime | None


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilityListItem]
    total: int
    page: int
    per_page: int
    pages: int


class CweItem(BaseModel):
    cwe_id: str
    name: str
    description: str | None


class AffectedProductItem(BaseModel):
    vendor: str | None
    product: str | None
    version_start: str | None
    version_end: str | None
    version_range_text: str | None


class ReferenceItem(BaseModel):
    url: str
    source: str | None


class EpssItem(BaseModel):
    epss_score: float
    percentile: float
    model_date: str


class KevItem(BaseModel):
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: str | None
    due_date: str | None
    short_description: str | None
    required_action: str | None
    ransomware_use: str | None


class RelatedVulnerabilityItem(BaseModel):
    cve_id: str
    title: str | None
    severity: str | None
    cvss_score: float | None
    published_at: datetime | None


class VulnerabilityDetail(BaseModel):
    cve_id: str
    title: str | None
    description: str
    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    severity: str | None
    published_at: datetime | None
    last_modified_at: datetime | None
    source: str
    source_url: str | None
    cwes: list[CweItem]
    affected_products: list[AffectedProductItem]
    references: list[ReferenceItem]
    epss: EpssItem | None
    kev: KevItem | None
    related: list[RelatedVulnerabilityItem]
    remediation: str | None
