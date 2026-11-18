"""Pydantic schemas for Phase 4 ingestion.

Every incoming record is validated against one of these schemas
*before* storage (see ``app.ingestion.run``); a record that fails
validation is skipped and counted, never stored half-parsed. The
same module carries the response schemas for the ingestion API.
"""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field, field_validator

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_PATTERN = re.compile(r"^CWE-\d+$")
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


# ------------------------------------------------------- inbound (validated)

class NvdVulnerabilitySchema(BaseModel):
    """Normalized NVD record, ready for the ``vulnerabilities`` table."""

    cve_id: str
    title: str | None = None
    description: str = Field(min_length=1)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_version: str | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    source: str = "nvd"
    source_url: str | None = None
    source_updated_at: datetime | None = None

    @field_validator("cve_id")
    @classmethod
    def cve_id_format(cls, value: str) -> str:
        if not CVE_PATTERN.match(value):
            raise ValueError(f"invalid CVE id: {value!r}")
        return value

    @field_validator("severity")
    @classmethod
    def severity_known(cls, value: str | None) -> str | None:
        if value is not None and value not in SEVERITIES:
            raise ValueError(f"unknown severity: {value!r}")
        return value

    @field_validator("cvss_version")
    @classmethod
    def cvss_version_known(cls, value: str | None) -> str | None:
        if value is not None and value not in ("3.1", "3.0", "2.0"):
            raise ValueError(f"unknown CVSS version: {value!r}")
        return value


class VulnerabilityReferenceSchema(BaseModel):
    url: str = Field(min_length=1)
    source: str | None = None
    tags: list[str] | None = None


class AffectedProductSchema(BaseModel):
    vendor: str | None = None
    product: str | None = None
    version_start: str | None = None
    version_end: str | None = None
    version_range_text: str | None = None


class KevEntrySchema(BaseModel):
    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: date | None = None
    due_date: date | None = None
    short_description: str | None = None
    required_action: str | None = None
    ransomware_use: str | None = None
    source: str = "cisa-kev"

    @field_validator("cve_id")
    @classmethod
    def cve_id_format(cls, value: str) -> str:
        if not CVE_PATTERN.match(value):
            raise ValueError(f"invalid CVE id: {value!r}")
        return value


class EpssScoreSchema(BaseModel):
    cve_id: str
    epss_score: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    model_date: date

    @field_validator("cve_id")
    @classmethod
    def cve_id_format(cls, value: str) -> str:
        if not CVE_PATTERN.match(value):
            raise ValueError(f"invalid CVE id: {value!r}")
        return value


class CweEntrySchema(BaseModel):
    cwe_id: str
    name: str = Field(min_length=1)
    description: str | None = None
    extended_description: str | None = None
    category: str | None = None
    source: str = "mitre-cwe"
    source_url: str | None = None

    @field_validator("cwe_id")
    @classmethod
    def cwe_id_format(cls, value: str) -> str:
        if not CWE_PATTERN.match(value):
            raise ValueError(f"invalid CWE id: {value!r}")
        return value


class AttackTechniqueSchema(BaseModel):
    technique_id: str
    name: str = Field(min_length=1)
    description: str | None = None
    tactic: str | None = None
    platforms: list[str] | None = None
    detection: str | None = None
    mitigations: list | None = None
    source: str = "mitre-attack"
    source_url: str | None = None

    @field_validator("technique_id")
    @classmethod
    def technique_id_format(cls, value: str) -> str:
        if not TECHNIQUE_PATTERN.match(value):
            raise ValueError(f"invalid technique id: {value!r}")
        return value


# ------------------------------------------------------ outbound (API)

class IngestionJobResponse(BaseModel):
    id: uuid.UUID
    source: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    records_fetched: int
    records_created: int
    records_updated: int
    records_skipped: int
    error_message: str | None
    triggered_by: str | None

    model_config = {"from_attributes": True}


class SourceStatusResponse(BaseModel):
    source: str
    display_name: str | None
    is_enabled: bool
    last_sync_at: datetime | None
    last_sync_status: str | None
    last_job: IngestionJobResponse | None = None


class IngestionSyncResponse(BaseModel):
    source: str
    job_id: uuid.UUID | None = None
    status: str
    records_fetched: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_skipped: int = 0
    error_message: str | None = None
