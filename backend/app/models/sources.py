"""Ingestion bookkeeping — DATABASE.md §2.12–2.13: data_sources, ingestion_jobs."""

import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, utcnow
from app.models.types import JSONB

# Seeded in the first migration (DATABASE.md §3) and by
# ``app.services.seed`` for test/dev databases built with create_all.
DATA_SOURCES = (
    ("nvd", "NVD — National Vulnerability Database",
     "https://services.nvd.nist.gov/rest/json/cves/2.0"),
    ("cisa-kev", "CISA Known Exploited Vulnerabilities",
     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
    ("epss", "FIRST EPSS — Exploit Prediction Scoring System",
     "https://api.first.org/data/v1/epss"),
    ("mitre-attack", "MITRE ATT&CK",
     "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"),
    ("mitre-cwe", "MITRE CWE",
     "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"),
)


class DataSource(Base):
    """§2.12 — one row per upstream intelligence source."""

    __tablename__ = "data_sources"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(String(64), unique=True, nullable=False)
    display_name = Column(String(128), nullable=True)
    base_url = Column(Text, nullable=True)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_sync_status = Column(String(32), nullable=True)
    is_enabled = Column(Boolean, nullable=False, default=True)

    jobs = relationship(
        "IngestionJob", back_populates="source", cascade="all, delete-orphan"
    )


class IngestionJob(Base):
    """§2.13 — one row per connector run."""

    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        Index(
            "ingestion_jobs_source_started", "source_id", "started_at"
        ),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id = Column(
        Uuid,
        ForeignKey("data_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    started_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    finished_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(32), nullable=False, default="running")
    records_fetched = Column(Integer, nullable=False, default=0)
    records_created = Column(Integer, nullable=False, default=0)
    records_updated = Column(Integer, nullable=False, default=0)
    records_skipped = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    triggered_by = Column(String(32), nullable=True)
    details = Column(JSONB, nullable=True)

    source = relationship("DataSource", back_populates="jobs")
