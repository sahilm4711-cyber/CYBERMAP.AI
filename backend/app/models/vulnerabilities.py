"""Intelligence models — DATABASE.md §2.4–2.11.

vulnerabilities, vulnerability_references, affected_products,
cwe_entries, attack_techniques, vulnerability_relationships,
kev_entries, epss_scores.
"""

import uuid

from sqlalchemy import (
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    Uuid,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin, utcnow
from app.models.types import JSONB


class Vulnerability(Base, TimestampMixin):
    """§2.4 — one row per CVE ID."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("vuln_severity", "severity"),
        Index("vuln_published_at", "published_at"),
        Index("vuln_cvss_score", "cvss_score"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id = Column(
        String(32), unique=True, nullable=False, index=True
    )
    title = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    cvss_score = Column(Numeric(3, 1), nullable=True)
    cvss_version = Column(String(8), nullable=True)
    cvss_vector = Column(String(255), nullable=True)
    severity = Column(String(16), nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=True)
    last_modified_at = Column(DateTime(timezone=True), nullable=True)
    # Provenance (DATABASE.md §1).
    source = Column(String(32), nullable=False, default="nvd")
    source_url = Column(Text, nullable=True)
    source_updated_at = Column(DateTime(timezone=True), nullable=True)
    ingested_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    references = relationship(
        "VulnerabilityReference",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    affected_products = relationship(
        "AffectedProduct",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    kev_entries = relationship("KevEntry", back_populates="vulnerability")
    epss_scores = relationship("EpssScore", back_populates="vulnerability")
    notes = relationship("ResearchNote", back_populates="vulnerability")
    saved_analyses = relationship(
        "SavedAnalysis",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )


class VulnerabilityReference(Base):
    """§2.5 — one URL per vulnerability (unique pair)."""

    __tablename__ = "vulnerability_references"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id", "url", name="uq_vuln_ref_vuln_url"
        ),
        Index("vuln_ref_vuln_id", "vulnerability_id"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(
        Uuid,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    url = Column(Text, nullable=False)
    source = Column(String(64), nullable=True)
    tags = Column(JSONB, nullable=True)

    vulnerability = relationship(
        "Vulnerability", back_populates="references"
    )


class AffectedProduct(Base):
    """§2.6 — vendor/product/version range affected by a CVE."""

    __tablename__ = "affected_products"
    __table_args__ = (
        Index(
            "affected_product_vendor_product", "vendor", "product"
        ),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(
        Uuid,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    vendor = Column(String(255), nullable=True)
    product = Column(String(255), nullable=True)
    version_start = Column(String(64), nullable=True)
    version_end = Column(String(64), nullable=True)
    version_range_text = Column(Text, nullable=True)

    vulnerability = relationship(
        "Vulnerability", back_populates="affected_products"
    )


class CweEntry(Base, TimestampMixin):
    """§2.7 — one row per CWE ID (MITRE CWE)."""

    __tablename__ = "cwe_entries"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    cwe_id = Column(String(16), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    extended_description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)
    source = Column(String(32), nullable=False, default="mitre-cwe")
    source_url = Column(Text, nullable=True)
    ingested_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AttackTechnique(Base, TimestampMixin):
    """§2.8 — MITRE ATT&CK enterprise techniques."""

    __tablename__ = "attack_techniques"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    technique_id = Column(String(16), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    tactic = Column(String(64), nullable=True)
    platforms = Column(JSONB, nullable=True)
    detection = Column(Text, nullable=True)
    mitigations = Column(JSONB, nullable=True)
    source = Column(String(32), nullable=False, default="mitre-attack")
    source_url = Column(Text, nullable=True)
    ingested_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class VulnerabilityRelationship(Base):
    """§2.9 — knowledge-graph edge.

    ``from_id`` / ``to_id`` are polymorphic UUIDs (they point at rows
    in different tables), so referential integrity is enforced in the
    service layer (Phase 7), per the DATABASE.md polymorphic note.
    """

    __tablename__ = "vulnerability_relationships"
    __table_args__ = (
        UniqueConstraint(
            "from_type",
            "from_id",
            "to_type",
            "to_id",
            "relationship",
            name="uq_vuln_rel_edge",
        ),
        Index("vuln_rel_from", "from_type", "from_id"),
        Index("vuln_rel_to", "to_type", "to_id"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    from_type = Column(String(32), nullable=False)
    from_id = Column(Uuid, nullable=False)
    to_type = Column(String(32), nullable=False)
    to_id = Column(Uuid, nullable=False)
    relationship = Column(String(64), nullable=False)
    source = Column(String(32), nullable=False)
    source_url = Column(Text, nullable=True)
    confidence = Column(String(16), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class KevEntry(Base, TimestampMixin):
    """§2.10 — CISA Known Exploited Vulnerabilities."""

    __tablename__ = "kev_entries"
    __table_args__ = (
        Index("kev_date_added", "date_added"),
        Index("kev_due_date", "due_date"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(32), unique=True, nullable=False)
    vulnerability_id = Column(
        Uuid,
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    vendor_project = Column(String(255), nullable=True)
    product = Column(String(255), nullable=True)
    vulnerability_name = Column(String(255), nullable=True)
    date_added = Column(Date, nullable=True)
    due_date = Column(Date, nullable=True)
    short_description = Column(Text, nullable=True)
    required_action = Column(Text, nullable=True)
    ransomware_use = Column(String(32), nullable=True)
    source = Column(String(32), nullable=False, default="cisa-kev")
    ingested_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    vulnerability = relationship(
        "Vulnerability", back_populates="kev_entries"
    )


class EpssScore(Base):
    """§2.11 — FIRST EPSS scores; one row per CVE per model date."""

    __tablename__ = "epss_scores"
    __table_args__ = (
        UniqueConstraint(
            "cve_id", "model_date", name="uq_epss_cve_model_date"
        ),
        Index("epss_score_idx", "epss_score"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(32), nullable=False)
    vulnerability_id = Column(
        Uuid,
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    epss_score = Column(Numeric(6, 5), nullable=False)
    percentile = Column(Numeric(6, 5), nullable=False)
    model_date = Column(Date, nullable=False)
    ingested_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    vulnerability = relationship(
        "Vulnerability", back_populates="epss_scores"
    )
