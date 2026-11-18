"""Ingestion orchestration (Phase 4).

``run_ingestion(source_name, db, triggered_by)`` runs one connector
end to end: creates an ``IngestionJob`` row (status ``running``),
fetches, validates (Pydantic — malformed records are skipped and
counted, never stored half-parsed), dedups with safe upserts (match
on the natural key; update only when ``source_updated_at`` is newer;
never overwrite a verified record with incomplete data), updates the
``DataSource`` row, finishes the job row with counts, and writes an
``audit_logs`` row (action ``ingestion.run``).

CLI (from ``backend/`` with the venv)::

    python -m app.ingestion.run --source all|nvd|kev|epss|mitre [--limit N] [--days N] [--full]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.ingestion import connectors
from app.integrations import epss as epss_client
from app.integrations import kev as kev_client
from app.integrations import mitre as mitre_client
from app.integrations import nvd as nvd_client
from app.models import (
    AffectedProduct,
    AttackTechnique,
    CweEntry,
    DataSource,
    EpssScore,
    IngestionJob,
    KevEntry,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityRelationship,
)
from app.models.base import as_utc_aware, utcnow
from app.schemas.ingestion import (
    AffectedProductSchema,
    AttackTechniqueSchema,
    CweEntrySchema,
    EpssScoreSchema,
    KevEntrySchema,
    NvdVulnerabilitySchema,
    VulnerabilityReferenceSchema,
)
from app.services.audit import write_audit_log

# Canonical source names (data_sources.name) and the aliases the CLI
# and API accept. "mitre" runs both MITRE catalogs.
SOURCE_ALIASES = {
    "nvd": "nvd",
    "kev": "cisa-kev",
    "cisa-kev": "cisa-kev",
    "epss": "epss",
    "mitre-attack": "mitre-attack",
    "mitre-cwe": "mitre-cwe",
    "mitre": "mitre",
}
ALL_SOURCES = ("mitre-cwe", "mitre-attack", "nvd", "cisa-kev", "epss")

_VULN_UPDATABLE = (
    "title",
    "description",
    "cvss_score",
    "cvss_version",
    "cvss_vector",
    "severity",
    "published_at",
    "last_modified_at",
    "source_url",
    "source_updated_at",
)


# ------------------------------------------------------------ fetch layer
# One function per source so tests can monkeypatch them with fixtures
# (no live HTTP in tests) without touching the HTTP clients.

def fetch_nvd_records(
    *,
    days: int = 7,
    limit: int | None = None,
    full: bool = False,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    if full:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        return nvd_client.fetch_nvd_full(
            start, end, limit=limit, client=client, sleep=sleep
        )
    return nvd_client.fetch_nvd_incremental(
        days=days, limit=limit, client=client, sleep=sleep
    )


def fetch_kev_records(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    return kev_client.fetch_kev_catalog(client=client, sleep=sleep)


def fetch_epss_records(
    db: Session,
    *,
    limit: int | None = None,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[dict], object]:
    """EPSS scores for the CVE ids already in the database."""
    query = db.query(Vulnerability.cve_id).order_by(Vulnerability.cve_id)
    if limit is not None:
        query = query.limit(limit)
    cve_ids = [row[0] for row in query.all()]
    records, model_date = epss_client.fetch_epss_scores(
        cve_ids, client=client, sleep=sleep
    )
    return records, model_date


def fetch_attack_records(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    return mitre_client.fetch_attack_techniques(client=client, sleep=sleep)


def fetch_cwe_records(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    return mitre_client.fetch_cwe_entries(client=client, sleep=sleep)


# ------------------------------------------------------------- store layer

def _new_counts() -> dict:
    return {"fetched": 0, "created": 0, "updated": 0, "skipped": 0}


def _record_skip(
    counts: dict, details: dict, reason: str
) -> None:
    counts["skipped"] += 1
    reasons = details.setdefault("skipped_reasons", {})
    reasons[reason] = reasons.get(reason, 0) + 1


def _store_nvd_record(
    db: Session, parsed: dict, counts: dict, details: dict
) -> None:
    """Validate + safe-upsert one parsed NVD record (incl. children)."""
    try:
        vuln_data = NvdVulnerabilitySchema(
            **parsed["vulnerability"]
        ).model_dump()
    except ValidationError as exc:
        _record_skip(counts, details, f"validation: {exc.errors()[0]['type']}")
        return

    cve_id = vuln_data["cve_id"]
    existing = (
        db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    )
    if existing is None:
        vuln = Vulnerability(**vuln_data)
        db.add(vuln)
        db.flush()
        counts["created"] += 1
    else:
        new_updated = as_utc_aware(vuln_data.get("source_updated_at"))
        old_updated = as_utc_aware(existing.source_updated_at)
        if new_updated is None or (
            old_updated is not None and new_updated <= old_updated
        ):
            _record_skip(counts, details, "not_newer")
            return
        # Newer record: overwrite only with values the new record
        # actually carries — never blank a verified field with NULL.
        for field in _VULN_UPDATABLE:
            if vuln_data.get(field) is not None:
                setattr(existing, field, vuln_data[field])
        existing.ingested_at = utcnow()
        vuln = existing
        counts["updated"] += 1

    for ref_raw in parsed.get("references", []):
        try:
            ref = VulnerabilityReferenceSchema(**ref_raw).model_dump()
        except ValidationError:
            _record_skip(counts, details, "validation: reference")
            continue
        already = (
            db.query(VulnerabilityReference)
            .filter(
                VulnerabilityReference.vulnerability_id == vuln.id,
                VulnerabilityReference.url == ref["url"],
            )
            .first()
        )
        if already is None:
            db.add(VulnerabilityReference(vulnerability_id=vuln.id, **ref))

    for prod_raw in parsed.get("products", []):
        try:
            prod = AffectedProductSchema(**prod_raw).model_dump()
        except ValidationError:
            _record_skip(counts, details, "validation: product")
            continue
        already = (
            db.query(AffectedProduct)
            .filter(
                AffectedProduct.vulnerability_id == vuln.id,
                AffectedProduct.vendor == prod["vendor"],
                AffectedProduct.product == prod["product"],
                AffectedProduct.version_start == prod["version_start"],
                AffectedProduct.version_end == prod["version_end"],
            )
            .first()
        )
        if already is None:
            db.add(AffectedProduct(vulnerability_id=vuln.id, **prod))

    for cwe_id in parsed.get("cwe_ids", []):
        cwe = db.query(CweEntry).filter(CweEntry.cwe_id == cwe_id).first()
        if cwe is None:
            missing = details.setdefault("missing_cwe_links", [])
            if cwe_id not in missing and len(missing) < 100:
                missing.append(cwe_id)
            continue
        already = (
            db.query(VulnerabilityRelationship)
            .filter(
                VulnerabilityRelationship.from_type == "vulnerability",
                VulnerabilityRelationship.from_id == vuln.id,
                VulnerabilityRelationship.to_type == "cwe",
                VulnerabilityRelationship.to_id == cwe.id,
                VulnerabilityRelationship.relationship == "HAS_WEAKNESS",
            )
            .first()
        )
        if already is None:
            db.add(
                VulnerabilityRelationship(
                    from_type="vulnerability",
                    from_id=vuln.id,
                    to_type="cwe",
                    to_id=cwe.id,
                    relationship="HAS_WEAKNESS",
                    source="nvd",
                    source_url=vuln_data.get("source_url"),
                    confidence="verified",
                )
            )


def _upsert_simple(
    db: Session,
    model,
    key_filter: dict,
    data: dict,
    counts: dict,
    details: dict,
) -> None:
    """Generic upsert for KEV / EPSS / CWE / technique rows.

    Creates when the natural key is absent, updates when any field
    changed, counts as skipped when identical.
    """
    existing = db.query(model).filter_by(**key_filter).first()
    if existing is None:
        db.add(model(**data))
        counts["created"] += 1
        return
    changed = False
    for field, value in data.items():
        if value is None:
            continue
        if getattr(existing, field) != value:
            setattr(existing, field, value)
            changed = True
    if changed:
        counts["updated"] += 1
    else:
        _record_skip(counts, details, "unchanged")


def _store_kev_records(
    db: Session, raw_records: list[dict], counts: dict, details: dict
) -> None:
    for raw in raw_records:
        try:
            data = KevEntrySchema(**connectors.parse_kev_record(raw)).model_dump()
        except ValidationError as exc:
            _record_skip(counts, details, f"validation: {exc.errors()[0]['type']}")
            continue
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.cve_id == data["cve_id"])
            .first()
        )
        if vuln is not None:
            data["vulnerability_id"] = vuln.id
        _upsert_simple(
            db, KevEntry, {"cve_id": data["cve_id"]}, data, counts, details
        )


def _store_epss_records(
    db: Session,
    raw_records: list[dict],
    model_date,
    counts: dict,
    details: dict,
) -> None:
    if model_date is None:
        _record_skip(counts, details, "no_model_date")
        return
    for raw in raw_records:
        try:
            data = EpssScoreSchema(
                **connectors.parse_epss_record(raw, model_date)
            ).model_dump()
        except ValidationError as exc:
            _record_skip(counts, details, f"validation: {exc.errors()[0]['type']}")
            continue
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.cve_id == data["cve_id"])
            .first()
        )
        if vuln is not None:
            data["vulnerability_id"] = vuln.id
        _upsert_simple(
            db,
            EpssScore,
            {"cve_id": data["cve_id"], "model_date": data["model_date"]},
            data,
            counts,
            details,
        )


def _store_cwe_records(
    db: Session, raw_records: list[dict], counts: dict, details: dict
) -> None:
    for raw in raw_records:
        try:
            data = CweEntrySchema(**connectors.parse_cwe_record(raw)).model_dump()
        except ValidationError as exc:
            _record_skip(counts, details, f"validation: {exc.errors()[0]['type']}")
            continue
        _upsert_simple(
            db, CweEntry, {"cwe_id": data["cwe_id"]}, data, counts, details
        )


def _store_attack_records(
    db: Session, raw_records: list[dict], counts: dict, details: dict
) -> None:
    for raw in raw_records:
        try:
            data = AttackTechniqueSchema(
                **connectors.parse_attack_technique_record(raw)
            ).model_dump()
        except ValidationError as exc:
            _record_skip(counts, details, f"validation: {exc.errors()[0]['type']}")
            continue
        _upsert_simple(
            db,
            AttackTechnique,
            {"technique_id": data["technique_id"]},
            data,
            counts,
            details,
        )


# ---------------------------------------------------------- orchestration

def _get_data_source(db: Session, name: str) -> DataSource:
    source = db.query(DataSource).filter(DataSource.name == name).first()
    if source is None:
        raise ValueError(f"unknown data source: {name!r}")
    return source


def _run_single(
    source_name: str,
    db: Session,
    triggered_by: str | None,
    *,
    days: int = 7,
    limit: int | None = None,
    full: bool = False,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Run one canonical source; return its job summary dict."""
    source = _get_data_source(db, source_name)
    job = IngestionJob(
        source_id=source.id, status="running", triggered_by=triggered_by
    )
    db.add(job)
    db.commit()  # the running row must be visible (API rate limiting)

    counts = _new_counts()
    details: dict = {}
    error_message: str | None = None
    try:
        if source_name == "nvd":
            raw = fetch_nvd_records(
                days=days, limit=limit, full=full, client=client, sleep=sleep
            )
            counts["fetched"] = len(raw)
            for record in raw:
                _store_nvd_record(
                    db, connectors.parse_nvd_record(record), counts, details
                )
        elif source_name == "cisa-kev":
            raw = fetch_kev_records(client=client, sleep=sleep)
            counts["fetched"] = len(raw)
            if limit is not None:
                raw = raw[:limit]
            _store_kev_records(db, raw, counts, details)
        elif source_name == "epss":
            raw, model_date = fetch_epss_records(
                db, limit=limit, client=client, sleep=sleep
            )
            counts["fetched"] = len(raw)
            details["model_date"] = (
                model_date.isoformat() if model_date else None
            )
            _store_epss_records(db, raw, model_date, counts, details)
        elif source_name == "mitre-attack":
            raw = fetch_attack_records(client=client, sleep=sleep)
            counts["fetched"] = len(raw)
            if limit is not None:
                raw = raw[:limit]
            _store_attack_records(db, raw, counts, details)
        elif source_name == "mitre-cwe":
            raw = fetch_cwe_records(client=client, sleep=sleep)
            counts["fetched"] = len(raw)
            if limit is not None:
                raw = raw[:limit]
            _store_cwe_records(db, raw, counts, details)
        else:  # pragma: no cover - guarded by SOURCE_ALIASES
            raise ValueError(f"no fetcher for source: {source_name!r}")

        job.status = (
            "partial"
            if counts["skipped"] > 0
            and (counts["created"] + counts["updated"]) > 0
            else "success"
        )
    except Exception as exc:  # fetch or storage failure -> failed job
        db.rollback()
        db.add(job)
        job.status = "failed"
        error_message = str(exc)[:2000]
        counts = _new_counts()

    job.finished_at = utcnow()
    job.records_fetched = counts["fetched"]
    job.records_created = counts["created"]
    job.records_updated = counts["updated"]
    job.records_skipped = counts["skipped"]
    job.error_message = error_message
    job.details = details or None
    source.last_sync_at = utcnow()
    source.last_sync_status = job.status
    write_audit_log(
        db,
        "ingestion.run",
        entity_type="ingestion_job",
        entity_id=job.id,
        details={
            "source": source_name,
            "status": job.status,
            "fetched": counts["fetched"],
            "created": counts["created"],
            "updated": counts["updated"],
            "skipped": counts["skipped"],
        },
    )
    db.commit()
    return {
        "source": source_name,
        "job_id": job.id,
        "status": job.status,
        "records_fetched": counts["fetched"],
        "records_created": counts["created"],
        "records_updated": counts["updated"],
        "records_skipped": counts["skipped"],
        "error_message": error_message,
    }


def run_ingestion(
    source_name: str,
    db: Session,
    triggered_by: str | None = None,
    *,
    days: int = 7,
    limit: int | None = None,
    full: bool = False,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Run ingestion for ``source_name``.

    Accepts canonical names (``nvd``, ``cisa-kev``, ``epss``,
    ``mitre-attack``, ``mitre-cwe``) and aliases (``kev``, ``mitre``
    = both MITRE catalogs). Returns a job-summary dict; for
    ``mitre`` the counts are combined and ``jobs`` lists both.
    """
    canonical = SOURCE_ALIASES.get(source_name)
    if canonical is None:
        raise ValueError(f"unknown ingestion source: {source_name!r}")
    if canonical == "mitre":
        first = _run_single(
            "mitre-attack", db, triggered_by, days=days, limit=limit,
            full=full, client=client, sleep=sleep,
        )
        second = _run_single(
            "mitre-cwe", db, triggered_by, days=days, limit=limit,
            full=full, client=client, sleep=sleep,
        )
        jobs = [first, second]
        status = (
            "failed"
            if all(j["status"] == "failed" for j in jobs)
            else "partial"
            if any(j["status"] in ("failed", "partial") for j in jobs)
            else "success"
        )
        return {
            "source": "mitre",
            "job_id": None,
            "status": status,
            "records_fetched": sum(j["records_fetched"] for j in jobs),
            "records_created": sum(j["records_created"] for j in jobs),
            "records_updated": sum(j["records_updated"] for j in jobs),
            "records_skipped": sum(j["records_skipped"] for j in jobs),
            "error_message": "; ".join(
                filter(None, (j["error_message"] for j in jobs))
            )
            or None,
            "jobs": jobs,
        }
    return _run_single(
        canonical, db, triggered_by, days=days, limit=limit,
        full=full, client=client, sleep=sleep,
    )


def ingest_seed(db: Session, triggered_by: str | None = None) -> dict:
    """Store the labelled SEED dataset (see ``seed_data.py``).

    Only used when live ingestion is impossible. Every record has
    ``source="seed"`` and is never described as live intelligence.
    """
    from app.ingestion.seed_data import SEED_RECORDS

    source = _get_data_source(db, "nvd")
    job = IngestionJob(
        source_id=source.id,
        status="running",
        triggered_by=triggered_by,
        details={"seed": True},
    )
    db.add(job)
    db.commit()
    counts = _new_counts()
    details: dict = {"seed": True}
    counts["fetched"] = len(SEED_RECORDS)
    for record in SEED_RECORDS:
        _store_nvd_record(db, record, counts, details)
    job.status = "success"
    job.finished_at = utcnow()
    job.records_fetched = counts["fetched"]
    job.records_created = counts["created"]
    job.records_updated = counts["updated"]
    job.records_skipped = counts["skipped"]
    job.details = details
    write_audit_log(
        db,
        "ingestion.run",
        entity_type="ingestion_job",
        entity_id=job.id,
        details={"source": "seed", "status": "success", **counts},
    )
    db.commit()
    return {
        "source": "seed",
        "job_id": job.id,
        "status": "success",
        **counts,
        "error_message": None,
    }


# -------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CyberMap AI ingestion runner (Phase 4)."
    )
    parser.add_argument(
        "--source",
        default="all",
        choices=["all", "nvd", "kev", "epss", "mitre", "mitre-attack", "mitre-cwe"],
        help="which source to sync (default: all)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="NVD window in days (incremental) or full-fetch window (default: 7)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="cap records stored per source",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="NVD: fetch by published date instead of last-modified",
    )
    args = parser.parse_args(argv)

    from app.core.database import SessionLocal
    from app.models import Base  # noqa: F401  (registers all models)
    from app.services.seed import seed_roles_and_sources

    db = SessionLocal()
    try:
        Base.metadata.create_all(bind=db.get_bind())
        seed_roles_and_sources(db)
        sources = ALL_SOURCES if args.source == "all" else [args.source]
        summaries = []
        for name in sources:
            summary = run_ingestion(
                name,
                db,
                triggered_by="cli",
                days=args.days,
                limit=args.limit,
                full=args.full,
            )
            summaries.append(summary)
            print(json.dumps(summary, default=str))
        failed = [s for s in summaries if s["status"] == "failed"]
        return 1 if failed else 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
