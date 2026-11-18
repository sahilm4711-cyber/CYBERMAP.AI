"""Ingestion orchestration tests (Phase 4).

Fetch functions in ``app.ingestion.run`` are monkeypatched with the
fixture records, so no live HTTP happens here.
"""

from datetime import date

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.ingestion import run as run_module
from app.integrations.common import IngestionHTTPError
from app.models import (
    AffectedProduct,
    AttackTechnique,
    CweEntry,
    EpssScore,
    IngestionJob,
    KevEntry,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityRelationship,
)
from tests.ingestion_fixtures import (
    ATTACK_BUNDLE,
    CWE_XML_SAMPLE,
    EPSS_RESPONSE,
    KEV_RECORD,
    NVD_FULL_RECORD,
    NVD_NO_CVSS_RECORD,
)


def _run(db_session, source, **kwargs):
    return run_module.run_ingestion(
        source, db_session, triggered_by="test", sleep=lambda _: None, **kwargs
    )


def test_nvd_ingest_creates_vuln_refs_products_and_cwe_link(
    db_session: Session, monkeypatch,
):
    # CWE entries must exist first for the HAS_WEAKNESS edge.
    monkeypatch.setattr(
        run_module, "fetch_cwe_records",
        lambda **kw: [
            {"cwe_id": "CWE-79", "name": "Cross-site Scripting",
             "description": "XSS.", "extended_description": None,
             "category": None, "source": "mitre-cwe",
             "source_url": "https://cwe.mitre.org/data/definitions/79.html"},
            {"cwe_id": "CWE-89", "name": "SQL Injection",
             "description": "SQLi.", "extended_description": None,
             "category": None, "source": "mitre-cwe",
             "source_url": "https://cwe.mitre.org/data/definitions/89.html"},
        ],
    )
    _run(db_session, "mitre-cwe")
    monkeypatch.setattr(
        run_module, "fetch_nvd_records",
        lambda **kw: [NVD_FULL_RECORD],
    )
    summary = _run(db_session, "nvd")
    assert summary["status"] == "success"
    assert summary["records_fetched"] == 1
    assert summary["records_created"] == 1

    vuln = db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-12345").first()
    assert vuln is not None
    assert float(vuln.cvss_score) == 9.8
    assert vuln.severity == "CRITICAL"
    refs = db_session.query(VulnerabilityReference).filter_by(vulnerability_id=vuln.id).all()
    assert len(refs) == 2
    products = db_session.query(AffectedProduct).filter_by(vulnerability_id=vuln.id).all()
    assert len(products) == 2
    assert {p.product for p in products} == {"examplelib", "otherlib"}
    edges = db_session.query(VulnerabilityRelationship).filter_by(
        from_id=vuln.id, relationship="HAS_WEAKNESS"
    ).all()
    assert len(edges) == 2
    assert all(e.confidence == "verified" and e.source == "nvd" for e in edges)

    job = db_session.query(IngestionJob).order_by(IngestionJob.started_at.desc()).first()
    assert job.status == "success"
    assert job.records_created == 1


def test_safe_upsert_second_run_creates_zero_and_older_does_not_overwrite(
    db_session: Session, monkeypatch,
):
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [NVD_FULL_RECORD]
    )
    first = _run(db_session, "nvd")
    assert first["records_created"] == 1

    second = _run(db_session, "nvd")
    assert second["records_created"] == 0
    assert second["records_updated"] == 0
    assert second["records_skipped"] == 1

    # Older lastModified must not overwrite the newer record.
    older = {
        "cve": {
            **NVD_FULL_RECORD["cve"],
            "lastModified": "2024-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "STALE description."}],
            "metrics": {},
        }
    }
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [older]
    )
    third = _run(db_session, "nvd")
    assert third["records_created"] == 0
    assert third["records_updated"] == 0
    vuln = db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-12345").first()
    assert vuln.description.startswith("A test vulnerability")
    assert float(vuln.cvss_score) == 9.8

    # Newer lastModified updates (and never blanks verified fields).
    newer = {
        "cve": {
            **NVD_FULL_RECORD["cve"],
            "lastModified": "2024-03-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Updated description."}],
            "metrics": {},
        }
    }
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [newer]
    )
    fourth = _run(db_session, "nvd")
    assert fourth["records_updated"] == 1
    vuln = db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-12345").first()
    assert vuln.description == "Updated description."
    assert float(vuln.cvss_score) == 9.8  # incomplete newer data kept old score


def test_malformed_record_is_skipped_not_stored(
    db_session: Session, monkeypatch,
):
    bad = {"cve": {"id": "NOT-A-CVE", "descriptions": [{"lang": "en", "value": "bad"}]}}
    monkeypatch.setattr(
        run_module, "fetch_nvd_records",
        lambda **kw: [bad, NVD_NO_CVSS_RECORD],
    )
    summary = _run(db_session, "nvd")
    assert summary["records_fetched"] == 2
    assert summary["records_created"] == 1
    assert summary["records_skipped"] == 1
    assert summary["status"] == "partial"
    assert db_session.query(Vulnerability).filter_by(cve_id="NOT-A-CVE").first() is None


def test_kev_ingest_links_existing_vulnerability(
    db_session: Session, monkeypatch,
):
    monkeypatch.setattr(
        run_module, "fetch_nvd_records", lambda **kw: [NVD_FULL_RECORD]
    )
    _run(db_session, "nvd")
    monkeypatch.setattr(
        run_module, "fetch_kev_records", lambda **kw: [KEV_RECORD]
    )
    summary = _run(db_session, "kev")
    assert summary["records_created"] == 1
    kev = db_session.query(KevEntry).filter_by(cve_id="CVE-2024-12345").first()
    assert kev is not None
    assert kev.vulnerability_id is not None
    assert kev.date_added == date(2024, 2, 10)
    assert kev.ransomware_use == "Known"


def test_epss_ingest_stores_scores_for_known_cves(
    db_session: Session, monkeypatch,
):
    monkeypatch.setattr(
        run_module, "fetch_nvd_records",
        lambda **kw: [NVD_FULL_RECORD, NVD_NO_CVSS_RECORD],
    )
    _run(db_session, "nvd")
    monkeypatch.setattr(
        run_module, "fetch_epss_records",
        lambda db, **kw: (EPSS_RESPONSE["data"], date(2024, 2, 15)),
    )
    summary = _run(db_session, "epss")
    assert summary["records_created"] == 2
    score = (
        db_session.query(EpssScore)
        .filter_by(cve_id="CVE-2024-12345", model_date=date(2024, 2, 15))
        .first()
    )
    assert score is not None
    assert float(score.epss_score) == pytest.approx(0.91234)
    assert score.vulnerability_id is not None


def test_mitre_attack_and_cwe_ingest(db_session: Session, monkeypatch):
    from app.integrations import mitre as mitre_client

    monkeypatch.setattr(
        run_module, "fetch_attack_records",
        lambda **kw: mitre_client.parse_attack_techniques(ATTACK_BUNDLE),
    )
    summary = _run(db_session, "mitre-attack")
    assert summary["records_created"] == 1
    tech = db_session.query(AttackTechnique).filter_by(technique_id="T1059.001").first()
    assert tech is not None
    assert tech.tactic == "Execution"

    monkeypatch.setattr(
        run_module, "fetch_cwe_records",
        lambda **kw: mitre_client.parse_cwe_xml(CWE_XML_SAMPLE.encode("utf-8")),
    )
    summary = _run(db_session, "mitre-cwe")
    assert summary["records_created"] == 2
    cwe = db_session.query(CweEntry).filter_by(cwe_id="CWE-79").first()
    assert cwe is not None
    assert cwe.name.startswith("Improper Neutralization of Input")


def test_persistent_upstream_failure_fails_job_with_error_message(
    db_session: Session, monkeypatch,
):
    def _boom(**kw):
        raise IngestionHTTPError("GET https://example.invalid returned HTTP 500")

    monkeypatch.setattr(run_module, "fetch_nvd_records", _boom)
    summary = _run(db_session, "nvd")
    assert summary["status"] == "failed"
    assert "500" in (summary["error_message"] or "")
    job = db_session.query(IngestionJob).order_by(IngestionJob.started_at.desc()).first()
    assert job.status == "failed"
    assert job.error_message is not None
    assert job.records_created == 0


def test_unknown_source_raises(db_session: Session):
    with pytest.raises(ValueError):
        run_module.run_ingestion("nope", db_session, triggered_by="test")
