"""Threat-intelligence center queries — Phase 5.

KEV additions, EPSS ranking, the merged timeline, and the
CVSS-vs-EPSS-vs-KEV explainer. The explainer is static text: the
three metrics measure different things and are not interchangeable.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import (
    DataSource,
    EpssScore,
    IngestionJob,
    KevEntry,
    Vulnerability,
)
from app.models.base import as_utc_aware

METRICS_EXPLAINED = {
    "note": (
        "CVSS, EPSS and KEV measure three different things and are "
        "explicitly NOT interchangeable. A high "
        "CVSS score does not mean a vulnerability is being exploited, "
        "a high EPSS score does not mean it is severe, and absence "
        "from KEV does not mean it is safe. Use all three together."
    ),
    "metrics": [
        {
            "name": "CVSS",
            "what_it_measures": (
                "How severe a vulnerability is if it is exploited — "
                "the technical impact on confidentiality, integrity "
                "and availability, plus how easy it is to reach and "
                "exploit in theory."
            ),
            "scale": (
                "0.0–10.0, mapped to None (0.0), Low (0.1–3.9), "
                "Medium (4.0–6.9), High (7.0–8.9), Critical (9.0–10.0)."
            ),
            "what_high_means": (
                "Exploitation would cause serious damage. It says "
                "nothing about whether anyone is actually exploiting it."
            ),
            "what_it_does_not_mean": (
                "It does not predict exploitation, and it does not "
                "mean the vulnerability is being used in real attacks."
            ),
            "limitations": [
                "Scored once at disclosure; rarely updated as the threat changes.",
                "Does not consider whether exploit code exists or who is targeted.",
                "Two CVEs with the same score can pose very different real-world risk.",
            ],
        },
        {
            "name": "EPSS",
            "what_it_measures": (
                "The estimated probability that a vulnerability will "
                "be exploited in the wild in the next 30 days, based "
                "on observed exploitation data and vulnerability features."
            ),
            "scale": (
                "0.0–1.0 (a probability), with a percentile showing "
                "where the score ranks against all scored CVEs."
            ),
            "what_high_means": (
                "Exploitation in the next 30 days is comparatively "
                "likely. A score of 0.9 means roughly a 9-in-10 "
                "estimated chance — prioritise it even if its CVSS is "
                "only Medium."
            ),
            "what_it_does_not_mean": (
                "It is not a severity score and not proof of "
                "exploitation. A low EPSS does not make a Critical CVE "
                "harmless."
            ),
            "limitations": [
                "A statistical estimate, not a certainty; it changes daily.",
                "Only covers CVEs the EPSS model scores.",
                "Can miss targeted exploitation of a rarely-scored vulnerability.",
            ],
        },
        {
            "name": "KEV (CISA Known Exploited Vulnerabilities)",
            "what_it_measures": (
                "Whether a vulnerability is confirmed to have been "
                "exploited in the wild, as catalogued by CISA — with "
                "a remediation due date."
            ),
            "scale": (
                "A yes/no list, not a number. Each entry carries a "
                "date added, a due date, the affected vendor/product "
                "and the required action."
            ),
            "what_high_means": (
                "Being listed means exploitation is confirmed. Treat "
                "it as the highest-priority signal and meet the due date."
            ),
            "what_it_does_not_mean": (
                "Absence from KEV does not mean 'not exploited' — it "
                "means exploitation has not been confirmed and "
                "catalogued yet."
            ),
            "limitations": [
                "Only lists vulnerabilities CISA has confirmed and chosen to catalogue.",
                "There is a delay between first exploitation and listing.",
                "Most exploited vulnerabilities are never listed.",
            ],
        },
    ],
}


def list_kev(
    db: Session, page: int = 1, per_page: int = 20
) -> dict:
    """Newest KEV additions first (``date_added`` desc)."""
    query = db.query(KevEntry).order_by(
        KevEntry.date_added.desc().nulls_last()
    )
    total = query.count()
    pages = max(1, math.ceil(total / per_page)) if total else 1
    rows = query.offset((page - 1) * per_page).limit(per_page).all()
    indexed = {
        r[0] for r in db.query(Vulnerability.cve_id).all()
    }
    return {
        "items": [
            {
                "cve_id": k.cve_id,
                "vendor_project": k.vendor_project,
                "product": k.product,
                "vulnerability_name": k.vulnerability_name,
                "date_added": k.date_added,
                "due_date": k.due_date,
                "short_description": k.short_description,
                "required_action": k.required_action,
                "ransomware_use": k.ransomware_use,
                "is_indexed": k.cve_id in indexed,
            }
            for k in rows
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


def epss_ranking(
    db: Session, page: int = 1, per_page: int = 20
) -> dict:
    """Top CVEs by latest EPSS score, descending."""
    latest = (
        db.query(
            EpssScore.cve_id,
            func.max(EpssScore.model_date).label("max_date"),
        )
        .group_by(EpssScore.cve_id)
        .subquery()
    )
    query = (
        db.query(EpssScore, Vulnerability)
        .join(
            latest,
            (EpssScore.cve_id == latest.c.cve_id)
            & (EpssScore.model_date == latest.c.max_date),
        )
        .outerjoin(
            Vulnerability, Vulnerability.cve_id == EpssScore.cve_id
        )
        .order_by(EpssScore.epss_score.desc())
    )
    total = query.count()
    pages = max(1, math.ceil(total / per_page)) if total else 1
    rows = query.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "items": [
            {
                "cve_id": score.cve_id,
                "title": vuln.title if vuln is not None else None,
                "severity": vuln.severity if vuln is not None else None,
                "cvss_score": (
                    float(vuln.cvss_score)
                    if vuln is not None and vuln.cvss_score is not None
                    else None
                ),
                "epss_score": float(score.epss_score),
                "percentile": float(score.percentile),
                "model_date": score.model_date,
            }
            for score, vuln in rows
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


def get_timeline(db: Session, limit: int = 50) -> dict:
    """Newest events merged: CVEs published, KEV additions, jobs."""
    events: list[dict] = []

    for vuln in (
        db.query(Vulnerability)
        .filter(Vulnerability.published_at.is_not(None))
        .order_by(Vulnerability.published_at.desc())
        .limit(20)
        .all()
    ):
        events.append(
            {
                "type": "cve",
                "date": as_utc_aware(vuln.published_at),
                "label": (
                    f"{vuln.cve_id} published"
                    + (f" — {vuln.title}" if vuln.title else "")
                ),
                "cve_id": vuln.cve_id,
                "source": vuln.source,
                "status": vuln.severity,
            }
        )

    for kev in (
        db.query(KevEntry)
        .filter(KevEntry.date_added.is_not(None))
        .order_by(KevEntry.date_added.desc())
        .limit(20)
        .all()
    ):
        events.append(
            {
                "type": "kev",
                "date": datetime.combine(
                    kev.date_added, datetime.min.time()
                ).replace(tzinfo=timezone.utc),
                "label": (
                    f"{kev.cve_id} added to CISA KEV"
                    + (
                        f" — {kev.vulnerability_name}"
                        if kev.vulnerability_name
                        else ""
                    )
                ),
                "cve_id": kev.cve_id,
                "source": "cisa-kev",
                "status": kev.ransomware_use,
            }
        )

    source_names = {
        row.id: row.name for row in db.query(DataSource).all()
    }
    for job in (
        db.query(IngestionJob)
        .order_by(IngestionJob.started_at.desc())
        .limit(20)
        .all()
    ):
        events.append(
            {
                "type": "ingestion",
                "date": as_utc_aware(job.started_at),
                "label": (
                    f"Ingestion run: {source_names.get(job.source_id, 'unknown')} "
                    f"({job.status}, {job.records_created} created)"
                ),
                "cve_id": None,
                "source": source_names.get(job.source_id, "unknown"),
                "status": job.status,
            }
        )

    events.sort(
        key=lambda e: e["date"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return {"events": events[:limit]}


def get_metrics_explained() -> dict:
    """Static CVSS vs EPSS vs KEV explainer (no DB data)."""
    return METRICS_EXPLAINED
