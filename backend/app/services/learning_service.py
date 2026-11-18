"""Learning center content — Phase 8.

Topics are static JSON files under ``app/data/learning/`` (one
file per topic), written in the project's own words. Related real
records are resolved live from the database: each topic's
``related_cwe_ids`` are matched to CWE rows, then to
vulnerabilities linked by a ``HAS_WEAKNESS`` relationship, so the
educational text and the real records are always clearly separate.
"""

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import (
    CweEntry,
    Vulnerability,
    VulnerabilityRelationship,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "learning"

_cache: dict[str, dict] | None = None


def _load_all() -> dict[str, dict]:
    global _cache
    if _cache is None:
        _cache = {}
        if DATA_DIR.is_dir():
            for path in sorted(DATA_DIR.glob("*.json")):
                topic = json.loads(path.read_text(encoding="utf-8"))
                _cache[topic["slug"]] = topic
    return _cache


def list_topics() -> list[dict]:
    """Slugs + titles only (lightweight list endpoint)."""
    return [
        {"slug": t["slug"], "title": t["title"]}
        for t in _load_all().values()
    ]


def get_topic(slug: str) -> dict | None:
    return _load_all().get(slug)


def related_real_records(
    db: Session, cwe_ids: list[str], limit: int = 3
) -> list[dict]:
    """Up to ``limit`` real vulnerabilities linked to the topic's
    CWEs. Returns an empty list honestly when nothing matches
    (e.g. a fresh database with no relationships yet)."""
    if not cwe_ids:
        return []
    cwes = (
        db.query(CweEntry)
        .filter(CweEntry.cwe_id.in_(cwe_ids))
        .all()
    )
    if not cwes:
        return []
    rels = (
        db.query(VulnerabilityRelationship)
        .filter(
            VulnerabilityRelationship.from_type == "vulnerability",
            VulnerabilityRelationship.to_type == "cwe",
            VulnerabilityRelationship.to_id.in_([c.id for c in cwes]),
            VulnerabilityRelationship.relationship == "HAS_WEAKNESS",
        )
        .limit(limit)
        .all()
    )
    if not rels:
        return []
    vulns = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.id.in_([r.from_id for r in rels])
        )
        .all()
    )
    cwe_by_id = {c.id: c.cwe_id for c in cwes}
    rel_cwe = {r.from_id: cwe_by_id.get(r.to_id) for r in rels}
    return [
        {
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": (
                float(v.cvss_score) if v.cvss_score is not None else None
            ),
            "description": (v.description or "")[:300],
            "related_cwe_id": rel_cwe.get(v.id),
        }
        for v in vulns
    ][:limit]
