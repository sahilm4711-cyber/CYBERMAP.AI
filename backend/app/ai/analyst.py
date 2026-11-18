"""AI vulnerability analyst — Phase 6.

``analyze_vulnerability`` returns the exact 10-section structure
(see ``app/schemas/ai.py``) either from a configured LLM provider
(grounded prompt + JSON parsing) or from the rule-based fallback.

Fallback rules (data honesty, ARCHITECTURE.md §9):
- Every number (CVSS, EPSS) comes from the database record and is
  cited; nothing is invented.
- Any section lacking data says "Not available in the indexed record".
- Confidence is "low" with the limitation "rule-based summary — no
  AI provider configured".
- Retrieved chunk text is never executed and never treated as
  instructions; the fallback only assembles sentences from DB fields.
"""

import json
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.ai.adapters import AIProviderError, get_adapter
from app.ai.embeddings import retrieve
from app.ai.rag import build_grounded_messages
from app.models import (
    AffectedProduct,
    CweEntry,
    EpssScore,
    KevEntry,
    SavedAnalysis,
    User,
    Vulnerability,
    VulnerabilityRelationship,
)
from app.models.base import as_utc_aware
from app.schemas.ai import ANALYSIS_TYPES

NOT_AVAILABLE = "Not available in the indexed record"
FALLBACK_LIMITATION = "rule-based summary — no AI provider configured"
MAX_ANALYSES_PER_HOUR = 10

SECTION_KEYS = (
    "executive_summary",
    "technical_explanation",
    "root_cause",
    "potential_impact",
    "affected_components",
    "risk_assessment",
    "defensive_verification",
    "remediation",
    "references",
    "confidence_and_limitations",
)

_TYPE_FOCUS = {
    "simple": "Give a clear, beginner-friendly overview.",
    "advanced": "Give a deep technical analysis for an experienced researcher.",
    "impact": "Focus on the potential impact and blast radius.",
    "affected_systems": "Focus on which systems, products and versions are affected.",
    "root_cause": "Focus on the underlying root cause and weakness.",
    "attack_scenarios": "Focus on realistic attack scenarios an attacker could use.",
    "verification": "Focus on how a defender can verify whether they are affected and whether exploitation occurred.",
    "remediation": "Focus on concrete remediation and patching steps.",
    "prevention": "Focus on preventing this class of vulnerability in future development.",
    "assessment": "Give a full assessment covering all ten sections evenly.",
}


class VulnerabilityNotFoundError(Exception):
    """No vulnerability with the requested CVE ID exists."""


class RateLimitExceededError(Exception):
    """User exceeded MAX_ANALYSES_PER_HOUR analyses in the last hour."""


class InvalidAnalysisTypeError(ValueError):
    """analysis_type is not one of ANALYSIS_TYPES."""


# ------------------------------------------------------------------
# Record gathering (DB facts only)
# ------------------------------------------------------------------

def _record_facts(db: Session, vuln: Vulnerability) -> dict:
    """Collect every DB fact the analysis may cite for ``vuln``."""
    kev = (
        db.query(KevEntry)
        .filter(KevEntry.cve_id == vuln.cve_id)
        .first()
    )
    epss = (
        db.query(EpssScore)
        .filter(EpssScore.cve_id == vuln.cve_id)
        .order_by(EpssScore.model_date.desc())
        .first()
    )
    cwes: list[CweEntry] = []
    rels = (
        db.query(VulnerabilityRelationship)
        .filter(
            VulnerabilityRelationship.from_type == "vulnerability",
            VulnerabilityRelationship.from_id == vuln.id,
            VulnerabilityRelationship.relationship == "HAS_WEAKNESS",
            VulnerabilityRelationship.to_type == "cwe",
        )
        .all()
    )
    for rel in rels:
        cwe = (
            db.query(CweEntry)
            .filter(CweEntry.id == rel.to_id)
            .first()
        )
        if cwe is not None:
            cwes.append(cwe)
    products = (
        db.query(AffectedProduct)
        .filter(AffectedProduct.vulnerability_id == vuln.id)
        .all()
    )
    references = [
        {"label": ref.source or "reference", "url": ref.url}
        for ref in vuln.references
    ]
    if vuln.source_url:
        references.insert(
            0, {"label": vuln.source or "source", "url": vuln.source_url}
        )
    return {
        "vuln": vuln,
        "kev": kev,
        "epss": epss,
        "cwes": cwes,
        "products": products,
        "references": references,
    }


def _citations_for(facts: dict, rag_results: list[dict]) -> list[dict]:
    citations: list[dict] = []
    vuln = facts["vuln"]
    citations.append(
        {
            "cve_id": vuln.cve_id,
            "source": vuln.source,
            "url": vuln.source_url,
        }
    )
    for ref in facts["references"]:
        citations.append(
            {"cve_id": vuln.cve_id, "source": ref["label"], "url": ref["url"]}
        )
    for cwe in facts["cwes"]:
        citations.append(
            {"cwe_id": cwe.cwe_id, "source": cwe.source, "url": cwe.source_url}
        )
    for item in rag_results:
        key = {
            "vulnerability": "cve_id",
            "cwe": "cwe_id",
            "attack_technique": "technique_id",
        }.get(item["entity_type"])
        if key:
            citations.append(
                {
                    key: _entity_external_id(
                        item["entity_type"], item["chunk_text"]
                    ),
                    "source": item["entity_type"],
                    "url": item.get("source_url"),
                }
            )
    # De-duplicate by (label, url).
    seen: set[tuple] = set()
    unique: list[dict] = []
    for cit in citations:
        marker = (
            cit.get("cve_id") or cit.get("cwe_id") or cit.get("technique_id"),
            cit.get("url"),
        )
        if marker not in seen:
            seen.add(marker)
            unique.append(cit)
    return unique


def _entity_external_id(entity_type: str, chunk_text: str) -> str | None:
    match = re.match(r"\s*(CVE-\d{4}-\d{4,7}|CWE-\d+|T\d+(?:\.\d+)?)", chunk_text or "")
    return match.group(1) if match else None


# ------------------------------------------------------------------
# Rule-based fallback (works with no provider)
# ------------------------------------------------------------------

def build_rule_based_analysis(
    db: Session, vuln: Vulnerability, analysis_type: str
) -> dict:
    """Assemble the 10-section analysis purely from DB facts.

    Never invents CVE facts, CVSS or EPSS scores. Sections without
    data say so explicitly.
    """
    facts = _record_facts(db, vuln)
    kev = facts["kev"]
    epss = facts["epss"]
    cwes = facts["cwes"]
    products = facts["products"]

    severity = vuln.severity or "unknown"
    cvss = (
        f"{float(vuln.cvss_score):.1f}"
        if vuln.cvss_score is not None
        else None
    )
    cvss_version = vuln.cvss_version or ""
    cwe_text = (
        ", ".join(f"{c.cwe_id} ({c.name})" for c in cwes)
        if cwes
        else None
    )
    kev_text = "Yes — listed in CISA KEV" if kev else "No"
    epss_text = (
        f"{float(epss.epss_score):.5f} (percentile "
        f"{float(epss.percentile):.5f}, model date {epss.model_date})"
        if epss
        else None
    )

    executive = (
        f"{vuln.cve_id} is a vulnerability with severity {severity}"
        + (f" and a CVSS base score of {cvss}" if cvss else " (no CVSS score recorded)")
        + f". {vuln.description or NOT_AVAILABLE} "
        f"Known exploited (CISA KEV): {kev_text}."
    )
    technical = vuln.description or NOT_AVAILABLE
    if cvss:
        technical += (
            f" CVSS base score {cvss}"
            + (f" (version {cvss_version})" if cvss_version else "")
            + (f", vector {vuln.cvss_vector}" if vuln.cvss_vector else "")
            + "."
        )
    root_cause = (
        f"Associated weakness: {cwe_text}."
        if cwe_text
        else NOT_AVAILABLE
    )
    if cwes and cwes[0].description:
        root_cause += f" {cwes[0].description}"
    impact_parts = []
    if kev:
        impact_parts.append(
            "This vulnerability is known to be exploited in the wild "
            "(CISA KEV listing)"
            + (
                f"; CISA requires remediation by {kev.due_date}"
                if kev.due_date
                else ""
            )
            + "."
        )
    if epss_text:
        impact_parts.append(
            f"EPSS exploitation probability estimate: {epss_text}."
        )
    if severity in ("CRITICAL", "HIGH"):
        impact_parts.append(
            f"Severity is {severity}, so successful exploitation is "
            "likely to have a significant effect on affected systems."
        )
    potential_impact = (
        " ".join(impact_parts) if impact_parts else NOT_AVAILABLE
    )
    if products:
        affected = "; ".join(
            f"{p.vendor or 'unknown vendor'} {p.product or 'unknown product'}"
            + (f" ({p.version_range_text})" if p.version_range_text else "")
            for p in products
        )
    else:
        affected = NOT_AVAILABLE
    if cvss:
        risk = (
            f"CVSS base score {cvss} with severity {severity}. "
            f"Known exploited (KEV): {kev_text}. "
            + (
                f"EPSS score {epss_text}."
                if epss_text
                else "No EPSS score is recorded for this CVE."
            )
        )
    else:
        risk = (
            "No CVSS score is recorded for this vulnerability, so a "
            "score-based risk rating cannot be given. "
            f"Known exploited (KEV): {kev_text}. "
            + (
                f"EPSS score {epss_text}."
                if epss_text
                else "No EPSS score is recorded for this CVE."
            )
        )
    verification = (
        "Check whether any affected product listed above is installed "
        "in your environment and compare its version against the "
        "affected range; review the vendor references for detection "
        "guidance."
        if products
        else NOT_AVAILABLE
    )
    remediation = (
        "Apply the vendor patch or upgrade to a fixed version; if no "
        "patch is available yet, apply the vendor's recommended "
        "workaround or mitigation and monitor the references below. "
        + (
            f"CISA KEV required action: {kev.required_action}"
            if kev and kev.required_action
            else ""
        )
    ).strip()
    return {
        "executive_summary": executive,
        "technical_explanation": technical,
        "root_cause": root_cause,
        "potential_impact": potential_impact,
        "affected_components": affected,
        "risk_assessment": risk,
        "defensive_verification": verification,
        "remediation": remediation,
        "references": facts["references"],
        "confidence_and_limitations": {
            "confidence": "low",
            "limitations": [
                FALLBACK_LIMITATION,
                "Built only from the indexed database record; no "
                "external sources were consulted beyond the stored "
                "references.",
            ],
        },
    }


# ------------------------------------------------------------------
# Provider path
# ------------------------------------------------------------------

def _parse_provider_analysis(raw: str) -> dict | None:
    """Parse the provider's JSON reply into the 10-section dict.

    Returns None when the reply is not valid JSON with all ten
    sections (caller then falls back to the rule-based analysis).
    """
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        data = json.loads(raw[start:end])
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if not all(key in data for key in SECTION_KEYS):
        return None
    sections: dict = {}
    for key in SECTION_KEYS:
        if key == "references":
            refs = data.get("references") or []
            clean_refs = []
            for ref in refs if isinstance(refs, list) else []:
                if isinstance(ref, dict) and ref.get("url"):
                    clean_refs.append(
                        {
                            "label": str(ref.get("label", "reference")),
                            "url": str(ref["url"]),
                        }
                    )
            sections["references"] = clean_refs
        elif key == "confidence_and_limitations":
            cal = data.get("confidence_and_limitations")
            if isinstance(cal, dict):
                sections[key] = {
                    "confidence": str(cal.get("confidence", "low")),
                    "limitations": [
                        str(x) for x in cal.get("limitations", [])
                        if isinstance(x, str)
                    ],
                }
            else:
                sections[key] = {
                    "confidence": "low",
                    "limitations": [str(cal)] if cal else [],
                }
        else:
            value = data.get(key)
            sections[key] = str(value) if value is not None else NOT_AVAILABLE
    return sections


def _provider_analysis(
    db: Session,
    vuln: Vulnerability,
    analysis_type: str,
    facts: dict,
    rag_results: list[dict],
) -> tuple[dict, str, str | None]:
    """Run the provider; returns (sections, ai_mode, model).

    Raises AIProviderError / ValueError on failure so the caller can
    fall back.
    """
    adapter = get_adapter()
    if adapter is None:
        raise AIProviderError("No AI provider configured")
    focus = _TYPE_FOCUS.get(analysis_type, "")
    record_text = (
        f"CVE: {vuln.cve_id}\n"
        f"Description: {vuln.description or NOT_AVAILABLE}\n"
        f"Severity: {vuln.severity or NOT_AVAILABLE}\n"
        f"CVSS: "
        + (
            f"{float(vuln.cvss_score):.1f}"
            if vuln.cvss_score is not None
            else NOT_AVAILABLE
        )
        + "\n"
        f"CWE: "
        + (
            ", ".join(f"{c.cwe_id} ({c.name})" for c in facts["cwes"])
            if facts["cwes"]
            else NOT_AVAILABLE
        )
        + "\n"
        f"KEV listed: {'yes' if facts['kev'] else 'no'}\n"
        f"EPSS: "
        + (
            f"{float(facts['epss'].epss_score):.5f}"
            if facts["epss"]
            else NOT_AVAILABLE
        )
        + "\n"
        f"References: "
        + (
            ", ".join(r["url"] for r in facts["references"])
            if facts["references"]
            else NOT_AVAILABLE
        )
    )
    task = (
        "Analyse the vulnerability described by the database record "
        f"below. {focus} Return ONLY a JSON object with exactly these "
        "ten keys: executive_summary, technical_explanation, "
        "root_cause, potential_impact, affected_components, "
        "risk_assessment, defensive_verification, remediation, "
        "references (list of {label, url} using only the URLs in the "
        "record), confidence_and_limitations "
        "({confidence, limitations}). Use only facts from the record "
        "and retrieved context; never invent CVSS, EPSS or other "
        "scores.\n\n"
        f"DATABASE RECORD:\n{record_text}"
    )
    messages = build_grounded_messages(
        task,
        rag_results,
        task="Analyse the vulnerability from the database record.",
        system_prompt=(
            "You are a security research assistant. Answer only from "
            "the provided database facts and retrieved context."
        ),
    )
    raw = adapter.chat(messages)
    sections = _parse_provider_analysis(raw)
    if sections is None:
        raise AIProviderError("Provider reply could not be parsed")
    # Provider references must come from the DB record; keep the
    # record's references as the authoritative citation list.
    sections["references"] = facts["references"]
    return sections, "provider", adapter.model


# ------------------------------------------------------------------
# Rate limiting + public entry point
# ------------------------------------------------------------------

def _check_rate_limit(db: Session, user: User) -> None:
    # SQLite stores naive datetimes; compare in Python with aware
    # conversion so the check works on both dialects.
    from datetime import timedelta

    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    rows = (
        db.query(SavedAnalysis)
        .filter(SavedAnalysis.user_id == user.id)
        .all()
    )
    count = sum(
        1
        for row in rows
        if as_utc_aware(row.created_at) is not None
        and as_utc_aware(row.created_at) >= one_hour_ago
    )
    if count >= MAX_ANALYSES_PER_HOUR:
        raise RateLimitExceededError(
            f"Rate limit: max {MAX_ANALYSES_PER_HOUR} analyses per "
            "user per hour"
        )


def analyze_vulnerability(
    db: Session,
    cve_id: str,
    analysis_type: str,
    user: User | None = None,
) -> dict:
    """Analyse ``cve_id``; returns the envelope dict.

    ``{cve_id, analysis_type, ai_mode, model, fallback_reason,
    analysis: {10 sections}, citations: [...]}``. Saves a
    ``saved_analyses`` row when ``user`` is provided.
    """
    if analysis_type not in ANALYSIS_TYPES:
        raise InvalidAnalysisTypeError(
            f"Unknown analysis_type: {analysis_type!r}"
        )
    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.cve_id == cve_id)
        .first()
    )
    if vuln is None:
        raise VulnerabilityNotFoundError(f"Unknown CVE: {cve_id}")
    if user is not None:
        _check_rate_limit(db, user)

    facts = _record_facts(db, vuln)
    rag_results = retrieve(db, vuln.cve_id, top_k=5)
    citations = _citations_for(facts, rag_results)

    sections: dict | None = None
    ai_mode = "fallback"
    model: str | None = None
    fallback_reason: str | None = None
    adapter = None
    try:
        adapter = get_adapter()
    except ValueError as exc:
        fallback_reason = str(exc)
    if adapter is not None:
        try:
            sections, ai_mode, model = _provider_analysis(
                db, vuln, analysis_type, facts, rag_results
            )
        except (AIProviderError, ValueError) as exc:
            fallback_reason = str(exc)
            sections = None
    else:
        fallback_reason = "no AI provider configured"
    if sections is None:
        sections = build_rule_based_analysis(db, vuln, analysis_type)
        ai_mode = "fallback"
        model = None

    result = {
        "cve_id": vuln.cve_id,
        "analysis_type": analysis_type,
        "ai_mode": ai_mode,
        "model": model,
        "fallback_reason": fallback_reason,
        "analysis": sections,
        "citations": citations,
    }
    if user is not None:
        db.add(
            SavedAnalysis(
                user_id=user.id,
                vulnerability_id=vuln.id,
                analysis_type=analysis_type,
                content=sections,
                ai_mode=ai_mode,
                model=model,
            )
        )
        db.commit()
    return result
