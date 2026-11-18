"""Normalization: raw upstream records -> dicts matching Phase 3 models.

One function per source. Missing data stays ``None`` — values are
never invented. Every dict these functions return is validated by a
Pydantic schema in ``app.schemas.ingestion`` before storage (see
``app.ingestion.run``).
"""

from __future__ import annotations

import re
from datetime import date, datetime

_CWE_VALUE = re.compile(r"^(?:CWE-)?(\d+)$")


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _english_text(descriptions: list | None) -> str | None:
    """Prefer the English description; fall back to the first one."""
    if not descriptions:
        return None
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    first = descriptions[0].get("value")
    return first or None


# --------------------------------------------------------------------- NVD

_CVSS_ORDER = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _pick_cvss(metrics: dict | None) -> dict:
    """Best CVSS available: v3.1, then v3.0, then v2.0 (all NULL if none)."""
    result = {
        "cvss_score": None,
        "cvss_version": None,
        "cvss_vector": None,
        "severity": None,
    }
    if not metrics:
        return result
    for key, version in _CVSS_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        if data.get("baseScore") is None:
            continue
        result["cvss_score"] = float(data["baseScore"])
        result["cvss_version"] = data.get("version") or version
        result["cvss_vector"] = data.get("vectorString")
        result["severity"] = data.get("baseSeverity")
        return result
    return result


def _normalize_cwe_id(value: str | None) -> str | None:
    """``"CWE-79"`` / ``"79"`` -> ``"CWE-79"``; anything else -> None."""
    if not value:
        return None
    match = _CWE_VALUE.match(value.strip())
    if not match:
        return None
    return f"CWE-{match.group(1)}"


def _parse_cpe_match(match: dict) -> dict | None:
    """One ``cpeMatch`` entry -> an affected-product dict (or None)."""
    criteria = match.get("criteria") or ""
    parts = criteria.split(":")
    # cpe:2.3:<part>:<vendor>:<product>:<version>:...
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    vendor = parts[3] if parts[3] not in ("*", "-") else None
    product = parts[4] if parts[4] not in ("*", "-") else None
    version = parts[5] if parts[5] not in ("*", "-") else None
    version_start = (
        match.get("versionStartIncluding")
        or match.get("versionStartExcluding")
        or version
    )
    version_end = (
        match.get("versionEndIncluding")
        or match.get("versionEndExcluding")
        or version
    )
    range_bits: list[str] = []
    if match.get("versionStartIncluding"):
        range_bits.append(f">= {match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        range_bits.append(f"> {match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        range_bits.append(f"<= {match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        range_bits.append(f"< {match['versionEndExcluding']}")
    if not range_bits and version:
        range_bits.append(f"== {version}")
    return {
        "vendor": vendor,
        "product": product,
        "version_start": version_start,
        "version_end": version_end,
        "version_range_text": ", ".join(range_bits) or None,
    }


def _walk_nodes(nodes: list, products: list[dict]) -> None:
    for node in nodes or []:
        for match in node.get("cpeMatch") or []:
            if not match.get("vulnerable", True):
                continue
            parsed = _parse_cpe_match(match)
            if parsed is not None and parsed not in products:
                products.append(parsed)
        # NVD nests matches under both "children" and "nodes"
        # (the top-level "configurations" entries use "nodes").
        _walk_nodes(node.get("children") or [], products)
        _walk_nodes(node.get("nodes") or [], products)


def parse_nvd_record(raw: dict) -> dict:
    """Normalize one NVD ``vulnerabilities`` entry.

    Returns ``{"vulnerability": {...}, "references": [...],
    "products": [...], "cwe_ids": [...]}``.
    """
    cve = raw.get("cve") or {}
    cve_id = cve.get("id")
    description = _english_text(cve.get("descriptions"))
    cvss = _pick_cvss(cve.get("metrics"))
    last_modified = _parse_datetime(cve.get("lastModified"))
    published = _parse_datetime(cve.get("published"))

    vulnerability = {
        "cve_id": cve_id,
        "title": None,
        "description": description,
        "cvss_score": cvss["cvss_score"],
        "cvss_version": cvss["cvss_version"],
        "cvss_vector": cvss["cvss_vector"],
        "severity": cvss["severity"],
        "published_at": published,
        "last_modified_at": last_modified,
        "source": "nvd",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if cve_id
        else None,
        "source_updated_at": last_modified,
    }

    references = []
    seen_urls: set[str] = set()
    for ref in cve.get("references") or []:
        url = ref.get("url")
        # NVD can list the same URL twice under different sources;
        # (vulnerability_id, url) is unique, so keep the first.
        if url and url not in seen_urls:
            seen_urls.add(url)
            references.append(
                {
                    "url": url,
                    "source": ref.get("source"),
                    "tags": ref.get("tags") or None,
                }
            )

    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            normalized = _normalize_cwe_id(desc.get("value"))
            if normalized and normalized not in cwe_ids:
                cwe_ids.append(normalized)

    products: list[dict] = []
    _walk_nodes(cve.get("configurations") or [], products)

    return {
        "vulnerability": vulnerability,
        "references": references,
        "products": products,
        "cwe_ids": cwe_ids,
    }


# --------------------------------------------------------------------- KEV

def parse_kev_record(raw: dict) -> dict:
    """Normalize one CISA KEV ``vulnerabilities`` entry."""
    return {
        "cve_id": raw.get("cveID"),
        "vendor_project": raw.get("vendorProject"),
        "product": raw.get("product"),
        "vulnerability_name": raw.get("vulnerabilityName"),
        "date_added": _parse_date(raw.get("dateAdded")),
        "due_date": _parse_date(raw.get("dueDate")),
        "short_description": raw.get("shortDescription"),
        "required_action": raw.get("requiredAction"),
        "ransomware_use": raw.get("knownRansomwareCampaignUse"),
        "source": "cisa-kev",
    }


# -------------------------------------------------------------------- EPSS

def parse_epss_record(raw: dict, model_date: date | None) -> dict:
    """Normalize one FIRST EPSS ``data`` entry."""
    effective_date = model_date or _parse_date(raw.get("date"))
    return {
        "cve_id": raw.get("cve"),
        "epss_score": float(raw["epss"]) if raw.get("epss") is not None else None,
        "percentile": float(raw["percentile"])
        if raw.get("percentile") is not None
        else None,
        "model_date": effective_date,
    }


# ----------------------------------------------------------- MITRE (already
# normalized by app.integrations.mitre; thin wrappers keep the
# connector API uniform for app.ingestion.run)

def parse_attack_technique_record(raw: dict) -> dict:
    """Pass through a dict from ``mitre.parse_attack_techniques``."""
    return {
        "technique_id": raw.get("technique_id"),
        "name": raw.get("name"),
        "description": raw.get("description"),
        "tactic": raw.get("tactic"),
        "platforms": raw.get("platforms"),
        "detection": raw.get("detection"),
        "mitigations": raw.get("mitigations"),
        "source": "mitre-attack",
        "source_url": raw.get("source_url"),
    }


def parse_cwe_record(raw: dict) -> dict:
    """Pass through a dict from ``mitre.parse_cwe_xml``."""
    return {
        "cwe_id": raw.get("cwe_id"),
        "name": raw.get("name"),
        "description": raw.get("description"),
        "extended_description": raw.get("extended_description"),
        "category": raw.get("category"),
        "source": "mitre-cwe",
        "source_url": raw.get("source_url"),
    }
