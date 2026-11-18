"""MITRE ATT&CK + MITRE CWE clients (Phase 4).

- ATT&CK enterprise STIX bundle (~30 MB):
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
  Parsed with plain ``json``; only ``attack-pattern`` objects are kept.
- CWE catalog (zipped XML):
  https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  The zip is downloaded, the XML extracted and parsed with
  ``xml.etree.ElementTree``; only ``Weakness`` entries are kept.

Downloaded files are cached under ``backend/data/cache/`` (gitignored)
so re-runs do not re-download; pass ``force=True`` to refresh.
"""

from __future__ import annotations

import io
import json
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable

import httpx

from app.integrations.common import make_client

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "cache"
ATTACK_CACHE_FILE = CACHE_DIR / "enterprise-attack.json"
CWE_CACHE_FILE = CACHE_DIR / "cwec_latest.xml.zip"


def _download(
    url: str,
    cache_path: Path,
    client: httpx.Client | None,
    sleep: Callable[[float], None],
    force: bool,
) -> Path:
    """Download ``url`` to ``cache_path`` (or reuse the cached copy).

    Streams to disk in 1 MB chunks: the ATT&CK bundle is ~50 MB and
    buffering the whole body stalls through the egress proxy.
    Retries 429 / 5xx / timeouts with exponential backoff (1s / 2s /
    4s), honouring ``Retry-After``; a failed attempt removes its
    partial file before retrying.
    """
    from app.integrations.common import (
        BACKOFF_SECONDS,
        RETRYABLE_STATUS,
        IngestionHTTPError,
    )

    if cache_path.exists() and not force:
        return cache_path
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    own_client = client is None
    http = client or make_client(
        {"User-Agent": "CyberMap-AI/0.1.0 (ingestion)"}
    )
    try:
        for attempt in range(3):
            try:
                with http.stream("GET", url, timeout=300.0) as response:
                    if response.status_code == 200:
                        with cache_path.open("wb") as handle:
                            for chunk in response.iter_bytes(1024 * 1024):
                                handle.write(chunk)
                        return cache_path
                    if response.status_code in RETRYABLE_STATUS:
                        retry_after = response.headers.get("Retry-After")
                        delay = BACKOFF_SECONDS[attempt]
                        if retry_after:
                            try:
                                delay = max(delay, float(retry_after))
                            except ValueError:
                                pass
                        if attempt < 2:
                            sleep(delay)
                            continue
                        raise IngestionHTTPError(
                            f"GET {url} returned HTTP {response.status_code}"
                        )
                    raise IngestionHTTPError(
                        f"GET {url} returned HTTP {response.status_code}"
                    )
            except httpx.TimeoutException as exc:
                if cache_path.exists():
                    cache_path.unlink()
                if attempt < 2:
                    sleep(BACKOFF_SECONDS[attempt])
                    continue
                raise IngestionHTTPError(
                    f"GET {url} timed out after 3 attempts"
                ) from exc
    finally:
        if own_client:
            http.close()
    raise IngestionHTTPError(f"GET {url} failed after 3 attempts")


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


# ---------------------------------------------------------------- ATT&CK

def fetch_attack_bundle(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    force: bool = False,
) -> dict:
    """Download (or reuse the cached) ATT&CK bundle; return parsed JSON."""
    path = _download(ATTACK_URL, ATTACK_CACHE_FILE, client, sleep, force)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_attack_techniques(bundle: dict) -> list[dict]:
    """Extract normalized technique dicts from a STIX bundle.

    Keeps ``attack-pattern`` objects (skipping revoked/deprecated
    ones). ``technique_id`` is the ``T####(.###)`` external id,
    ``tactic`` the first kill-chain phase name (capitalized),
    ``source_url`` the mitre-attack external reference URL.
    """
    techniques: list[dict] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id: str | None = None
        source_url: str | None = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                source_url = ref.get("url")
                break
        if not external_id:
            continue
        tactic: str | None = None
        phases = obj.get("kill_chain_phases") or []
        if phases:
            phase_name = phases[0].get("phase_name")
            if phase_name:
                tactic = phase_name.replace("-", " ").title()
        techniques.append(
            {
                "technique_id": external_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "tactic": tactic,
                "platforms": obj.get("x_mitre_platforms") or None,
                "detection": obj.get("x_mitre_detection"),
                "mitigations": None,
                "source": "mitre-attack",
                "source_url": source_url,
            }
        )
    return techniques


def fetch_attack_techniques(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    force: bool = False,
) -> list[dict]:
    """Download the ATT&CK bundle and return parsed techniques."""
    return parse_attack_techniques(fetch_attack_bundle(client, sleep, force))


# --------------------------------------------------------------------- CWE

def fetch_cwe_zip(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    force: bool = False,
) -> Path:
    """Download (or reuse the cached) CWE XML zip; return its path."""
    return _download(CWE_ZIP_URL, CWE_CACHE_FILE, client, sleep, force)


def parse_cwe_xml(xml_bytes: bytes) -> list[dict]:
    """Parse CWE XML bytes into normalized weakness dicts.

    Namespace-agnostic: element tags are matched on their local name,
    so any ``cwec`` schema version parses. Only ``Weakness`` entries
    are kept (categories/views are skipped).
    """
    root = ET.fromstring(xml_bytes)
    entries: list[dict] = []
    for weakness in root.iter():
        if _local_name(weakness.tag) != "Weakness":
            continue
        cwe_id = weakness.get("ID")
        name = weakness.get("Name")
        if not cwe_id or not name:
            continue
        description: str | None = None
        extended: str | None = None
        for child in weakness:
            local = _local_name(child.tag)
            if local == "Description":
                description = "".join(child.itertext()).strip() or None
            elif local == "Extended_Description":
                extended = "".join(child.itertext()).strip() or None
        entries.append(
            {
                "cwe_id": f"CWE-{cwe_id}",
                "name": name,
                "description": description,
                "extended_description": extended,
                "category": None,
                "source": "mitre-cwe",
                "source_url": "https://cwe.mitre.org/data/definitions/"
                f"{cwe_id}.html",
            }
        )
    return entries


def fetch_cwe_entries(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    force: bool = False,
) -> list[dict]:
    """Download the CWE zip, extract its XML and return parsed entries."""
    zip_path = fetch_cwe_zip(client, sleep, force)
    with zipfile.ZipFile(zip_path) as archive:
        xml_names = [
            name for name in archive.namelist() if name.endswith(".xml")
        ]
        if not xml_names:
            raise ValueError("CWE zip contains no XML file")
        xml_bytes = archive.read(xml_names[0])
    return parse_cwe_xml(xml_bytes)
