"""CISA Known Exploited Vulnerabilities (KEV) catalog client (Phase 4).

Single JSON feed:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The payload is ``{"vulnerabilities": [...], ...}``; each entry has
``cveID``, ``vendorProject``, ``product``, ``vulnerabilityName``,
``dateAdded``, ``dueDate``, ``shortDescription``, ``requiredAction``
and ``knownRansomwareCampaignUse``.
"""

from __future__ import annotations

import time
from typing import Callable

import httpx

from app.integrations.common import get_with_retry, make_client

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch_kev(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """Download the full KEV catalog; return the ``vulnerabilities`` list."""
    own_client = client is None
    http = client or make_client(
        {"User-Agent": "CyberMap-AI/0.1.0 (ingestion)"}
    )
    try:
        response = get_with_retry(http, KEV_URL, sleep=sleep)
        payload = response.json()
    finally:
        if own_client:
            http.close()
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("KEV feed has no 'vulnerabilities' list")
    return vulnerabilities


def fetch_kev_catalog(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """Alias used by ``app.ingestion.run``."""
    return fetch_kev(client=client, sleep=sleep)
