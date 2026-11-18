"""FIRST EPSS (Exploit Prediction Scoring System) client (Phase 4).

https://api.first.org/data/v1/epss

- ``GET /data/v1/epss?cve=CVE-2021-44228,CVE-...`` returns
  ``{"status": "OK", "model_date": "YYYY-MM-DD", "data": [{"cve",
  "epss", "percentile"}, ...]}``.
- CVE ids are sent comma-separated, chunked at 100 per request.
- The daily model date comes back in every response.
"""

from __future__ import annotations

import time
from datetime import date
from typing import Callable

import httpx

from app.integrations.common import get_with_retry, make_client

EPSS_URL = "https://api.first.org/data/v1/epss"
CHUNK_SIZE = 100


def _parse_model_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def fetch_epss_scores(
    cve_ids: list[str],
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[dict], date | None]:
    """Fetch EPSS scores for ``cve_ids`` (chunked at 100/request).

    Returns ``(records, model_date)`` where each record is the raw
    ``{"cve", "epss", "percentile"}`` dict from the API.
    """
    ids = [cve for cve in dict.fromkeys(cve_ids) if cve]
    if not ids:
        return [], None
    own_client = client is None
    http = client or make_client(
        {"User-Agent": "CyberMap-AI/0.1.0 (ingestion)"}
    )
    records: list[dict] = []
    model_date: date | None = None
    try:
        for start in range(0, len(ids), CHUNK_SIZE):
            chunk = ids[start : start + CHUNK_SIZE]
            response = get_with_retry(
                http,
                EPSS_URL,
                params={"cve": ",".join(chunk)},
                sleep=sleep,
            )
            payload = response.json()
            if payload.get("status") != "OK":
                raise ValueError(
                    f"EPSS API returned status {payload.get('status')!r}"
                )
            model_date = _parse_model_date(payload.get("model_date"))
            data = payload.get("data", [])
            if model_date is None and data:
                # The live API carries the date per record ("date"),
                # not as a top-level "model_date".
                model_date = _parse_model_date(data[0].get("date"))
            records.extend(data)
    finally:
        if own_client:
            http.close()
    return records, model_date


def fetch_epss_model_date(
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> date | None:
    """Return the current EPSS model date (probed with one known CVE)."""
    _, model_date = fetch_epss_scores(
        ["CVE-2021-44228"], client=client, sleep=sleep
    )
    return model_date
