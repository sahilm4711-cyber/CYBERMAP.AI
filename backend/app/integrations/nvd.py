"""NVD CVE API 2.0 client (Phase 4).

https://services.nvd.nist.gov/rest/json/cves/2.0

- Incremental fetch by ``lastModStartDate`` / ``lastModEndDate``.
- Full fetch by ``pubStartDate`` / ``pubEndDate``.
- Paginated with ``resultsPerPage`` / ``startIndex`` (max 2000/page).
- Optional ``NVD_API_KEY`` from the environment (never hardcoded).
- Rate limit: without a key NVD allows 5 requests / 30 s, so a
  minimum 6 s gap is enforced between requests; with a key 0.6 s.
- Retries with exponential backoff via ``common.get_with_retry``.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx

from app.integrations.common import RateLimiter, get_with_retry, make_client

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000

# NVD allows 5 requests / 30 s without a key (30/5 = 6 s gap) and
# 50 requests / 30 s with a key (0.6 s gap).
GAP_NO_KEY_SECONDS = 6.0
GAP_WITH_KEY_SECONDS = 0.6


def _nvd_date(value: datetime) -> str:
    """Format a datetime the way the NVD API expects it."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class NvdClient:
    """Sync NVD client. Pass an ``httpx.Client`` in tests (MockTransport)."""

    def __init__(
        self,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or None
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep
        gap = GAP_WITH_KEY_SECONDS if self.api_key else GAP_NO_KEY_SECONDS
        self._limiter = RateLimiter(gap)

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = make_client(
                {"User-Agent": "CyberMap-AI/0.1.0 (ingestion)"}
            )
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def _get(self, params: dict) -> dict:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        self._limiter.wait(self._sleep)
        response = get_with_retry(
            self._get_client(),
            NVD_BASE_URL,
            params=params,
            headers=headers,
            sleep=self._sleep,
        )
        return response.json()

    def fetch_cves(
        self,
        *,
        start: datetime,
        end: datetime,
        mode: str = "lastmod",
        limit: int | None = None,
    ) -> list[dict]:
        """Fetch raw NVD ``vulnerabilities`` entries.

        ``mode="lastmod"`` queries by last-modified date (incremental);
        ``mode="pub"`` queries by published date (full). ``limit`` caps
        the total number of records returned.
        """
        if mode == "lastmod":
            date_params = {
                "lastModStartDate": _nvd_date(start),
                "lastModEndDate": _nvd_date(end),
            }
        elif mode == "pub":
            date_params = {
                "pubStartDate": _nvd_date(start),
                "pubEndDate": _nvd_date(end),
            }
        else:
            raise ValueError(f"unknown NVD fetch mode: {mode!r}")

        records: list[dict] = []
        start_index = 0
        total_results: int | None = None
        while True:
            params = {
                **date_params,
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            }
            payload = self._get(params)
            batch = payload.get("vulnerabilities", [])
            if total_results is None:
                total_results = int(payload.get("totalResults", 0))
            records.extend(batch)
            if limit is not None and len(records) >= limit:
                return records[:limit]
            start_index += len(batch)
            if not batch or start_index >= total_results:
                break
        return records

    def fetch_incremental(
        self, days: int = 7, limit: int | None = None
    ) -> list[dict]:
        """CVEs modified in the last ``days`` days."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        return self.fetch_cves(start=start, end=end, mode="lastmod", limit=limit)

    def fetch_full(
        self,
        start: datetime,
        end: datetime,
        limit: int | None = None,
    ) -> list[dict]:
        """CVEs published between ``start`` and ``end``."""
        return self.fetch_cves(start=start, end=end, mode="pub", limit=limit)


def fetch_nvd_incremental(
    days: int = 7,
    limit: int | None = None,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """Convenience wrapper used by ``app.ingestion.run``."""
    nvd = NvdClient(client=client, sleep=sleep)
    try:
        return nvd.fetch_incremental(days=days, limit=limit)
    finally:
        nvd.close()


def fetch_nvd_full(
    start: datetime,
    end: datetime,
    limit: int | None = None,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """Convenience wrapper used by ``app.ingestion.run``."""
    nvd = NvdClient(client=client, sleep=sleep)
    try:
        return nvd.fetch_full(start=start, end=end, limit=limit)
    finally:
        nvd.close()
