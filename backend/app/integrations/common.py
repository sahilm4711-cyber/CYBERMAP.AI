"""Shared HTTP helpers for the ingestion connectors (Phase 4).

Every external call goes through :func:`get_with_retry`: up to 3
attempts with exponential backoff (1s / 2s / 4s) on 429 / 5xx /
timeouts, honouring ``Retry-After`` when the server sends one.
``RateLimiter`` enforces a minimum gap between requests (NVD allows
5 requests / 30 s without an API key, hence the 6 s default gap).
"""

from __future__ import annotations

import time
from typing import Callable

import httpx

RETRYABLE_STATUS = (429, 500, 502, 503, 504)
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (1.0, 2.0, 4.0)


class IngestionHTTPError(Exception):
    """An upstream source could not be fetched after all retries."""


def get_with_retry(
    client: httpx.Client,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float = 60.0,
    max_attempts: int = MAX_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """GET ``url`` with exponential-backoff retries.

    Returns the response on any 2xx. Raises :class:`IngestionHTTPError`
    on persistent 429/5xx, on a non-retryable 4xx, or after the final
    failed attempt. ``sleep`` is injectable so tests run instantly.
    """
    last_error: Exception | None = None
    for attempt in range(max_attempts):
        try:
            response = client.get(
                url, params=params, headers=headers, timeout=timeout
            )
        except httpx.TimeoutException as exc:
            last_error = exc
            if attempt < max_attempts - 1:
                sleep(BACKOFF_SECONDS[attempt])
                continue
            raise IngestionHTTPError(
                f"GET {url} timed out after {max_attempts} attempts"
            ) from exc
        except httpx.HTTPError as exc:
            raise IngestionHTTPError(f"GET {url} failed: {exc}") from exc

        if response.status_code == 200:
            return response
        if response.status_code in RETRYABLE_STATUS:
            last_error = IngestionHTTPError(
                f"GET {url} returned HTTP {response.status_code}"
            )
            if attempt < max_attempts - 1:
                retry_after = response.headers.get("Retry-After")
                delay = BACKOFF_SECONDS[attempt]
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
                sleep(delay)
                continue
            raise last_error
        raise IngestionHTTPError(
            f"GET {url} returned HTTP {response.status_code}"
        )
    raise IngestionHTTPError(f"GET {url} failed after {max_attempts} attempts")


def make_client(headers: dict | None = None) -> httpx.Client:
    """Build an httpx client for upstream ingestion calls.

    This VM's ``NO_PROXY`` contains bracketed IPv6 entries (``[::1]``)
    that httpx's environment-proxy parser rejects with
    ``Invalid port: ':1]'``. Reading the proxy URL from the
    environment directly and passing ``trust_env=False`` avoids that
    parser while still routing through the egress proxy when one is
    configured. No proxy env var -> direct client.
    """
    import os

    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    # The egress proxy MITMs TLS with a CA that lives in the system
    # bundle, not in certifi's — verify against the system bundle
    # when it exists (never disable verification).
    verify: str | bool = True
    for candidate in (
        os.environ.get("SSL_CERT_FILE"),
        "/etc/ssl/certs/ca-certificates.crt",
    ):
        if candidate and os.path.exists(candidate):
            verify = candidate
            break
    return httpx.Client(
        headers=headers or {},
        proxy=proxy or None,
        trust_env=False,
        follow_redirects=True,
        verify=verify,
    )


class RateLimiter:
    """Enforce a minimum gap between requests to one upstream."""

    def __init__(self, min_gap_seconds: float) -> None:
        self.min_gap_seconds = min_gap_seconds
        self._last_request_at: float | None = None

    def wait(self, sleep: Callable[[float], None] = time.sleep) -> None:
        now = time.monotonic()
        if self._last_request_at is not None:
            elapsed = now - self._last_request_at
            if elapsed < self.min_gap_seconds:
                sleep(self.min_gap_seconds - elapsed)
        self._last_request_at = time.monotonic()
