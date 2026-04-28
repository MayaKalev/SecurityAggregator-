"""HTTP client for the NVD CVE API v2.0.

Owns rate limiting (sliding window) and retry (exponential backoff with
jitter, honors `Retry-After`). Public surface: `nvd_get(params) -> dict`.
"""

from __future__ import annotations

import logging
import os
import random
import time
from collections import deque
from typing import Any
from http import HTTPStatus

import requests

log = logging.getLogger("nvd_client")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTTP_TIMEOUT = 30

# NVD rate limits: 5 req / 30s without a key, 50 req / 30s with one.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_RATE_WINDOW_SEC = 30.0
NVD_RATE_LIMIT = 50 if NVD_API_KEY else 5
NVD_MAX_WINDOW_DAYS = 120
# Retry policy.
RETRY_ATTEMPTS = 5
RETRY_BASE_SEC = 1.0
RETRY_MAX_SEC = 30.0
RETRY_STATUS = {
    HTTPStatus.TOO_MANY_REQUESTS,     # 429
    HTTPStatus.INTERNAL_SERVER_ERROR, # 500
    HTTPStatus.BAD_GATEWAY,           # 502
    HTTPStatus.SERVICE_UNAVAILABLE,   # 503
    HTTPStatus.GATEWAY_TIMEOUT        # 504
}


class SlidingWindowRateLimiter:
    """Block until adding a request keeps us under `max_requests` per `window` s."""

    def __init__(self, max_requests: int, window: float) -> None:
        self.max_requests = max_requests
        self.window = window
        self._timestamps: deque[float] = deque()

    def acquire(self) -> None:
        now = time.monotonic()
        self._evict_expired(now)
        if len(self._timestamps) >= self.max_requests:
            sleep_for = self.window - (now - self._timestamps[0]) + 0.05
            log.info("nvd rate limit reached — sleeping %.2fs", sleep_for)
            time.sleep(sleep_for)
            self._evict_expired(time.monotonic())
        self._timestamps.append(time.monotonic())

    def _evict_expired(self, now: float) -> None:
        while self._timestamps and now - self._timestamps[0] >= self.window:
            self._timestamps.popleft()


rate_limiter = SlidingWindowRateLimiter(NVD_RATE_LIMIT, NVD_RATE_WINDOW_SEC)


def backoff_delay(attempt: int, retry_after_header: str | None) -> float:
    """Exponential backoff + jitter. Honors server's Retry-After when present."""
    if retry_after_header:
        try:
            return min(float(retry_after_header), RETRY_MAX_SEC)
        except ValueError:
            pass  # could be an HTTP-date — fall through to exponential
    base = min(RETRY_BASE_SEC * (2 ** (attempt - 1)), RETRY_MAX_SEC)
    return base + random.uniform(0, base * 0.25)


def nvd_get(params: dict[str, Any]) -> dict[str, Any]:
    """GET against NVD with rate limiting + retry. Returns parsed JSON.
    """
    headers = {"User-Agent": "security-intel-aggregator/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    last_exc: Exception | None = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        rate_limiter.acquire()
        try:
            resp = requests.get(NVD_URL, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            last_exc = exc
            if attempt == RETRY_ATTEMPTS:
                break
            delay = backoff_delay(attempt, None)
            log.warning(
                "nvd network error (%s) on attempt %d/%d — retrying in %.1fs",
                type(exc).__name__, attempt, RETRY_ATTEMPTS, delay,
            )
            time.sleep(delay)
            continue

        if resp.status_code < HTTPStatus.BAD_REQUEST:
            return resp.json()

        if resp.status_code in RETRY_STATUS and attempt < RETRY_ATTEMPTS:
            delay = backoff_delay(attempt, resp.headers.get("Retry-After"))
            log.warning(
                "nvd HTTP %d on attempt %d/%d — retrying in %.1fs",
                resp.status_code, attempt, RETRY_ATTEMPTS, delay,
            )
            time.sleep(delay)
            continue

        resp.raise_for_status()

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"nvd request failed after {RETRY_ATTEMPTS} attempts")
