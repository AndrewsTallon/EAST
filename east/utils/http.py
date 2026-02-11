"""HTTP utility functions for EAST tool.

Implements service-aware retry policies that respect API-specific overload
semantics (SSL Labs 529 → 30 min cooldown, 503 → 15 min, etc.) and per-host
rate limiting via token-bucket / semaphore controls.
"""

import json
import random
import time
import threading
import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3

# Browser-like headers to avoid being blocked by WAFs/APIs
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}

# HTTP status codes that should NOT be retried (client errors)
NO_RETRY_STATUSES = {400, 401, 403, 404, 405, 406, 410, 422}

# ---------------------------------------------------------------------------
# SSL Labs–specific status handling (per v4 API documentation)
# ---------------------------------------------------------------------------
# 529 = service overloaded → cool down ~30 minutes, retry once
# 503 = service unavailable → cool down ~15 minutes, retry once
# 429 = rate limited → exponential backoff starting at 30s, cap 600s
# Other 5xx = standard exponential backoff with jitter, max 5 attempts
SSLLABS_529_COOLDOWN = 1800   # 30 minutes in seconds
SSLLABS_503_COOLDOWN = 900    # 15 minutes in seconds
SSLLABS_429_INITIAL_BACKOFF = 30   # seconds
SSLLABS_429_MAX_BACKOFF = 600      # 10 minutes cap

# Default overload statuses (for non-SSL-Labs services)
RATE_LIMIT_STATUSES = {429, 529}

# Backoff schedules (seconds) — used for generic services
STANDARD_BACKOFF = [2, 4, 8, 16, 32]
RATE_LIMIT_BACKOFF = [5, 15, 45]


# ---------------------------------------------------------------------------
# Per-host rate limiter
# ---------------------------------------------------------------------------

class _HostRateLimiter:
    """Simple per-host concurrency and rate limiter.

    Supports two modes:
    - **Semaphore** (``max_concurrent``): limits how many requests to a host
      can be in-flight at the same time (e.g. SSL Labs: 1).
    - **Min interval** (``min_interval_sec``): enforces a minimum gap between
      successive requests to a host (e.g. crt.sh: 1 req/sec).
    """

    def __init__(self):
        self._lock = threading.Lock()
        # host → threading.Semaphore
        self._semaphores: dict[str, threading.Semaphore] = {}
        # host → last-request epoch
        self._last_request: dict[str, float] = {}
        # host → minimum interval in seconds
        self._intervals: dict[str, float] = {}
        # host → total HTTP call count
        self._call_counts: dict[str, int] = {}

    def configure(self, host: str, *, max_concurrent: int = 10, min_interval_sec: float = 0.0):
        """Register rate-limit settings for *host*."""
        with self._lock:
            self._semaphores[host] = threading.Semaphore(max_concurrent)
            self._intervals[host] = min_interval_sec
            self._call_counts.setdefault(host, 0)

    def acquire(self, host: str):
        """Block until it is safe to make a request to *host*."""
        sem = self._semaphores.get(host)
        if sem is not None:
            sem.acquire()

        interval = self._intervals.get(host, 0.0)
        if interval > 0:
            with self._lock:
                last = self._last_request.get(host, 0.0)
                elapsed = time.monotonic() - last
                if elapsed < interval:
                    wait = interval - elapsed
                    logger.debug("Rate limiter: sleeping %.2fs before request to %s", wait, host)
                    time.sleep(wait)

    def release(self, host: str):
        """Signal that a request to *host* has completed."""
        with self._lock:
            self._last_request[host] = time.monotonic()
        sem = self._semaphores.get(host)
        if sem is not None:
            sem.release()

    def record_call(self, host: str):
        """Increment the total HTTP call counter for *host*."""
        with self._lock:
            self._call_counts[host] = self._call_counts.get(host, 0) + 1

    def get_call_count(self, host: str) -> int:
        with self._lock:
            return self._call_counts.get(host, 0)

    def get_all_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._call_counts)


# Module-level singleton
host_limiter = _HostRateLimiter()

# Pre-configure known services
host_limiter.configure("api.ssllabs.com", max_concurrent=1, min_interval_sec=0.0)
host_limiter.configure("crt.sh", max_concurrent=1, min_interval_sec=1.0)


def _extract_host(url: str) -> str:
    """Return the hostname portion of a URL."""
    from urllib.parse import urlparse
    return urlparse(url).hostname or ""


# ---------------------------------------------------------------------------
# Backoff helpers
# ---------------------------------------------------------------------------

def _get_wait(backoff_schedule: list[int], attempt: int, jitter: bool = False) -> float:
    """Return wait time from a backoff schedule, clamping to last value.

    When *jitter* is True, the base wait is multiplied by a random factor
    between 0.5 and 1.5 to spread load across retrying clients.
    """
    if attempt < len(backoff_schedule):
        base = backoff_schedule[attempt]
    else:
        base = backoff_schedule[-1]

    if jitter:
        return base * (0.5 + random.random())  # 0.5x – 1.5x
    return float(base)


def _exp_backoff_429(attempt: int) -> float:
    """Exponential backoff for 429 with jitter, starting at 30s, capped at 10min."""
    base = min(SSLLABS_429_INITIAL_BACKOFF * (2 ** attempt), SSLLABS_429_MAX_BACKOFF)
    return base * (0.5 + random.random())


# ---------------------------------------------------------------------------
# SSL Labs–aware request function
# ---------------------------------------------------------------------------

def make_request(
    url: str,
    method: str = "GET",
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
    overload_statuses: Optional[set[int]] = None,
    standard_backoff_schedule: Optional[list[int]] = None,
    overload_backoff_schedule: Optional[list[int]] = None,
    jitter: bool = False,
    ssllabs_mode: bool = False,
    no_retry_on_404: bool = False,
) -> Optional[requests.Response]:
    """Make an HTTP request with retry logic and exponential backoff.

    Retry behaviour depends on the *ssllabs_mode* flag:

    **ssllabs_mode=True** (per SSL Labs v4 API docs):
      - 529 (overloaded): sleep 30 min, retry **once**.
      - 503 (unavailable): sleep 15 min, retry **once**.
      - 429 (rate limited): exponential backoff 30s→10min with jitter.
      - Other 5xx: standard backoff with jitter, max 5 attempts.

    **ssllabs_mode=False** (generic):
      - *overload_statuses* (default 429/529): retry with overload backoff.
      - 5xx: retry with standard backoff.
      - Connection / timeout errors: retry with standard backoff.

    Common to both modes:
      - 4xx (except overload codes): NO retry, return ``None``.
      - ``no_retry_on_404=True``: explicitly skip retry on 404.
    """
    effective_overload = overload_statuses if overload_statuses is not None else RATE_LIMIT_STATUSES
    effective_std_backoff = standard_backoff_schedule or STANDARD_BACKOFF
    effective_ol_backoff = overload_backoff_schedule or RATE_LIMIT_BACKOFF

    # In ssllabs_mode the retry count is governed per-status (not the caller's value)
    max_attempts = (retries + 1) if not ssllabs_mode else max(retries + 1, 5)

    merged_headers = dict(DEFAULT_HEADERS)
    if headers:
        merged_headers.update(headers)

    host = _extract_host(url)

    for attempt in range(max_attempts):
        # Per-host rate-limit gate
        host_limiter.acquire(host)
        try:
            host_limiter.record_call(host)
            call_num = host_limiter.get_call_count(host)
            logger.info(
                "HTTP %s %s (attempt %d/%d, total calls to %s: %d)",
                method, url, attempt + 1, max_attempts, host, call_num,
            )

            response = requests.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=merged_headers,
                timeout=timeout,
            )
        except requests.exceptions.Timeout:
            host_limiter.release(host)
            if attempt < max_attempts - 1:
                wait_time = _get_wait(effective_std_backoff, attempt, jitter=True)
                logger.warning(
                    "Timeout reaching %s (attempt %d/%d). Retrying in %.1fs...",
                    url, attempt + 1, max_attempts, wait_time,
                )
                time.sleep(wait_time)
                continue
            logger.error("Timeout reaching %s after %d attempts.", url, max_attempts)
            return None

        except requests.exceptions.ConnectionError:
            host_limiter.release(host)
            if attempt < max_attempts - 1:
                wait_time = _get_wait(effective_std_backoff, attempt, jitter=True)
                logger.warning(
                    "Connection error to %s (attempt %d/%d). Retrying in %.1fs...",
                    url, attempt + 1, max_attempts, wait_time,
                )
                time.sleep(wait_time)
                continue
            logger.error("Connection to %s failed after %d attempts.", url, max_attempts)
            return None

        except requests.exceptions.RequestException as e:
            host_limiter.release(host)
            logger.error("Unexpected request error for %s: %s", url, e)
            return None
        else:
            host_limiter.release(host)

        # ---- Evaluate response ----
        status = response.status_code

        # Success
        if response.ok:
            logger.debug("HTTP %d from %s", status, url)
            return response

        logger.info("HTTP %d from %s", status, url)

        # ---- SSL Labs–specific handling ----
        if ssllabs_mode:
            if status == 529:
                if attempt == 0:
                    logger.warning(
                        "SSL Labs overloaded (529). Cooling down for 30 minutes "
                        "before single retry. [%s]", url,
                    )
                    time.sleep(SSLLABS_529_COOLDOWN)
                    continue
                # Already retried once after cooldown — give up.
                logger.error(
                    "SSL Labs still returning 529 after 30-min cooldown. Giving up. [%s]", url,
                )
                return None

            if status == 503:
                if attempt == 0:
                    logger.warning(
                        "SSL Labs unavailable (503). Cooling down for 15 minutes "
                        "before single retry. [%s]", url,
                    )
                    time.sleep(SSLLABS_503_COOLDOWN)
                    continue
                logger.error(
                    "SSL Labs still returning 503 after 15-min cooldown. Giving up. [%s]", url,
                )
                return None

            if status == 429:
                if attempt < max_attempts - 1:
                    wait_time = _exp_backoff_429(attempt)
                    logger.warning(
                        "SSL Labs rate limited (429, attempt %d/%d). "
                        "Backing off %.1fs (exp backoff, cap 10min). [%s]",
                        attempt + 1, max_attempts, wait_time, url,
                    )
                    time.sleep(wait_time)
                    continue
                logger.error(
                    "SSL Labs rate limited (429) after %d attempts. Giving up. [%s]",
                    max_attempts, url,
                )
                return None

            # Other 5xx in ssllabs_mode — standard backoff with jitter
            if 500 <= status < 600:
                if attempt < max_attempts - 1:
                    wait_time = _get_wait(effective_std_backoff, attempt, jitter=True)
                    logger.warning(
                        "SSL Labs server error (%d, attempt %d/%d). "
                        "Retrying in %.1fs... [%s]",
                        status, attempt + 1, max_attempts, wait_time, url,
                    )
                    time.sleep(wait_time)
                    continue
                logger.error(
                    "SSL Labs server error (%d) after %d attempts. [%s]",
                    status, max_attempts, url,
                )
                return None

            # 4xx client error in ssllabs_mode — no retry
            if 400 <= status < 500:
                logger.error(
                    "Client error from SSL Labs: HTTP %d — not retrying. [%s]",
                    status, url,
                )
                return None

        # ---- Generic (non-ssllabs_mode) handling ----

        # Explicit no-retry on 404
        if no_retry_on_404 and status == 404:
            logger.error("HTTP 404 from %s — not retrying (no_retry_on_404).", url)
            return None

        # Rate-limited or overloaded — retry with heavy backoff
        if status in effective_overload:
            if attempt < max_attempts - 1:
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait_time = float(int(retry_after))
                else:
                    wait_time = _get_wait(effective_ol_backoff, attempt, jitter=jitter)
                logger.warning(
                    "Rate limited / overloaded at %s (HTTP %d, attempt %d/%d). "
                    "Retrying in %.1fs...",
                    url, status, attempt + 1, max_attempts, wait_time,
                )
                time.sleep(wait_time)
                continue
            logger.error(
                "Rate limited / overloaded at %s (HTTP %d) after %d attempts.",
                url, status, max_attempts,
            )
            return None

        # Non-retryable client error
        if 400 <= status < 500:
            logger.error(
                "Client error from %s: HTTP %d — not retrying.", url, status,
            )
            return None

        # Other server errors (5xx) — retry with standard backoff
        if attempt < max_attempts - 1:
            wait_time = _get_wait(effective_std_backoff, attempt, jitter=jitter)
            logger.warning(
                "Server error from %s (HTTP %d, attempt %d/%d). "
                "Retrying in %.1fs...",
                url, status, attempt + 1, max_attempts, wait_time,
            )
            time.sleep(wait_time)
        else:
            logger.error(
                "Request to %s failed with HTTP %d after %d attempts.",
                url, status, max_attempts,
            )
            return None

    return None


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def get_json(
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
    **kwargs: Any,
) -> Optional[dict | list]:
    """Make a GET request and return parsed JSON response.

    Extra keyword arguments are forwarded to :func:`make_request` (e.g.
    ``overload_statuses``, ``jitter``, ``ssllabs_mode``).
    """
    response = make_request(
        url, params=params, headers=headers, timeout=timeout, retries=retries,
        **kwargs,
    )
    if response is not None:
        try:
            return response.json()
        except ValueError:
            logger.error("Failed to parse JSON from %s", url)
            return None
    return None


def post_json(
    url: str,
    data: Optional[dict] = None,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
    **kwargs: Any,
) -> Optional[dict]:
    """Make a POST request and return parsed JSON response."""
    merged = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        merged.update(headers)
    response = make_request(
        url,
        method="POST",
        data=data,
        params=params,
        headers=merged,
        timeout=timeout,
        retries=retries,
        **kwargs,
    )
    if response is not None:
        try:
            return response.json()
        except ValueError:
            logger.error("Failed to parse JSON from %s", url)
            return None
    return None


def check_api_health(url: str, timeout: int = 10) -> bool:
    """Quick health check — returns True if the endpoint responds 2xx.

    A 429/529 is treated as 'alive but busy', so still returns True.
    """
    try:
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
        # 2xx → healthy.  429/529 → service exists but throttled → still alive.
        return resp.ok or resp.status_code in RATE_LIMIT_STATUSES
    except Exception:
        return False


def log_call_summary():
    """Log total HTTP call counts per host. Call at end of scan."""
    counts = host_limiter.get_all_counts()
    if counts:
        logger.info("=== HTTP call summary ===")
        for host, count in sorted(counts.items()):
            logger.info("  %s: %d total HTTP calls", host, count)
        logger.info("=========================")
