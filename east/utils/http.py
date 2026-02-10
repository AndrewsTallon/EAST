"""HTTP utility functions for EAST tool."""

import random
import time
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

# Status codes that indicate rate limiting / overload — retry with heavy backoff
RATE_LIMIT_STATUSES = {429, 529}

# Backoff schedules (seconds)
# Standard server errors: 2s, 4s, 8s
STANDARD_BACKOFF = [2, 4, 8]
# Rate-limit / overload (429, 529): 5s, 15s, 45s
RATE_LIMIT_BACKOFF = [5, 15, 45]


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
) -> Optional[requests.Response]:
    """Make an HTTP request with retry logic and exponential backoff.

    Retry behaviour:
    - 4xx (except codes in *overload_statuses*): NO retry, return None
    - *overload_statuses* (default 429/529): retry with overload backoff
    - 5xx: retry with standard backoff
    - Connection / timeout errors: retry with standard backoff

    Extra parameters (all optional):
    - *overload_statuses*: status codes treated as overload (default {429, 529}).
    - *standard_backoff_schedule*: backoff sequence for 5xx / network errors.
    - *overload_backoff_schedule*: backoff sequence for overload codes.
    - *jitter*: when True, randomise each wait ±50 % to avoid thundering herd.
    """
    effective_overload = overload_statuses if overload_statuses is not None else RATE_LIMIT_STATUSES
    effective_std_backoff = standard_backoff_schedule if standard_backoff_schedule is not None else STANDARD_BACKOFF
    effective_ol_backoff = overload_backoff_schedule if overload_backoff_schedule is not None else RATE_LIMIT_BACKOFF

    merged_headers = dict(DEFAULT_HEADERS)
    if headers:
        merged_headers.update(headers)

    for attempt in range(retries + 1):
        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=merged_headers,
                timeout=timeout,
            )

            # Success
            if response.ok:
                return response

            status = response.status_code

            # Rate-limited or overloaded — retry with heavy backoff
            if status in effective_overload:
                if attempt < retries:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait_time = float(int(retry_after))
                    else:
                        wait_time = _get_wait(effective_ol_backoff, attempt, jitter=jitter)
                    logger.warning(
                        "Rate limited / overloaded at %s (HTTP %d, attempt %d/%d). "
                        "Retrying in %.1fs...",
                        url, status, attempt + 1, retries + 1, wait_time,
                    )
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(
                        "Rate limited / overloaded at %s (HTTP %d) after %d attempts.",
                        url, status, retries + 1,
                    )
                    return None

            # Non-retryable client error (exclude anything in effective_overload)
            if 400 <= status < 500 and status not in effective_overload:
                logger.error(
                    "Client error from %s: HTTP %d — not retrying.", url, status,
                )
                return None

            # Other server errors (5xx) — retry with standard backoff
            if attempt < retries:
                wait_time = _get_wait(effective_std_backoff, attempt, jitter=jitter)
                logger.warning(
                    "Server error from %s (HTTP %d, attempt %d/%d). "
                    "Retrying in %.1fs...",
                    url, status, attempt + 1, retries + 1, wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    "Request to %s failed with HTTP %d after %d attempts.",
                    url, status, retries + 1,
                )
                return None

        except requests.exceptions.Timeout:
            if attempt < retries:
                wait_time = _get_wait(effective_std_backoff, attempt, jitter=jitter)
                logger.warning(
                    "Timeout reaching %s (attempt %d/%d). Retrying in %.1fs...",
                    url, attempt + 1, retries + 1, wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error("Timeout reaching %s after %d attempts.", url, retries + 1)
                return None

        except requests.exceptions.ConnectionError:
            if attempt < retries:
                wait_time = _get_wait(effective_std_backoff, attempt, jitter=jitter)
                logger.warning(
                    "Connection error to %s (attempt %d/%d). Retrying in %.1fs...",
                    url, attempt + 1, retries + 1, wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    "Connection to %s failed after %d attempts.", url, retries + 1,
                )
                return None

        except requests.exceptions.RequestException as e:
            logger.error("Unexpected request error for %s: %s", url, e)
            return None

    return None


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
    ``overload_statuses``, ``jitter``, ``overload_backoff_schedule``).
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
