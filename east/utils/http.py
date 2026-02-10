"""HTTP utility functions for EAST tool."""

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


def _get_wait(backoff_schedule: list[int], attempt: int) -> int:
    """Return wait time from a backoff schedule, clamping to last value."""
    if attempt < len(backoff_schedule):
        return backoff_schedule[attempt]
    return backoff_schedule[-1]


def make_request(
    url: str,
    method: str = "GET",
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
) -> Optional[requests.Response]:
    """Make an HTTP request with retry logic and exponential backoff.

    Retry behaviour:
    - 4xx (except 429): NO retry, return None immediately
    - 429 / 529: retry with heavy backoff (5s → 15s → 45s)
    - 5xx: retry with standard backoff (2s → 4s → 8s)
    - Connection / timeout errors: retry with standard backoff
    """
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
            if status in RATE_LIMIT_STATUSES:
                if attempt < retries:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait_time = int(retry_after)
                    else:
                        wait_time = _get_wait(RATE_LIMIT_BACKOFF, attempt)
                    logger.warning(
                        "Rate limited / overloaded at %s (HTTP %d, attempt %d/%d). "
                        "Retrying in %ds...",
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

            # Non-retryable client error
            if status in NO_RETRY_STATUSES:
                logger.error(
                    "Client error from %s: HTTP %d — not retrying.", url, status,
                )
                return None

            # Other server errors (5xx) — retry with standard backoff
            if attempt < retries:
                wait_time = _get_wait(STANDARD_BACKOFF, attempt)
                logger.warning(
                    "Server error from %s (HTTP %d, attempt %d/%d). "
                    "Retrying in %ds...",
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
                wait_time = _get_wait(STANDARD_BACKOFF, attempt)
                logger.warning(
                    "Timeout reaching %s (attempt %d/%d). Retrying in %ds...",
                    url, attempt + 1, retries + 1, wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error("Timeout reaching %s after %d attempts.", url, retries + 1)
                return None

        except requests.exceptions.ConnectionError:
            if attempt < retries:
                wait_time = _get_wait(STANDARD_BACKOFF, attempt)
                logger.warning(
                    "Connection error to %s (attempt %d/%d). Retrying in %ds...",
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
) -> Optional[dict | list]:
    """Make a GET request and return parsed JSON response."""
    response = make_request(
        url, params=params, headers=headers, timeout=timeout, retries=retries,
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
