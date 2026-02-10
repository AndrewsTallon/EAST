"""HTTP utility functions for EAST tool."""

import time
import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 2


def make_request(
    url: str,
    method: str = "GET",
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
) -> Optional[requests.Response]:
    """Make an HTTP request with retry logic and exponential backoff."""
    default_headers = {
        "User-Agent": "EAST-Scanner/1.0 (Security Assessment Tool)",
    }
    if headers:
        default_headers.update(headers)

    for attempt in range(retries + 1):
        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=default_headers,
                timeout=timeout,
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if attempt < retries:
                wait_time = BACKOFF_FACTOR ** attempt
                logger.warning(
                    "Request to %s failed (attempt %d/%d): %s. Retrying in %ds...",
                    url, attempt + 1, retries + 1, str(e), wait_time,
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    "Request to %s failed after %d attempts: %s",
                    url, retries + 1, str(e),
                )
                return None
    return None


def get_json(
    url: str,
    params: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
) -> Optional[dict]:
    """Make a GET request and return JSON response."""
    response = make_request(url, params=params, timeout=timeout, retries=retries)
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
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = MAX_RETRIES,
) -> Optional[dict]:
    """Make a POST request and return JSON response."""
    response = make_request(
        url,
        method="POST",
        data=data,
        params=params,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
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
