"""Local file-based cache for API responses.

Stores JSON results under ``.cache/<service>/<key>.json`` so that repeated
scans can skip expensive API calls when recent results are available.
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default cache root — relative to the working directory
_CACHE_ROOT = Path(".cache")

# Default max-age in seconds (24 hours)
DEFAULT_MAX_AGE = 86400


def _cache_dir(service: str) -> Path:
    d = _CACHE_ROOT / service
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_key(hostname: str, options: Optional[dict] = None) -> str:
    """Generate a safe filename from hostname + options."""
    raw = hostname
    if options:
        # Sort keys for deterministic hashing
        raw += "|" + json.dumps(options, sort_keys=True)
    # Use the hostname directly if simple enough, otherwise hash
    safe = hostname.replace(".", "_").replace("/", "_")
    if options:
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        safe = f"{safe}_{h}"
    return safe


def get_cached(service: str, hostname: str, options: Optional[dict] = None,
               max_age: int = DEFAULT_MAX_AGE) -> Optional[dict]:
    """Return cached JSON data if it exists and is younger than *max_age* seconds.

    Returns ``None`` if no valid cache entry is found.
    """
    key = _cache_key(hostname, options)
    path = _cache_dir(service) / f"{key}.json"

    if not path.exists():
        logger.debug("Cache miss for %s/%s (file does not exist)", service, key)
        return None

    age = time.time() - path.stat().st_mtime
    if age > max_age:
        logger.info(
            "Cache expired for %s/%s (age %.0fs > max %ds)",
            service, key, age, max_age,
        )
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        logger.info(
            "Cache hit for %s/%s (age %.0fs, max %ds)",
            service, key, age, max_age,
        )
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read cache %s: %s", path, exc)
        return None


def set_cached(service: str, hostname: str, data: Any,
               options: Optional[dict] = None) -> None:
    """Write *data* to the cache as JSON."""
    key = _cache_key(hostname, options)
    path = _cache_dir(service) / f"{key}.json"

    try:
        path.write_text(json.dumps(data, default=str), encoding="utf-8")
        logger.info("Cached result for %s/%s → %s", service, key, path)
    except OSError as exc:
        logger.warning("Failed to write cache %s: %s", path, exc)
