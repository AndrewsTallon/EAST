"""Input validation utilities for EAST tool."""

import re
from typing import Optional

import validators as v


def validate_domain(domain: str) -> bool:
    """Validate that a string is a proper domain name."""
    if not domain:
        return False
    result = v.domain(domain)
    return result is True


def validate_url(url: str) -> bool:
    """Validate that a string is a proper URL."""
    if not url:
        return False
    result = v.url(url)
    return result is True


def sanitize_domain(domain: str) -> str:
    """Sanitize a domain name by stripping protocol and trailing paths."""
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    return domain.lower()


def validate_test_names(test_names: list[str], available_tests: list[str]) -> tuple[list[str], list[str]]:
    """Validate test names and return (valid, invalid) lists."""
    valid = [t for t in test_names if t in available_tests]
    invalid = [t for t in test_names if t not in available_tests]
    return valid, invalid
