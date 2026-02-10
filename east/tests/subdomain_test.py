"""Subdomain enumeration test runner for EAST tool."""

import io
import logging
from typing import Any, Optional

import dns.resolver
import dns.exception
import requests

from east.tests.base import TestRunner, TestResult
from east.visuals.badges import create_grade_badge, create_status_badge
from east.utils.http import get_json

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"

RESOLVER_TIMEOUT = 5
RESOLVER_LIFETIME = 10

# Common subdomain prefixes for DNS brute force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "dev", "staging", "api", "app", "admin", "portal",
    "vpn", "remote", "test", "owa", "autodiscover", "mx",
    "imap", "cloud", "git", "jenkins", "ci", "cdn", "static",
    "media", "assets", "img", "images", "docs", "wiki", "support",
    "help", "status", "monitor", "grafana", "kibana", "elastic",
    "store", "shop", "secure", "login", "sso", "auth",
    "m", "mobile", "beta", "demo", "sandbox",
]


class SubdomainTestRunner(TestRunner):
    """Enumerate subdomains via Certificate Transparency and DNS brute force."""

    name = "subdomains"
    description = "Subdomain Enumeration"

    def __init__(self, domain: str):
        super().__init__(domain)
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.timeout = RESOLVER_TIMEOUT
        self.resolver.lifetime = RESOLVER_LIFETIME
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    def run(self) -> TestResult:
        """Execute subdomain enumeration."""
        try:
            # Certificate Transparency search
            ct_subdomains = self._search_certificate_transparency()

            # DNS brute force for common subdomains
            dns_subdomains = self._dns_brute_force()

            # Merge results
            all_subdomains = sorted(set(ct_subdomains) | set(dns_subdomains))

            # Resolve subdomains to IPs
            resolved = self._resolve_subdomains(all_subdomains)

            return self._build_result(all_subdomains, resolved, ct_subdomains, dns_subdomains)

        except Exception as e:
            logger.exception("Subdomain test failed for %s", self.domain)
            return self._create_error_result(str(e))

    def _search_certificate_transparency(self) -> list[str]:
        """Search Certificate Transparency logs via crt.sh."""
        subdomains = set()

        try:
            data = get_json(
                CRT_SH_URL,
                params={"q": f"%.{self.domain}", "output": "json"},
                timeout=30,
                retries=2,
            )

            if data and isinstance(data, list):
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # crt.sh may return multiple names separated by newlines
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Filter to only subdomains of our domain
                        if name.endswith(f".{self.domain}") and name != self.domain:
                            # Skip wildcard entries
                            if not name.startswith("*"):
                                subdomains.add(name)

                self.logger.info(
                    "Found %d unique subdomains via CT logs for %s",
                    len(subdomains), self.domain,
                )
        except Exception as e:
            self.logger.warning("CT log search failed for %s: %s", self.domain, e)

        return sorted(subdomains)

    def _dns_brute_force(self) -> list[str]:
        """Check for common subdomain names via DNS resolution."""
        found = []

        for prefix in COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{self.domain}"
            try:
                self.resolver.resolve(subdomain, "A")
                found.append(subdomain)
                self.logger.debug("Found subdomain: %s", subdomain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue

        self.logger.info(
            "Found %d subdomains via DNS brute force for %s",
            len(found), self.domain,
        )
        return found

    def _resolve_subdomains(self, subdomains: list[str]) -> dict[str, str]:
        """Resolve subdomains to their IP addresses."""
        resolved = {}
        for subdomain in subdomains[:100]:  # Limit to first 100
            try:
                answers = self.resolver.resolve(subdomain, "A")
                ips = [str(rdata) for rdata in answers]
                resolved[subdomain] = ", ".join(ips)
            except Exception:
                resolved[subdomain] = "Unresolved"
        return resolved

    def _build_result(
        self,
        all_subdomains: list[str],
        resolved: dict[str, str],
        ct_subdomains: list[str],
        dns_subdomains: list[str],
    ) -> TestResult:
        """Build a TestResult from subdomain enumeration."""
        count = len(all_subdomains)

        # Score (informational — more subdomains isn't necessarily bad)
        # But a large surface area increases risk
        if count <= 5:
            score = 90
            grade = "A"
        elif count <= 15:
            score = 80
            grade = "A-"
        elif count <= 30:
            score = 70
            grade = "B"
        elif count <= 50:
            score = 60
            grade = "B-"
        elif count <= 100:
            score = 50
            grade = "C"
        else:
            score = 40
            grade = "C-"

        max_score = 100

        # Visuals
        visuals = {}
        visuals["count_badge"] = create_status_badge(
            f"{count} Subdomains Found",
            status="info" if count <= 20 else "warning",
        )

        # Summary
        summary = (
            f"Subdomains: {count} found | "
            f"CT Logs: {len(ct_subdomains)} | "
            f"DNS Brute Force: {len(dns_subdomains)}"
        )

        # Tables
        tables = []

        # Subdomain inventory table (limit to 50 for report readability)
        display_subdomains = all_subdomains[:50]
        sub_rows = []
        for sub in display_subdomains:
            ip = resolved.get(sub, "N/A")
            source_parts = []
            if sub in ct_subdomains:
                source_parts.append("CT")
            if sub in dns_subdomains:
                source_parts.append("DNS")
            source = ", ".join(source_parts) or "CT"
            sub_rows.append([sub, ip, source])

        if count > 50:
            sub_rows.append(["...", f"({count - 50} more)", "..."])

        tables.append({
            "title": "Discovered Subdomains",
            "headers": ["Subdomain", "IP Address", "Source"],
            "rows": sub_rows,
        })

        # Summary statistics table
        unique_ips = set(
            ip for ip in resolved.values()
            if ip not in ("Unresolved", "N/A")
        )
        stats_rows = [
            ["Total Subdomains", str(count)],
            ["From CT Logs", str(len(ct_subdomains))],
            ["From DNS Brute Force", str(len(dns_subdomains))],
            ["Unique IP Addresses", str(len(unique_ips))],
            ["Resolved", str(sum(1 for v in resolved.values() if v != "Unresolved"))],
            ["Unresolved", str(sum(1 for v in resolved.values() if v == "Unresolved"))],
        ]
        tables.append({
            "title": "Enumeration Summary",
            "headers": ["Metric", "Count"],
            "rows": stats_rows,
        })

        # Recommendations
        recommendations = self._generate_recommendations(count, all_subdomains, resolved)

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=score,
            max_score=max_score,
            summary=summary,
            details={
                "total_count": count,
                "ct_count": len(ct_subdomains),
                "dns_count": len(dns_subdomains),
                "subdomains": all_subdomains,
                "resolved": resolved,
            },
            recommendations=recommendations,
            visuals=visuals,
            tables=tables,
        )

    def _generate_recommendations(
        self,
        count: int,
        subdomains: list[str],
        resolved: dict[str, str],
    ) -> list[dict[str, str]]:
        """Generate subdomain recommendations."""
        recs = []

        if count > 50:
            recs.append({
                "severity": "warning",
                "text": f"Large attack surface detected: {count} subdomains found. "
                        "Review and decommission any unused subdomains to reduce exposure.",
            })
        elif count > 20:
            recs.append({
                "severity": "info",
                "text": f"{count} subdomains discovered. Review periodically to ensure "
                        "all are still in active use and properly maintained.",
            })

        # Check for potentially sensitive subdomains
        sensitive_prefixes = [
            "admin", "test", "staging", "dev", "debug", "internal",
            "jenkins", "git", "ci", "beta", "sandbox", "demo",
        ]
        sensitive_found = [
            s for s in subdomains
            if any(s.startswith(f"{p}.") for p in sensitive_prefixes)
        ]
        if sensitive_found:
            recs.append({
                "severity": "warning",
                "text": f"Potentially sensitive subdomains found: {', '.join(sensitive_found[:5])}. "
                        "Ensure these are properly secured and not publicly accessible unless intended.",
            })

        # Check for unresolved subdomains (possible dangling DNS)
        unresolved = [s for s, ip in resolved.items() if ip == "Unresolved"]
        if unresolved:
            recs.append({
                "severity": "info",
                "text": f"{len(unresolved)} subdomain(s) appear in CT logs but don't resolve. "
                        "These may be decommissioned or indicate dangling DNS records.",
            })

        if not recs:
            recs.append({
                "severity": "info",
                "text": "Subdomain attack surface appears manageable. "
                        "Continue periodic enumeration to detect unauthorized subdomains.",
            })

        return recs
