"""Blacklist checking test runner for EAST tool."""

import io
import logging
import socket
from typing import Any, Optional

import dns.resolver
import dns.exception
import dns.reversename

from east.tests.base import TestRunner, TestResult
from east.visuals.badges import create_grade_badge, create_status_badge
from east.visuals.charts import create_security_headers_chart

logger = logging.getLogger(__name__)

RESOLVER_TIMEOUT = 10
RESOLVER_LIFETIME = 20

# DNS-based blacklist providers to check
DNSBL_PROVIDERS = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "b.barracudacentral.org": "Barracuda",
    "dnsbl.sorbs.net": "SORBS",
    "spam.dnsbl.sorbs.net": "SORBS Spam",
    "dnsbl-1.uceprotect.net": "UCEPROTECT Level 1",
    "cbl.abuseat.org": "Composite Blocking List",
    "psbl.surriel.com": "PSBL",
    "dyna.spamrats.com": "SpamRATS",
    "spam.spamrats.com": "SpamRATS Spam",
}

# URI-based blacklists for domain checking
URIBL_PROVIDERS = {
    "multi.surbl.org": "SURBL",
    "dbl.spamhaus.org": "Spamhaus DBL",
}


class BlacklistTestRunner(TestRunner):
    """Check domain and IP against DNS-based blacklists."""

    name = "blacklist"
    description = "Domain & IP Blacklist Check"

    def __init__(self, domain: str):
        super().__init__(domain)
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.timeout = RESOLVER_TIMEOUT
        self.resolver.lifetime = RESOLVER_LIFETIME
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    def run(self) -> TestResult:
        """Execute blacklist checks."""
        try:
            # Resolve domain to IP
            ip_address = self._resolve_ip()

            # Check IP-based blacklists
            ip_results = {}
            if ip_address:
                ip_results = self._check_ip_blacklists(ip_address)

            # Check domain-based blacklists
            domain_results = self._check_domain_blacklists()

            return self._build_result(ip_address, ip_results, domain_results)

        except Exception as e:
            logger.exception("Blacklist test failed for %s", self.domain)
            return self._create_error_result(str(e))

    def _resolve_ip(self) -> Optional[str]:
        """Resolve domain to its IP address."""
        try:
            answers = self.resolver.resolve(self.domain, "A")
            for rdata in answers:
                return str(rdata)
        except Exception as e:
            self.logger.warning("Could not resolve %s to IP: %s", self.domain, e)
        return None

    def _check_ip_blacklists(self, ip: str) -> dict[str, dict[str, Any]]:
        """Check an IP address against DNSBL providers."""
        results = {}
        reversed_ip = ".".join(reversed(ip.split(".")))

        for bl_host, bl_name in DNSBL_PROVIDERS.items():
            query = f"{reversed_ip}.{bl_host}"
            try:
                answers = self.resolver.resolve(query, "A")
                # If we get a response, the IP is listed
                response_ip = str(answers[0])
                results[bl_name] = {
                    "listed": True,
                    "response": response_ip,
                    "provider": bl_host,
                }
                self.logger.warning("IP %s listed on %s (%s)", ip, bl_name, response_ip)
            except dns.resolver.NXDOMAIN:
                results[bl_name] = {
                    "listed": False,
                    "response": "",
                    "provider": bl_host,
                }
            except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
                results[bl_name] = {
                    "listed": False,
                    "response": "Query failed",
                    "provider": bl_host,
                }
            except Exception as e:
                self.logger.debug("Error checking %s: %s", bl_name, e)
                results[bl_name] = {
                    "listed": False,
                    "response": "Error",
                    "provider": bl_host,
                }

        return results

    def _check_domain_blacklists(self) -> dict[str, dict[str, Any]]:
        """Check domain against URI-based blacklists."""
        results = {}

        for bl_host, bl_name in URIBL_PROVIDERS.items():
            query = f"{self.domain}.{bl_host}"
            try:
                answers = self.resolver.resolve(query, "A")
                response_ip = str(answers[0])
                results[bl_name] = {
                    "listed": True,
                    "response": response_ip,
                    "provider": bl_host,
                }
                self.logger.warning("Domain %s listed on %s", self.domain, bl_name)
            except dns.resolver.NXDOMAIN:
                results[bl_name] = {
                    "listed": False,
                    "response": "",
                    "provider": bl_host,
                }
            except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
                results[bl_name] = {
                    "listed": False,
                    "response": "Query failed",
                    "provider": bl_host,
                }
            except Exception as e:
                self.logger.debug("Error checking %s: %s", bl_name, e)
                results[bl_name] = {
                    "listed": False,
                    "response": "Error",
                    "provider": bl_host,
                }

        return results

    def _build_result(
        self,
        ip_address: Optional[str],
        ip_results: dict[str, dict],
        domain_results: dict[str, dict],
    ) -> TestResult:
        """Build a TestResult from blacklist checks."""
        all_results = {**ip_results, **domain_results}

        # Count listings
        listed_count = sum(1 for r in all_results.values() if r.get("listed"))
        total_checked = len(all_results)
        clean_count = total_checked - listed_count

        # Score: start at 100, deduct for each listing
        if total_checked > 0:
            score = max(0, int(100 * (1 - (listed_count / total_checked) * 2)))
        else:
            score = 50
        max_score = 100

        # Grade
        if listed_count == 0:
            grade = "A"
        elif listed_count <= 1:
            grade = "B"
        elif listed_count <= 3:
            grade = "C"
        else:
            grade = "F"

        # Visuals
        visuals = {}
        visuals["grade_badge"] = create_grade_badge(grade, label="Blacklist Grade")

        if listed_count == 0:
            visuals["status_badge"] = create_status_badge(
                f"CLEAN - Not listed on {total_checked} blacklists",
                status="success",
            )
        else:
            visuals["status_badge_alert"] = create_status_badge(
                f"ALERT - Listed on {listed_count}/{total_checked} blacklists",
                status="critical",
            )

        # Status chart
        bl_status = {}
        for name, data in all_results.items():
            bl_status[name] = not data.get("listed", False)
        visuals["blacklist_chart"] = create_security_headers_chart(bl_status)

        # Summary
        summary = (
            f"Blacklist Grade: {grade} | "
            f"IP: {ip_address or 'N/A'} | "
            f"Listed: {listed_count}/{total_checked} blacklists"
        )

        # Tables
        tables = []

        # IP blacklist results
        if ip_results:
            ip_rows = []
            for name, data in ip_results.items():
                status = "Listed" if data["listed"] else "Not Listed"
                ip_rows.append([name, status, data.get("response", "")])
            tables.append({
                "title": f"IP Blacklist Check ({ip_address})",
                "headers": ["Blacklist", "Status", "Response"],
                "rows": ip_rows,
                "status_col": 1,
            })

        # Domain blacklist results
        if domain_results:
            domain_rows = []
            for name, data in domain_results.items():
                status = "Listed" if data["listed"] else "Not Listed"
                domain_rows.append([name, status, data.get("response", "")])
            tables.append({
                "title": f"Domain Blacklist Check ({self.domain})",
                "headers": ["Blacklist", "Status", "Response"],
                "rows": domain_rows,
                "status_col": 1,
            })

        # Recommendations
        recommendations = self._generate_recommendations(listed_count, all_results)

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=score,
            max_score=max_score,
            summary=summary,
            details={
                "ip_address": ip_address,
                "ip_results": ip_results,
                "domain_results": domain_results,
                "listed_count": listed_count,
                "total_checked": total_checked,
            },
            recommendations=recommendations,
            visuals=visuals,
            tables=tables,
        )

    def _generate_recommendations(
        self,
        listed_count: int,
        all_results: dict[str, dict],
    ) -> list[dict[str, str]]:
        """Generate blacklist recommendations."""
        recs = []

        if listed_count == 0:
            recs.append({
                "severity": "info",
                "text": "Domain and IP are not listed on any checked blacklists. "
                        "Continue monitoring regularly to maintain clean status.",
            })
        else:
            listed_on = [name for name, data in all_results.items() if data.get("listed")]

            recs.append({
                "severity": "critical",
                "text": f"Listed on {listed_count} blacklist(s): {', '.join(listed_on)}. "
                        "This may affect email deliverability and reputation. "
                        "Investigate the cause and request delisting.",
            })

            for bl_name in listed_on:
                recs.append({
                    "severity": "warning",
                    "text": f"Request delisting from {bl_name}. Visit the provider's "
                            "website for delisting procedures.",
                })

        return recs
