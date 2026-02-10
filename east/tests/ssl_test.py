"""SSL Labs test runner for EAST tool."""

import io
import time
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from east.tests.base import TestRunner, TestResult
from east.utils.http import get_json
from east.visuals.badges import create_grade_badge, create_status_badge
from east.visuals.charts import create_certificate_timeline, create_protocol_support_chart

logger = logging.getLogger(__name__)

SSL_LABS_API = "https://api.ssllabs.com/api/v3"
ANALYZE_ENDPOINT = f"{SSL_LABS_API}/analyze"
MAX_POLL_ATTEMPTS = 60
POLL_INTERVAL = 10  # seconds


class SSLLabsTestRunner(TestRunner):
    """Run SSL/TLS analysis using the SSL Labs API."""

    name = "ssl_labs"
    description = "SSL/TLS Certificate & Configuration Analysis"

    def run(self) -> TestResult:
        """Execute SSL Labs scan and return results."""
        try:
            # Start the analysis
            data = self._start_analysis()
            if data is None:
                return self._create_error_result(
                    "Failed to start SSL Labs analysis. The API may be unavailable."
                )

            # Poll for results
            data = self._poll_for_results(data)
            if data is None:
                return self._create_error_result(
                    "SSL Labs analysis timed out or failed."
                )

            return self._parse_results(data)

        except Exception as e:
            logger.exception("SSL Labs test failed for %s", self.domain)
            return self._create_error_result(str(e))

    def _start_analysis(self) -> Optional[dict]:
        """Start an SSL Labs analysis."""
        params = {
            "host": self.domain,
            "publish": "off",
            "startNew": "off",
            "fromCache": "on",
            "maxAge": "24",
            "all": "done",
        }
        self.logger.info("Starting SSL Labs analysis for %s", self.domain)
        result = get_json(ANALYZE_ENDPOINT, params=params, timeout=60, retries=2)

        if result is None:
            # Try starting a new scan
            params["startNew"] = "on"
            del params["fromCache"]
            del params["maxAge"]
            result = get_json(ANALYZE_ENDPOINT, params=params, timeout=60, retries=2)

        return result

    def _poll_for_results(self, data: dict) -> Optional[dict]:
        """Poll the SSL Labs API until analysis is complete."""
        status = data.get("status", "")

        for attempt in range(MAX_POLL_ATTEMPTS):
            if status == "READY":
                return data
            elif status == "ERROR":
                self.logger.error("SSL Labs returned error: %s",
                                  data.get("statusMessage", "Unknown error"))
                return None
            elif status in ("DNS", "IN_PROGRESS"):
                self.logger.info("SSL Labs analysis in progress (attempt %d/%d)...",
                                 attempt + 1, MAX_POLL_ATTEMPTS)
                time.sleep(POLL_INTERVAL)
                data = get_json(
                    ANALYZE_ENDPOINT,
                    params={"host": self.domain, "all": "done"},
                    timeout=60,
                    retries=1,
                )
                if data is None:
                    return None
                status = data.get("status", "")
            else:
                self.logger.warning("Unknown SSL Labs status: %s", status)
                time.sleep(POLL_INTERVAL)
                data = get_json(
                    ANALYZE_ENDPOINT,
                    params={"host": self.domain, "all": "done"},
                    timeout=60,
                    retries=1,
                )
                if data is None:
                    return None
                status = data.get("status", "")

        self.logger.error("SSL Labs analysis timed out for %s", self.domain)
        return None

    def _parse_results(self, data: dict) -> TestResult:
        """Parse the SSL Labs API response into a TestResult."""
        endpoints = data.get("endpoints", [])
        if not endpoints:
            return self._create_error_result("No endpoints found in SSL Labs response.")

        # Use the first endpoint (primary)
        ep = endpoints[0]
        grade = ep.get("grade", "T")
        grade_trust = ep.get("gradeTrustIgnored", grade)
        has_warnings = ep.get("hasWarnings", False)

        # Extract certificate details
        cert_details = self._extract_cert_details(ep)
        protocol_details = self._extract_protocol_details(ep)
        vulnerability_details = self._extract_vulnerabilities(ep)

        # Generate visuals
        visuals = {}

        # Grade badge
        visuals["grade_badge"] = create_grade_badge(grade, label="SSL Labs Grade")

        # Certificate timeline
        not_before = cert_details.get("not_before")
        not_after = cert_details.get("not_after")
        if not_before and not_after:
            visuals["cert_timeline"] = create_certificate_timeline(
                not_before, not_after, domain=self.domain
            )

        # Protocol support chart
        if protocol_details:
            visuals["protocol_chart"] = create_protocol_support_chart(protocol_details)

        # Build summary
        summary = (
            f"SSL Labs Grade: {grade} | "
            f"Certificate: {cert_details.get('subject', 'N/A')} | "
            f"Issuer: {cert_details.get('issuer', 'N/A')}"
        )

        # Build tables
        tables = []

        # Certificate info table
        cert_table_rows = [
            ["Subject", cert_details.get("subject", "N/A")],
            ["Issuer", cert_details.get("issuer", "N/A")],
            ["Valid From", cert_details.get("not_before_str", "N/A")],
            ["Valid Until", cert_details.get("not_after_str", "N/A")],
            ["Key Algorithm", cert_details.get("key_alg", "N/A")],
            ["Key Size", cert_details.get("key_size", "N/A")],
            ["Signature Algorithm", cert_details.get("sig_alg", "N/A")],
        ]
        tables.append({
            "title": "Certificate Details",
            "headers": ["Property", "Value"],
            "rows": cert_table_rows,
        })

        # Protocol support table
        if protocol_details:
            proto_rows = [
                [name, "Supported" if supported else "Not Supported"]
                for name, supported in protocol_details.items()
            ]
            tables.append({
                "title": "Protocol Support",
                "headers": ["Protocol", "Status"],
                "rows": proto_rows,
                "status_col": 1,
            })

        # Vulnerabilities table
        if vulnerability_details:
            vuln_rows = [
                [name, "Pass" if not vulnerable else "Fail"]
                for name, vulnerable in vulnerability_details.items()
            ]
            tables.append({
                "title": "Vulnerability Checks",
                "headers": ["Vulnerability", "Status"],
                "rows": vuln_rows,
                "status_col": 1,
            })

        # Score mapping (approximate from grade)
        score_map = {
            "A+": 100, "A": 95, "A-": 90,
            "B+": 85, "B": 80, "B-": 75,
            "C+": 70, "C": 65, "C-": 60,
            "D": 50, "E": 40, "F": 20, "T": 0, "M": 0,
        }
        score = score_map.get(grade, 50)

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=score,
            max_score=100,
            summary=summary,
            details={
                "grade": grade,
                "grade_trust_ignored": grade_trust,
                "has_warnings": has_warnings,
                "certificate": cert_details,
                "protocols": protocol_details,
                "vulnerabilities": vulnerability_details,
                "ip_address": ep.get("ipAddress", "N/A"),
                "server_name": ep.get("serverName", "N/A"),
            },
            recommendations=self._generate_recommendations(grade, cert_details, protocol_details, vulnerability_details),
            visuals=visuals,
            tables=tables,
        )

    def _extract_cert_details(self, endpoint: dict) -> dict:
        """Extract certificate details from endpoint data."""
        details = endpoint.get("details", {})
        cert_chains = details.get("certChains", [])

        cert_info = {
            "subject": "N/A",
            "issuer": "N/A",
            "not_before": None,
            "not_after": None,
            "not_before_str": "N/A",
            "not_after_str": "N/A",
            "key_alg": "N/A",
            "key_size": "N/A",
            "sig_alg": "N/A",
        }

        if cert_chains:
            certs = cert_chains[0].get("certIds", [])
            # Try to get cert details from the details section
            all_certs = details.get("certs", [])
            if all_certs:
                leaf_cert = all_certs[0]
                cert_info["subject"] = leaf_cert.get("commonNames", ["N/A"])[0] if leaf_cert.get("commonNames") else "N/A"
                cert_info["issuer"] = leaf_cert.get("issuerLabel", "N/A")
                cert_info["sig_alg"] = leaf_cert.get("sigAlg", "N/A")
                cert_info["key_alg"] = leaf_cert.get("keyAlg", "N/A")
                cert_info["key_size"] = str(leaf_cert.get("keySize", "N/A"))

                not_before_ms = leaf_cert.get("notBefore")
                not_after_ms = leaf_cert.get("notAfter")

                if not_before_ms:
                    nb = datetime.fromtimestamp(not_before_ms / 1000, tz=timezone.utc)
                    cert_info["not_before"] = nb
                    cert_info["not_before_str"] = nb.strftime("%Y-%m-%d %H:%M UTC")

                if not_after_ms:
                    na = datetime.fromtimestamp(not_after_ms / 1000, tz=timezone.utc)
                    cert_info["not_after"] = na
                    cert_info["not_after_str"] = na.strftime("%Y-%m-%d %H:%M UTC")

        return cert_info

    def _extract_protocol_details(self, endpoint: dict) -> dict[str, bool]:
        """Extract TLS protocol support from endpoint data."""
        details = endpoint.get("details", {})
        protocols_data = details.get("protocols", [])

        protocol_map = {
            "SSL 2.0": False,
            "SSL 3.0": False,
            "TLS 1.0": False,
            "TLS 1.1": False,
            "TLS 1.2": False,
            "TLS 1.3": False,
        }

        for proto in protocols_data:
            name = proto.get("name", "")
            version = proto.get("version", "")
            key = f"{name} {version}"
            if key in protocol_map:
                protocol_map[key] = True

        return protocol_map

    def _extract_vulnerabilities(self, endpoint: dict) -> dict[str, bool]:
        """Extract vulnerability check results from endpoint data."""
        details = endpoint.get("details", {})

        vulns = {}

        # Heartbleed
        vulns["Heartbleed"] = details.get("heartbleed", False)

        # POODLE
        poodle_tls = details.get("poodleTls", 0)
        vulns["POODLE (TLS)"] = poodle_tls == 2

        # ROBOT
        robot = details.get("robotResult", 0)
        vulns["ROBOT"] = robot == 1

        # Ticketbleed
        vulns["Ticketbleed"] = details.get("ticketbleed", 0) == 2

        # OpenSSL CCS
        vulns["OpenSSL CCS"] = details.get("openSslCcs", 0) in (2, 3)

        # LUCKY13
        vulns["LUCKY13"] = details.get("openSSLLuckyMinus20", 0) == 2

        # FREAK
        vulns["FREAK"] = details.get("freak", False)

        # Logjam
        vulns["Logjam"] = details.get("logjam", False)

        # DROWN
        vulns["DROWN"] = details.get("drownVulnerable", False)

        return vulns

    def _generate_recommendations(
        self,
        grade: str,
        cert_details: dict,
        protocols: dict[str, bool],
        vulnerabilities: dict[str, bool],
    ) -> list[dict[str, str]]:
        """Generate recommendations based on SSL Labs results."""
        recs = []

        # Grade-based recommendations
        if grade in ("F", "T", "M"):
            recs.append({
                "severity": "critical",
                "text": "The SSL/TLS configuration has critical issues. "
                        "Immediate remediation is required to ensure secure communications.",
            })
        elif grade in ("D", "E"):
            recs.append({
                "severity": "critical",
                "text": "The SSL/TLS configuration is poorly rated. "
                        "Significant improvements are needed.",
            })
        elif grade.startswith("C"):
            recs.append({
                "severity": "warning",
                "text": "The SSL/TLS configuration needs improvement. "
                        "Consider upgrading protocols and cipher suites.",
            })
        elif grade.startswith("B"):
            recs.append({
                "severity": "warning",
                "text": "The SSL/TLS configuration is adequate but could be improved "
                        "to achieve an A rating.",
            })

        # Protocol recommendations
        if protocols.get("SSL 2.0") or protocols.get("SSL 3.0"):
            recs.append({
                "severity": "critical",
                "text": "Disable SSL 2.0 and SSL 3.0 protocols. These are known to be "
                        "insecure and vulnerable to attacks.",
            })

        if protocols.get("TLS 1.0") or protocols.get("TLS 1.1"):
            recs.append({
                "severity": "warning",
                "text": "Consider disabling TLS 1.0 and TLS 1.1. These older protocols "
                        "are deprecated and should be replaced with TLS 1.2 or 1.3.",
            })

        if not protocols.get("TLS 1.3"):
            recs.append({
                "severity": "info",
                "text": "Enable TLS 1.3 for improved performance and security. "
                        "TLS 1.3 provides stronger encryption and faster handshakes.",
            })

        # Certificate recommendations
        not_after = cert_details.get("not_after")
        if not_after:
            days_remaining = (not_after - datetime.now(timezone.utc)).days
            if days_remaining < 0:
                recs.append({
                    "severity": "critical",
                    "text": "The SSL certificate has expired! Renew immediately.",
                })
            elif days_remaining < 30:
                recs.append({
                    "severity": "critical",
                    "text": f"The SSL certificate expires in {days_remaining} days. "
                            "Renew urgently.",
                })
            elif days_remaining < 90:
                recs.append({
                    "severity": "warning",
                    "text": f"The SSL certificate expires in {days_remaining} days. "
                            "Plan for renewal.",
                })

        # Vulnerability recommendations
        active_vulns = [name for name, vulnerable in vulnerabilities.items() if vulnerable]
        if active_vulns:
            recs.append({
                "severity": "critical",
                "text": f"Vulnerabilities detected: {', '.join(active_vulns)}. "
                        "Apply patches and update server configuration immediately.",
            })

        if not recs:
            recs.append({
                "severity": "info",
                "text": "SSL/TLS configuration looks good. Continue monitoring "
                        "for new vulnerabilities and certificate expiration.",
            })

        return recs
