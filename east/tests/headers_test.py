"""Security headers analysis test runner for EAST tool."""

import io
import logging
from typing import Any, Optional

import requests

from east.tests.base import TestRunner, TestResult
from east.visuals.badges import create_grade_badge, create_score_gauge
from east.visuals.charts import create_security_headers_chart

logger = logging.getLogger(__name__)

# Security headers to check with their descriptions
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS, clickjacking, and other code injection attacks",
        "weight": 15,
        "critical": True,
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections, prevents downgrade attacks",
        "weight": 15,
        "critical": True,
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding",
        "weight": 10,
        "critical": True,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing attacks",
        "weight": 10,
        "critical": True,
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "weight": 8,
        "critical": False,
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs available to the page",
        "weight": 8,
        "critical": False,
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still useful for older browsers)",
        "weight": 5,
        "critical": False,
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Controls cross-origin window interaction",
        "weight": 5,
        "critical": False,
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource loading",
        "weight": 5,
        "critical": False,
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls cross-origin embedding",
        "weight": 5,
        "critical": False,
    },
    "Cache-Control": {
        "description": "Controls caching behavior for sensitive content",
        "weight": 5,
        "critical": False,
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls Adobe Flash/PDF cross-domain policy",
        "weight": 4,
        "critical": False,
    },
}

# Headers that should NOT be present (information disclosure)
DISCLOSURE_HEADERS = {
    "Server": "Reveals web server software and version",
    "X-Powered-By": "Reveals backend technology/framework",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}

REQUEST_TIMEOUT = 15


class SecurityHeadersTestRunner(TestRunner):
    """Analyze HTTP security headers for a domain."""

    name = "security_headers"
    description = "HTTP Security Headers Analysis"

    def run(self) -> TestResult:
        """Execute security headers analysis."""
        try:
            response_data = self._fetch_headers()
            if response_data is None:
                return self._create_error_result(
                    f"Could not connect to https://{self.domain}"
                )

            return self._analyze_headers(response_data)

        except Exception as e:
            logger.exception("Security headers test failed for %s", self.domain)
            return self._create_error_result(str(e))

    def _fetch_headers(self) -> Optional[dict[str, Any]]:
        """Fetch HTTP response headers from the domain."""
        urls = [f"https://{self.domain}", f"http://{self.domain}"]

        for url in urls:
            try:
                response = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "EAST-Scanner/1.0 (Security Assessment Tool)",
                    },
                )
                return {
                    "headers": dict(response.headers),
                    "status_code": response.status_code,
                    "url": response.url,
                    "is_https": response.url.startswith("https://"),
                }
            except requests.exceptions.SSLError:
                self.logger.warning("SSL error for %s, trying HTTP", url)
                continue
            except requests.exceptions.ConnectionError:
                self.logger.warning("Connection error for %s", url)
                continue
            except requests.exceptions.Timeout:
                self.logger.warning("Timeout connecting to %s", url)
                continue
            except Exception as e:
                self.logger.warning("Error fetching %s: %s", url, e)
                continue

        return None

    def _analyze_headers(self, response_data: dict[str, Any]) -> TestResult:
        """Analyze the response headers."""
        headers = response_data["headers"]
        is_https = response_data["is_https"]

        # Check security headers
        present_headers = {}
        missing_headers = {}
        header_values = {}

        total_weight = 0
        earned_weight = 0

        for header_name, info in SECURITY_HEADERS.items():
            weight = info["weight"]
            total_weight += weight

            # Case-insensitive header lookup
            value = None
            for h_name, h_value in headers.items():
                if h_name.lower() == header_name.lower():
                    value = h_value
                    break

            if value is not None:
                present_headers[header_name] = True
                header_values[header_name] = value
                earned_weight += weight
            else:
                missing_headers[header_name] = info
                present_headers[header_name] = False

        # Check disclosure headers
        disclosure_found = {}
        for header_name, description in DISCLOSURE_HEADERS.items():
            for h_name, h_value in headers.items():
                if h_name.lower() == header_name.lower():
                    disclosure_found[header_name] = h_value
                    break

        # HTTPS bonus
        if is_https:
            earned_weight += 5
        total_weight += 5

        # Score calculation
        score = int(100 * earned_weight / total_weight) if total_weight > 0 else 0
        score = min(100, max(0, score))

        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "A-"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        # Visuals
        visuals = {}
        visuals["grade_badge"] = create_grade_badge(grade, label="Headers Grade")
        visuals["score_gauge"] = create_score_gauge(score, 100, label="Security Headers Score")

        # Headers presence chart
        chart_data = {}
        for header_name in SECURITY_HEADERS:
            chart_data[header_name] = present_headers.get(header_name, False)
        visuals["headers_chart"] = create_security_headers_chart(chart_data)

        # Summary
        present_count = sum(1 for v in present_headers.values() if v)
        total_count = len(SECURITY_HEADERS)
        summary = (
            f"Security Headers Grade: {grade} | "
            f"Score: {score}/100 | "
            f"Present: {present_count}/{total_count} headers | "
            f"HTTPS: {'Yes' if is_https else 'No'}"
        )

        # Tables
        tables = []

        # Security headers table
        header_rows = []
        for header_name, info in SECURITY_HEADERS.items():
            is_present = present_headers.get(header_name, False)
            status = "Present" if is_present else "Missing"
            value = header_values.get(header_name, "")
            # Truncate long values
            if len(value) > 60:
                value = value[:57] + "..."
            importance = "Critical" if info["critical"] else "Recommended"
            header_rows.append([header_name, status, importance, value or "-"])

        tables.append({
            "title": "Security Headers Analysis",
            "headers": ["Header", "Status", "Importance", "Value"],
            "rows": header_rows,
            "status_col": 1,
        })

        # Information disclosure table
        if disclosure_found:
            disc_rows = []
            for header_name, value in disclosure_found.items():
                desc = DISCLOSURE_HEADERS.get(header_name, "")
                disc_rows.append([header_name, value, desc])
            tables.append({
                "title": "Information Disclosure Headers",
                "headers": ["Header", "Value", "Risk"],
                "rows": disc_rows,
            })

        # Connection info table
        conn_rows = [
            ["Final URL", response_data.get("url", "N/A")],
            ["Status Code", str(response_data.get("status_code", "N/A"))],
            ["HTTPS", "Yes" if is_https else "No"],
        ]
        tables.append({
            "title": "Connection Details",
            "headers": ["Property", "Value"],
            "rows": conn_rows,
        })

        # Recommendations
        recommendations = self._generate_recommendations(
            missing_headers, disclosure_found, is_https, header_values
        )

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=score,
            max_score=100,
            summary=summary,
            details={
                "present_headers": present_headers,
                "header_values": header_values,
                "missing_headers": list(missing_headers.keys()),
                "disclosure_headers": disclosure_found,
                "is_https": is_https,
                "status_code": response_data.get("status_code"),
                "final_url": response_data.get("url"),
            },
            recommendations=recommendations,
            visuals=visuals,
            tables=tables,
        )

    def _generate_recommendations(
        self,
        missing: dict[str, dict],
        disclosure: dict[str, str],
        is_https: bool,
        header_values: dict[str, str],
    ) -> list[dict[str, str]]:
        """Generate security header recommendations."""
        recs = []

        if not is_https:
            recs.append({
                "severity": "critical",
                "text": "The site is not using HTTPS. Enable HTTPS to encrypt "
                        "all traffic between clients and the server.",
            })

        # Critical missing headers
        critical_missing = [
            name for name, info in missing.items() if info.get("critical")
        ]

        if "Strict-Transport-Security" in critical_missing:
            recs.append({
                "severity": "critical",
                "text": "Add Strict-Transport-Security header: "
                        "'max-age=31536000; includeSubDomains; preload' "
                        "to enforce HTTPS and prevent downgrade attacks.",
            })

        if "Content-Security-Policy" in critical_missing:
            recs.append({
                "severity": "critical",
                "text": "Implement a Content-Security-Policy header to prevent "
                        "cross-site scripting (XSS) and data injection attacks. "
                        "Start with a report-only policy to test before enforcing.",
            })

        if "X-Frame-Options" in critical_missing:
            recs.append({
                "severity": "warning",
                "text": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent "
                        "clickjacking attacks.",
            })

        if "X-Content-Type-Options" in critical_missing:
            recs.append({
                "severity": "warning",
                "text": "Add 'X-Content-Type-Options: nosniff' to prevent "
                        "MIME type sniffing attacks.",
            })

        # Non-critical missing
        optional_missing = [
            name for name, info in missing.items() if not info.get("critical")
        ]
        if optional_missing:
            recs.append({
                "severity": "info",
                "text": f"Consider adding these recommended headers: "
                        f"{', '.join(optional_missing[:4])}.",
            })

        # Disclosure headers
        if disclosure:
            header_names = ", ".join(disclosure.keys())
            recs.append({
                "severity": "warning",
                "text": f"Information disclosure headers detected: {header_names}. "
                        "Remove or mask these headers to reduce attack surface.",
            })

        # Check HSTS configuration quality
        hsts_value = header_values.get("Strict-Transport-Security", "")
        if hsts_value:
            if "max-age=" in hsts_value:
                try:
                    max_age = int(hsts_value.split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:
                        recs.append({
                            "severity": "info",
                            "text": f"HSTS max-age is {max_age} seconds "
                                    f"({max_age // 86400} days). Consider increasing "
                                    "to at least 31536000 (1 year).",
                        })
                except (ValueError, IndexError):
                    pass
            if "includesubdomains" not in hsts_value.lower():
                recs.append({
                    "severity": "info",
                    "text": "HSTS header does not include 'includeSubDomains'. "
                            "Consider adding it to protect all subdomains.",
                })

        if not recs:
            recs.append({
                "severity": "info",
                "text": "Security headers are well configured. Continue monitoring "
                        "for new security header best practices.",
            })

        return recs
