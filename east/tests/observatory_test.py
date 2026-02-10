"""Mozilla Observatory test runner for EAST tool."""

import io
import time
import logging
from typing import Any, Optional

import requests

from east.tests.base import TestRunner, TestResult
from east.utils.http import get_json, post_json, check_api_health, DEFAULT_HEADERS
from east.visuals.badges import create_grade_badge, create_score_gauge
from east.visuals.charts import create_security_headers_chart

logger = logging.getLogger(__name__)

OBSERVATORY_API = "https://http-observatory.security.mozilla.org/api/v1"
ANALYZE_ENDPOINT = f"{OBSERVATORY_API}/analyze"
SCAN_RESULTS_ENDPOINT = f"{OBSERVATORY_API}/getScanResults"

MAX_POLL_ATTEMPTS = 24   # 24 * 5s = 2 minutes max wait
POLL_INTERVAL = 5        # seconds between status checks


# Mapping of test names to human-readable descriptions
TEST_DESCRIPTIONS = {
    "content-security-policy": "Content Security Policy (CSP)",
    "contribute": "Contribute.json",
    "cookies": "Cookies",
    "cross-origin-resource-sharing": "Cross-Origin Resource Sharing (CORS)",
    "public-key-pinning": "HTTP Public Key Pinning (HPKP)",
    "redirection": "HTTP Redirection",
    "referrer-policy": "Referrer Policy",
    "strict-transport-security": "HTTP Strict Transport Security (HSTS)",
    "subresource-integrity": "Subresource Integrity (SRI)",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "x-xss-protection": "X-XSS-Protection",
}


class MozillaObservatoryTestRunner(TestRunner):
    """Run security analysis using Mozilla HTTP Observatory."""

    name = "mozilla_observatory"
    description = "Mozilla HTTP Observatory Security Analysis"

    def run(self) -> TestResult:
        """Execute Mozilla Observatory scan and return results."""
        try:
            # Health check
            if not self._check_health():
                return self._create_error_result(
                    "Mozilla Observatory API is currently unavailable."
                )

            # Try cached results first (fast GET)
            analysis = self._get_cached_results()

            # If no cached result, initiate a new scan via POST
            if analysis is None or analysis.get("state") != "FINISHED":
                analysis = self._initiate_scan()
                if analysis is None:
                    return self._create_error_result(
                        "Failed to start Mozilla Observatory analysis."
                    )

            # Poll until FINISHED (if not already)
            if analysis.get("state") != "FINISHED":
                analysis = self._poll_for_results()
                if analysis is None:
                    return self._create_error_result(
                        "Mozilla Observatory analysis timed out or failed."
                    )

            # Get detailed per-test results
            scan_id = analysis.get("scan_id")
            scan_results = self._get_scan_results(scan_id)

            return self._parse_results(analysis, scan_results)

        except Exception as e:
            logger.exception("Mozilla Observatory test failed for %s", self.domain)
            return self._create_error_result(str(e))

    # ------------------------------------------------------------------
    # API interaction
    # ------------------------------------------------------------------

    def _check_health(self) -> bool:
        """Quick check that the Observatory API is reachable."""
        self.logger.info("Checking Mozilla Observatory API health...")
        # The analyze endpoint with a known domain is the lightest check
        return check_api_health(ANALYZE_ENDPOINT + "?host=mozilla.org", timeout=10)

    def _get_cached_results(self) -> Optional[dict]:
        """GET the analysis endpoint — returns cached/recent results if any."""
        self.logger.info("Checking for cached Observatory results for %s", self.domain)
        return get_json(
            ANALYZE_ENDPOINT,
            params={"host": self.domain},
            timeout=30,
            retries=2,
        )

    def _initiate_scan(self) -> Optional[dict]:
        """POST to the analysis endpoint to start a new scan."""
        self.logger.info("Initiating new Observatory scan for %s", self.domain)
        return post_json(
            ANALYZE_ENDPOINT,
            params={"host": self.domain},
            data={"hidden": "true", "rescan": "true"},
            timeout=30,
            retries=2,
        )

    def _poll_for_results(self) -> Optional[dict]:
        """Poll via GET until the scan reaches FINISHED state."""
        for attempt in range(MAX_POLL_ATTEMPTS):
            self.logger.info(
                "Observatory scan in progress (attempt %d/%d)...",
                attempt + 1, MAX_POLL_ATTEMPTS,
            )
            time.sleep(POLL_INTERVAL)

            data = get_json(
                ANALYZE_ENDPOINT,
                params={"host": self.domain},
                timeout=30,
                retries=1,
            )
            if data is None:
                continue  # transient failure, keep trying

            state = data.get("state", "")
            if state == "FINISHED":
                return data
            if state in ("FAILED", "ABORTED"):
                self.logger.error("Observatory scan state: %s", state)
                return None

        self.logger.error("Observatory analysis timed out for %s", self.domain)
        return None

    def _get_scan_results(self, scan_id: Optional[int]) -> Optional[dict]:
        """Get detailed per-test scan results by scan ID."""
        if scan_id is None:
            return None
        return get_json(
            SCAN_RESULTS_ENDPOINT,
            params={"scan": str(scan_id)},
            timeout=30,
            retries=2,
        )

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _parse_results(self, analysis: dict, scan_results: Optional[dict]) -> TestResult:
        """Parse Observatory results into a TestResult."""
        grade = analysis.get("grade", "N/A")
        score = analysis.get("score", 0)
        tests_passed = analysis.get("tests_passed", 0)
        tests_failed = analysis.get("tests_failed", 0)
        tests_quantity = analysis.get("tests_quantity", 0)

        # Generate visuals
        visuals = {}

        # Grade badge
        visuals["grade_badge"] = create_grade_badge(grade, label="Observatory Grade")

        # Score gauge
        # Observatory scores can go above 100 with bonus points; cap display at 100
        display_score = min(score, 100) if score >= 0 else 0
        visuals["score_gauge"] = create_score_gauge(
            display_score, max_score=100, label="Security Score"
        )

        # Security headers chart from scan results
        headers_status = self._extract_headers_status(scan_results)
        if headers_status:
            visuals["headers_chart"] = create_security_headers_chart(headers_status)

        # Build summary
        summary = (
            f"Mozilla Observatory Grade: {grade} | "
            f"Score: {score}/100 | "
            f"Tests Passed: {tests_passed}/{tests_quantity}"
        )

        # Build tables
        tables = []

        # Overview table
        overview_rows = [
            ["Grade", grade],
            ["Score", f"{score}/100"],
            ["Tests Passed", str(tests_passed)],
            ["Tests Failed", str(tests_failed)],
            ["Total Tests", str(tests_quantity)],
        ]
        tables.append({
            "title": "Observatory Overview",
            "headers": ["Metric", "Value"],
            "rows": overview_rows,
        })

        # Detailed test results table
        if scan_results:
            test_rows = []
            for test_name, test_data in sorted(scan_results.items()):
                readable_name = TEST_DESCRIPTIONS.get(test_name, test_name)
                passed = test_data.get("pass", False)
                score_modifier = test_data.get("score_modifier", 0)
                result_text = test_data.get("result", "N/A")

                status = "Pass" if passed else "Fail"
                modifier = f"+{score_modifier}" if score_modifier > 0 else str(score_modifier)

                test_rows.append([readable_name, status, modifier, result_text])

            tables.append({
                "title": "Detailed Test Results",
                "headers": ["Test", "Status", "Score Impact", "Result"],
                "rows": test_rows,
                "status_col": 1,
            })

        # Determine effective score for result (keep actual score)
        result_score = max(0, min(score, 100))

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=result_score,
            max_score=100,
            summary=summary,
            details={
                "grade": grade,
                "score": score,
                "tests_passed": tests_passed,
                "tests_failed": tests_failed,
                "tests_quantity": tests_quantity,
                "scan_id": analysis.get("scan_id"),
                "likelihood_indicator": analysis.get("likelihood_indicator", "N/A"),
            },
            recommendations=self._generate_recommendations(grade, score, scan_results),
            visuals=visuals,
            tables=tables,
        )

    def _extract_headers_status(self, scan_results: Optional[dict]) -> dict[str, bool]:
        """Extract security header presence from scan results."""
        if not scan_results:
            return {}

        # Key security headers to report on
        header_tests = {
            "content-security-policy": "Content-Security-Policy",
            "strict-transport-security": "Strict-Transport-Security (HSTS)",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "referrer-policy": "Referrer-Policy",
            "x-xss-protection": "X-XSS-Protection",
            "cookies": "Secure Cookies",
            "redirection": "HTTPS Redirection",
            "cross-origin-resource-sharing": "CORS Policy",
        }

        status = {}
        for test_key, display_name in header_tests.items():
            if test_key in scan_results:
                status[display_name] = scan_results[test_key].get("pass", False)

        return status

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        grade: str,
        score: int,
        scan_results: Optional[dict],
    ) -> list[dict[str, str]]:
        """Generate recommendations based on Observatory results."""
        recs = []

        # Grade-based recommendations
        if grade in ("F",):
            recs.append({
                "severity": "critical",
                "text": "The web server has critical security header deficiencies. "
                        "Multiple important security headers are missing.",
            })
        elif grade in ("D", "D+", "D-"):
            recs.append({
                "severity": "critical",
                "text": "The web server security configuration needs significant improvement. "
                        "Several key security headers are missing or misconfigured.",
            })
        elif grade.startswith("C"):
            recs.append({
                "severity": "warning",
                "text": "The web server has some security headers but key ones are missing. "
                        "Improvement is recommended.",
            })
        elif grade.startswith("B"):
            recs.append({
                "severity": "warning",
                "text": "The web server has a reasonable security configuration but "
                        "could be strengthened further.",
            })

        # Specific test recommendations
        if scan_results:
            failed_tests = {
                name: data for name, data in scan_results.items()
                if not data.get("pass", False)
            }

            if "content-security-policy" in failed_tests:
                recs.append({
                    "severity": "warning",
                    "text": "Implement a Content-Security-Policy (CSP) header to prevent "
                            "cross-site scripting (XSS) and data injection attacks.",
                })

            if "strict-transport-security" in failed_tests:
                recs.append({
                    "severity": "critical",
                    "text": "Implement HTTP Strict Transport Security (HSTS) to force "
                            "HTTPS connections and prevent downgrade attacks.",
                })

            if "x-content-type-options" in failed_tests:
                recs.append({
                    "severity": "warning",
                    "text": "Add 'X-Content-Type-Options: nosniff' header to prevent "
                            "MIME type sniffing attacks.",
                })

            if "x-frame-options" in failed_tests:
                recs.append({
                    "severity": "warning",
                    "text": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header "
                            "to prevent clickjacking attacks.",
                })

            if "referrer-policy" in failed_tests:
                recs.append({
                    "severity": "info",
                    "text": "Set a Referrer-Policy header to control how much referrer "
                            "information is shared with other sites.",
                })

            if "redirection" in failed_tests:
                recs.append({
                    "severity": "critical",
                    "text": "Ensure all HTTP requests are redirected to HTTPS to "
                            "protect data in transit.",
                })

        if not recs:
            recs.append({
                "severity": "info",
                "text": "Security headers are well configured. Continue monitoring "
                        "for any changes or new best practices.",
            })

        return recs
