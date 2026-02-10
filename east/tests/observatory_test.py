"""Mozilla Observatory test runner for EAST tool.

Uses the MDN HTTP Observatory v2 API:
https://observatory-api.mdn.mozilla.net/api/v2/scan
"""

import io
import logging
from typing import Any, Optional

from east.tests.base import TestRunner, TestResult
from east.utils.http import post_json, check_api_health, DEFAULT_HEADERS
from east.visuals.badges import create_grade_badge, create_score_gauge

logger = logging.getLogger(__name__)

# MDN Observatory v2 API
OBSERVATORY_API = "https://observatory-api.mdn.mozilla.net/api/v2"
SCAN_ENDPOINT = f"{OBSERVATORY_API}/scan"


class MozillaObservatoryTestRunner(TestRunner):
    """Run security analysis using MDN HTTP Observatory v2 API."""

    name = "mozilla_observatory"
    description = "Mozilla HTTP Observatory Security Analysis"

    def run(self) -> TestResult:
        """Execute Mozilla Observatory scan and return results."""
        try:
            # v2 API: single POST returns results synchronously
            # (or cached results if scanned within the last 60s)
            self.logger.info("Scanning %s via Observatory v2 API...", self.domain)

            data = post_json(
                SCAN_ENDPOINT,
                params={"host": self.domain},
                timeout=60,
                retries=4,
                overload_statuses={429, 502, 503, 529},
                overload_backoff_schedule=[5, 15, 30, 60],
                jitter=True,
            )

            if data is None:
                return self._create_error_result(
                    "Mozilla Observatory API returned no data. "
                    "The service may be temporarily unavailable."
                )

            # Check for error in response
            if data.get("error"):
                return self._create_error_result(
                    f"Observatory error: {data.get('error')} — "
                    f"{data.get('message', '')}"
                )

            return self._parse_results(data)

        except Exception as e:
            logger.exception("Mozilla Observatory test failed for %s", self.domain)
            return self._create_error_result(str(e))

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _parse_results(self, data: dict) -> TestResult:
        """Parse Observatory v2 response into a TestResult."""
        grade = data.get("grade", "N/A")
        score = data.get("score", 0)
        tests_passed = data.get("tests_passed", 0)
        tests_failed = data.get("tests_failed", 0)
        tests_quantity = data.get("tests_quantity", 0)
        scan_id = data.get("id")
        details_url = data.get("details_url", "")

        # Generate visuals
        visuals = {}

        visuals["grade_badge"] = create_grade_badge(grade, label="Observatory Grade")

        # Observatory scores can exceed 100 with bonus points; cap display
        display_score = min(score, 100) if score >= 0 else 0
        visuals["score_gauge"] = create_score_gauge(
            display_score, max_score=100, label="Security Score"
        )

        # Summary
        summary = (
            f"Mozilla Observatory Grade: {grade} | "
            f"Score: {score}/100 | "
            f"Tests Passed: {tests_passed}/{tests_quantity}"
        )

        # Tables
        tables = []

        overview_rows = [
            ["Grade", grade],
            ["Score", f"{score}/100"],
            ["Tests Passed", str(tests_passed)],
            ["Tests Failed", str(tests_failed)],
            ["Total Tests", str(tests_quantity)],
            ["Scan ID", str(scan_id) if scan_id else "N/A"],
        ]
        if details_url:
            overview_rows.append(["Full Report", details_url])
        tables.append({
            "title": "Observatory Overview",
            "headers": ["Metric", "Value"],
            "rows": overview_rows,
        })

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
                "scan_id": scan_id,
                "details_url": details_url,
            },
            recommendations=self._generate_recommendations(grade, score),
            visuals=visuals,
            tables=tables,
        )

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        grade: str,
        score: int,
    ) -> list[dict[str, str]]:
        """Generate recommendations based on Observatory results."""
        recs = []

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

        # General recommendations based on score thresholds
        if score < 50:
            recs.append({
                "severity": "critical",
                "text": "Implement HTTP Strict Transport Security (HSTS) to force "
                        "HTTPS connections and prevent downgrade attacks.",
            })
            recs.append({
                "severity": "warning",
                "text": "Implement a Content-Security-Policy (CSP) header to prevent "
                        "cross-site scripting (XSS) and data injection attacks.",
            })
            recs.append({
                "severity": "warning",
                "text": "Add 'X-Content-Type-Options: nosniff' and "
                        "'X-Frame-Options: DENY' headers.",
            })
        elif score < 75:
            recs.append({
                "severity": "warning",
                "text": "Review missing security headers. Consider adding "
                        "Content-Security-Policy, Referrer-Policy, and "
                        "Permissions-Policy headers.",
            })

        if not recs:
            recs.append({
                "severity": "info",
                "text": "Security headers are well configured. Continue monitoring "
                        "for any changes or new best practices.",
            })

        return recs
