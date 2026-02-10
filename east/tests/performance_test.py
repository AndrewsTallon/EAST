"""Performance test runner using Lighthouse CLI or PageSpeed API."""

import json
import shutil
import subprocess
from typing import Any

from east.tests.base import TestResult, TestRunner
from east.utils.http import get_json

PAGESPEED_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"


class PerformanceTestRunner(TestRunner):
    """Measure web performance with Lighthouse (local) or PageSpeed API."""

    name = "performance"
    description = "Web performance analysis via Lighthouse or PageSpeed"

    def __init__(self, domain: str, pagespeed_key: str = ""):
        super().__init__(domain)
        self.pagespeed_key = pagespeed_key

    def run(self) -> TestResult:
        try:
            if self.pagespeed_key:
                result = self._run_pagespeed_api()
                if result is not None:
                    return self._parse_pagespeed_result(result, source="PageSpeed API")

            if shutil.which("lighthouse") is None:
                return self._create_error_result(
                    "Lighthouse CLI not found. Install Node.js + lighthouse (`npm i -g lighthouse`) "
                    "or provide api_keys.google_pagespeed."
                )

            return self._run_lighthouse_local()
        except Exception as exc:
            return self._create_error_result(str(exc))

    def _run_pagespeed_api(self) -> dict[str, Any] | None:
        params = {
            "url": f"https://{self.domain}",
            "strategy": "mobile",
            "key": self.pagespeed_key,
            "category": ["performance", "accessibility", "best-practices", "seo"],
        }
        return get_json(PAGESPEED_ENDPOINT, params=params, timeout=90, retries=2)

    def _run_lighthouse_local(self) -> TestResult:
        cmd = [
            "lighthouse",
            f"https://{self.domain}",
            "--quiet",
            "--output=json",
            "--output-path=stdout",
            "--chrome-flags=--headless --no-sandbox --disable-dev-shm-usage",
            "--only-categories=performance,accessibility,best-practices,seo",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "Unknown lighthouse error"
            return self._create_error_result(f"Lighthouse failed: {err}")

        payload = json.loads(proc.stdout)
        return self._parse_lighthouse_result(payload, source="Lighthouse Local")

    def _parse_lighthouse_result(self, payload: dict[str, Any], source: str) -> TestResult:
        categories = payload.get("categories", {})
        perf = int((categories.get("performance", {}).get("score", 0) or 0) * 100)
        access = int((categories.get("accessibility", {}).get("score", 0) or 0) * 100)
        best = int((categories.get("best-practices", {}).get("score", 0) or 0) * 100)
        seo = int((categories.get("seo", {}).get("score", 0) or 0) * 100)
        overall = round((perf + access + best + seo) / 4)

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            score=overall,
            max_score=100,
            grade=self._grade(overall),
            summary=f"Performance score {overall}/100 ({source})",
            details={
                "source": source,
                "performance": perf,
                "accessibility": access,
                "best_practices": best,
                "seo": seo,
            },
            tables=[
                {
                    "title": "Performance Metrics",
                    "headers": ["Category", "Score"],
                    "rows": [
                        ["Performance", f"{perf}/100"],
                        ["Accessibility", f"{access}/100"],
                        ["Best Practices", f"{best}/100"],
                        ["SEO", f"{seo}/100"],
                        ["Overall", f"{overall}/100"],
                    ],
                }
            ],
            recommendations=self._recommendations(overall),
        )

    def _parse_pagespeed_result(self, payload: dict[str, Any], source: str) -> TestResult:
        lighthouse = payload.get("lighthouseResult", {})
        return self._parse_lighthouse_result(lighthouse, source=source)

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    @staticmethod
    def _recommendations(score: int) -> list[dict[str, str]]:
        if score < 60:
            return [{"severity": "critical", "text": "Improve page performance: reduce JS/CSS and optimize assets."}]
        if score < 80:
            return [{"severity": "warning", "text": "Improve Core Web Vitals by optimizing render-blocking resources."}]
        return [{"severity": "info", "text": "Performance posture is healthy; continue monitoring."}]
