"""Performance test runner using Lighthouse CLI or PageSpeed API."""

import json
import os
import shutil
import subprocess
import tempfile
import shlex
from typing import Any

from east.tests.base import TestResult, TestRunner


class PerformanceTestRunner(TestRunner):
    """Measure web performance with local Lighthouse CLI."""

    name = "performance"
    description = "Web performance analysis via Lighthouse or PageSpeed"

    def __init__(self, domain: str, pagespeed_key: str = ""):
        super().__init__(domain)
        self.pagespeed_key = pagespeed_key

    def run(self) -> TestResult:
        try:
            return self._run_lighthouse_local()
        except Exception as exc:
            return self._create_error_result(str(exc))

    def _run_lighthouse_local(self) -> TestResult:
        with tempfile.NamedTemporaryFile(prefix="east-lighthouse-", suffix=".json", delete=False) as tmp:
            output_path = tmp.name

        cmd, diag = self._build_lighthouse_command(output_path)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        except Exception as exc:
            return self._create_error_result(
                f"Lighthouse failed to start: {exc}. {self._format_diagnostics(diag, cmd)}"
            )

        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "Unknown lighthouse error"
            return self._create_error_result(f"Lighthouse failed: {err}. {self._format_diagnostics(diag, cmd)}")

        if not os.path.exists(output_path):
            return self._create_error_result(
                "Lighthouse did not produce output JSON. Ensure Chrome/Chromium is installed and runnable. "
                f"{self._format_diagnostics(diag, cmd)}"
            )

        with open(output_path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)

        return self._parse_lighthouse_result(payload, source="Lighthouse Local")

    def _build_lighthouse_command(self, output_path: str) -> tuple[list[str], dict[str, Any]]:
        """Build cross-platform Lighthouse command with executable resolution."""
        node = shutil.which("node")
        npm = shutil.which("npm") or shutil.which("npm.cmd")
        profile_base = self._prepare_profile_dir()

        base_args = [
            f"https://{self.domain}",
            "--quiet",
            "--output=json",
            f"--output-path={output_path}",
            f"--chrome-flags={self._build_chrome_flags(profile_base)}",
            "--only-categories=performance,accessibility,best-practices,seo",
        ]

        diag = {
            "node_detected": bool(node),
            "npm_detected": bool(npm),
            "profile_dir": str(profile_base),
        }

        if os.name != "nt":
            lighthouse = shutil.which("lighthouse")
            if lighthouse:
                diag["executable"] = lighthouse
                return [lighthouse, *base_args], diag

            npx = shutil.which("npx")
            if npx:
                diag["executable"] = npx
                return [npx, "--yes", "lighthouse", *base_args], diag

            raise RuntimeError(
                "Node.js/npm was not found. Install Node.js LTS and Lighthouse (`npm i -g lighthouse`) "
                "or ensure `npx` is available in PATH."
            )

        lighthouse_cmd = shutil.which("lighthouse.cmd") or shutil.which("lighthouse.bat") or shutil.which("lighthouse.exe")
        if lighthouse_cmd:
            diag["executable"] = lighthouse_cmd
            return [lighthouse_cmd, *base_args], diag

        npx_cmd = shutil.which("npx.cmd") or shutil.which("npx.exe") or shutil.which("npx.bat")
        if npx_cmd:
            diag["executable"] = npx_cmd
            return [npx_cmd, "--yes", "lighthouse", *base_args], diag

        lighthouse_ps1 = shutil.which("lighthouse")
        if lighthouse_ps1 and lighthouse_ps1.lower().endswith(".ps1"):
            diag["executable"] = lighthouse_ps1
            raise RuntimeError(
                "Windows PATH resolves Lighthouse to a .ps1 shim, which cannot be launched reliably from Python. "
                "Install/repair npm shims so `lighthouse.cmd` or `npx.cmd` is available."
            )

        if not node or not npm:
            raise RuntimeError(
                "Node.js/npm was not found. Install Node.js LTS, reopen terminal, and rerun EAST."
            )

        raise RuntimeError(
            "Lighthouse CLI was not found as an executable shim. Install globally with `npm i -g lighthouse` "
            "or run with npm available so EAST can use `npx` automatically."
        )

    def _prepare_profile_dir(self) -> str:
        """Create a stable Chrome profile directory for Lighthouse runs."""
        if os.name == "nt":
            localappdata = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
            base_dir = os.path.join(localappdata, "EAST", "lighthouse_profiles", self.domain)
        else:
            base_dir = os.path.join(tempfile.gettempdir(), "east", "lighthouse_profiles", self.domain)

        cache_dir = os.path.join(base_dir, "cache")
        os.makedirs(cache_dir, exist_ok=True)
        return base_dir

    @staticmethod
    def _build_chrome_flags(profile_base: str) -> str:
        """Build Chrome flags string for stable headless Lighthouse runs."""
        cache_dir = os.path.join(profile_base, "cache")
        return (
            "--headless=new --disable-gpu --no-first-run --no-default-browser-check "
            f"--user-data-dir={shlex.quote(str(profile_base))} "
            f"--disk-cache-dir={shlex.quote(str(cache_dir))}"
        )

    @staticmethod
    def _format_diagnostics(diag: dict[str, Any], cmd: list[str]) -> str:
        """Build compact diagnostic context for subprocess failures."""
        command_preview = " ".join(shlex.quote(part) for part in cmd[:6])
        if len(cmd) > 6:
            command_preview += " ..."
        return (
            "Diagnostics: "
            f"executable={diag.get('executable', '<unresolved>')}; "
            f"node_detected={diag.get('node_detected')}; "
            f"npm_detected={diag.get('npm_detected')}; "
            f"cmd={command_preview}"
        )

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
