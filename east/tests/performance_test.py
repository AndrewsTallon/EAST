"""Performance test runner using Lighthouse CLI or PageSpeed API."""

import json
import logging
import ntpath
import os
import shutil
import subprocess
import tempfile
import time
import shlex
from typing import Any

from east.tests.base import TestResult, TestRunner


LOGGER = logging.getLogger(__name__)


class PerformanceTestRunner(TestRunner):
    """Measure web performance with local Lighthouse CLI."""

    name = "performance"
    description = "Web performance analysis via Lighthouse or PageSpeed"

    _PRIMARY_CORE_WEB_VITALS = {
        "largest-contentful-paint": {
            "label": "LCP",
            "unit": "ms",
            "good": 2500,
            "needs_improvement": 4000,
            "interpretation": "Measures how quickly the largest above-the-fold content is rendered.",
            "degraded_causes": "Needs Improvement/Poor usually indicates slow server responses, redirects, heavy hero media, or render-blocking CSS/JS delaying paint.",
        },
        "interaction-to-next-paint": {
            "label": "INP",
            "unit": "ms",
            "good": 200,
            "needs_improvement": 500,
            "interpretation": "Measures interface responsiveness from user input to the next visual update.",
            "degraded_causes": "Needs Improvement/Poor usually points to long JavaScript tasks, main-thread contention, or excessive third-party scripts.",
        },
        "cumulative-layout-shift": {
            "label": "CLS",
            "unit": "unitless",
            "good": 0.1,
            "needs_improvement": 0.25,
            "interpretation": "Measures unexpected layout movement while the page loads or updates.",
            "degraded_causes": "Needs Improvement/Poor usually comes from unsized media, injected content, or late-loading fonts that reflow layout.",
        },
    }

    _SUPPORTING_METRICS = {
        "first-contentful-paint": {
            "label": "FCP",
            "unit": "ms",
            "good": 1800,
            "needs_improvement": 3000,
        },
        "total-blocking-time": {
            "label": "TBT",
            "unit": "ms",
            "good": 200,
            "needs_improvement": 600,
        },
    }

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
        run_env = self._build_lighthouse_env()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240, env=run_env)
        except Exception as exc:
            self._safe_cleanup(output_path)
            return self._create_error_result(
                f"Lighthouse failed to start: {exc}. {self._format_diagnostics(diag, cmd)}"
            )

        if proc.returncode != 0:
            payload = self._try_load_output_payload(output_path)
            err = proc.stderr.strip() or proc.stdout.strip() or "Unknown lighthouse error"
            if payload and self._is_cleanup_eperm(err):
                # Known Windows file-lock issue — results are captured, cleanup
                # is cosmetic.  Log at DEBUG to avoid cluttering output.
                LOGGER.debug(
                    "Lighthouse EPERM during temp dir cleanup (Windows file lock) — "
                    "results captured successfully at %s.",
                    output_path,
                )
                result = self._parse_lighthouse_result(payload, source="Lighthouse Local")
                self._safe_cleanup(output_path)
                return result

            self._safe_cleanup(output_path)
            return self._create_error_result(f"Lighthouse failed: {err}. {self._format_diagnostics(diag, cmd)}")

        payload = self._try_load_output_payload(output_path)
        if payload is None:
            self._safe_cleanup(output_path)
            return self._create_error_result(
                "Lighthouse did not produce output JSON. Ensure Chrome/Chromium is installed and runnable. "
                f"{self._format_diagnostics(diag, cmd)}"
            )

        result = self._parse_lighthouse_result(payload, source="Lighthouse Local")
        self._safe_cleanup(output_path)
        return result

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
        """Create a unique Chrome profile directory for this Lighthouse run.

        Uses PID + monotonic timestamp to avoid collisions across concurrent
        runs for the same domain.
        """
        unique_suffix = f"{os.getpid()}_{int(time.monotonic() * 1000)}"
        if os.name == "nt":
            localappdata = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
            base_dir = ntpath.join(
                localappdata, "EAST", "lighthouse_profiles",
                f"{self.domain}_{unique_suffix}",
            )
        else:
            base_dir = os.path.join(
                tempfile.gettempdir(), "east", "lighthouse_profiles",
                f"{self.domain}_{unique_suffix}",
            )

        cache_dir = os.path.join(base_dir, "cache")
        os.makedirs(cache_dir, exist_ok=True)
        return base_dir

    @staticmethod
    def _build_chrome_flags(profile_base: str) -> str:
        """Build Chrome flags string for stable headless Lighthouse runs."""
        cache_dir = os.path.join(profile_base, "cache")
        return (
            "--headless=new --disable-gpu --no-first-run --no-default-browser-check "
            f"--user-data-dir={profile_base} "
            f"--disk-cache-dir={cache_dir}"
        )

    @staticmethod
    def _is_cleanup_eperm(error_text: str) -> bool:
        lowered = error_text.lower()
        return "eperm" in lowered and "destroytmp" in lowered

    @staticmethod
    def _safe_cleanup(path: str) -> None:
        """Try to remove *path* with delayed retries for Windows file locks.

        Retries after 0.5s and 2s if the initial delete fails with a
        permission error.  Failures are logged at DEBUG level — cleanup is
        cosmetic and must never affect scan results.
        """
        if not path or not os.path.exists(path):
            return
        delays = [0, 0.5, 2.0]
        for i, delay in enumerate(delays):
            if delay > 0:
                time.sleep(delay)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)
                return
            except PermissionError:
                LOGGER.debug(
                    "Cleanup attempt %d/%d for %s failed (EPERM) — will %s.",
                    i + 1, len(delays), path,
                    "retry" if i < len(delays) - 1 else "give up",
                )
            except OSError as exc:
                LOGGER.debug("Cleanup of %s failed: %s — ignoring.", path, exc)
                return
        LOGGER.debug(
            "Could not clean up %s after %d attempts — leaving for manual cleanup.",
            path, len(delays),
        )

    @staticmethod
    def _try_load_output_payload(output_path: str) -> dict[str, Any] | None:
        if not os.path.exists(output_path):
            return None

        try:
            with open(output_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    def _build_lighthouse_env(self) -> dict[str, str] | None:
        if os.name != "nt":
            return None

        localappdata = os.environ.get("LOCALAPPDATA")
        if not localappdata:
            return None

        stable_tmp = ntpath.join(localappdata, "EAST", "tmp")
        os.makedirs(stable_tmp, exist_ok=True)
        env = os.environ.copy()
        env["TEMP"] = stable_tmp
        env["TMP"] = stable_tmp
        return env

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
        audits = payload.get("audits", {})
        perf = int((categories.get("performance", {}).get("score", 0) or 0) * 100)
        access = int((categories.get("accessibility", {}).get("score", 0) or 0) * 100)
        best = int((categories.get("best-practices", {}).get("score", 0) or 0) * 100)
        seo = int((categories.get("seo", {}).get("score", 0) or 0) * 100)
        overall = round((perf + access + best + seo) / 4)

        core_web_vitals_rows = self._build_core_web_vitals_rows(audits)
        supporting_metrics_rows = self._build_supporting_metrics_rows(audits)
        top_opportunities_rows = self._build_top_opportunities_rows(audits)

        tables = [
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
        ]

        if core_web_vitals_rows:
            tables.append(
                {
                    "title": "Core Web Vitals",
                    "headers": ["Metric", "Value", "Status", "Interpretation"],
                    "rows": core_web_vitals_rows,
                }
            )

        if supporting_metrics_rows:
            tables.append(
                {
                    "title": "Supporting Metrics",
                    "headers": ["Metric", "Value", "Status"],
                    "rows": supporting_metrics_rows,
                }
            )

        if top_opportunities_rows:
            tables.append(
                {
                    "title": "Top Performance Opportunities",
                    "headers": ["Opportunity", "Cause + Impact"],
                    "rows": top_opportunities_rows,
                }
            )

        context_note = (
            "Assessment Context: These Lighthouse metrics are lab-based simulations from a controlled test run. "
            "Real-user (field) performance may differ by device, network conditions, and geography."
        )

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            score=overall,
            max_score=100,
            grade=self._grade(overall),
            summary=f"Performance score {overall}/100 ({source}). {context_note}",
            details={
                "source": source,
                "performance": perf,
                "accessibility": access,
                "best_practices": best,
                "seo": seo,
            },
            tables=tables,
            recommendations=self._recommendations(core_web_vitals_rows),
        )

    def _build_core_web_vitals_rows(self, audits: dict[str, Any]) -> list[list[str]]:
        rows: list[list[str]] = []
        for audit_id, definition in self._PRIMARY_CORE_WEB_VITALS.items():
            audit = audits.get(audit_id, {})
            numeric_value = audit.get("numericValue")
            if numeric_value is None:
                continue

            status = self._metric_status(
                float(numeric_value),
                good=float(definition["good"]),
                needs_improvement=float(definition["needs_improvement"]),
            )

            rows.append(
                [
                    definition["label"],
                    self._format_metric_value(float(numeric_value), unit=definition["unit"]),
                    status,
                    self._metric_interpretation(status, definition["interpretation"], definition["degraded_causes"]),
                ]
            )

        return rows

    def _build_supporting_metrics_rows(self, audits: dict[str, Any]) -> list[list[str]]:
        rows: list[list[str]] = []
        for audit_id, definition in self._SUPPORTING_METRICS.items():
            audit = audits.get(audit_id, {})
            numeric_value = audit.get("numericValue")
            if numeric_value is None:
                continue

            rows.append(
                [
                    definition["label"],
                    self._format_metric_value(float(numeric_value), unit=definition["unit"]),
                    self._metric_status(
                        float(numeric_value),
                        good=float(definition["good"]),
                        needs_improvement=float(definition["needs_improvement"]),
                    ),
                ]
            )

        return rows

    @staticmethod
    def _metric_interpretation(status: str, interpretation: str, degraded_causes: str) -> str:
        if status == "Good":
            return interpretation
        return f"{interpretation} {degraded_causes}"

    @staticmethod
    def _metric_status(value: float, good: float, needs_improvement: float) -> str:
        if value <= good:
            return "Good"
        if value <= needs_improvement:
            return "Needs Improvement"
        return "Poor"

    @staticmethod
    def _format_metric_value(value: float, unit: str) -> str:
        if unit == "ms":
            if value >= 1000:
                return f"{value / 1000:.2f}s"
            return f"{int(round(value))}ms"
        if unit == "unitless":
            return f"{value:.3f}".rstrip("0").rstrip(".")
        return str(value)

    def _build_top_opportunities_rows(self, audits: dict[str, Any]) -> list[list[str]]:
        candidates: list[tuple[float, str, str]] = []

        for audit in audits.values():
            if not isinstance(audit, dict):
                continue

            score = audit.get("score")
            details = audit.get("details")
            if score is None or score >= 1 or not isinstance(details, dict):
                continue

            savings_ms = details.get("overallSavingsMs") or 0
            savings_bytes = details.get("overallSavingsBytes") or 0
            if savings_ms <= 0 and savings_bytes <= 0:
                continue

            title = audit.get("title") or "Untitled opportunity"
            impact = float(savings_ms) + (float(savings_bytes) / 1024)
            cause_impact = self._build_cause_impact_statement(
                audit_key=str(title),
                savings_ms=float(savings_ms),
                savings_bytes=float(savings_bytes),
            )
            candidates.append((impact, str(title), cause_impact))

        top_candidates = sorted(candidates, key=lambda item: item[0], reverse=True)[:3]
        return [[title, analysis] for _, title, analysis in top_candidates]

    @staticmethod
    def _format_savings(savings_ms: float, savings_bytes: float) -> str:
        segments: list[str] = []
        if savings_ms > 0:
            segments.append(f"{int(round(savings_ms))}ms")
        if savings_bytes > 0:
            segments.append(f"{int(round(savings_bytes / 1024))}KB")
        return " / ".join(segments)

    def _build_cause_impact_statement(self, audit_key: str, savings_ms: float, savings_bytes: float) -> str:
        key = audit_key.lower()
        likely_source = "asset delivery and main-thread contention"
        if "redirect" in key:
            likely_source = "redirect chains before final HTML response"
        elif "javascript" in key or "script" in key:
            likely_source = "large JavaScript payloads and execution cost"
        elif "render-block" in key or "render blocking" in key:
            likely_source = "render-blocking CSS/JS in the critical path"

        savings = self._format_savings(savings_ms=savings_ms, savings_bytes=savings_bytes)
        return f"• Cause: {likely_source}. • Impact: Lighthouse estimates recoverable latency/transfer of {savings}."

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
    def _recommendations(core_web_vitals_rows: list[list[str]]) -> list[dict[str, str]]:
        statuses = [row[2] for row in core_web_vitals_rows if len(row) >= 3]
        if any(status == "Poor" for status in statuses):
            return [{"severity": "critical", "text": "At least one Core Web Vital is Poor; targeted optimization is required before release confidence is high."}]
        if statuses and all(status == "Good" for status in statuses):
            return [{"severity": "info", "text": "All Core Web Vitals are Good; performance posture is healthy. Continue monitoring for regressions."}]
        return [{"severity": "warning", "text": "Core Web Vitals are mixed (Good/Needs Improvement); prioritize bottlenecks in critical rendering and JavaScript execution."}]
