"""Screenshot test runner using Playwright."""

import os
import subprocess
from pathlib import Path

from east.tests.base import TestResult, TestRunner


class ScreenshotTestRunner(TestRunner):
    """Capture a website screenshot via Playwright."""

    name = "screenshots"
    description = "Homepage screenshot capture via Playwright"

    @staticmethod
    def diagnose_playwright_prereqs() -> dict:
        diag = {
            "playwright_python": False,
            "browser_launch": False,
            "playwright_cli": shutil_which("playwright"),
            "python": shutil_which("python") or shutil_which("python3"),
            "playwright_browsers_path": os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""),
            "errors": [],
        }
        try:
            from playwright.sync_api import sync_playwright
            diag["playwright_python"] = True
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_content("<html><body><h1>EAST Doctor</h1></body></html>")
                browser.close()
            diag["browser_launch"] = True
        except Exception as exc:
            diag["errors"].append(str(exc))
        return diag

    def run(self) -> TestResult:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return self._create_error_result(
                "Playwright Python package is not installed. Install `playwright` in EAST venv and run "
                "`python -m playwright install --with-deps chromium`."
            )

        output_dir = Path("artifacts/screenshots")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{self.domain.replace('.', '_')}.png"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.goto(f"https://{self.domain}", timeout=45000, wait_until="networkidle")
                page.screenshot(path=str(output_path), full_page=True)
                browser.close()
        except Exception as exc:
            msg = str(exc)
            if "Executable doesn't exist" in msg or "Please run the following command" in msg:
                browsers_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "<default-user-cache>")
                return self._create_error_result(
                    "Playwright is installed but Chromium browser binaries are missing for the current EAST runtime user. "
                    f"Current PLAYWRIGHT_BROWSERS_PATH={browsers_path}. Install browsers with: "
                    "`python -m playwright install --with-deps chromium` "
                    "(or `playwright install chromium` if using global playwright CLI)."
                )
            return self._create_error_result(
                f"Failed to capture screenshot: {exc}. Ensure browser binaries are installed for the same user that runs EAST."
            )

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade="N/A",
            score=100,
            summary=f"Screenshot captured at {output_path}",
            details={
                "screenshot_path": str(output_path),
                "playwright_browsers_path": os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""),
            },
            tables=[
                {
                    "title": "Screenshot Artifact",
                    "headers": ["Field", "Value"],
                    "rows": [
                        ["Path", str(output_path)],
                        ["PLAYWRIGHT_BROWSERS_PATH", os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "(default)")],
                    ],
                }
            ],
            recommendations=[{"severity": "info", "text": "Review screenshot manually for visual security issues."}],
        )


def shutil_which(name: str) -> str | None:
    try:
        import shutil

        return shutil.which(name)
    except Exception:
        return None
