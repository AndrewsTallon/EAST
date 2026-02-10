"""Screenshot test runner using Playwright."""

from pathlib import Path

from east.tests.base import TestResult, TestRunner


class ScreenshotTestRunner(TestRunner):
    """Capture a website screenshot via Playwright."""

    name = "screenshots"
    description = "Homepage screenshot capture via Playwright"

    def run(self) -> TestResult:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return self._create_error_result(
                "Playwright is not installed. Install `playwright` and run `playwright install chromium`."
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
            return self._create_error_result(
                f"Failed to capture screenshot: {exc}. Ensure browser binaries are installed (`playwright install chromium`)."
            )

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade="N/A",
            score=100,
            summary=f"Screenshot captured at {output_path}",
            details={"screenshot_path": str(output_path)},
            tables=[
                {
                    "title": "Screenshot Artifact",
                    "headers": ["Field", "Value"],
                    "rows": [["Path", str(output_path)]],
                }
            ],
            recommendations=[{"severity": "info", "text": "Review screenshot manually for visual security issues."}],
        )
