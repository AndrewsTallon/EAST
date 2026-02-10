"""Cookie security test runner."""

import requests

from east.tests.base import TestResult, TestRunner


class CookiesTestRunner(TestRunner):
    """Analyze cookie security attributes."""

    name = "cookies"
    description = "Cookie security flags analysis"

    def run(self) -> TestResult:
        try:
            resp = requests.get(f"https://{self.domain}", timeout=25, allow_redirects=True)
            cookies = list(resp.cookies)

            if not cookies:
                return TestResult(
                    test_name=self.name,
                    domain=self.domain,
                    success=True,
                    grade="A",
                    score=100,
                    summary="No cookies were observed in the HTTP response.",
                    details={"cookie_count": 0},
                    recommendations=[{"severity": "info", "text": "No cookies detected during scan."}],
                )

            secure = httponly = samesite = 0
            rows = []
            for c in cookies:
                rest = c._rest if hasattr(c, "_rest") else {}
                has_secure = bool(c.secure)
                has_httponly = "HttpOnly" in rest or "httponly" in {str(k).lower() for k in rest.keys()}
                has_samesite = any(str(k).lower() == "samesite" for k in rest.keys())

                secure += int(has_secure)
                httponly += int(has_httponly)
                samesite += int(has_samesite)

                rows.append([
                    c.name,
                    "Yes" if has_secure else "No",
                    "Yes" if has_httponly else "No",
                    "Yes" if has_samesite else "No",
                    c.domain or self.domain,
                ])

            total = len(cookies)
            ratio = (secure + httponly + samesite) / (total * 3)
            score = round(ratio * 100)

            return TestResult(
                test_name=self.name,
                domain=self.domain,
                success=True,
                grade=self._grade(score),
                score=score,
                summary=f"Detected {total} cookie(s). Security flag coverage: {score}%.",
                details={
                    "cookie_count": total,
                    "secure_count": secure,
                    "httponly_count": httponly,
                    "samesite_count": samesite,
                },
                tables=[
                    {
                        "title": "Cookie Security Flags",
                        "headers": ["Cookie", "Secure", "HttpOnly", "SameSite", "Domain"],
                        "rows": rows,
                    }
                ],
                recommendations=self._recommendations(score),
            )
        except requests.RequestException as exc:
            return self._create_error_result(f"Cookie check failed: {exc}")

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    @staticmethod
    def _recommendations(score: int) -> list[dict[str, str]]:
        if score < 60:
            return [{"severity": "critical", "text": "Set Secure, HttpOnly, and SameSite on all session cookies."}]
        if score < 85:
            return [{"severity": "warning", "text": "Harden cookie flags for any cookie missing Secure/HttpOnly/SameSite."}]
        return [{"severity": "info", "text": "Cookie security flags look well configured."}]
