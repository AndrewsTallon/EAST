"""Open ports test runner using nmap."""

import shutil
import subprocess

from east.tests.base import TestResult, TestRunner


class OpenPortsTestRunner(TestRunner):
    """Scan common TCP ports with nmap."""

    name = "open_ports"
    description = "Open ports discovery via nmap"

    def run(self) -> TestResult:
        if shutil.which("nmap") is None:
            return self._create_error_result(
                "nmap is not installed. Install nmap to enable open ports scanning."
            )

        try:
            cmd = ["nmap", "-Pn", "-T4", "--top-ports", "100", self.domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if proc.returncode not in (0, 1):
                return self._create_error_result(proc.stderr.strip() or "nmap failed")

            open_ports = []
            for line in proc.stdout.splitlines():
                if "/tcp" in line and " open " in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        open_ports.append((parts[0], parts[2]))

            score = max(0, 100 - (len(open_ports) * 10))
            rows = [[port, service] for port, service in open_ports] or [["-", "No open top-100 TCP ports detected"]]

            return TestResult(
                test_name=self.name,
                domain=self.domain,
                success=True,
                grade=self._grade(len(open_ports)),
                score=score,
                summary=f"Detected {len(open_ports)} open port(s) in top 100 TCP ports.",
                details={"open_ports": [{"port": p, "service": s} for p, s in open_ports]},
                tables=[
                    {
                        "title": "Open Ports",
                        "headers": ["Port", "Service"],
                        "rows": rows,
                    }
                ],
                recommendations=self._recommendations(open_ports),
            )
        except subprocess.TimeoutExpired:
            return self._create_error_result("nmap scan timed out")

    @staticmethod
    def _grade(open_count: int) -> str:
        if open_count == 0:
            return "A"
        if open_count <= 2:
            return "B"
        if open_count <= 5:
            return "C"
        if open_count <= 10:
            return "D"
        return "F"

    @staticmethod
    def _recommendations(open_ports: list[tuple[str, str]]) -> list[dict[str, str]]:
        if not open_ports:
            return [{"severity": "info", "text": "No unexpected ports detected in top-100 scan."}]
        recs = [{"severity": "warning", "text": "Review exposed services and restrict unnecessary ports."}]
        risky = [p for p, _ in open_ports if p.startswith(("21/", "23/", "3389/"))]
        if risky:
            recs.append({"severity": "critical", "text": f"Potentially risky ports exposed: {', '.join(risky)}."})
        return recs
