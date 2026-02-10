"""Email authentication test runner for EAST tool (SPF, DKIM, DMARC)."""

import io
import logging
import re
from typing import Any, Optional

import dns.resolver
import dns.exception

from east.tests.base import TestRunner, TestResult
from east.visuals.badges import create_grade_badge, create_status_badge
from east.visuals.charts import create_security_headers_chart

logger = logging.getLogger(__name__)

RESOLVER_TIMEOUT = 10
RESOLVER_LIFETIME = 30

# Common DKIM selectors to try
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "mail", "dkim", "smtp",
    "s1", "s2", "sig1",
    "mandrill", "everlytickey1", "everlytickey2",
    "cm", "mxvault",
]


class EmailAuthTestRunner(TestRunner):
    """Run email authentication checks (SPF, DKIM, DMARC)."""

    name = "email_auth"
    description = "Email Authentication (SPF, DKIM, DMARC)"

    def __init__(self, domain: str):
        super().__init__(domain)
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.timeout = RESOLVER_TIMEOUT
        self.resolver.lifetime = RESOLVER_LIFETIME
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    def run(self) -> TestResult:
        """Execute email authentication checks."""
        try:
            spf_result = self._check_spf()
            dkim_result = self._check_dkim()
            dmarc_result = self._check_dmarc()

            return self._build_result(spf_result, dkim_result, dmarc_result)

        except Exception as e:
            logger.exception("Email auth test failed for %s", self.domain)
            return self._create_error_result(str(e))

    def _check_spf(self) -> dict[str, Any]:
        """Check SPF record for the domain."""
        result = {
            "found": False,
            "record": "",
            "valid": False,
            "mechanisms": [],
            "policy": "",
            "issues": [],
        }

        try:
            answers = self.resolver.resolve(self.domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["found"] = True
                    result["record"] = txt
                    result.update(self._parse_spf(txt))
                    break

        except dns.resolver.NoAnswer:
            result["issues"].append("No TXT records found")
        except dns.resolver.NXDOMAIN:
            result["issues"].append("Domain does not exist")
        except dns.exception.Timeout:
            result["issues"].append("DNS query timed out")
        except Exception as e:
            result["issues"].append(f"Error: {e}")

        return result

    def _parse_spf(self, record: str) -> dict[str, Any]:
        """Parse and validate an SPF record."""
        parsed = {
            "valid": True,
            "mechanisms": [],
            "policy": "neutral",
            "issues": [],
        }

        parts = record.split()
        for part in parts[1:]:  # Skip 'v=spf1'
            part_lower = part.lower()

            if part_lower in ("-all", "~all", "+all", "?all"):
                policy_map = {
                    "-all": "reject",
                    "~all": "softfail",
                    "+all": "pass_all",
                    "?all": "neutral",
                }
                parsed["policy"] = policy_map.get(part_lower, "unknown")
                parsed["mechanisms"].append(part)

                if part_lower == "+all":
                    parsed["issues"].append(
                        "SPF policy uses '+all' which allows any sender. "
                        "This effectively disables SPF protection."
                    )
                    parsed["valid"] = False
            else:
                parsed["mechanisms"].append(part)

        # Check for too many DNS lookups (max 10)
        lookup_mechanisms = ["include:", "a:", "mx:", "ptr:", "exists:", "redirect="]
        lookup_count = sum(
            1 for m in parsed["mechanisms"]
            if any(m.lower().startswith(lm) for lm in lookup_mechanisms)
        )
        if lookup_count > 10:
            parsed["issues"].append(
                f"SPF record has {lookup_count} DNS lookups (max 10). "
                "This may cause SPF validation failures."
            )

        return parsed

    def _check_dkim(self) -> dict[str, Any]:
        """Check for DKIM records using common selectors."""
        result = {
            "found": False,
            "selectors_found": [],
            "records": {},
            "issues": [],
        }

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            try:
                answers = self.resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "k=" in txt or "p=" in txt:
                        result["found"] = True
                        result["selectors_found"].append(selector)
                        result["records"][selector] = txt
                        self.logger.info("DKIM found with selector '%s' for %s", selector, self.domain)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
            except Exception:
                continue

        if not result["found"]:
            # Also try CNAME records (some providers use CNAME for DKIM)
            for selector in DKIM_SELECTORS[:5]:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                try:
                    answers = self.resolver.resolve(dkim_domain, "CNAME")
                    if answers:
                        result["found"] = True
                        result["selectors_found"].append(f"{selector} (CNAME)")
                        result["records"][selector] = f"CNAME -> {answers[0]}"
                except Exception:
                    continue

        if not result["found"]:
            result["issues"].append(
                "No DKIM records found with common selectors. "
                "DKIM may use a custom selector not in our search list."
            )

        return result

    def _check_dmarc(self) -> dict[str, Any]:
        """Check DMARC record for the domain."""
        result = {
            "found": False,
            "record": "",
            "policy": "",
            "subdomain_policy": "",
            "rua": "",
            "ruf": "",
            "pct": 100,
            "issues": [],
        }

        dmarc_domain = f"_dmarc.{self.domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    result["found"] = True
                    result["record"] = txt
                    result.update(self._parse_dmarc(txt))
                    break

        except dns.resolver.NoAnswer:
            result["issues"].append("No DMARC record found")
        except dns.resolver.NXDOMAIN:
            result["issues"].append("No DMARC record found")
        except dns.exception.Timeout:
            result["issues"].append("DNS query timed out")
        except Exception as e:
            result["issues"].append(f"Error: {e}")

        return result

    def _parse_dmarc(self, record: str) -> dict[str, Any]:
        """Parse a DMARC record."""
        parsed = {
            "policy": "none",
            "subdomain_policy": "",
            "rua": "",
            "ruf": "",
            "pct": 100,
            "issues": [],
        }

        parts = record.split(";")
        for part in parts:
            part = part.strip()
            if part.startswith("p="):
                parsed["policy"] = part[2:].strip()
            elif part.startswith("sp="):
                parsed["subdomain_policy"] = part[3:].strip()
            elif part.startswith("rua="):
                parsed["rua"] = part[4:].strip()
            elif part.startswith("ruf="):
                parsed["ruf"] = part[4:].strip()
            elif part.startswith("pct="):
                try:
                    parsed["pct"] = int(part[4:].strip())
                except ValueError:
                    pass

        # Check for weak policies
        if parsed["policy"] == "none":
            parsed["issues"].append(
                "DMARC policy is set to 'none' (monitoring only). "
                "Consider upgrading to 'quarantine' or 'reject'."
            )

        if parsed["pct"] < 100:
            parsed["issues"].append(
                f"DMARC only applies to {parsed['pct']}% of messages. "
                "Consider setting pct=100 for full coverage."
            )

        if not parsed["rua"]:
            parsed["issues"].append(
                "No aggregate report URI (rua) specified. "
                "Add rua to receive DMARC aggregate reports."
            )

        return parsed

    def _build_result(
        self,
        spf: dict[str, Any],
        dkim: dict[str, Any],
        dmarc: dict[str, Any],
    ) -> TestResult:
        """Build a TestResult from email auth checks."""
        # Score calculation
        score = 0
        max_score = 100

        if spf["found"] and spf.get("valid", False):
            score += 35
            if spf.get("policy") in ("reject", "softfail"):
                score += 5
        elif spf["found"]:
            score += 15

        if dkim["found"]:
            score += 30

        if dmarc["found"]:
            score += 20
            policy = dmarc.get("policy", "none")
            if policy == "reject":
                score += 10
            elif policy == "quarantine":
                score += 5

        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "A-"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        # Visuals
        visuals = {}
        visuals["grade_badge"] = create_grade_badge(grade, label="Email Auth Grade")

        auth_status = {
            "SPF Record": spf["found"],
            "SPF Valid Policy": spf.get("valid", False) and spf.get("policy") in ("reject", "softfail"),
            "DKIM Record": dkim["found"],
            "DMARC Record": dmarc["found"],
            "DMARC Enforcement": dmarc.get("policy") in ("quarantine", "reject"),
        }
        visuals["auth_status_chart"] = create_security_headers_chart(auth_status)

        # Summary
        summary = (
            f"Email Auth Grade: {grade} | "
            f"SPF: {'Found' if spf['found'] else 'Missing'} | "
            f"DKIM: {'Found' if dkim['found'] else 'Not Found'} | "
            f"DMARC: {'Found' if dmarc['found'] else 'Missing'}"
        )

        # Tables
        tables = []

        # SPF details
        spf_rows = [
            ["SPF Record Found", "Pass" if spf["found"] else "Fail"],
            ["SPF Record", spf.get("record", "N/A") or "N/A"],
            ["SPF Policy", spf.get("policy", "N/A") or "N/A"],
            ["Mechanisms Count", str(len(spf.get("mechanisms", [])))],
        ]
        tables.append({
            "title": "SPF (Sender Policy Framework)",
            "headers": ["Property", "Value"],
            "rows": spf_rows,
        })

        # DKIM details
        dkim_rows = [
            ["DKIM Record Found", "Pass" if dkim["found"] else "Fail"],
            ["Selectors Found", ", ".join(dkim.get("selectors_found", [])) or "None"],
        ]
        for selector, record in dkim.get("records", {}).items():
            truncated = record[:80] + "..." if len(record) > 80 else record
            dkim_rows.append([f"Selector: {selector}", truncated])
        tables.append({
            "title": "DKIM (DomainKeys Identified Mail)",
            "headers": ["Property", "Value"],
            "rows": dkim_rows,
        })

        # DMARC details
        dmarc_rows = [
            ["DMARC Record Found", "Pass" if dmarc["found"] else "Fail"],
            ["DMARC Record", dmarc.get("record", "N/A") or "N/A"],
            ["Policy", dmarc.get("policy", "N/A") or "N/A"],
            ["Subdomain Policy", dmarc.get("subdomain_policy", "N/A") or "N/A"],
            ["Report URI (rua)", dmarc.get("rua", "N/A") or "N/A"],
            ["Percentage", f"{dmarc.get('pct', 'N/A')}%"],
        ]
        tables.append({
            "title": "DMARC (Domain-based Message Authentication)",
            "headers": ["Property", "Value"],
            "rows": dmarc_rows,
        })

        # Recommendations
        recommendations = self._generate_recommendations(spf, dkim, dmarc)

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=score,
            max_score=max_score,
            summary=summary,
            details={
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
            },
            recommendations=recommendations,
            visuals=visuals,
            tables=tables,
        )

    def _generate_recommendations(
        self,
        spf: dict[str, Any],
        dkim: dict[str, Any],
        dmarc: dict[str, Any],
    ) -> list[dict[str, str]]:
        """Generate email authentication recommendations."""
        recs = []

        # SPF recommendations
        if not spf["found"]:
            recs.append({
                "severity": "critical",
                "text": "No SPF record found. Implement SPF to prevent email spoofing. "
                        "Add a TXT record like: v=spf1 include:_spf.google.com ~all",
            })
        else:
            for issue in spf.get("issues", []):
                recs.append({"severity": "warning", "text": issue})

        # DKIM recommendations
        if not dkim["found"]:
            recs.append({
                "severity": "warning",
                "text": "No DKIM records found with common selectors. Ensure DKIM is "
                        "configured with your email provider to authenticate outgoing messages.",
            })

        # DMARC recommendations
        if not dmarc["found"]:
            recs.append({
                "severity": "critical",
                "text": "No DMARC record found. Implement DMARC to protect against email "
                        "spoofing. Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
            })
        else:
            for issue in dmarc.get("issues", []):
                severity = "warning" if "none" in issue.lower() else "info"
                recs.append({"severity": severity, "text": issue})

        if not recs:
            recs.append({
                "severity": "info",
                "text": "Email authentication configuration is solid. All three protocols "
                        "(SPF, DKIM, DMARC) are properly configured.",
            })

        return recs
