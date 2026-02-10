"""DNS test runner for EAST tool."""

import io
import logging
from typing import Any, Optional

import dns.resolver
import dns.rdatatype
import dns.dnssec
import dns.name
import dns.query
import dns.message

from east.tests.base import TestRunner, TestResult
from east.visuals.badges import create_grade_badge, create_status_badge
from east.visuals.charts import create_security_headers_chart

logger = logging.getLogger(__name__)

# Common DNS record types to check
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]

RESOLVER_TIMEOUT = 10
RESOLVER_LIFETIME = 30


class DNSTestRunner(TestRunner):
    """Run DNS record lookups and DNSSEC validation."""

    name = "dns_lookup"
    description = "DNS Records & DNSSEC Validation"

    def __init__(self, domain: str):
        super().__init__(domain)
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.timeout = RESOLVER_TIMEOUT
        self.resolver.lifetime = RESOLVER_LIFETIME
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    def run(self) -> TestResult:
        """Execute DNS lookups and DNSSEC validation."""
        try:
            records = self._lookup_all_records()
            dnssec_valid = self._check_dnssec()
            ns_records = records.get("NS", [])
            mx_records = records.get("MX", [])

            return self._build_result(records, dnssec_valid, ns_records, mx_records)

        except Exception as e:
            logger.exception("DNS test failed for %s", self.domain)
            return self._create_error_result(str(e))

    def _lookup_all_records(self) -> dict[str, list[str]]:
        """Look up all common DNS record types."""
        records: dict[str, list[str]] = {}

        for rtype in RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                record_list = []
                for rdata in answers:
                    record_list.append(str(rdata))
                records[rtype] = record_list
                self.logger.info("Found %d %s records for %s", len(record_list), rtype, self.domain)
            except dns.resolver.NoAnswer:
                self.logger.debug("No %s records for %s", rtype, self.domain)
            except dns.resolver.NXDOMAIN:
                self.logger.warning("Domain %s does not exist", self.domain)
                break
            except dns.resolver.NoNameservers:
                self.logger.warning("No nameservers for %s (%s)", self.domain, rtype)
            except dns.exception.Timeout:
                self.logger.warning("Timeout querying %s for %s", rtype, self.domain)
            except Exception as e:
                self.logger.debug("Error querying %s for %s: %s", rtype, self.domain, e)

        return records

    def _check_dnssec(self) -> bool:
        """Check if DNSSEC is enabled and valid for the domain."""
        try:
            # Query for DNSKEY records
            name = dns.name.from_text(self.domain)
            request = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.udp(request, "8.8.8.8", timeout=RESOLVER_TIMEOUT)

            # Check if we got DNSKEY records with the AD (Authenticated Data) flag
            if response.flags & dns.flags.AD:
                self.logger.info("DNSSEC validated for %s (AD flag set)", self.domain)
                return True

            # Also check if DNSKEY records exist
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    self.logger.info("DNSKEY records found for %s", self.domain)
                    return True

            # Try querying with a DNSSEC-validating resolver
            request = dns.message.make_query(name, dns.rdatatype.A, want_dnssec=True)
            request.flags |= dns.flags.AD
            response = dns.query.udp(request, "8.8.8.8", timeout=RESOLVER_TIMEOUT)

            if response.flags & dns.flags.AD:
                return True

            return False

        except Exception as e:
            self.logger.debug("DNSSEC check failed for %s: %s", self.domain, e)
            return False

    def _build_result(
        self,
        records: dict[str, list[str]],
        dnssec_valid: bool,
        ns_records: list[str],
        mx_records: list[str],
    ) -> TestResult:
        """Build a TestResult from DNS lookup data."""
        # Determine grade based on findings
        has_a = bool(records.get("A"))
        has_aaaa = bool(records.get("AAAA"))
        has_mx = bool(records.get("MX"))
        has_ns = bool(records.get("NS"))

        score = 0
        max_score = 100

        if has_a:
            score += 20
        if has_aaaa:
            score += 15
        if has_mx:
            score += 15
        if has_ns:
            score += 20
        if dnssec_valid:
            score += 30

        # Grade mapping
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "A-"
        elif score >= 70:
            grade = "B+"
        elif score >= 55:
            grade = "B"
        elif score >= 40:
            grade = "C"
        else:
            grade = "D"

        # Generate visuals
        visuals = {}
        visuals["grade_badge"] = create_grade_badge(grade, label="DNS Grade")

        # DNSSEC status chart
        dns_checks = {
            "A Records": has_a,
            "AAAA Records (IPv6)": has_aaaa,
            "MX Records (Mail)": has_mx,
            "NS Records": has_ns,
            "DNSSEC Enabled": dnssec_valid,
        }
        visuals["dns_status_chart"] = create_security_headers_chart(dns_checks)

        # Build summary
        record_count = sum(len(v) for v in records.values())
        summary = (
            f"DNS Grade: {grade} | "
            f"Records Found: {record_count} | "
            f"DNSSEC: {'Enabled' if dnssec_valid else 'Not Detected'}"
        )

        # Build tables
        tables = []

        # DNS records table
        dns_rows = []
        for rtype in RECORD_TYPES:
            recs = records.get(rtype, [])
            if recs:
                for rec in recs:
                    dns_rows.append([rtype, rec])
            else:
                dns_rows.append([rtype, "No records found"])

        tables.append({
            "title": "DNS Records",
            "headers": ["Record Type", "Value"],
            "rows": dns_rows,
        })

        # DNSSEC status table
        dnssec_rows = [
            ["DNSSEC Validation", "Valid" if dnssec_valid else "Not Supported"],
            ["IPv6 Support (AAAA)", "Present" if has_aaaa else "Missing"],
        ]
        tables.append({
            "title": "DNS Security",
            "headers": ["Check", "Status"],
            "rows": dnssec_rows,
            "status_col": 1,
        })

        # Recommendations
        recommendations = self._generate_recommendations(
            has_a, has_aaaa, has_mx, has_ns, dnssec_valid
        )

        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=True,
            grade=grade,
            score=score,
            max_score=max_score,
            summary=summary,
            details={
                "records": records,
                "dnssec_valid": dnssec_valid,
                "record_count": record_count,
            },
            recommendations=recommendations,
            visuals=visuals,
            tables=tables,
        )

    def _generate_recommendations(
        self,
        has_a: bool,
        has_aaaa: bool,
        has_mx: bool,
        has_ns: bool,
        dnssec_valid: bool,
    ) -> list[dict[str, str]]:
        """Generate DNS recommendations."""
        recs = []

        if not has_a:
            recs.append({
                "severity": "critical",
                "text": "No A records found. The domain may not resolve correctly.",
            })

        if not has_aaaa:
            recs.append({
                "severity": "info",
                "text": "No AAAA (IPv6) records found. Consider adding IPv6 support "
                        "for improved connectivity and future-readiness.",
            })

        if not has_mx:
            recs.append({
                "severity": "warning",
                "text": "No MX records found. Email delivery to this domain may fail "
                        "or rely on A record fallback.",
            })

        if not has_ns:
            recs.append({
                "severity": "critical",
                "text": "No NS records found. This may indicate DNS delegation issues.",
            })

        if not dnssec_valid:
            recs.append({
                "severity": "warning",
                "text": "DNSSEC is not enabled. Implement DNSSEC to protect against DNS "
                        "spoofing and cache poisoning attacks.",
            })

        if not recs:
            recs.append({
                "severity": "info",
                "text": "DNS configuration looks healthy. Continue monitoring for "
                        "any changes or issues.",
            })

        return recs
