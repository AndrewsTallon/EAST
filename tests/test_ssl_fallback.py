"""Regression tests for SSL Labs fallback to local TLS probing.

Asserts that the report-facing ``TestResult`` structure is identical
regardless of whether SSL Labs or the local fallback engine produced the
data — keeping the report rendering code unchanged.
"""

import io
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

from east.tests.ssl_test import SSLLabsTestRunner
from east.tests.base import TestResult


# ── Fixtures ──────────────────────────────────────────────────────────────

FAKE_SSLLABS_API_RESPONSE = {
    "status": "READY",
    "endpoints": [
        {
            "ipAddress": "93.184.216.34",
            "serverName": "example.com",
            "grade": "A",
            "gradeTrustIgnored": "A",
            "hasWarnings": False,
            "details": {
                "certChains": [{"certIds": ["abc123"]}],
                "certs": [
                    {
                        "commonNames": ["example.com"],
                        "issuerLabel": "Let's Encrypt Authority X3",
                        "sigAlg": "SHA256withRSA",
                        "keyAlg": "RSA",
                        "keySize": 2048,
                        "notBefore": 1700000000000,  # 2023-11-14
                        "notAfter": 1800000000000,  # 2027-01-15
                    }
                ],
                "protocols": [
                    {"name": "TLS", "version": "1.2"},
                    {"name": "TLS", "version": "1.3"},
                ],
                "heartbleed": False,
                "poodleTls": 0,
                "robotResult": 0,
                "ticketbleed": 0,
                "openSslCcs": 0,
                "openSSLLuckyMinus20": 0,
                "freak": False,
                "logjam": False,
                "drownVulnerable": False,
            },
        }
    ],
}

FAKE_LOCAL_PROBE_RESULT = {
    "tool": "openssl",
    "grade": "A",
    "certificate": {
        "subject": "example.com",
        "issuer": "Let's Encrypt Authority X3",
        "not_before": datetime(2023, 11, 14, tzinfo=timezone.utc),
        "not_after": datetime(2027, 1, 15, tzinfo=timezone.utc),
        "not_before_str": "2023-11-14 00:00 UTC",
        "not_after_str": "2027-01-15 00:00 UTC",
        "key_alg": "RSA",
        "key_size": "2048",
        "sig_alg": "SHA256withRSA",
    },
    "protocols": {
        "SSL 2.0": False,
        "SSL 3.0": False,
        "TLS 1.0": False,
        "TLS 1.1": False,
        "TLS 1.2": True,
        "TLS 1.3": True,
    },
    "vulnerabilities": {
        "Heartbleed": False,
        "POODLE (TLS)": False,
        "ROBOT": False,
        "Ticketbleed": False,
        "OpenSSL CCS": False,
        "LUCKY13": False,
        "FREAK": False,
        "Logjam": False,
        "DROWN": False,
    },
    "ip_address": "93.184.216.34",
    "server_name": "example.com",
}


# ── Required report-facing keys ──────────────────────────────────────────
# These are the keys the report rendering code accesses on a successful
# TestResult from the SSL Labs test.  Any change here must be reflected in
# the report code.

REQUIRED_TOP_LEVEL = {
    "test_name", "domain", "success", "grade", "score", "max_score",
    "summary", "details", "recommendations", "visuals", "tables",
}

REQUIRED_DETAILS_KEYS = {
    "grade", "grade_trust_ignored", "has_warnings",
    "certificate", "protocols", "vulnerabilities",
    "ip_address", "server_name",
}

REQUIRED_CERT_KEYS = {
    "subject", "issuer",
    "not_before", "not_after",
    "not_before_str", "not_after_str",
    "key_alg", "key_size", "sig_alg",
}

REQUIRED_PROTOCOL_KEYS = {
    "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3",
}

REQUIRED_VULN_KEYS = {
    "Heartbleed", "POODLE (TLS)", "ROBOT", "Ticketbleed",
    "OpenSSL CCS", "LUCKY13", "FREAK", "Logjam", "DROWN",
}

REQUIRED_VISUAL_KEYS = {"grade_badge"}  # always present

REQUIRED_TABLE_TITLES = {"Certificate Details", "Protocol Support", "Vulnerability Checks"}


class _ResultStructureAssertions:
    """Mixin with shared structural assertions."""

    def assert_result_structure(self, result: TestResult):
        """Assert that a TestResult has the full report-facing shape."""
        # Top-level fields
        for key in REQUIRED_TOP_LEVEL:
            self.assertTrue(
                hasattr(result, key),
                f"Missing top-level field: {key}",
            )

        self.assertTrue(result.success, f"Expected success=True, got error: {result.error}")
        self.assertEqual(result.test_name, "ssl_labs")
        self.assertIsInstance(result.score, int)
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 100)
        self.assertIsInstance(result.summary, str)
        self.assertTrue(len(result.summary) > 0)

        # details dict
        details = result.details
        self.assertIsInstance(details, dict)
        for key in REQUIRED_DETAILS_KEYS:
            self.assertIn(key, details, f"Missing details key: {key}")

        # certificate sub-dict
        cert = details["certificate"]
        self.assertIsInstance(cert, dict)
        for key in REQUIRED_CERT_KEYS:
            self.assertIn(key, cert, f"Missing certificate key: {key}")

        # protocols
        protocols = details["protocols"]
        self.assertIsInstance(protocols, dict)
        for key in REQUIRED_PROTOCOL_KEYS:
            self.assertIn(key, protocols, f"Missing protocol key: {key}")
            self.assertIsInstance(protocols[key], bool)

        # vulnerabilities
        vulns = details["vulnerabilities"]
        self.assertIsInstance(vulns, dict)
        for key in REQUIRED_VULN_KEYS:
            self.assertIn(key, vulns, f"Missing vulnerability key: {key}")
            self.assertIsInstance(vulns[key], bool)

        # visuals
        for key in REQUIRED_VISUAL_KEYS:
            self.assertIn(key, result.visuals, f"Missing visual: {key}")
            self.assertIsInstance(result.visuals[key], io.BytesIO)

        # tables
        table_titles = {t["title"] for t in result.tables}
        for title in REQUIRED_TABLE_TITLES:
            self.assertIn(title, table_titles, f"Missing table: {title}")

        for table in result.tables:
            self.assertIn("headers", table)
            self.assertIn("rows", table)
            self.assertIsInstance(table["rows"], list)
            self.assertTrue(len(table["rows"]) > 0)

        # recommendations
        self.assertIsInstance(result.recommendations, list)
        self.assertTrue(len(result.recommendations) > 0)
        for rec in result.recommendations:
            self.assertIn("severity", rec)
            self.assertIn("text", rec)
            self.assertIn(
                rec["severity"], ("critical", "warning", "info"),
                f"Unknown severity: {rec['severity']}",
            )


class TestSSLLabsResultStructure(unittest.TestCase, _ResultStructureAssertions):
    """Verify that SSL Labs engine produces correct report-facing structure."""

    @patch("east.tests.ssl_test.get_cached", return_value=FAKE_SSLLABS_API_RESPONSE)
    def test_ssllabs_result_shape(self, mock_cache):
        runner = SSLLabsTestRunner("example.com", email="test@example.com")
        result = runner.run()
        self.assert_result_structure(result)
        # Engine metadata
        self.assertEqual(result.details["_engine"]["name"], "ssllabs")

    @patch("east.tests.ssl_test.get_cached", return_value=FAKE_SSLLABS_API_RESPONSE)
    def test_ssllabs_grade_and_score(self, mock_cache):
        runner = SSLLabsTestRunner("example.com", email="test@example.com")
        result = runner.run()
        self.assertEqual(result.grade, "A")
        self.assertEqual(result.score, 95)


class TestLocalFallbackResultStructure(unittest.TestCase, _ResultStructureAssertions):
    """Verify that the local fallback engine produces identical structure."""

    @patch("east.tests.ssl_test.get_cached", return_value=None)
    @patch("east.tests.local_tls.run_local_tls_probe", return_value=FAKE_LOCAL_PROBE_RESULT)
    def test_local_fallback_result_shape(self, mock_probe, mock_cache):
        runner = SSLLabsTestRunner(
            "example.com",
            email="",
            fallback_enabled=True,
        )
        result = runner.run()
        self.assert_result_structure(result)
        # Engine metadata confirms local
        self.assertEqual(result.details["_engine"]["name"], "local")
        self.assertEqual(result.details["_engine"]["tool"], "openssl")
        self.assertIn("fallback_reason", result.details["_engine"])

    @patch("east.tests.ssl_test.get_cached", return_value=None)
    @patch("east.tests.local_tls.run_local_tls_probe", return_value=FAKE_LOCAL_PROBE_RESULT)
    def test_local_fallback_grade_and_score(self, mock_probe, mock_cache):
        runner = SSLLabsTestRunner(
            "example.com",
            email="",
            fallback_enabled=True,
        )
        result = runner.run()
        self.assertEqual(result.grade, "A")
        self.assertEqual(result.score, 95)


class TestFallbackBehavior(unittest.TestCase):
    """Verify the fallback decision logic."""

    def test_no_email_no_fallback_returns_error(self):
        """Without email and without fallback enabled, should error."""
        runner = SSLLabsTestRunner(
            "example.com",
            email="",
            fallback_enabled=False,
        )
        result = runner.run()
        self.assertFalse(result.success)
        self.assertIn("No email", result.error)

    @patch("east.tests.ssl_test.get_cached", return_value=None)
    @patch("east.tests.local_tls.run_local_tls_probe", return_value=FAKE_LOCAL_PROBE_RESULT)
    def test_no_email_with_fallback_succeeds(self, mock_probe, mock_cache):
        """Without email but with fallback enabled, should succeed via local."""
        runner = SSLLabsTestRunner(
            "example.com",
            email="",
            fallback_enabled=True,
        )
        result = runner.run()
        self.assertTrue(result.success)
        self.assertEqual(result.details["_engine"]["name"], "local")
        self.assertEqual(result.details["_engine"]["fallback_reason"], "no_email")

    @patch("east.tests.ssl_test.get_cached", return_value=None)
    @patch("east.tests.local_tls.run_local_tls_probe", return_value=None)
    def test_fallback_also_fails_returns_error(self, mock_probe, mock_cache):
        """When both SSL Labs and local fallback fail, returns error result."""
        runner = SSLLabsTestRunner(
            "example.com",
            email="",
            fallback_enabled=True,
        )
        result = runner.run()
        self.assertFalse(result.success)
        self.assertIn("No email", result.error)

    @patch("east.tests.ssl_test.get_cached", return_value=None)
    @patch("east.tests.local_tls.run_local_tls_probe", return_value=FAKE_LOCAL_PROBE_RESULT)
    def test_ssllabs_api_failure_triggers_fallback(self, mock_probe, mock_cache):
        """When SSL Labs API fails, fallback is used."""
        runner = SSLLabsTestRunner(
            "example.com",
            email="test@example.com",
            fallback_enabled=True,
        )
        with patch.object(runner, "_start_or_fetch", return_value=None):
            result = runner.run()
            self.assertTrue(result.success)
            self.assertEqual(result.details["_engine"]["name"], "local")
            self.assertEqual(
                result.details["_engine"]["fallback_reason"], "api_not_responding",
            )


class TestResultStructureParity(unittest.TestCase, _ResultStructureAssertions):
    """Cross-engine parity: both engines produce structurally identical output."""

    @patch("east.tests.ssl_test.get_cached", return_value=FAKE_SSLLABS_API_RESPONSE)
    def _get_ssllabs_result(self, mock_cache):
        runner = SSLLabsTestRunner("example.com", email="test@example.com")
        return runner.run()

    @patch("east.tests.ssl_test.get_cached", return_value=None)
    @patch("east.tests.local_tls.run_local_tls_probe", return_value=FAKE_LOCAL_PROBE_RESULT)
    def _get_local_result(self, mock_probe, mock_cache):
        runner = SSLLabsTestRunner(
            "example.com",
            email="",
            fallback_enabled=True,
        )
        return runner.run()

    def test_both_engines_produce_same_keys(self):
        """The set of keys in details, visuals, and tables match."""
        ssllabs_result = self._get_ssllabs_result()
        local_result = self._get_local_result()

        # Both should pass full structural check
        self.assert_result_structure(ssllabs_result)
        self.assert_result_structure(local_result)

        # Same top-level attribute set (excluding timestamp which varies)
        for attr in ("test_name", "success", "max_score"):
            self.assertEqual(
                getattr(ssllabs_result, attr),
                getattr(local_result, attr),
                f"Attribute mismatch: {attr}",
            )

        # Same detail keys (minus _engine which is intentionally different)
        ssl_keys = set(ssllabs_result.details.keys()) - {"_engine"}
        local_keys = set(local_result.details.keys()) - {"_engine"}
        self.assertEqual(ssl_keys, local_keys, "Details keys differ between engines")

        # Same table titles
        ssl_titles = {t["title"] for t in ssllabs_result.tables}
        local_titles = {t["title"] for t in local_result.tables}
        self.assertEqual(ssl_titles, local_titles, "Table titles differ between engines")

        # Same visual keys
        ssl_visuals = set(ssllabs_result.visuals.keys())
        local_visuals = set(local_result.visuals.keys())
        self.assertEqual(ssl_visuals, local_visuals, "Visual keys differ between engines")


class TestComputeGrade(unittest.TestCase):
    """Verify the local grade computation heuristic."""

    def test_good_config_gets_a(self):
        from east.tests.local_tls import compute_grade
        protocols = {
            "SSL 2.0": False, "SSL 3.0": False,
            "TLS 1.0": False, "TLS 1.1": False,
            "TLS 1.2": True, "TLS 1.3": True,
        }
        vulns = {k: False for k in REQUIRED_VULN_KEYS}
        cert = {"not_after": datetime(2027, 1, 1, tzinfo=timezone.utc)}
        self.assertEqual(compute_grade(protocols, vulns, cert), "A")

    def test_legacy_protocols_penalized(self):
        from east.tests.local_tls import compute_grade
        protocols = {
            "SSL 2.0": True, "SSL 3.0": True,
            "TLS 1.0": True, "TLS 1.1": True,
            "TLS 1.2": True, "TLS 1.3": False,
        }
        vulns = {k: False for k in REQUIRED_VULN_KEYS}
        cert = {"not_after": datetime(2027, 1, 1, tzinfo=timezone.utc)}
        grade = compute_grade(protocols, vulns, cert)
        # With SSL 2.0 (50) + SSL 3.0 (40) + TLS 1.0 (15) + TLS 1.1 (10) + no 1.3 (5) = 120 penalty → F
        self.assertEqual(grade, "F")

    def test_expired_cert_penalized(self):
        from east.tests.local_tls import compute_grade
        protocols = {
            "SSL 2.0": False, "SSL 3.0": False,
            "TLS 1.0": False, "TLS 1.1": False,
            "TLS 1.2": True, "TLS 1.3": True,
        }
        vulns = {k: False for k in REQUIRED_VULN_KEYS}
        cert = {"not_after": datetime(2020, 1, 1, tzinfo=timezone.utc)}
        grade = compute_grade(protocols, vulns, cert)
        self.assertIn(grade, ("D", "F"))


if __name__ == "__main__":
    unittest.main()
