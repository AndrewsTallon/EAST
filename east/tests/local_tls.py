"""Local TLS probe fallback for when SSL Labs is unavailable.

Tries, in order: sslyze (Python library), testssl.sh (CLI), then raw
OpenSSL s_client probing.  Each adapter normalises its output to the same
intermediate dict consumed by ``SSLLabsTestRunner._build_test_result``.
"""

import io
import json
import logging
import shutil
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Intermediate result shape ────────────────────────────────────────────
# Every adapter must return a dict of this form (or ``None`` on failure):
#
#   {
#       "tool": str,               # "sslyze" | "testssl" | "openssl"
#       "grade": str,              # e.g. "A", "B+", "F"
#       "certificate": {           # same keys as SSLLabsTestRunner
#           "subject", "issuer",
#           "not_before", "not_after",          # datetime | None
#           "not_before_str", "not_after_str",  # str
#           "key_alg", "key_size", "sig_alg",
#       },
#       "protocols": {str: bool},  # "SSL 2.0" … "TLS 1.3"
#       "vulnerabilities": {str: bool},
#       "ip_address": str,
#       "server_name": str,
#   }
# ─────────────────────────────────────────────────────────────────────────

_DEFAULT_PROTOCOLS = {
    "SSL 2.0": False,
    "SSL 3.0": False,
    "TLS 1.0": False,
    "TLS 1.1": False,
    "TLS 1.2": False,
    "TLS 1.3": False,
}

_DEFAULT_VULNS = {
    "Heartbleed": False,
    "POODLE (TLS)": False,
    "ROBOT": False,
    "Ticketbleed": False,
    "OpenSSL CCS": False,
    "LUCKY13": False,
    "FREAK": False,
    "Logjam": False,
    "DROWN": False,
}


def _resolve_ip(domain: str) -> str:
    """Resolve the domain to its first IPv4 address, or 'N/A'."""
    try:
        return socket.getaddrinfo(domain, 443, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError):
        return "N/A"


# ── Grade heuristic ──────────────────────────────────────────────────────

def compute_grade(
    protocols: dict[str, bool],
    vulnerabilities: dict[str, bool],
    cert_details: dict[str, Any],
) -> str:
    """Derive a letter grade from local probe data.

    The mapping is intentionally conservative: local probes cannot assess
    cipher-suite ordering, HSTS preload, or CAA in the same depth as SSL
    Labs, so the best achievable grade is ``A`` (never ``A+``).
    """
    penalty = 0

    # Deprecated / insecure protocols
    if protocols.get("SSL 2.0"):
        penalty += 50
    if protocols.get("SSL 3.0"):
        penalty += 40
    if protocols.get("TLS 1.0"):
        penalty += 15
    if protocols.get("TLS 1.1"):
        penalty += 10

    # Missing modern protocols
    if not protocols.get("TLS 1.2") and not protocols.get("TLS 1.3"):
        penalty += 30
    if not protocols.get("TLS 1.3"):
        penalty += 5

    # Active vulnerabilities
    for name, vuln in vulnerabilities.items():
        if vuln:
            penalty += 25

    # Expired certificate
    not_after = cert_details.get("not_after")
    if not_after and isinstance(not_after, datetime):
        if not_after < datetime.now(timezone.utc):
            penalty += 50

    score = max(0, 100 - penalty)
    if score >= 90:
        return "A"
    if score >= 80:
        return "B+"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ─────────────────────────────────────────────────────────────────────────
# sslyze adapter
# ─────────────────────────────────────────────────────────────────────────

def _probe_sslyze(domain: str, timeout: int = 30) -> Optional[dict]:
    """Run sslyze and return normalised result dict, or None on failure."""
    try:
        from sslyze import (
            Scanner,
            ScanCommand,
            ServerScanRequest,
            ServerNetworkLocation,
        )
    except ImportError:
        logger.debug("sslyze not importable — skipping")
        return None

    try:
        location = ServerNetworkLocation(hostname=domain, port=443)
        scan_request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.OPENSSL_CCS_INJECTION,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        result = None
        for server_result in scanner.get_results():
            result = server_result
            break

        if result is None:
            return None

        # Check connectivity
        if result.connectivity_error_trace:
            logger.warning("sslyze connectivity error for %s", domain)
            return None

        scan = result.scan_result

        # ── Certificate ─────────────────────────────────────────────
        cert_info: dict[str, Any] = {
            "subject": "N/A",
            "issuer": "N/A",
            "not_before": None,
            "not_after": None,
            "not_before_str": "N/A",
            "not_after_str": "N/A",
            "key_alg": "N/A",
            "key_size": "N/A",
            "sig_alg": "N/A",
        }
        cert_result = scan.certificate_info
        if cert_result and cert_result.status.name == "COMPLETED":
            deployments = cert_result.result.certificate_deployments
            if deployments:
                leaf = deployments[0].received_certificate_chain[0]
                cert_info["subject"] = leaf.subject.rfc4514_string()
                cert_info["issuer"] = leaf.issuer.rfc4514_string()
                cert_info["not_before"] = leaf.not_valid_before_utc if hasattr(leaf, 'not_valid_before_utc') else leaf.not_valid_before.replace(tzinfo=timezone.utc)
                cert_info["not_after"] = leaf.not_valid_after_utc if hasattr(leaf, 'not_valid_after_utc') else leaf.not_valid_after.replace(tzinfo=timezone.utc)
                if cert_info["not_before"]:
                    cert_info["not_before_str"] = cert_info["not_before"].strftime(
                        "%Y-%m-%d %H:%M UTC"
                    )
                if cert_info["not_after"]:
                    cert_info["not_after_str"] = cert_info["not_after"].strftime(
                        "%Y-%m-%d %H:%M UTC"
                    )
                pub_key = leaf.public_key()
                cert_info["key_size"] = str(getattr(pub_key, "key_size", "N/A"))
                cert_info["key_alg"] = type(pub_key).__name__.replace("_", " ")
                cert_info["sig_alg"] = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "N/A"

        # ── Protocols ───────────────────────────────────────────────
        protocols = dict(_DEFAULT_PROTOCOLS)
        proto_map = {
            "ssl_2_0_cipher_suites": "SSL 2.0",
            "ssl_3_0_cipher_suites": "SSL 3.0",
            "tls_1_0_cipher_suites": "TLS 1.0",
            "tls_1_1_cipher_suites": "TLS 1.1",
            "tls_1_2_cipher_suites": "TLS 1.2",
            "tls_1_3_cipher_suites": "TLS 1.3",
        }
        for attr, label in proto_map.items():
            cmd_result = getattr(scan, attr, None)
            if cmd_result and cmd_result.status.name == "COMPLETED":
                protocols[label] = len(cmd_result.result.accepted_cipher_suites) > 0

        # ── Vulnerabilities ─────────────────────────────────────────
        vulns = dict(_DEFAULT_VULNS)
        hb = getattr(scan, "heartbleed", None)
        if hb and hb.status.name == "COMPLETED":
            vulns["Heartbleed"] = hb.result.is_vulnerable_to_heartbleed
        robot = getattr(scan, "robot", None)
        if robot and robot.status.name == "COMPLETED":
            vulns["ROBOT"] = robot.result.robot_result.name not in (
                "NOT_VULNERABLE_NO_ORACLE",
                "NOT_VULNERABLE_RSA_NOT_SUPPORTED",
            )
        ccs = getattr(scan, "openssl_ccs_injection", None)
        if ccs and ccs.status.name == "COMPLETED":
            vulns["OpenSSL CCS"] = ccs.result.is_vulnerable_to_ccs_injection

        grade = compute_grade(protocols, vulns, cert_info)

        return {
            "tool": "sslyze",
            "grade": grade,
            "certificate": cert_info,
            "protocols": protocols,
            "vulnerabilities": vulns,
            "ip_address": _resolve_ip(domain),
            "server_name": domain,
        }
    except Exception as exc:
        logger.warning("sslyze probe failed for %s: %s", domain, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────
# testssl.sh adapter
# ─────────────────────────────────────────────────────────────────────────

def _probe_testssl(domain: str, timeout: int = 120) -> Optional[dict]:
    """Run testssl.sh and return normalised result dict, or None."""
    testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")
    if not testssl_bin:
        logger.debug("testssl.sh not found on PATH — skipping")
        return None

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        cmd = [
            testssl_bin,
            "--jsonfile", tmp_path,
            "--warnings", "off",
            "--color", "0",
            "--quiet",
            f"{domain}:443",
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if proc.returncode not in (0, 1):
            logger.warning("testssl.sh exited %d for %s", proc.returncode, domain)
            return None

        with open(tmp_path) as f:
            data = json.load(f)

        if not data:
            return None

        # Parse the JSON array of findings
        findings: dict[str, str] = {}
        for entry in data:
            fid = entry.get("id", "")
            finding = entry.get("finding", "")
            severity = entry.get("severity", "")
            findings[fid] = finding

        # Certificate
        cert_info: dict[str, Any] = {
            "subject": findings.get("cert_commonName", "N/A"),
            "issuer": findings.get("cert_caIssuers", findings.get("cert_issuer", "N/A")),
            "not_before": None,
            "not_after": None,
            "not_before_str": findings.get("cert_notBefore", "N/A"),
            "not_after_str": findings.get("cert_notAfter", "N/A"),
            "key_alg": findings.get("cert_keyAlgorithm", "N/A"),
            "key_size": findings.get("cert_keySize", "N/A"),
            "sig_alg": findings.get("cert_signatureAlgorithm", "N/A"),
        }
        # Parse dates
        for key, date_key in [("not_before", "cert_notBefore"), ("not_after", "cert_notAfter")]:
            raw = findings.get(date_key, "")
            if raw:
                for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y"):
                    try:
                        cert_info[key] = datetime.strptime(raw.strip(), fmt).replace(
                            tzinfo=timezone.utc
                        )
                        break
                    except ValueError:
                        continue

        # Protocols
        protocols = dict(_DEFAULT_PROTOCOLS)
        proto_ids = {
            "SSLv2": "SSL 2.0",
            "SSLv3": "SSL 3.0",
            "TLS1": "TLS 1.0",
            "TLS1_1": "TLS 1.1",
            "TLS1_2": "TLS 1.2",
            "TLS1_3": "TLS 1.3",
        }
        for tid, label in proto_ids.items():
            val = findings.get(tid, "").lower()
            protocols[label] = "offered" in val or "enabled" in val

        # Vulnerabilities
        vulns = dict(_DEFAULT_VULNS)
        vuln_ids = {
            "heartbleed": "Heartbleed",
            "POODLE_TLS": "POODLE (TLS)",
            "ROBOT": "ROBOT",
            "ticketbleed": "Ticketbleed",
            "ccs": "OpenSSL CCS",
            "LUCKY13": "LUCKY13",
            "FREAK": "FREAK",
            "LOGJAM": "Logjam",
            "DROWN": "DROWN",
        }
        for tid, label in vuln_ids.items():
            val = findings.get(tid, "").lower()
            vulns[label] = "vulnerable" in val

        grade = findings.get("overall_grade", "")
        if not grade:
            grade = compute_grade(protocols, vulns, cert_info)

        return {
            "tool": "testssl",
            "grade": grade,
            "certificate": cert_info,
            "protocols": protocols,
            "vulnerabilities": vulns,
            "ip_address": _resolve_ip(domain),
            "server_name": domain,
        }
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("testssl.sh probe failed for %s: %s", domain, exc)
        return None
    except Exception as exc:
        logger.warning("testssl.sh probe failed for %s: %s", domain, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────
# OpenSSL s_client adapter
# ─────────────────────────────────────────────────────────────────────────

def _openssl_check_protocol(domain: str, flag: str, timeout: int = 10) -> bool:
    """Return True if the server accepts a connection with the given protocol flag."""
    try:
        proc = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{domain}:443",
                flag,
                "-servername", domain,
            ],
            input=b"",
            capture_output=True,
            timeout=timeout,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        # A successful handshake contains "Protocol  :" and no error alerts
        return "BEGIN CERTIFICATE" in output and "alert" not in output.lower().split("protocol")[0]
    except Exception:
        return False


def _probe_openssl(domain: str, timeout: int = 30) -> Optional[dict]:
    """Probe TLS with the openssl CLI tool and return normalised result dict."""
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        logger.debug("openssl not found on PATH — skipping")
        return None

    try:
        # Get certificate and connection info
        proc = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{domain}:443",
                "-servername", domain,
                "-showcerts",
            ],
            input=b"",
            capture_output=True,
            timeout=timeout,
        )
        conn_output = proc.stdout.decode("utf-8", errors="replace")

        if "BEGIN CERTIFICATE" not in conn_output:
            logger.warning("openssl could not connect to %s:443", domain)
            return None

        # Extract the leaf certificate PEM
        pem_start = conn_output.index("-----BEGIN CERTIFICATE-----")
        pem_end = conn_output.index("-----END CERTIFICATE-----", pem_start) + len(
            "-----END CERTIFICATE-----"
        )
        leaf_pem = conn_output[pem_start:pem_end]

        # Parse certificate with openssl x509
        x509_proc = subprocess.run(
            [
                "openssl", "x509",
                "-noout",
                "-subject", "-issuer", "-dates", "-pubkey",
                "-text",
            ],
            input=leaf_pem.encode(),
            capture_output=True,
            text=True,
            timeout=10,
        )
        x509_out = x509_proc.stdout

        cert_info: dict[str, Any] = {
            "subject": "N/A",
            "issuer": "N/A",
            "not_before": None,
            "not_after": None,
            "not_before_str": "N/A",
            "not_after_str": "N/A",
            "key_alg": "N/A",
            "key_size": "N/A",
            "sig_alg": "N/A",
        }

        for line in x509_out.splitlines():
            line = line.strip()
            if line.startswith("subject="):
                cert_info["subject"] = line.split("=", 1)[1].strip()
            elif line.startswith("issuer="):
                cert_info["issuer"] = line.split("=", 1)[1].strip()
            elif line.startswith("notBefore="):
                raw = line.split("=", 1)[1].strip()
                cert_info["not_before_str"] = raw
                try:
                    dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    cert_info["not_before"] = dt
                    cert_info["not_before_str"] = dt.strftime("%Y-%m-%d %H:%M UTC")
                except ValueError:
                    pass
            elif line.startswith("notAfter="):
                raw = line.split("=", 1)[1].strip()
                cert_info["not_after_str"] = raw
                try:
                    dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    cert_info["not_after"] = dt
                    cert_info["not_after_str"] = dt.strftime("%Y-%m-%d %H:%M UTC")
                except ValueError:
                    pass
            elif "Signature Algorithm:" in line:
                cert_info["sig_alg"] = line.split(":", 1)[1].strip()
            elif "Public Key Algorithm:" in line:
                cert_info["key_alg"] = line.split(":", 1)[1].strip()
            elif "Public-Key:" in line:
                # e.g. "Public-Key: (2048 bit)"
                import re
                m = re.search(r"\((\d+)\s*bit\)", line)
                if m:
                    cert_info["key_size"] = m.group(1)

        # Protocol probing
        protocols = dict(_DEFAULT_PROTOCOLS)
        proto_flags = {
            "TLS 1.0": "-tls1",
            "TLS 1.1": "-tls1_1",
            "TLS 1.2": "-tls1_2",
            "TLS 1.3": "-tls1_3",
        }
        for label, flag in proto_flags.items():
            protocols[label] = _openssl_check_protocol(domain, flag, timeout=10)

        # OpenSSL cannot reliably test for specific vulns; mark as unknown (False)
        vulns = dict(_DEFAULT_VULNS)

        grade = compute_grade(protocols, vulns, cert_info)

        return {
            "tool": "openssl",
            "grade": grade,
            "certificate": cert_info,
            "protocols": protocols,
            "vulnerabilities": vulns,
            "ip_address": _resolve_ip(domain),
            "server_name": domain,
        }
    except Exception as exc:
        logger.warning("openssl probe failed for %s: %s", domain, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────

# Tool preference order (default)
DEFAULT_TOOL_PREFERENCE = ["sslyze", "testssl", "openssl"]

_ADAPTERS = {
    "sslyze": _probe_sslyze,
    "testssl": _probe_testssl,
    "openssl": _probe_openssl,
}


def run_local_tls_probe(
    domain: str,
    tool_preference: Optional[list[str]] = None,
    timeout: int = 120,
) -> Optional[dict]:
    """Try each local TLS tool in preference order; return first success.

    Returns a normalised result dict (see module docstring) or ``None`` if
    every tool failed.
    """
    preference = tool_preference or DEFAULT_TOOL_PREFERENCE

    for tool_name in preference:
        adapter = _ADAPTERS.get(tool_name)
        if adapter is None:
            logger.warning("Unknown local TLS tool: %s — skipping", tool_name)
            continue
        logger.info("Attempting local TLS probe with %s for %s", tool_name, domain)
        result = adapter(domain, timeout=timeout)
        if result is not None:
            logger.info(
                "Local TLS probe succeeded with %s for %s (grade=%s)",
                tool_name, domain, result.get("grade", "?"),
            )
            return result
        logger.info("Local TLS probe with %s failed for %s — trying next", tool_name, domain)

    logger.error("All local TLS probes failed for %s", domain)
    return None
