# EAST - External Attack Surface Test

A professional security assessment tool that scans domains for externally visible vulnerabilities and generates polished Word document reports with charts, badges, and actionable recommendations.

## Features

- **11 automated security tests** covering SSL/TLS, DNS, email auth, blacklists, subdomains, headers, performance, cookies, ports, and screenshots
- **Professional .docx reports** with cover page, executive summary, visual charts, formatted tables, and appendix
- **Rich CLI** with color output and scan summaries
- **Async scan engine** shared across CLI and web UI with rate limiting for SSL Labs and Observatory
- **FastAPI web UI** for local scans with per-job log streaming and DOCX download
- **YAML configuration** for multi-domain scans with customizable test selection
- **Visual output** including grade badges, score gauges, protocol charts, and status indicators

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

### Requirements

- Python 3.10+
- See `requirements.txt` for full dependency list:
  - `python-docx` - Word document generation
  - `matplotlib` - Charts and graphs
  - `Pillow` - Image processing
  - `requests` - HTTP requests
  - `dnspython` - DNS queries
  - `validators` - Input validation
  - `pyyaml` - Configuration
  - `click` - CLI interface
  - `rich` - Terminal output


Additional local tools for new tests:


### Linux server reliability checklist (Lighthouse + Playwright + SSL fallback)

Run this once on the server as a sudo-capable user:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm chromium-browser openssl
python -m playwright install --with-deps chromium
pip install sslyze
# Optional but recommended fallback tier:
# git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
# sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

Then validate with:

```bash
python -m east.cli doctor
```

Environment variables supported by EAST for deterministic server runtime:

- `EAST_CHROME_PATH` (or `CHROME_PATH`): absolute Chrome/Chromium binary path used by Lighthouse.
- `PLAYWRIGHT_BROWSERS_PATH`: shared browser cache path for Playwright binaries (useful with systemd/docker and non-root users).
- `EAST_DATA_DIR`: directory where the web UI persists job metadata (`jobs.json`) so refresh/restart keeps scan history.

Lighthouse runs with server-safe flags on Linux (`--no-sandbox --disable-dev-shm-usage`) in addition to headless flags.


- Node.js + Lighthouse CLI (`npm i -g lighthouse`) for local performance scans
- `nmap` for open ports scanning (gracefully skipped with clear report/log error if unavailable)
- Playwright browsers for screenshots: `playwright install chromium`

### Windows note for Lighthouse

On Windows, EAST resolves Lighthouse using executable shims automatically:

- Prefers `lighthouse.cmd` / `.bat` / `.exe`
- Falls back to `npx.cmd --yes lighthouse ...`
- Does **not** execute `lighthouse.ps1` shims; requires `lighthouse.cmd` or `npx.cmd`

Setup steps:

1. Install Node.js LTS
2. Install Lighthouse globally: `npm i -g lighthouse`
3. Reopen PowerShell/terminal so PATH updates

## Usage

### Quick Scan

```bash
# Scan a single domain
python -m east.cli scan --domain example.com --output report.docx

# Scan multiple domains
python -m east.cli scan --domain example.com --domain test.com --output report.docx

# Or use comma-separated list
python -m east.cli scan --domains example.com,test.com --output report.docx
```

### Using a Config File

```bash
python -m east.cli scan --config config.yaml
```

### Run Specific Tests

```bash
# Only run DNS and email authentication tests
python -m east.cli scan --domain example.com --tests dns_lookup,email_auth

# SSL and security headers only
python -m east.cli scan --domain example.com --tests ssl_labs,security_headers
```


### Performance smoke checks

Use these quick checks to validate performance scanning and report generation:

```bash
# Performance-only run (local Lighthouse, no API keys)
python -m east.cli scan --domains genwayhome.com --tests performance --output tmp-performance.docx

# Full run without performance
python -m east.cli scan --domains genwayhome.com --tests ssl_labs,dns_lookup,email_auth,security_headers --output tmp-no-performance.docx
```

If local Lighthouse dependencies are missing (Node/Chrome/Lighthouse), EAST marks the performance test as `ERROR` with diagnostics and continues report generation.

### Web UI (FastAPI)

```bash
# Start local web server
uvicorn east.web.app:app --host 0.0.0.0 --port 8000

# Open browser at
# http://localhost:8000
```

The UI supports multi-domain scans by entering comma-separated domains and selecting tests.

### Other Commands

```bash
# List all available tests
python -m east.cli list-tests

# Show version
python -m east.cli version

# Verbose output for debugging
python -m east.cli scan --domain example.com --verbose
```

### If Installed as a Package

```bash
east-scan scan --domain example.com --output report.docx
east-scan list-tests
```

## Configuration

Create a `config.yaml` file to configure scans:

```yaml
domains:
  - example.com
  - app.example.com

client_info:
  name: "Acme Corp"
  contact: "Security Team"

tests:
  enabled:
    - ssl_labs
    - mozilla_observatory
    - dns_lookup
    - spf
    - dkim
    - dmarc
    - blacklist
    - subdomains
    - security_headers
  disabled:
    - vulnerability_scan

api_keys:
  google_pagespeed: ""    # Optional, for future performance testing
  mxtoolbox: ""           # Optional

output:
  format: "docx"
  filename_template: "EAST_{client}_{date}.docx"
  include_raw_data: true
  screenshots: true

branding:
  logo: "assets/logo.png"           # Optional logo for cover page
  company_name: "Your Security Co"
  color_scheme: "professional"
```

## Available Tests

| Test | Config Name | Description |
|------|-------------|-------------|
| SSL/TLS Analysis | `ssl_labs` | Certificate validation, protocol support, cipher suites, and vulnerability checks via SSL Labs API |
| Mozilla Observatory | `mozilla_observatory` | HTTP security headers assessment with score and grade |
| DNS Records & DNSSEC | `dns_lookup` | A, AAAA, MX, NS, CNAME, TXT record lookups and DNSSEC validation |
| Email Authentication | `email_auth` (or `spf`, `dkim`, `dmarc`) | SPF record validation, DKIM selector discovery, DMARC policy analysis |
| Blacklist Check | `blacklist` | IP and domain checked against 12 DNS-based blacklists (Spamhaus, SpamCop, Barracuda, etc.) |
| Subdomain Enumeration | `subdomains` | Discovery via Certificate Transparency logs (crt.sh) and DNS brute force of 50 common prefixes |
| Security Headers | `security_headers` | Analysis of 12 security headers and 4 information disclosure headers with weighted scoring |
| Performance | `performance` | Lighthouse local performance categories (or optional Google PageSpeed API key) |
| Cookies | `cookies` | Cookie attributes review for Secure, HttpOnly, and SameSite protections |
| Open Ports | `open_ports` | nmap top-100 TCP scan with exposed service listing |
| Screenshots | `screenshots` | Full-page web screenshot capture with Playwright |

## Report Output

Generated reports include:

1. **Cover Page** - Client name, date, branding
2. **Executive Summary** - Score dashboard, findings count by severity, top recommendations
3. **Table of Contents** - Auto-generated field (update in Word)
4. **Per-Domain Results** - Each test gets its own section with:
   - Description of what was tested
   - Visual grade badges and score gauges
   - Charts (protocol support, header checklist, certificate timeline, etc.)
   - Formatted data tables with color-coded status
   - Prioritized recommendations (Critical / Warning / Info)
5. **Appendix** - Methodology, tools used, scoring guide, disclaimer

## Project Structure

```
east/
├── __init__.py              # Package version
├── cli.py                   # Click CLI with Rich progress output
├── config.py                # YAML configuration loader
├── report.py                # Word document report generator
├── tests/
│   ├── base.py              # TestRunner base class and TestResult dataclass
│   ├── ssl_test.py          # SSL Labs API integration
│   ├── observatory_test.py  # Mozilla Observatory API integration
│   ├── dns_test.py          # DNS record lookups + DNSSEC
│   ├── email_test.py        # SPF, DKIM, DMARC checks
│   ├── blacklist_test.py    # DNSBL IP/domain checking
│   ├── subdomain_test.py    # CT log + DNS brute force enumeration
│   ├── headers_test.py      # HTTP security headers analysis
│   ├── performance_test.py  # Lighthouse/PageSpeed performance checks
│   ├── cookies_test.py      # Cookie security attribute analysis
│   ├── open_ports_test.py   # nmap-based open ports scan
│   └── screenshot_test.py   # Playwright screenshot capture
├── web/
│   └── app.py               # FastAPI web UI with SSE logs + report download
├── scan_engine.py           # Shared async orchestrator for CLI + web
├── visuals/
│   ├── badges.py            # Grade badges, score gauges, status indicators
│   ├── charts.py            # Certificate timeline, protocol chart, dashboard
│   └── tables.py            # Professional formatted tables with status colors
└── utils/
    ├── http.py              # HTTP client with retry/backoff
    └── validators.py        # Domain/URL validation helpers
```

## Project Status

### Implemented (Phase 1 & 2)

- [x] Project structure and modular architecture
- [x] CLI interface with Click + Rich
- [x] YAML configuration system
- [x] Professional Word document generation
- [x] SSL Labs API integration
- [x] Mozilla Observatory API integration
- [x] DNS record lookups (A, AAAA, MX, NS, CNAME, TXT)
- [x] DNSSEC validation
- [x] SPF record lookup and validation
- [x] DKIM record discovery (16 common selectors)
- [x] DMARC policy analysis
- [x] Blacklist checking (10 IP-based + 2 domain-based DNSBLs)
- [x] Subdomain enumeration (CT logs + DNS brute force)
- [x] HTTP security headers analysis (12 security + 4 disclosure headers)
- [x] Grade badges, score gauges, and chart generation
- [x] Professional table formatting with color-coded status
- [x] Executive summary dashboard
- [x] Recommendations engine with severity levels

### Not Yet Implemented (Phase 3 & 4)

- [x] Website performance testing (Lighthouse local + optional Google PageSpeed Insights API key)
- [x] Cookie analysis (Secure, HttpOnly, SameSite flags)
- [x] Open ports scanning (nmap, graceful skip when missing)
- [x] Screenshot integration (Playwright)
- [x] Async/parallel test execution with rate limiting for SSL Labs + Observatory
- [x] Local FastAPI web interface with SSE logs and report download
- [ ] Logo/branding asset

## Notes

- **SSL Labs**: Uses cached results when available (max 24h). A fresh scan can take several minutes per domain.
- **Rate Limits**: SSL Labs allows ~1 scan per domain per hour. The tool uses `fromCache` by default.
- **Blacklist Checks**: Some DNSBL providers may rate-limit queries. Results are best-effort.
- **Subdomain Enumeration**: Only discovers publicly visible subdomains. CT log results depend on certificates issued for the domain.
- **DKIM Discovery**: Checks 16 common selectors. Custom selectors not in the list won't be found (this is a known limitation of DKIM's design).
