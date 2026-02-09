# EAST Report Automation Tool - Project Specification

## Project Overview
Build a professional External Attack Surface Test (EAST) automation tool that generates visually appealing Word documents with charts, screenshots, and formatted results - similar to the example report provided.

## Core Requirements

### 1. Architecture
- **Language**: Python 3.10+
- **Structure**: Modular design with separate test runners
- **Config**: YAML-based configuration for domains and test selection
- **Output**: Professional Word documents (.docx) with visual elements

### 2. Key Dependencies
```
python-docx          # Word document generation
matplotlib           # Charts and graphs
Pillow              # Image processing
requests            # HTTP requests
dnspython           # DNS queries
validators          # Input validation
pyyaml              # Configuration
click               # CLI interface
rich                # Beautiful terminal output
```

## Test Modules to Implement

### Phase 1: Core Tests (Implement First)

#### 1. SSL/TLS Testing
- **API**: SSL Labs API (https://api.ssllabs.com/api/v3/)
- **Endpoint**: `/analyze?host={domain}`
- **Visual Output**: 
  - Grade badge image (A+, A, B, etc.)
  - Certificate expiration timeline chart
  - Protocol support table
- **Data to Capture**:
  - Overall grade
  - Certificate validity dates
  - Protocol versions (TLS 1.2, 1.3)
  - Cipher suites
  - Vulnerabilities (Heartbleed, POODLE, etc.)

#### 2. Mozilla Observatory
- **API**: Mozilla HTTP Observatory API
- **Endpoint**: `https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}`
- **Visual Output**:
  - Score gauge (0-100)
  - Security headers checklist with ✓/✗
  - Grade badge
- **Data to Capture**:
  - Overall score and grade
  - Individual header tests (CSP, HSTS, X-Frame-Options, etc.)
  - Recommendations

#### 3. DNS Tests
- **Method**: Direct DNS queries using dnspython
- **Tests**:
  - A/AAAA records
  - MX records
  - NS records
  - DNSSEC validation
- **Visual Output**:
  - DNS record table
  - DNSSEC validation status badge

#### 4. Email Authentication
- **Tests**:
  - SPF record lookup and validation
  - DKIM record discovery
  - DMARC policy analysis
- **Visual Output**:
  - Traffic light indicators (🟢 Pass, 🟡 Warning, 🔴 Fail)
  - Policy details table
- **Implementation**:
  - Query TXT records for `_dmarc.{domain}`
  - Query for `default._domainkey.{domain}`
  - Parse and validate SPF syntax

#### 5. Blacklist Check
- **Services to Check**:
  - Spamhaus
  - SURBL
  - RATS-Spam
  - Barracuda
- **API Options**: 
  - MXToolbox API (requires key)
  - Or direct DNS queries to blacklist servers
- **Visual Output**:
  - Status table with 🟢/🔴 indicators
  - Alert badges for any listings

#### 6. Subdomain Enumeration
- **Method**: 
  - Certificate Transparency logs (crt.sh API)
  - DNS brute force (common subdomains list)
- **API**: `https://crt.sh/?q=%.{domain}&output=json`
- **Visual Output**:
  - Subdomain tree diagram
  - Count badge

### Phase 2: Advanced Tests

#### 7. Website Performance (Lighthouse)
- **Tool**: Google PageSpeed Insights API
- **Endpoint**: `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}`
- **Visual Output**:
  - Performance score gauge (0-100)
  - Core Web Vitals chart
  - Waterfall chart (if possible)

#### 8. Security Headers Analysis
- **Method**: Direct HTTP requests
- **Headers to Check**:
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security
  - Referrer-Policy
  - Permissions-Policy
- **Visual Output**:
  - Matrix table with status indicators
  - Missing headers highlighted in red

#### 9. Cookie Analysis
- **Tests**:
  - Secure flag presence
  - HttpOnly flag
  - SameSite attribute
  - Expiration
  - Third-party cookies detection
- **Visual Output**:
  - Cookie inventory table
  - Risk level badges

#### 10. Open Ports Scan
- **Tool**: Python socket library (basic scan)
- **Ports**: Common ports (21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443)
- **Visual Output**:
  - Port status table
  - Service identification

## Document Generation Specifications

### Document Structure
```
1. Cover Page
   - Client name
   - Report date
   - EAST logo/branding

2. Executive Summary (1-2 pages)
   - Overall security score/grade
   - Critical findings count
   - High-level recommendations
   - Quick stats dashboard

3. Table of Contents (auto-generated)

4. Test Results by Category
   For each test:
   - Section header with icon
   - Test purpose explanation
   - Visual results (charts/badges/tables)
   - Findings summary
   - Detailed recommendations
   - Screenshots/evidence

5. Appendix
   - Full test data
   - Methodology
   - Tools used
```

### Visual Design Guidelines

#### Color Scheme
- **Success/Pass**: #28a745 (green)
- **Warning**: #ffc107 (yellow)
- **Critical/Fail**: #dc3545 (red)
- **Info**: #17a2b8 (blue)
- **Headers**: #2c3e50 (dark blue-gray)

#### Charts & Graphics
1. **Grade Badges**: Circular badges with letter grades (A+, B, C, etc.)
2. **Score Gauges**: Semi-circular speedometer-style gauges
3. **Status Icons**: ✓ (green check), ⚠ (yellow warning), ✗ (red X)
4. **Timeline Charts**: For certificate expiration, etc.
5. **Bar Charts**: For performance metrics
6. **Tables**: Professional formatting with alternating row colors

#### Screenshot Integration
- Capture actual test results as images where possible
- Frame screenshots with subtle borders
- Add captions below each image
- Ensure high DPI for clarity

### Implementation Details

#### Report Generator Class
```python
class EASTReportGenerator:
    def __init__(self, config):
        self.document = Document()
        self.config = config
        self.results = {}
        
    def create_cover_page(self, client_name, date)
    def add_executive_summary(self)
    def add_section(self, title, test_results)
    def add_chart(self, chart_type, data)
    def add_table(self, headers, rows)
    def add_screenshot(self, image_path, caption)
    def add_recommendation(self, severity, text)
    def generate_toc(self)
    def save(self, output_path)
```

#### Test Runner Base Class
```python
class TestRunner:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}
        
    def run(self)              # Execute test
    def parse_results(self)     # Parse API/tool output
    def generate_visual(self)   # Create chart/badge
    def get_recommendations(self) # Generate recommendations
```

## CLI Interface

### Commands
```bash
# Run all tests on a domain
east-scan --domain example.com --output report.docx

# Run specific tests
east-scan --domain example.com --tests ssl,dns,email

# Use config file
east-scan --config config.yaml

# Multiple domains
east-scan --domains example.com,test.com --output reports/

# Verbose output with progress
east-scan --domain example.com --verbose
```

### Configuration File (config.yaml)
```yaml
domains:
  - genwayhome.com
  - openmortgage.com
  - toolkit.genwayhome.org

client_info:
  name: "GenWay Home Mortgage"
  contact: "Security Team"

tests:
  enabled:
    - ssl_labs
    - mozilla_observatory
    - dns_lookup
    - dnssec
    - spf
    - dkim
    - dmarc
    - blacklist
    - subdomains
    - security_headers
    - cookies
    - performance
    - open_ports
  
  disabled:
    - vulnerability_scan  # Requires commercial tools

api_keys:
  google_pagespeed: "YOUR_API_KEY"
  mxtoolbox: "YOUR_API_KEY"  # Optional

output:
  format: "docx"
  filename_template: "EAST_{client}_{date}.docx"
  include_raw_data: true
  screenshots: true

branding:
  logo: "assets/logo.png"
  company_name: "Your Security Company"
  color_scheme: "professional"
```

## Implementation Phases

### Phase 1: Foundation (Week 1)
- [ ] Project structure setup
- [ ] CLI interface with Click
- [ ] Configuration loading
- [ ] Basic document generation
- [ ] SSL Labs integration
- [ ] Mozilla Observatory integration

### Phase 2: Core Tests (Week 2)
- [ ] DNS tests (all)
- [ ] Email authentication (SPF/DKIM/DMARC)
- [ ] Blacklist checking
- [ ] Subdomain enumeration
- [ ] Chart generation with matplotlib

### Phase 3: Visual Polish (Week 3)
- [ ] Professional document styling
- [ ] Badge/gauge generation
- [ ] Table formatting
- [ ] Screenshot integration
- [ ] Executive summary dashboard

### Phase 4: Advanced Features (Week 4)
- [ ] Performance testing
- [ ] Security headers analysis
- [ ] Cookie analysis
- [ ] Open ports scanning
- [ ] Error handling & logging

## Technical Considerations

### Rate Limiting
- SSL Labs: Max 1 request per domain per hour
- Implement caching to avoid repeated scans
- Add delay between API calls

### Error Handling
- Graceful degradation if API is unavailable
- Retry logic with exponential backoff
- Clear error messages in report

### Performance
- Async/parallel test execution where possible
- Progress indicators in CLI
- Estimated time remaining

### Security
- Never include API keys in reports
- Sanitize sensitive data
- Secure storage of credentials

## Sample Output Structure

```
project/
├── east/
│   ├── __init__.py
│   ├── cli.py              # Click CLI interface
│   ├── config.py           # Configuration loader
│   ├── report.py           # Report generator
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── base.py         # Base test runner
│   │   ├── ssl_test.py
│   │   ├── dns_test.py
│   │   ├── email_test.py
│   │   ├── blacklist_test.py
│   │   └── ...
│   ├── visuals/
│   │   ├── __init__.py
│   │   ├── charts.py       # Chart generation
│   │   ├── badges.py       # Badge creation
│   │   └── tables.py       # Table formatting
│   └── utils/
│       ├── __init__.py
│       ├── http.py         # HTTP utilities
│       ├── dns.py          # DNS utilities
│       └── validators.py
├── assets/
│   ├── logo.png
│   ├── templates/
│   └── styles/
├── config.yaml
├── requirements.txt
├── setup.py
├── README.md
└── examples/
    └── sample_report.docx
```

## Success Criteria

The tool should:
1. ✅ Generate professional Word documents matching the sample quality
2. ✅ Include visual charts, badges, and formatted tables
3. ✅ Execute all Phase 1 tests automatically
4. ✅ Provide clear CLI with progress indicators
5. ✅ Handle errors gracefully
6. ✅ Be configurable via YAML
7. ✅ Complete a full scan in under 10 minutes
8. ✅ Produce actionable recommendations

## Next Steps for Claude Code

1. Review this specification
2. Set up the project structure
3. Implement the foundation (CLI, config, basic report)
4. Start with SSL Labs and Mozilla Observatory tests
5. Add visual generation capabilities
6. Iterate on document styling to match the sample
7. Expand to remaining tests

**Key Focus**: Make it look professional and visually appealing, not just functional. The report should impress clients!
