# Domain & NetUtils Monitor

A comprehensive domain and network utilities monitoring agent for DevOps engineers and system administrators. Monitor multiple domains for WHOIS expiration, SSL certificate validity, HTTP status, DNS records, security configurations, and RBL listings.

## Features

### Core Monitoring
- **WHOIS Monitoring**: Track domain registration status and expiration dates with smart alerts
- **SSL Certificate Checks**: Verify certificate validity, expiration, and chain integrity
- **HTTP/HTTPS Status**: Monitor website availability, response codes, and redirect chains
- **DNS Record Queries**: Check A, AAAA, MX, NS, and TXT records with parallel resolution
- **DNS Propagation**: Verify DNS changes across multiple public DNS servers (Google, Cloudflare, Quad9)
- **DNS Cache Validation**: Compare local DNS cache with public DNS results

### Security Monitoring
- **Email Security**: Validate SPF, DMARC, and DKIM configurations
- **DNSSEC**: Check DNS security extensions status
- **HTTP Security Headers**: Verify HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **RBL Checks**: Detect if domain or mail server IPs are blacklisted (Spamhaus, Barracuda, SpamCop)

### Performance & Usability
- **Parallel Execution**: Fast concurrent checks using async I/O (5-second timeout per check)
- **Smart Status Calculation**: Overall status based on critical checks (HTTP, SSL, WHOIS, SPF, DMARC)
- **Tree-Structured Output**: Clean hierarchical display with full message visibility
- **Individual Security Breakdown**: Detailed view of each security check (SPF, DMARC, DNSSEC, Headers)
- **Color-Coded Results**: Green (OK), Yellow (Warning), Red (Error/Critical)
- **Quiet Mode**: Error logs suppressed by default (use --debug for verbose output)
- **Export Options**: Save results to JSON or CSV format with full details

## Installation

### Via pip (when published)

```bash
pip install domain-netutils-monitor
```

### From source

```bash
git clone <repository-url>
cd domain-netutils-monitor
pip install -e .
```

### Requirements

- Python 3.10 or higher
- Internet connection for DNS and external API queries

## Quick Start

### 1. Create a manifest file

Create a `domains.yaml` file with your domains:

```yaml
default_checks:
  - whois
  - ssl
  - http
  - dns
  - security
  - rbl

domains:
  - name: example.com
    tags:
      - production
      - main
    dkim_selectors:
      - google
      - mailgun

  - name: test.com
    tags:
      - staging
    checks:
      - http
      - dns
```

### 2. Run the monitor

```bash
# Use default manifest file (domains.yaml or domains.json)
domain-monitor

# Specify a manifest file
domain-monitor -f /path/to/domains.yaml

# Check a single domain without a manifest
domain-monitor -d example.com

# Export results to JSON
domain-monitor -f domains.yaml -o report.json

# Export results to CSV
domain-monitor -f domains.yaml -o report.csv

# Enable debug logging
domain-monitor --log-level DEBUG
```

## Usage

### Command-Line Options

```
Options:
  -f, --file PATH          Path to manifest file (YAML/JSON)
  -d, --domain TEXT        Single domain to check (ad-hoc mode)
  -o, --output PATH        Output file path (.json or .csv)
  --log-level [DEBUG|INFO|WARNING|ERROR]
                          Logging level (default: INFO)
  --debug                 Enable debug mode with verbose console output
  --help                  Show this message and exit
```

**Note:** By default, error logs are suppressed in console output. Use `--debug` flag to see detailed error messages and execution logs.

### Manifest File Format

The manifest file defines which domains to monitor and what checks to perform.

#### YAML Format

```yaml
# Default checks applied to all domains (unless overridden)
default_checks:
  - whois
  - ssl
  - http
  - dns
  - security
  - rbl

# List of domains to monitor
domains:
  - name: example.com           # Required: domain name
    tags:                        # Optional: tags for organization
      - production
      - critical
    checks:                      # Optional: override default_checks
      - whois
      - ssl
      - http
    dkim_selectors:              # Optional: DKIM selectors to check
      - google
      - mailgun
      - default

  - name: another-domain.com
    tags:
      - staging
    # Uses default_checks if not specified
```

#### JSON Format

```json
{
  "default_checks": [
    "whois",
    "ssl",
    "http",
    "dns",
    "security",
    "rbl"
  ],
  "domains": [
    {
      "name": "example.com",
      "tags": ["production", "critical"],
      "checks": ["whois", "ssl", "http"],
      "dkim_selectors": ["google", "mailgun"]
    },
    {
      "name": "another-domain.com",
      "tags": ["staging"]
    }
  ]
}
```

## Check Types

### whois
Queries WHOIS information to retrieve:
- Domain registrar
- Registration status
- Expiration date

**Status Indicators:**
- 🔴 RED: Expires within 30 days
- 🟡 YELLOW: Expires within 60 days
- 🟢 GREEN: Expires in 60+ days

### ssl
Verifies SSL/TLS certificate:
- Certificate issuer
- Subject and Subject Alternative Names (SANs)
- Expiration date

**Status Indicators:**
- 🔴 RED: Expired or expires within 7 days
- 🟡 YELLOW: Expires within 14 days
- 🟢 GREEN: Expires in 14+ days

### http
Checks HTTP/HTTPS status:
- HTTP status code
- Redirect chain tracking
- Final destination URL

**Status Indicators:**
- 🟢 GREEN: 200 OK
- 🟡 YELLOW: 3xx redirects
- 🔴 RED: 4xx/5xx errors

### dns
Queries DNS records:
- A records (IPv4 addresses)
- AAAA records (IPv6 addresses)
- MX records (mail servers)
- NS records (nameservers)
- TXT records
- DNS propagation check across multiple public DNS servers
- Local DNS cache vs public DNS comparison

**Status Indicators:**
- 🟡 YELLOW: Propagation mismatch or cache mismatch
- 🟢 GREEN: All records consistent

### security
Validates security configurations:
- **SPF**: Sender Policy Framework records
- **DMARC**: Email authentication policy
- **DKIM**: Email signature verification (requires selectors)
- **DNSSEC**: DNS security extensions
- **HTTP Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options

**Status Indicators:**
- 🟡 YELLOW: Missing or misconfigured security records
- 🟢 GREEN: All security checks passed

### rbl
Checks Real-time Blackhole Lists:
- Queries domain A records
- Queries MX server IPs
- Checks against major RBL services (Spamhaus, Barracuda, SpamCop)

**Status Indicators:**
- 🔴 RED: Listed in one or more RBLs
- 🟢 GREEN: Not listed

## Output Examples

### Console Tree Output

The tool displays results in a clean tree structure for better visibility:

```
Domain Monitoring Results

✓ example.com (prod, main) - 1.2s
├── ✓ HTTP: HTTP 200
├── ✓ SSL: SSL certificate valid for 45 days
├── ✓ WHOIS: Domain expires in 180 days
├── ✓ DNS: All DNS records resolved successfully
├── ✓ SECURITY:
│   ├── ✓ SPF: SPF record valid
│   ├── ✓ DMARC: DMARC record found with policy: quarantine
│   ├── ✓ DNSSEC: DNSSEC Enabled
│   └── ✓ Security Headers: All security headers present
└── ✓ RBL: Not listed in any RBL (3 IP(s) checked)

⚠ test.com (staging) - 1.5s
├── ✓ HTTP: HTTP 200
├── ⚠ SSL: SSL certificate valid for 10 days
├── ⚠ WHOIS: Domain expires in 25 days
├── ✓ DNS: All DNS records resolved successfully
├── ⚠ SECURITY:
│   ├── ✗ SPF: Missing SPF
│   ├── ✗ DMARC: Missing DMARC
│   ├── ✗ DNSSEC: DNSSEC Not Enabled
│   └── ✗ Security Headers: Missing Headers: Content-Security-Policy, X-Frame-Options
└── ✓ RBL: Not listed in any RBL (2 IP(s) checked)

✗ old-site.com (legacy) - 2.1s
├── ✗ HTTP: HTTP 404
├── ✗ SSL: SSL certificate expired 5 days ago
├── ✗ WHOIS: Domain expires in 5 days (CRITICAL)
├── ✓ DNS: All DNS records resolved successfully
├── ⚠ SECURITY:
│   ├── ✗ SPF: Missing SPF
│   ├── ✗ DMARC: Missing DMARC
│   ├── ✗ DNSSEC: DNSSEC Not Enabled
│   └── ✗ Security Headers: Missing Headers: Strict-Transport-Security, Content-Security-Policy
└── ✗ RBL: LISTED: 2 listing(s) found

Summary: 3 domain(s) checked
  ✓ OK: 1
  ⚠ Warning: 1
  ✗ Error/Critical: 1
```

**Key Features:**
- ✓/✗ icons for quick status identification
- Color coding (green=OK, yellow=warning, red=error)
- Hierarchical tree structure for easy reading
- Individual security check breakdown (SPF, DMARC, DNSSEC, Headers)
- Execution time per domain
- Full messages without truncation

### JSON Export

```json
{
  "timestamp": "2025-11-13T15:30:00",
  "total_domains": 3,
  "domains": [
    {
      "domain": "example.com",
      "tags": ["prod", "main"],
      "overall_status": "OK",
      "execution_time": 1.2,
      "checks": {
        "whois": {
          "status": "OK",
          "message": "Domain expires in 180 days",
          "details": {
            "registrar": "Example Registrar",
            "expiration_date": "2026-05-05T00:00:00",
            "days_until_expiry": 180
          },
          "timestamp": "2025-11-13T15:30:01"
        },
        "ssl": {
          "status": "OK",
          "message": "SSL certificate valid for 45 days",
          "details": {
            "issuer": "Let's Encrypt",
            "subject": "example.com",
            "expiration_date": "2025-12-28T23:59:59",
            "days_until_expiry": 45
          },
          "timestamp": "2025-11-13T15:30:01"
        },
        "http": {
          "status": "OK",
          "message": "HTTP 200",
          "details": {
            "status_code": 200,
            "final_url": "https://example.com"
          },
          "timestamp": "2025-11-13T15:30:01"
        },
        "security": {
          "status": "OK",
          "message": "Critical security checks passed",
          "details": {
            "spf": {
              "status": "OK",
              "message": "SPF record valid",
              "record": "v=spf1 include:_spf.google.com ~all"
            },
            "dmarc": {
              "status": "OK",
              "message": "DMARC record found with policy: quarantine",
              "policy": "quarantine"
            },
            "dnssec": {
              "status": "OK",
              "message": "DNSSEC Enabled"
            }
          },
          "timestamp": "2025-11-13T15:30:02"
        }
      }
    }
  ]
}
```

## Configuration

### Default Manifest Location

The tool looks for manifest files in the following order:
1. File specified with `-f` flag
2. `domains.yaml` in current directory
3. `domains.json` in current directory

### Logging

Logs are written to `domain-monitor.log` in the current directory.

Log levels:
- **DEBUG**: Detailed execution flow, all queries
- **INFO**: Check start/completion, summary (default)
- **WARNING**: Non-critical issues
- **ERROR**: Check failures, network errors

### Timeouts

Default timeout for all checks: 10 seconds

## Performance

The tool uses asynchronous I/O for parallel execution with optimized timeouts:

- **5 domains**: ~1-2 seconds
- **10 domains**: ~2-5 seconds
- **50 domains**: ~10-20 seconds
- **100 domains**: ~30-60 seconds

**Performance Features:**
- Parallel DNS queries for faster resolution
- 5-second timeout per check (configurable)
- Concurrent domain checking (up to 20 domains simultaneously)
- Optimized DNS resolver with 2-second query timeout

Performance depends on network conditions and domain responsiveness.

## Troubleshooting

### Common Issues

**"No manifest file found"**
- Create a `domains.yaml` or `domains.json` file in the current directory
- Or specify the file path with `-f` flag

**"WHOIS query failed"**
- Some domains may have WHOIS privacy protection
- Rate limiting may occur with many domains
- Check network connectivity

**"SSL connection failed"**
- Domain may not support HTTPS
- Certificate may be invalid or self-signed
- Firewall may be blocking port 443

**"DNS query timeout"**
- Check network connectivity
- DNS servers may be rate limiting
- Domain may not exist

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=domain_monitor --cov-report=html

# Run type checking
mypy src/domain_monitor

# Format code
black src/ tests/

# Lint code
ruff check src/ tests/
```

### Project Structure

```
domain-netutils-monitor/
├── src/
│   └── domain_monitor/
│       ├── __init__.py
│       ├── main.py              # CLI entry point
│       ├── config.py            # Configuration loading
│       ├── executor.py          # Parallel execution
│       ├── reporter.py          # Output formatting
│       └── checkers/
│           ├── __init__.py
│           ├── base_checker.py  # Base checker class
│           ├── whois.py         # WHOIS checker
│           ├── ssl.py           # SSL checker
│           ├── http.py          # HTTP checker
│           ├── dns.py           # DNS checker
│           ├── security.py      # Security checker
│           └── rbl.py           # RBL checker
├── tests/                       # Unit and integration tests
├── examples/                    # Sample manifest files
├── pyproject.toml              # Package configuration
└── README.md                   # This file
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - see LICENSE file for details.

## Support

For issues, questions, or contributions, please visit the project repository.

## Acknowledgments

This tool uses the following open-source libraries:
- click - Command-line interface
- dnspython - DNS queries
- python-whois - WHOIS queries
- aiohttp - Async HTTP client
- pyOpenSSL - SSL certificate handling
- rich - Terminal formatting
- PyYAML - YAML parsing
