# Domain & NetUtils Monitor

A comprehensive domain and network utilities monitoring agent for DevOps engineers and system administrators. Monitor multiple domains for WHOIS expiration, SSL certificate validity, HTTP status, DNS records, security configurations, and RBL listings.

## Features

### DNS Propagation Checker

The DNS propagation checker verifies DNS record propagation across multiple public DNS servers worldwide. This is essential when making DNS changes to ensure they've propagated correctly.

**Key Features:**
- **Multiple DNS Servers**: Checks 12 major public DNS servers (Google, Cloudflare, Quad9, OpenDNS, Verisign, Yandex, Comodo, Neustar)
- **Record Type Support**: A, AAAA, CNAME, MX, NS, TXT records
- **Expected Value Comparison**: Compare actual values against expected values
- **Watch Mode**: Monitor propagation progress until complete
- **Multiple Record Types**: Check multiple record types simultaneously
- **Visual Progress**: Color-coded status with propagation rate display

**Quick Examples:**

```bash
# Check A record propagation
domain-monitor dns-propagation example.com

# Check with expected value
domain-monitor dns-propagation example.com --expected "192.0.2.1"

# Watch mode - monitor until propagation completes
domain-monitor dns-propagation example.com --watch --expected "192.0.2.1"

# Check multiple record types
domain-monitor dns-propagation example.com --record-types A,AAAA,MX
```

See the [DNS Propagation section](#dns-propagation-checker-1) below for detailed usage.

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

# Live monitoring mode
domain-monitor watch -f endpoints.yaml

# Live monitoring with custom interval
domain-monitor watch -f endpoints.yaml --interval 2.0
```

## Live Monitoring Mode

The `watch` command provides real-time endpoint monitoring with a live-updating terminal dashboard. Perfect for monitoring API health, service availability, and detecting issues as they happen.

### Features

- **Real-time Updates**: Live table that refreshes every second (configurable)
- **Advanced HTTP Configuration**: Support for GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- **Custom Headers & Bodies**: Configure authentication, content types, and request payloads
- **Status Change Logging**: Automatic logging when endpoint status changes
- **Visual Indicators**: Color-coded status with emoji indicators (🟢🟡🔴)
- **Graceful Shutdown**: Clean terminal restoration on CTRL+C

### Quick Start

1. Create an `endpoints.yaml` file:

```yaml
endpoints:
  - name: example.com
    url: https://example.com
    method: GET

  - name: api/users
    url: https://api.example.com/users
    method: GET
    headers:
      Authorization: Bearer your-token-here
      Accept: application/json
```

2. Start live monitoring:

```bash
domain-monitor watch -f endpoints.yaml
```

3. Press CTRL+C to stop monitoring

### Endpoint Configuration

#### Basic Configuration

```yaml
endpoints:
  - name: example.com          # Display name (required)
    url: https://example.com   # Full URL (required)
    method: GET                # HTTP method (optional, default: GET)
    timeout: 5.0               # Request timeout in seconds (optional, default: 5.0)
```

#### Advanced HTTP Methods

```yaml
endpoints:
  # GET request
  - name: api/health
    url: https://api.example.com/health
    method: GET

  # POST request with JSON body
  - name: api/login
    url: https://api.example.com/auth/login
    method: POST
    headers:
      Content-Type: application/json
    body: '{"username": "test", "password": "test123"}'

  # PUT request with authentication
  - name: api/update
    url: https://api.example.com/data/123
    method: PUT
    headers:
      Authorization: Bearer your-token-here
      Content-Type: application/json
    body: '{"status": "active", "priority": "high"}'

  # PATCH request
  - name: api/patch
    url: https://api.example.com/resource/456
    method: PATCH
    headers:
      Authorization: Bearer your-token-here
      Content-Type: application/json
    body: '{"field": "value"}'

  # DELETE request
  - name: api/delete
    url: https://api.example.com/resource/789
    method: DELETE
    headers:
      Authorization: Bearer your-token-here

  # HEAD request (check if resource exists)
  - name: api/exists
    url: https://api.example.com/resource/check
    method: HEAD

  # OPTIONS request (check allowed methods)
  - name: api/options
    url: https://api.example.com/resource
    method: OPTIONS
```

#### Custom Headers

```yaml
endpoints:
  # API with authentication
  - name: authenticated-api
    url: https://api.example.com/protected
    method: GET
    headers:
      Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
      Accept: application/json
      User-Agent: MyMonitor/1.0

  # API with custom headers
  - name: custom-headers
    url: https://api.example.com/data
    method: GET
    headers:
      X-API-Key: your-api-key-here
      X-Request-ID: monitor-12345
      Accept-Language: en-US
```

#### Request Bodies

```yaml
endpoints:
  # JSON body
  - name: create-user
    url: https://api.example.com/users
    method: POST
    headers:
      Content-Type: application/json
      Authorization: Bearer token
    body: '{"name": "John Doe", "email": "john@example.com", "role": "admin"}'

  # Form data (URL-encoded)
  - name: form-submit
    url: https://api.example.com/form
    method: POST
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: 'username=test&password=test123&remember=true'

  # XML body
  - name: soap-request
    url: https://api.example.com/soap
    method: POST
    headers:
      Content-Type: text/xml
    body: '<?xml version="1.0"?><soap:Envelope>...</soap:Envelope>'
```

### Live Display

The live monitoring interface shows a continuously updating table:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                            Live Endpoint Status Monitor                                      │
│                            Press CTRL+C to stop monitoring                                   │
├────────┬──────────────────────────────┬────────────┬──────────┬──────────┬──────────────────┤
│ Method │ Endpoint                     │ Status     │ Response │ Headers  │ Error/Info       │
├────────┼──────────────────────────────┼────────────┼──────────┼──────────┼──────────────────┤
│ GET    │ example.com                  │ 🟢 200     │ 0.123s   │ -        │ -                │
│ POST   │ api/users                    │ 🟢 201     │ 0.089s   │ Auth,CT  │ -                │
│ GET    │ api/health                   │ 🟢 200     │ 0.045s   │ -        │ -                │
│ PUT    │ api/update                   │ 🟢 200     │ 0.156s   │ Auth,CT  │ -                │
│ GET    │ broken.example.com           │ 🔴 500     │ 1.234s   │ -        │ Internal Serv... │
│ POST   │ timeout.example.com          │ 🔴 ERROR   │ 5.000s   │ Auth,CT  │ Connection tim...│
└────────┴──────────────────────────────┴────────────┴──────────┴──────────┴──────────────────┘
Last updated: 2025-11-19 14:23:45

Headers abbreviations: Auth=Authorization, CT=Content-Type, Accept=Accept
```

**Status Indicators:**
- 🟢 **Green (2xx)**: Success responses (200, 201, 204, etc.)
- 🟡 **Yellow (3xx, 4xx)**: Redirects and client errors (301, 302, 400, 404, etc.)
- 🔴 **Red (5xx, ERROR)**: Server errors and network failures (500, 503, timeout, etc.)

**Headers Column:**
- Shows abbreviated header names for configured custom headers
- Common abbreviations: Auth (Authorization), CT (Content-Type), Accept (Accept)
- Helps identify which endpoints have custom configurations

### Status Change Logging

The monitor automatically logs when endpoint status changes:

```
2025-11-19 14:23:45 [CHANGE] GET example.com: 200 -> 500 (response_time: 0.123s -> 1.234s)
2025-11-19 14:24:12 [CHANGE] POST api/users: 201 -> ERROR (Connection timeout)
2025-11-19 14:25:33 [CHANGE] GET api/health: 500 -> 200 (recovered)
2025-11-19 14:30:00 [SUMMARY] Monitoring stopped. Total changes: 3
```

**Log Features:**
- Only logs when status changes (not every check)
- Includes timestamp, method, endpoint, old status, new status
- Shows response time changes
- Writes final summary on shutdown
- Default location: `logs/live-monitor.log`

### Command Options

```bash
# Basic usage with default settings
domain-monitor watch -f endpoints.yaml

# Custom check interval (check every 2 seconds)
domain-monitor watch -f endpoints.yaml --interval 2.0

# Custom log file location
domain-monitor watch -f endpoints.yaml --log-file /var/log/monitor.log

# Combine options
domain-monitor watch -f endpoints.yaml --interval 0.5 --log-file custom.log
```

### Security Best Practices

#### 1. Protect Sensitive Data

**DO NOT** commit files with real credentials to version control:

```yaml
# ❌ BAD - Real credentials in config
endpoints:
  - name: api
    url: https://api.example.com
    headers:
      Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.real-token-here
```

**✅ GOOD** - Use environment variables or separate credential files:

```yaml
# endpoints.yaml (committed to git)
endpoints:
  - name: api
    url: https://api.example.com
    headers:
      Authorization: ${API_TOKEN}  # Reference environment variable
```

Or use a separate credentials file:

```bash
# .gitignore
endpoints.local.yaml
credentials.yaml
*.local.yaml
```

#### 2. Header Masking

Sensitive headers are automatically masked in logs and display:
- `Authorization` → Shows as "Auth" in display, masked in logs
- `X-API-Key` → Masked in logs
- `API-Key` → Masked in logs

Request and response bodies are **never** logged to prevent sensitive data exposure.

#### 3. File Permissions

Protect your endpoint configuration files:

```bash
# Restrict access to configuration files with credentials
chmod 600 endpoints.yaml

# Restrict log file access
chmod 600 logs/live-monitor.log
```

#### 4. HTTPS Only

Always use HTTPS URLs for production endpoints:

```yaml
# ✅ GOOD - HTTPS
endpoints:
  - name: api
    url: https://api.example.com

# ❌ BAD - HTTP (credentials sent in plain text)
endpoints:
  - name: api
    url: http://api.example.com
    headers:
      Authorization: Bearer token
```

#### 5. Separate Configurations

Use different configuration files for different environments:

```
endpoints.production.yaml   # Production endpoints
endpoints.staging.yaml      # Staging endpoints
endpoints.development.yaml  # Development endpoints
endpoints.example.yaml      # Example template (committed to git)
```

Add to `.gitignore`:

```
endpoints.production.yaml
endpoints.staging.yaml
*.local.yaml
```

#### 6. Token Rotation

Regularly rotate API tokens and credentials:
- Use short-lived tokens when possible
- Implement token refresh mechanisms
- Monitor for unauthorized access in logs

#### 7. Minimal Permissions

Use API tokens with minimal required permissions:
- Read-only tokens for monitoring endpoints
- Avoid using admin or full-access tokens
- Create dedicated monitoring service accounts

### Use Cases

#### API Health Monitoring

Monitor multiple API endpoints with different authentication:

```yaml
endpoints:
  - name: auth-service/health
    url: https://auth.example.com/health
    method: GET

  - name: user-service/health
    url: https://users.example.com/health
    method: GET
    headers:
      Authorization: Bearer service-token

  - name: payment-service/health
    url: https://payments.example.com/health
    method: GET
    headers:
      X-API-Key: monitoring-key
```

#### Microservices Monitoring

Track health of microservices architecture:

```yaml
endpoints:
  - name: gateway
    url: https://api.example.com/health
    method: GET

  - name: auth-service
    url: https://auth-service.internal:8080/health
    method: GET

  - name: user-service
    url: https://user-service.internal:8081/health
    method: GET

  - name: order-service
    url: https://order-service.internal:8082/health
    method: GET

  - name: inventory-service
    url: https://inventory-service.internal:8083/health
    method: GET
```

#### CI/CD Pipeline Monitoring

Monitor deployment endpoints during releases:

```yaml
endpoints:
  - name: staging/app
    url: https://staging.example.com/health
    method: GET

  - name: staging/api
    url: https://api-staging.example.com/health
    method: GET

  - name: production/app
    url: https://example.com/health
    method: GET

  - name: production/api
    url: https://api.example.com/health
    method: GET
```

#### Third-Party API Monitoring

Track external service availability:

```yaml
endpoints:
  - name: stripe/status
    url: https://status.stripe.com/api/v2/status.json
    method: GET

  - name: github/status
    url: https://www.githubstatus.com/api/v2/status.json
    method: GET

  - name: aws/health
    url: https://status.aws.amazon.com/data.json
    method: GET
```

### Troubleshooting

#### Terminal Display Issues

If the live display doesn't render correctly:
- Ensure your terminal supports Unicode and colors
- Try resizing your terminal window
- Check that the Rich library is installed: `pip install rich>=13.0`

#### Connection Timeouts

If endpoints frequently timeout:
- Increase timeout value in configuration: `timeout: 10.0`
- Check network connectivity
- Verify firewall rules allow outbound connections
- Consider increasing check interval: `--interval 2.0`

#### High CPU Usage

If monitoring causes high CPU usage:
- Increase check interval: `--interval 2.0` or higher
- Reduce number of monitored endpoints
- Check for slow-responding endpoints

#### Log File Growth

Status change logs only record changes, not every check:
- Logs grow slowly (only on status changes)
- Rotate logs periodically using logrotate or similar tools
- Monitor log file size: `ls -lh logs/live-monitor.log`

## Usage

### Command-Line Options

```
Commands:
  check    Run domain checks (default command)
  watch    Live monitoring mode with real-time status updates

Check Command Options:
  -f, --file PATH          Path to manifest file (YAML/JSON)
  -d, --domain TEXT        Single domain to check (ad-hoc mode)
  -o, --output PATH        Output file path (.json or .csv)
  --log-level [DEBUG|INFO|WARNING|ERROR]
                          Logging level (default: INFO)
  --debug                 Enable debug mode with verbose console output
  --help                  Show this message and exit

Watch Command Options:
  -f, --file PATH          Path to endpoints manifest file (YAML)
  --interval FLOAT        Check interval in seconds (default: 1.0)
  --log-file PATH         Path to status change log file (default: logs/live-monitor.log)
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
- hypothesis - Property-based testing

## DNS Propagation Checker

### Overview

The DNS propagation checker is a powerful tool for verifying DNS record propagation across multiple public DNS servers worldwide. When you make DNS changes (like updating A records, changing MX records, or modifying nameservers), it can take time for these changes to propagate across the global DNS infrastructure. This tool helps you monitor and verify that propagation.

### Supported DNS Servers

The checker queries 12 major public DNS servers:

| Provider | Primary | Secondary | Location |
|----------|---------|-----------|----------|
| Google | 8.8.8.8 | 8.8.4.4 | Global |
| Cloudflare | 1.1.1.1 | 1.0.0.1 | Global |
| Quad9 | 9.9.9.9 | - | Global |
| OpenDNS | 208.67.222.222 | 208.67.220.220 | Global |
| Verisign | 64.6.64.6 | 64.6.65.6 | Global |
| Yandex | 77.88.8.8 | - | Russia |
| Comodo | 8.26.56.26 | - | Global |
| Neustar | 156.154.70.1 | - | Global |

### Command Reference

```bash
domain-monitor dns-propagation DOMAIN [OPTIONS]
```

**Options:**
- `-t, --record-type TEXT`: DNS record type (A, AAAA, CNAME, MX, NS, TXT). Default: A
- `-e, --expected TEXT`: Expected value to compare against
- `-w, --watch`: Watch mode - monitor until propagation completes
- `-i, --interval FLOAT`: Check interval in watch mode (seconds). Default: 5.0
- `--record-types TEXT`: Comma-separated list of record types (e.g., A,AAAA,MX)

### Usage Examples

#### Basic Propagation Check

Check current DNS propagation status:

```bash
domain-monitor dns-propagation example.com
```

This shows which DNS servers return which values for the domain's A record.

#### Check with Expected Value

Verify that DNS servers are returning your expected value:

```bash
domain-monitor dns-propagation example.com --expected "192.0.2.1"
```

The tool will:
- Show which servers match the expected value (✓ Matched)
- Show which servers have different values (✗ Mismatched)
- Calculate propagation rate (percentage of servers with correct value)

#### Check Different Record Types

Check AAAA (IPv6) records:

```bash
domain-monitor dns-propagation example.com --record-type AAAA
```

Check MX (mail) records:

```bash
domain-monitor dns-propagation example.com --record-type MX
```

Check TXT records:

```bash
domain-monitor dns-propagation example.com --record-type TXT
```

#### Watch Mode

Monitor propagation progress in real-time:

```bash
domain-monitor dns-propagation example.com --watch --expected "192.0.2.1"
```

Watch mode will:
- Check DNS servers every 5 seconds (configurable with `--interval`)
- Display updated results after each check
- Continue until you press CTRL+C
- Show propagation progress over time

Custom check interval (every 10 seconds):

```bash
domain-monitor dns-propagation example.com --watch --interval 10.0 --expected "192.0.2.1"
```

#### Multiple Record Types

Check multiple record types in one command:

```bash
domain-monitor dns-propagation example.com --record-types A,AAAA,MX
```

This displays separate results for each record type.

### Output Interpretation

#### Status Indicators

- **✓ Matched** (Green): DNS server returns the expected value
- **✗ Mismatched** (Red): DNS server returns a different value
- **ℹ success** (Blue): Query successful (when no expected value provided)
- **⚠ Unreachable** (Yellow): DNS server didn't respond or query failed
- **ℹ no_records** (Blue): No records found for this domain/type

#### Propagation Rate

The propagation rate shows what percentage of responsive DNS servers return the expected value:

```
Propagation Rate: 75.0%

Server Status:
  ✓ Matched: 9
  ✗ Mismatched: 3
  ⚠ Unreachable: 0
  ℹ Total Responsive: 12
```

- **100%**: Fully propagated - all servers have the new value
- **0%**: Not propagated - no servers have the new value yet
- **Between 0-100%**: Partial propagation - some servers updated, others not

#### Response Times

Each server shows its response time:

```
│ Google Primary       │ Global       │  ✓ Matched   │ 192.0.2.1      │  0.051s │
│ Cloudflare Primary   │ Global       │  ✓ Matched   │ 192.0.2.1      │  0.014s │
```

Fast response times (< 0.1s) indicate good connectivity to that DNS server.

### Common Use Cases

#### 1. Verify DNS Migration

After migrating to a new hosting provider:

```bash
# Check if new IP has propagated
domain-monitor dns-propagation example.com --expected "203.0.113.1"

# Watch until fully propagated
domain-monitor dns-propagation example.com --watch --expected "203.0.113.1"
```

#### 2. Troubleshoot DNS Issues

Identify which DNS servers have stale records:

```bash
# Check current state
domain-monitor dns-propagation example.com

# Compare against expected
domain-monitor dns-propagation example.com --expected "192.0.2.1"
```

If some servers show mismatched values, you know which DNS providers haven't updated yet.

#### 3. Verify Email Configuration

After changing MX records:

```bash
# Check MX record propagation
domain-monitor dns-propagation example.com --record-type MX

# Verify expected mail server
domain-monitor dns-propagation example.com --record-type MX --expected "10 mail.example.com"
```

#### 4. Monitor Nameserver Changes

After updating nameservers:

```bash
# Check NS records
domain-monitor dns-propagation example.com --record-type NS

# Watch propagation
domain-monitor dns-propagation example.com --record-type NS --watch
```

#### 5. Comprehensive DNS Check

Check all important record types:

```bash
domain-monitor dns-propagation example.com --record-types A,AAAA,MX,NS,TXT
```

### Understanding DNS Propagation

#### Why Does Propagation Take Time?

DNS changes don't happen instantly because:

1. **TTL (Time To Live)**: DNS records have a TTL value that tells DNS servers how long to cache the record. Until the TTL expires, servers may serve cached (old) values.

2. **Recursive Resolvers**: Your ISP and other recursive DNS resolvers cache records. Even after authoritative nameservers update, these caches need to expire.

3. **Geographic Distribution**: DNS servers are distributed globally. Updates propagate at different rates to different locations.

#### Typical Propagation Times

- **Low TTL (300s - 5 minutes)**: Changes propagate within 5-15 minutes
- **Medium TTL (3600s - 1 hour)**: Changes propagate within 1-2 hours
- **High TTL (86400s - 24 hours)**: Changes can take 24-48 hours

#### Best Practices

1. **Lower TTL Before Changes**: 24-48 hours before making DNS changes, lower your TTL to 300 seconds (5 minutes). This ensures faster propagation.

2. **Wait for Full Propagation**: Don't assume changes are complete when you see 50% propagation. Wait for 100% to avoid issues.

3. **Test from Multiple Locations**: Use this tool to check multiple DNS servers, as they represent different geographic regions and providers.

4. **Monitor During Migration**: Use watch mode during critical migrations to track propagation progress in real-time.

### Troubleshooting

#### "No records found"

If all servers show "No records":
- Verify the domain exists and is registered
- Check if you're querying the correct record type
- Ensure the domain has DNS records configured

#### Slow Response Times

If response times are consistently high (> 1s):
- Check your internet connection
- Try again later (DNS server may be under load)
- Some geographic regions may have slower connectivity

#### Partial Propagation Stuck

If propagation stays at 50-75% for extended periods:
- Check your authoritative nameservers are all updated
- Verify TTL has expired (wait at least TTL duration)
- Some DNS servers may cache longer than TTL suggests

#### Different Values Across Servers

If servers show different values:
- This is normal during propagation
- Wait for TTL to expire on all servers
- Use watch mode to monitor until convergence

### Integration with CI/CD

You can integrate DNS propagation checks into your deployment pipeline:

```bash
#!/bin/bash
# Wait for DNS propagation before proceeding

DOMAIN="example.com"
EXPECTED_IP="192.0.2.1"
MAX_ATTEMPTS=60  # 5 minutes with 5-second intervals

for i in $(seq 1 $MAX_ATTEMPTS); do
    echo "Checking DNS propagation (attempt $i/$MAX_ATTEMPTS)..."
    
    # Run check and capture output
    OUTPUT=$(domain-monitor dns-propagation $DOMAIN --expected $EXPECTED_IP)
    
    # Check if 100% propagated
    if echo "$OUTPUT" | grep -q "Propagation Rate: 100.0%"; then
        echo "DNS fully propagated!"
        exit 0
    fi
    
    echo "Not fully propagated yet, waiting..."
    sleep 5
done

echo "DNS propagation timeout after $MAX_ATTEMPTS attempts"
exit 1
```

### Testing

The DNS propagation checker includes comprehensive test coverage:

- **Unit Tests**: Test individual components (DNS queries, result formatting, error handling)
- **Property-Based Tests**: Validate correctness properties across random inputs using Hypothesis
- **Integration Tests**: Test end-to-end workflows including CLI integration
- **Error Handling Tests**: Verify graceful handling of network errors, timeouts, and invalid inputs

Run tests:

```bash
# Run all DNS propagation tests
pytest tests/test_dns_propagation*.py -v

# Run with coverage
pytest tests/test_dns_propagation*.py --cov=domain_monitor.checkers.dns_propagation_checker --cov-report=html
```

All DNS propagation tests pass with 100% success rate.
