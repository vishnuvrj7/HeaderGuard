# HeaderGuard 🛡️

A lightweight, fast web security scanner that detects missing security headers and provides automated remediation suggestions.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

✅ **Comprehensive Security Analysis** - Scans 9 critical security headers  
⚡ **Lightning Fast** - Concurrent scanning with configurable workers  
🎯 **Smart Scoring** - Risk-based scoring system with severity levels  
📊 **Multiple Output Formats** - Console, JSON, and CSV reports  
🔧 **Ready-to-Use Fixes** - Copy-paste HTTP header configurations  
🚀 **Zero Configuration** - Works out of the box  

## Security Headers Checked

| Header | Severity | Purpose |
|--------|----------|---------|
| `Content-Security-Policy` | 🔴 Critical | Prevents XSS and code injection |
| `Strict-Transport-Security` | 🔶 High | Enforces HTTPS connections |
| `X-Frame-Options` | 🟡 Medium | Prevents clickjacking |
| `X-Content-Type-Options` | 🟡 Medium | Prevents MIME sniffing |
| `Permissions-Policy` | 🟡 Medium | Controls browser features |
| `Cross-Origin-Opener-Policy` | 🟡 Medium | Isolates browsing contexts |
| `Cross-Origin-Embedder-Policy` | 🟡 Medium | Prevents unauthorized embedding |
| `Referrer-Policy` | 🔵 Low | Controls referrer information |
| `X-XSS-Protection` | 🔵 Low | Legacy XSS protection |

## Installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/headerguard.git
cd headerguard

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x headerguard.py
```

### Requirements
- Python 3.7 or higher
- `requests` library

### Dependencies
```bash
pip install requests>=2.28.0

# Optional: Enhanced features
pip install colorama tqdm rich
```

## Usage

### Basic Scanning

```bash
# Scan a single website
python headerguard.py https://example.com

# Scan multiple websites
python headerguard.py https://site1.com https://site2.com https://site3.com
```

### Advanced Options

```bash
# Custom timeout and workers
python headerguard.py https://example.com --timeout 15 --workers 10

# JSON output to file
python headerguard.py https://example.com --format json --output report.json

# CSV report
python headerguard.py https://example.com --format csv --output security-audit.csv

# Custom User-Agent
python headerguard.py https://example.com --user-agent "MySecurityBot/1.0"
```

### Command Line Options

```
positional arguments:
  urls                  URLs to scan

options:
  -h, --help            show this help message and exit
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --format {console,json,csv}
                        Output format (default: console)
  --output OUTPUT, -o OUTPUT
                        Output file (default: stdout)
  --workers WORKERS     Max concurrent workers (default: 5)
  --user-agent USER_AGENT
                        Custom User-Agent string
```

## Sample Output

### Console Report
```
================================================================================
HEADERGUARD SECURITY REPORT
================================================================================
Scan completed at: 2025-06-16 14:30:25
Total URLs scanned: 1

🔴 https://example.com
   Score: 45/100 (HIGH risk)
   Status: 200

   Missing Security Headers:
   🔴 CONTENT-SECURITY-POLICY (critical)
      Description: Prevents XSS and code injection attacks
      Fix: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

   🔶 STRICT-TRANSPORT-SECURITY (high)
      Description: Enforces secure HTTPS connections
      Fix: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

   Present Security Headers:
   ✅ X-FRAME-OPTIONS: SAMEORIGIN
   ✅ X-CONTENT-TYPE-OPTIONS: nosniff
```

### JSON Report
```json
[
  {
    "url": "https://example.com",
    "status_code": 200,
    "scan_time": "2025-06-16T14:30:25.123456",
    "overall_score": 45,
    "risk_level": "high",
    "checks": [
      {
        "header": "content-security-policy",
        "present": false,
        "value": null,
        "severity": "critical",
        "description": "Prevents XSS and code injection attacks",
        "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';"
      }
    ]
  }
]
```

## Use Cases

### 🔒 Security Audits
```bash
# Comprehensive security audit
python headerguard.py https://myapp.com --format json --output audit-2025.json
```

### 📊 Compliance Reporting
```bash
# Generate CSV for compliance reports
python headerguard.py https://app1.com https://app2.com --format csv --output compliance.csv
```

### 🚀 CI/CD Integration
```bash
# Automated security checks in pipelines
python headerguard.py $STAGING_URL --format json | jq '.[] | select(.overall_score < 80)'
```

### 🔄 Bulk Assessment
```bash
# Scan multiple domains from file
cat domains.txt | xargs python headerguard.py --workers 20 --format csv --output bulk-scan.csv
```

## Risk Levels & Scoring

| Score Range | Risk Level | Description |
|-------------|------------|-------------|
| 90-100 | 🟢 Low | Excellent security posture |
| 70-89 | 🟡 Medium | Good security, minor improvements needed |
| 50-69 | 🔶 High | Significant security gaps |
| 0-49 | 🔴 Critical | Major security vulnerabilities |

## Common Fixes

### Nginx Configuration
```nginx
# Add to server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Apache Configuration
```apache
# Add to .htaccess or virtual host
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

### Express.js (Node.js)
```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development

```bash
# Install development dependencies
pip install -r requirements.txt pytest black flake8 mypy

# Run tests
pytest

# Code formatting
black headerguard.py

# Linting
flake8 headerguard.py

# Type checking
mypy headerguard.py
```

## Roadmap

- [ ] Custom security header configurations
- [ ] Integration with security databases (CVE, OWASP)
- [ ] Historical scanning and trend analysis
- [ ] Docker container support
- [ ] Web dashboard interface
- [ ] Slack/Teams notifications
- [ ] Plugin system for custom checks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Security Headers Best Practices](https://securityheaders.com/)
