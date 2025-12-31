# 🔒 Advanced Penetration Testing Script v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

A comprehensive, high-tech penetration testing toolkit for authorized security assessments. This tool provides extensive vulnerability scanning capabilities for web applications, APIs, and network services.

## ⚠️ Ethical Use Warning

**This tool is intended for authorized security testing ONLY.**

Using this tool against websites without explicit permission from the owner is **ILLEGAL and UNETHICAL**. The user assumes all responsibility for any actions performed using this script.

## ✨ Features

### 🔍 Reconnaissance
- **Web Crawling**: Automated URL discovery with configurable depth
- **Technology Fingerprinting**: Detect CMS, frameworks, and server technologies
- **Subdomain Enumeration**: Discover subdomains via DNS resolution
- **Port Scanning**: Scan common ports for open services
- **JavaScript Analysis**: Extract API endpoints from JS files

### 💉 Injection Testing
- **SQL Injection**: Error-based and time-based blind SQLi detection
- **Cross-Site Scripting (XSS)**: Reflected and DOM-based XSS testing
- **Command Injection**: OS command injection detection
- **LDAP Injection**: LDAP query manipulation testing
- **Server-Side Template Injection (SSTI)**: Template engine exploitation
- **XML External Entity (XXE)**: XML parser vulnerability testing

### 🔐 Authentication & Authorization
- **CSRF Testing**: Cross-Site Request Forgery detection
- **Weak Credentials**: Default/common password testing
- **JWT Security**: Token analysis and algorithm verification
- **Session Management**: Cookie security analysis

### 🌐 API Security
- **REST API Testing**: Common API vulnerability checks
- **GraphQL Security**: Introspection and query batching tests
- **CORS Misconfiguration**: Cross-origin resource sharing analysis
- **Rate Limiting**: Brute force protection detection

### 🛡️ Security Headers & Configuration
- **HTTP Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **TLS/SSL Analysis**: Certificate and cipher suite verification
- **Cookie Security**: Secure, HttpOnly, SameSite attributes
- **Information Disclosure**: Sensitive file exposure detection

### 📊 Reporting
- **JSON Reports**: Machine-readable output
- **HTML Reports**: Beautiful, interactive reports
- **Console Output**: Color-coded real-time results
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW, INFO

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/MiChaelinzo/Advanced-Penetration-Testing-Script.git

# Navigate to the directory
cd Advanced-Penetration-Testing-Script

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Quick Scan (Interactive Mode)
```bash
python penetration_testing3.py
```
Or with URL:
```bash
python penetration_testing3.py https://example.com
```

### Advanced Scanner (Command Line)

#### Basic Scan
```bash
python scanner.py https://example.com
```

#### Full Comprehensive Scan
```bash
python scanner.py https://example.com --full-scan
```

#### With Custom Options
```bash
# Scan with port scanning and subdomain enumeration
python scanner.py https://example.com --scan-ports --enum-subdomains

# Save HTML report
python scanner.py https://example.com -o report.html --format html

# Use custom payload files
python scanner.py https://example.com --sqli-payloads sqli.txt --xss-payloads xss.txt

# Ignore SSL certificate errors
python scanner.py https://self-signed.local --no-verify-ssl

# Verbose output
python scanner.py https://example.com -v --full-scan
```

### Command Line Options

```
Target:
  url                   Target website URL (e.g., https://example.com)

Scan Options:
  --full-scan           Enable all scan features
  --crawl               Enable web crawling (default: enabled)
  --no-crawl            Disable web crawling
  --crawl-depth N       Maximum crawl depth (default: 2)
  --max-pages N         Maximum pages to crawl (default: 50)
  --scan-ports          Enable port scanning
  --enum-subdomains     Enable subdomain enumeration
  --test-creds          Test for weak credentials (default: enabled)
  --no-test-creds       Disable credential testing

Payload Files:
  --sqli-payloads FILE  Custom SQL injection payloads
  --xss-payloads FILE   Custom XSS payloads
  --dir-payloads FILE   Custom directory traversal payloads
  --username-list FILE  Custom usernames for testing
  --password-list FILE  Custom passwords for testing

Output Options:
  -o, --output FILE     Output file for report
  --format {json,html}  Report format (default: json)
  -v, --verbose         Enable verbose output
  -q, --quiet           Minimal output

Connection Options:
  --no-verify-ssl       Disable SSL certificate verification
  --timeout N           Request timeout in seconds (default: 10)
  --threads N           Number of concurrent threads (default: 10)
```

## 📁 Project Structure

```
Advanced-Penetration-Testing-Script/
├── scanner.py              # Main advanced scanner with full features
├── penetration_testing3.py # Quick interactive scanner
├── requirements.txt        # Python dependencies
├── README.md               # Documentation
├── LICENSE                 # MIT License
└── .github/
    ├── FUNDING.yml
    └── ISSUE_TEMPLATE/
```

## 🔧 Vulnerability Tests

| Category | Tests |
|----------|-------|
| **Injection** | SQL Injection, XSS, Command Injection, LDAP Injection, SSTI, XXE |
| **Authentication** | CSRF, Weak Credentials, Broken Session Management |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **TLS/SSL** | Certificate Validation, Protocol Version, Cipher Strength |
| **API Security** | CORS, GraphQL Introspection, JWT Analysis, Rate Limiting |
| **Information Disclosure** | Directory Traversal, Sensitive Files, Debug Mode |
| **Other** | Clickjacking, Open Redirect, Insecure File Upload, SSRF |

## 📋 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║           Advanced Web Vulnerability Scanner v2.0.0              ║
╚══════════════════════════════════════════════════════════════════╝

🚀 Starting comprehensive scan on https://example.com

📡 PHASE 1: Reconnaissance
----------------------------------------
🔬 Fingerprinting technologies...
  ✓ Detected: Nginx
  ✓ Detected: PHP
🕷️ Starting web crawl...
  Discovered 25 URLs, 8 JS files

🔍 PHASE 2: Vulnerability Testing
----------------------------------------
💉 Testing for SQL Injection vulnerabilities...
📝 Testing for XSS vulnerabilities...
🔒 Testing HTTP Security Headers...
  [MEDIUM] Missing Security Header - CSP

============================================================
📋 SCAN RESULTS
============================================================

📊 Summary:
   CRITICAL: 0
   HIGH: 1
   MEDIUM: 3
   LOW: 5
   INFO: 2
   TOTAL: 11

💾 Report saved to: report.html
```

## 🤝 Contributing

We welcome contributions to improve and expand this project! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution
- Additional vulnerability checks
- Improved detection accuracy
- Performance optimizations
- Documentation improvements
- Bug fixes

## 📜 Disclaimer

This project is for **educational and authorized security testing purposes only**. 

- Always obtain proper authorization before testing any system
- Do not use this tool against systems you don't own or have permission to test
- The authors are not responsible for any misuse or damage caused by this tool
- This tool should not be used in a production environment without proper validation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Updates

### v2.0.0 (2024)
- Complete rewrite with modern Python practices
- Added async/concurrent scanning
- Added web crawling and URL discovery
- Added technology fingerprinting
- Added subdomain enumeration
- Added port scanning
- Added SSTI, XXE, LDAP injection testing
- Added JWT security analysis
- Added GraphQL security testing
- Added API security testing
- Added CORS testing
- Added HTML report generation
- Improved detection accuracy
- Color-coded console output
- Comprehensive documentation

### v1.0.0 (2023)
- Initial release
- Basic vulnerability testing
- SQL injection, XSS, CSRF testing
- Cookie security analysis
- HTTP header checks

---

<p align="center">
  Made with ❤️ for the security community
</p>

![Cyberpunk Security](https://user-images.githubusercontent.com/68110223/216805944-5500f5b8-883f-4621-876a-d8c9da678813.png)
