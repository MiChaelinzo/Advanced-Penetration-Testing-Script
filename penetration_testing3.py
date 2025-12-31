#!/usr/bin/env python3
"""
Quick Security Scanner - Interactive Mode
A streamlined, interactive penetration testing script for rapid security assessments.

This is a simplified, interactive version of the main scanner.py tool.
For comprehensive scans, use scanner.py with command-line arguments.

Features:
- Interactive prompts for easy use
- Quick vulnerability checks
- Color-coded output
- Basic security testing

Usage:
    python penetration_testing3.py
    
For advanced scanning, use:
    python scanner.py https://target.com --full-scan
"""

import requests
import sys
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

# --- Configuration ---
VERSION = "2.0.0"

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    """Print the application banner."""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
║{Colors.BOLD}           Quick Security Scanner v{VERSION}                        {Colors.RESET}{Colors.CYAN}║
║           Interactive Penetration Testing Tool                   ║
╠══════════════════════════════════════════════════════════════════╣
║  {Colors.RED}⚠️  ETHICAL USE WARNING{Colors.CYAN}                                          ║
║  This tool is for authorized security testing ONLY.              ║
║  Unauthorized use is ILLEGAL. You assume ALL responsibility.     ║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def print_result(severity: str, message: str):
    """Print a colored result message."""
    colors = {
        "CRITICAL": Colors.MAGENTA,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.CYAN,
        "INFO": Colors.GREEN,
        "OK": Colors.GREEN
    }
    color = colors.get(severity, Colors.WHITE)
    print(f"  {color}[{severity}]{Colors.RESET} {message}")

def print_section(title: str):
    """Print a section header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}▶ {title}{Colors.RESET}")
    print("-" * 50)

def get_user_agent() -> str:
    """Get a random user agent string."""
    software_names = [SoftwareName.CHROME.value, SoftwareName.FIREFOX.value]
    operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
    return UserAgent(software_names=software_names, operating_systems=operating_systems).get_random_user_agent()

def make_request(url: str, method: str = "GET", data: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, timeout: int = 10, 
                 allow_redirects: bool = True) -> Optional[requests.Response]:
    """Make an HTTP request with error handling."""
    if headers is None:
        headers = {'User-Agent': get_user_agent()}
    
    try:
        if method.upper() == "GET":
            return requests.get(url, headers=headers, timeout=timeout, 
                              allow_redirects=allow_redirects, verify=False)
        elif method.upper() == "POST":
            return requests.post(url, headers=headers, data=data, 
                               timeout=timeout, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"  {Colors.RED}[ERROR]{Colors.RESET} Request failed: {str(e)[:50]}")
        return None

def test_sql_injection(website: str, headers: Dict) -> List[str]:
    """Test for SQL injection vulnerabilities."""
    print_section("Testing SQL Injection")
    findings = []
    
    payloads = [
        "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
        "1' ORDER BY 1--", "' UNION SELECT NULL--", "admin'--"
    ]
    
    sql_errors = [
        "sql syntax", "mysql", "sqlite", "postgresql",
        "syntax error", "unclosed quotation", "ora-"
    ]
    
    parsed = urlparse(website)
    test_params = ['id', 'user', 'username', 'search', 'q', 'query', 'page']
    
    for param in test_params:
        for payload in payloads:
            test_url = f"{website}?{param}={quote(payload)}"
            response = make_request(test_url, headers=headers)
            
            if response:
                response_lower = response.text.lower()
                if any(err in response_lower for err in sql_errors):
                    msg = f"Potential SQLi in parameter '{param}' with payload: {payload[:30]}"
                    print_result("CRITICAL", msg)
                    findings.append(msg)
                    break
    
    if not findings:
        print_result("OK", "No obvious SQL injection vulnerabilities found")
    
    return findings

def test_xss(website: str, headers: Dict) -> List[str]:
    """Test for Cross-Site Scripting vulnerabilities."""
    print_section("Testing XSS")
    findings = []
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert('XSS')</script>",
        "<svg onload=alert(1)>",
        "'-alert(1)-'"
    ]
    
    test_params = ['q', 'search', 'query', 'name', 'message', 'input']
    
    for param in test_params:
        for payload in payloads:
            test_url = f"{website}?{param}={quote(payload)}"
            response = make_request(test_url, headers=headers)
            
            if response and payload in response.text:
                msg = f"Reflected XSS in parameter '{param}'"
                print_result("HIGH", msg)
                findings.append(msg)
                break
    
    if not findings:
        print_result("OK", "No reflected XSS vulnerabilities found")
    
    return findings

def test_security_headers(website: str, headers: Dict) -> List[str]:
    """Test for missing security headers."""
    print_section("Testing Security Headers")
    findings = []
    
    response = make_request(website, headers=headers)
    if not response:
        return findings
    
    resp_headers = response.headers
    
    # Check important security headers
    security_headers = {
        "Content-Security-Policy": ("MEDIUM", "Missing CSP header - XSS risk"),
        "X-Frame-Options": ("MEDIUM", "Missing X-Frame-Options - Clickjacking risk"),
        "X-Content-Type-Options": ("LOW", "Missing X-Content-Type-Options"),
        "Strict-Transport-Security": ("MEDIUM", "Missing HSTS header"),
        "X-XSS-Protection": ("LOW", "Missing X-XSS-Protection"),
        "Referrer-Policy": ("LOW", "Missing Referrer-Policy"),
    }
    
    for header, (severity, message) in security_headers.items():
        if header not in resp_headers:
            print_result(severity, message)
            findings.append(message)
    
    # Check for information leakage
    if "Server" in resp_headers:
        server = resp_headers["Server"]
        if any(c.isdigit() for c in server):
            msg = f"Server header leaks version info: {server}"
            print_result("LOW", msg)
            findings.append(msg)
    
    if "X-Powered-By" in resp_headers:
        msg = f"X-Powered-By header reveals technology: {resp_headers['X-Powered-By']}"
        print_result("LOW", msg)
        findings.append(msg)
    
    if not findings:
        print_result("OK", "All major security headers present")
    
    return findings

def test_csrf(website: str, headers: Dict) -> List[str]:
    """Test for CSRF vulnerabilities."""
    print_section("Testing CSRF Protection")
    findings = []
    
    response = make_request(website, headers=headers)
    if not response:
        return findings
    
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form', method=re.compile('post', re.I))
    
    csrf_names = ['csrf', 'token', '_token', 'csrfmiddlewaretoken', 'authenticity_token', 'nonce']
    
    for i, form in enumerate(forms):
        has_csrf = False
        for input_tag in form.find_all('input', type='hidden'):
            name = (input_tag.get('name') or '').lower()
            if any(csrf in name for csrf in csrf_names):
                has_csrf = True
                break
        
        if not has_csrf:
            action = form.get('action', 'unknown')
            msg = f"POST form without CSRF token (action: {action})"
            print_result("MEDIUM", msg)
            findings.append(msg)
    
    if not findings:
        if forms:
            print_result("OK", f"All {len(forms)} POST forms have CSRF protection")
        else:
            print_result("INFO", "No POST forms found")
    
    return findings

def test_cookies(website: str, headers: Dict) -> List[str]:
    """Test cookie security."""
    print_section("Testing Cookie Security")
    findings = []
    
    response = make_request(website, headers=headers)
    if not response:
        return findings
    
    cookies = response.cookies
    
    if not cookies:
        print_result("INFO", "No cookies set by the server")
        return findings
    
    for cookie in cookies:
        issues = []
        
        # Check if it's a session-like cookie
        is_session = any(name in cookie.name.lower() for name in ['session', 'auth', 'token', 'login'])
        
        if not cookie.secure and website.startswith("https"):
            issues.append("missing Secure flag")
        
        if not cookie.has_nonstandard_attr('httponly'):
            issues.append("missing HttpOnly flag")
        
        samesite = cookie.get_nonstandard_attr('samesite', '').lower()
        if not samesite or samesite == 'none':
            issues.append("weak/missing SameSite")
        
        if issues:
            severity = "MEDIUM" if is_session else "LOW"
            msg = f"Cookie '{cookie.name}': {', '.join(issues)}"
            print_result(severity, msg)
            findings.append(msg)
    
    if not findings:
        print_result("OK", "All cookies have proper security attributes")
    
    return findings

def test_https(website: str) -> List[str]:
    """Test for HTTPS and SSL/TLS issues."""
    print_section("Testing HTTPS/TLS")
    findings = []
    
    if not website.startswith("https://"):
        msg = "Site does not use HTTPS - data transmitted in plaintext"
        print_result("HIGH", msg)
        findings.append(msg)
    else:
        try:
            response = requests.get(website, verify=True, timeout=10)
            print_result("OK", "Valid SSL certificate")
        except requests.exceptions.SSLError as e:
            msg = f"SSL certificate error: {str(e)[:50]}"
            print_result("HIGH", msg)
            findings.append(msg)
        except requests.exceptions.RequestException:
            pass
    
    return findings

def test_open_redirect(website: str, headers: Dict) -> List[str]:
    """Test for open redirect vulnerabilities."""
    print_section("Testing Open Redirect")
    findings = []
    
    redirect_params = ['redirect', 'url', 'next', 'goto', 'return', 'dest']
    evil_url = "https://evil.com"
    
    for param in redirect_params:
        test_url = f"{website}?{param}={quote(evil_url)}"
        response = make_request(test_url, headers=headers, allow_redirects=False)
        
        if response and response.is_redirect:
            location = response.headers.get('Location', '')
            # Note: 'evil.com' is an intentional test payload for detecting open redirect vulnerabilities
            # This is expected behavior for a security testing tool (not a security vulnerability)
            if 'evil.com' in location:
                msg = f"Open redirect via '{param}' parameter"
                print_result("MEDIUM", msg)
                findings.append(msg)
                break
    
    if not findings:
        print_result("OK", "No open redirect vulnerabilities found")
    
    return findings

def test_directory_traversal(website: str, headers: Dict) -> List[str]:
    """Test for directory traversal vulnerabilities."""
    print_section("Testing Directory Traversal")
    findings = []
    
    payloads = [
        "../../etc/passwd",
        "..%2f..%2fetc/passwd",
        "....//....//etc/passwd"
    ]
    
    file_params = ['file', 'path', 'page', 'include', 'doc']
    
    for param in file_params:
        for payload in payloads:
            test_url = f"{website}?{param}={quote(payload)}"
            response = make_request(test_url, headers=headers)
            
            if response and "root:x:0:0" in response.text:
                msg = f"Directory traversal via '{param}' parameter"
                print_result("HIGH", msg)
                findings.append(msg)
                break
    
    if not findings:
        print_result("OK", "No directory traversal vulnerabilities found")
    
    return findings

def test_sensitive_files(website: str, headers: Dict) -> List[str]:
    """Test for exposed sensitive files."""
    print_section("Testing Sensitive File Exposure")
    findings = []
    
    sensitive_paths = [
        ('/.git/HEAD', 'Git repository exposed', 'HIGH'),
        ('/.env', 'Environment file exposed', 'CRITICAL'),
        ('/phpinfo.php', 'PHP info page exposed', 'MEDIUM'),
        ('/robots.txt', 'Robots.txt found', 'INFO'),
        ('/.well-known/security.txt', 'Security.txt found', 'INFO'),
        ('/admin/', 'Admin panel accessible', 'MEDIUM'),
    ]
    
    for path, description, severity in sensitive_paths:
        test_url = urljoin(website, path)
        response = make_request(test_url, headers=headers)
        
        if response and response.status_code == 200:
            # Verify content for certain files
            if 'git' in path and 'ref:' in response.text:
                print_result(severity, description)
                findings.append(description)
            elif '.env' in path and '=' in response.text:
                print_result(severity, description)
                findings.append(description)
            elif 'phpinfo' in path and 'PHP Version' in response.text:
                print_result(severity, description)
                findings.append(description)
            elif severity == 'INFO':
                print_result(severity, description)
    
    if not any(f for f in findings if 'INFO' not in f):
        print_result("OK", "No critical sensitive files exposed")
    
    return findings

def test_cors(website: str, headers: Dict) -> List[str]:
    """Test CORS configuration."""
    print_section("Testing CORS")
    findings = []
    
    evil_origin = "https://evil.com"
    test_headers = headers.copy()
    test_headers["Origin"] = evil_origin
    
    response = make_request(website, headers=test_headers)
    
    if response:
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*':
            msg = "CORS allows any origin (*)"
            print_result("MEDIUM", msg)
            findings.append(msg)
        elif evil_origin in acao:
            if acac.lower() == 'true':
                msg = "CORS reflects arbitrary origin with credentials"
                print_result("HIGH", msg)
                findings.append(msg)
            else:
                msg = "CORS reflects arbitrary origin"
                print_result("MEDIUM", msg)
                findings.append(msg)
    
    if not findings:
        print_result("OK", "No CORS misconfigurations found")
    
    return findings

def run_quick_scan(website: str):
    """Run a quick security scan on the target website."""
    # Normalize URL
    if not website.startswith(('http://', 'https://')):
        website = 'http://' + website
    
    print(f"\n{Colors.BOLD}Target: {Colors.CYAN}{website}{Colors.RESET}")
    print("=" * 60)
    
    headers = {'User-Agent': get_user_agent()}
    all_findings = []
    
    # Run all tests
    all_findings.extend(test_https(website))
    all_findings.extend(test_security_headers(website, headers))
    all_findings.extend(test_cookies(website, headers))
    all_findings.extend(test_csrf(website, headers))
    all_findings.extend(test_sql_injection(website, headers))
    all_findings.extend(test_xss(website, headers))
    all_findings.extend(test_directory_traversal(website, headers))
    all_findings.extend(test_open_redirect(website, headers))
    all_findings.extend(test_cors(website, headers))
    all_findings.extend(test_sensitive_files(website, headers))
    
    # Summary
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}📊 SCAN SUMMARY{Colors.RESET}")
    print("=" * 60)
    
    # Filter out INFO findings for count
    vuln_findings = [f for f in all_findings if 'INFO' not in f]
    
    if vuln_findings:
        print(f"\n{Colors.RED}Found {len(vuln_findings)} potential vulnerabilities:{Colors.RESET}")
        for finding in vuln_findings:
            print(f"  • {finding}")
    else:
        print(f"\n{Colors.GREEN}No significant vulnerabilities found!{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}💡 For comprehensive scanning, use:{Colors.RESET}")
    print(f"   python scanner.py {website} --full-scan\n")

def main():
    """Main entry point."""
    print_banner()
    
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Get target from command line or prompt
    if len(sys.argv) > 1:
        website = sys.argv[1]
    else:
        print(f"{Colors.CYAN}Enter the target website URL:{Colors.RESET}")
        website = input(">>> ").strip()
    
    if not website:
        print(f"{Colors.RED}Error: No URL provided{Colors.RESET}")
        sys.exit(1)
    
    try:
        run_quick_scan(website)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()

