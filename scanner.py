#!/usr/bin/env python3

import requests
import argparse
import logging
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
from collections import defaultdict

# --- Configuration ---
# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default Payloads (can be overridden by files)
DEFAULT_SQLI_PAYLOADS = ["'", "''", "\"", "\\", "`", " OR 1=1 --", "' OR '1'='1", " UNION SELECT null, @@version -- "]
DEFAULT_XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "\"/><script>alert('XSS')</script>"]
DEFAULT_DIR_TRAVERSAL_PAYLOADS = ["../../etc/passwd", "../../../../etc/passwd", "..\\..\\Windows\\System32\\drivers\\etc\\hosts"]
DEFAULT_WEAK_USERNAMES = ["admin", "root", "test", "user", "administrator"]
DEFAULT_WEAK_PASSWORDS = ["password", "123456", "admin", "root", "test", "qwerty"]

# --- Ethical Use Warning ---
print("="*60)
print("!!! ETHICAL USE WARNING !!!")
print("This script is intended for educational purposes and authorized security testing ONLY.")
print("Using this tool against websites without explicit permission from the owner is ILLEGAL and UNETHICAL.")
print("The user assumes all responsibility for any actions performed using this script.")
print("="*60)
# ---

class WebVulnerabilityScanner:
    def __init__(self, base_url, args):
        if not base_url.startswith(('http://', 'https://')):
            self.base_url = 'http://' + base_url # Assume http if not specified
        else:
            self.base_url = base_url
        self.parsed_url = urlparse(self.base_url)
        self.args = args
        
        # Use a session object to persist cookies
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UserAgent(
                software_names=[sn.value for sn in SoftwareName], 
                operating_systems=[os.value for os in OperatingSystem]
            ).get_random_user_agent()
        })
        
        # Load payloads
        self.sqli_payloads = self._load_payloads(args.sqli_payloads, DEFAULT_SQLI_PAYLOADS)
        self.xss_payloads = self._load_payloads(args.xss_payloads, DEFAULT_XSS_PAYLOADS)
        self.dir_payloads = self._load_payloads(args.dir_payloads, DEFAULT_DIR_TRAVERSAL_PAYLOADS)
        self.weak_usernames = self._load_payloads(args.username_list, DEFAULT_WEAK_USERNAMES)
        self.weak_passwords = self._load_payloads(args.password_list, DEFAULT_WEAK_PASSWORDS)
        
        self.discovered_forms = []
        self.findings = [] # Store findings as dictionaries

    def _load_payloads(self, filepath, default_payloads):
        """Loads payloads from a file, falling back to defaults if file not found or empty."""
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                if payloads:
                    logging.info(f"Loaded {len(payloads)} payloads from {filepath}")
                    return payloads
                else:
                    logging.warning(f"Payload file {filepath} is empty, using defaults.")
            except FileNotFoundError:
                logging.warning(f"Payload file {filepath} not found, using defaults.")
            except Exception as e:
                logging.error(f"Error reading payload file {filepath}: {e}. Using defaults.")
        
        logging.info(f"Using default payloads ({len(default_payloads)}).")
        return default_payloads

    def _send_request(self, url, method="GET", data=None, files=None, cookies=None, allow_redirects=True, timeout=10):
        """Sends an HTTP request using the session object."""
        try:
            if method.upper() == "GET":
                response = self.session.get(url, params=data, verify=self.args.verify_ssl, timeout=timeout, allow_redirects=allow_redirects, cookies=cookies)
            elif method.upper() == "POST":
                response = self.session.post(url, data=data, files=files, verify=self.args.verify_ssl, timeout=timeout, allow_redirects=allow_redirects, cookies=cookies)
            else:
                logging.error(f"Unsupported HTTP method: {method}")
                return None
            
            # Optional: Raise exception for 4xx/5xx status codes if needed immediately
            # response.raise_for_status() 
            return response
        except requests.exceptions.SSLError as e:
            logging.error(f"SSL Error for {url}: {e}. Try running with --no-verify-ssl if target uses self-signed cert.")
            return None
        except requests.exceptions.Timeout:
            logging.warning(f"Request timed out for {url} (timeout={timeout}s)")
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error for {url}: {e}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred during request to {url}: {e}")
            return None
            
    def _add_finding(self, vulnerability_type, url, detail, payload=None, evidence=None):
        """Adds a structured finding to the list."""
        finding = {
            "type": vulnerability_type,
            "url": url,
            "detail": detail,
            "payload": payload,
            "evidence": evidence[:200] if evidence else None # Limit evidence size
        }
        self.findings.append(finding)
        logging.warning(f"[VULN FOUND] Type: {vulnerability_type}, URL: {url}, Detail: {detail}" + (f", Payload: {payload}" if payload else ""))

    def discover_forms(self, url):
        """Finds forms on a given URL."""
        logging.info(f"Discovering forms on {url}")
        response = self._send_request(url)
        if not response:
            return

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        logging.info(f"Found {len(forms)} forms on {url}")
        
        for form in forms:
            action = form.get("action")
            method = form.get("method", "GET").upper()
            form_url = urljoin(url, action) if action else url
            
            inputs = {}
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                input_type = input_tag.get("type", "text") # Default type
                value = input_tag.get("value", "")
                if name:
                    # For simplicity, just store name and type. Could store default values too.
                    inputs[name] = {'type': input_type, 'value': value} 
                    
            if inputs: # Only consider forms with inputs
                form_data = {"url": form_url, "method": method, "inputs": inputs}
                self.discovered_forms.append(form_data)
                logging.debug(f"Discovered form: {form_data}")

    # --- Vulnerability Test Methods ---

    def test_sql_injection(self):
        """Tests for SQL injection in URL parameters and discovered forms."""
        logging.info("Starting SQL Injection test...")
        
        # Test URL parameters (basic example, only first level)
        parsed = urlparse(self.base_url)
        query_params = parsed.query.split('&')
        if parsed.query:
            logging.info("Testing URL parameters for SQLi...")
            for param in query_params:
                 if '=' in param:
                    key = param.split('=', 1)[0]
                    for payload in self.sqli_payloads:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{key}={payload}"
                        response = self._send_request(test_url)
                        # Basic check: look for common SQL errors. More sophisticated checks needed for real scenarios.
                        if response and any(err in response.text.lower() for err in ["sql syntax", "mysql", "syntax error", "unclosed quotation mark"]):
                            self._add_finding("SQL Injection (Error-Based)", test_url, f"Potential error-based SQLi in URL parameter '{key}'", payload, response.text)

        # Test discovered forms
        logging.info("Testing discovered forms for SQLi...")
        for form in self.discovered_forms:
            form_url = form['url']
            method = form['method']
            
            for input_name in form['inputs']:
                for payload in self.sqli_payloads:
                    test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']} # Fill default values
                    test_data[input_name] = payload # Inject payload
                    
                    response = self._send_request(form_url, method=method, data=test_data)
                    if response and any(err in response.text.lower() for err in ["sql syntax", "mysql", "syntax error", "unclosed quotation mark"]):
                         self._add_finding("SQL Injection (Error-Based)", form_url, f"Potential error-based SQLi in form field '{input_name}'", payload, response.text)
                         
        logging.info("SQL Injection test finished.")

    def test_xss(self):
        """Tests for reflected XSS in URL parameters and discovered forms."""
        logging.info("Starting XSS test...")

        # Test URL parameters (basic)
        parsed = urlparse(self.base_url)
        query_params = parsed.query.split('&')
        if parsed.query:
            logging.info("Testing URL parameters for XSS...")
            for param in query_params:
                 if '=' in param:
                    key = param.split('=', 1)[0]
                    for payload in self.xss_payloads:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{key}={payload}"
                        response = self._send_request(test_url)
                        # Basic check: is the raw payload reflected in the response?
                        if response and payload in response.text:
                             self._add_finding("Cross-Site Scripting (XSS)", test_url, f"Potential reflected XSS in URL parameter '{key}'", payload, response.text)
        
        # Test discovered forms
        logging.info("Testing discovered forms for XSS...")
        for form in self.discovered_forms:
            form_url = form['url']
            method = form['method']
            
            for input_name in form['inputs']:
                 # Avoid testing password fields directly with visible payloads
                 if form['inputs'][input_name].get('type') == 'password':
                     continue
                     
                 for payload in self.xss_payloads:
                    test_data = {name: form['inputs'][name].get('value', 'test') for name in form['inputs']}
                    test_data[input_name] = payload
                    
                    response = self._send_request(form_url, method=method, data=test_data)
                    # Basic check: is the raw payload reflected in the response?
                    if response and payload in response.text:
                        self._add_finding("Cross-Site Scripting (XSS)", form_url, f"Potential reflected XSS in form field '{input_name}'", payload, response.text)
                        
        logging.info("XSS test finished.")

    def test_csrf(self):
        """Checks forms for missing CSRF tokens and session cookies for SameSite attribute."""
        logging.info("Starting CSRF test...")
        
        # Check forms discovered earlier
        for form in self.discovered_forms:
            if form['method'] == 'POST':
                has_csrf_token = False
                # Common CSRF token names - extend this list
                csrf_names = ['csrf_token', 'csrfmiddlewaretoken', '__requestverificationtoken', 'nonce', '_token'] 
                for input_name, details in form['inputs'].items():
                     # Check hidden fields or common names
                    if input_name.lower() in csrf_names or details.get('type') == 'hidden':
                        # Basic check - presence of *any* potential token. Real validation is complex.
                         has_csrf_token = True
                         break
                if not has_csrf_token:
                     self._add_finding("Cross-Site Request Forgery (CSRF)", form['url'], f"Potential CSRF vulnerability: Form may lack a CSRF token.", None, str(form['inputs']))

        # Check session cookie attributes after a request (if any cookies were set)
        response = self._send_request(self.base_url) # Make a request to get cookies
        if response and self.session.cookies:
            for cookie in self.session.cookies:
                 # Check common session cookie names - adapt as needed
                if 'session' in cookie.name.lower() or 'sessid' in cookie.name.lower():
                    if not cookie.has_nonstandard_attr('samesite') or cookie.get_nonstandard_attr('samesite', '').lower() not in ['lax', 'strict']:
                        self._add_finding("Cross-Site Request Forgery (CSRF)", self.base_url, f"Session cookie '{cookie.name}' lacks strong SameSite attribute (Strict or Lax).", None, f"Cookie: {cookie.name}={cookie.value}")
                        
        logging.info("CSRF test finished.")

    def test_insecure_file_upload(self):
        """Attempts to upload a harmless file to a common upload path."""
        logging.info("Starting Insecure File Upload test...")
        # This test is highly speculative without knowing the application structure
        upload_paths = ['/upload', '/uploads', '/files', '/admin/upload'] # Common guesses
        test_filename = "scanner_test.txt"
        test_content = b"This is a test file from the vulnerability scanner."

        for path in upload_paths:
            test_url = urljoin(self.base_url, path)
            files = {"file": (test_filename, test_content, "text/plain")} # Use 'file' as common name
            
            # Try without authentication first
            response = self._send_request(test_url, method="POST", files=files)
            
            # Basic check: look for success messages or presence of filename
            if response and (("upload successful" in response.text.lower() or test_filename in response.text) and response.status_code < 400):
                self._add_finding("Insecure File Upload", test_url, "Potential insecure file upload detected (successful response). Needs manual verification for execution.", test_filename, response.text)
                # Optionally try to access the uploaded file if a path is returned
            elif response and response.status_code in [401, 403]:
                logging.debug(f"File upload to {test_url} likely requires authentication.")
                # Could potentially add logic here to retry *if* weak creds were found earlier
            elif response is None:
                logging.debug(f"Request failed for file upload test to {test_url}") # Error logged in _send_request
                
        logging.info("Insecure File Upload test finished.")

    def test_directory_traversal(self):
        """Tests for directory traversal using common payloads."""
        logging.info("Starting Directory Traversal test...")
        
        # Test against base URL and potential directories
        paths_to_test = ['', '/static/', '/images/', '/files/', '/?file=', '/?page=', '/?include='] # Common injection points
        
        for path_segment in paths_to_test:
            for payload in self.dir_payloads:
                # Combine base, path segment, and payload carefully
                # Handle query parameter injection vs path injection
                if path_segment.endswith('='):
                    test_url = urljoin(self.base_url, path_segment + payload)
                else:
                     # Need to be careful not to create invalid URLs like http://site.com//path../..
                     base_path = urlparse(urljoin(self.base_url, path_segment)).path
                     # Ensure there's a single slash between host and payload if base_path is just '/'
                     if base_path == '/' and path_segment.endswith('/'):
                         effective_base = self.parsed_url.scheme + "://" + self.parsed_url.netloc 
                     else:
                          effective_base = urljoin(self.base_url, path_segment)
                     
                     # If effective_base ends with '/', remove leading '/' from payload if present
                     if effective_base.endswith('/') and payload.startswith('/'):
                          test_url = effective_base + payload[1:]
                     elif not effective_base.endswith('/') and not payload.startswith('/'):
                          test_url = effective_base + '/' + payload
                     else:
                          test_url = effective_base + payload
                          
                # Avoid requesting the exact same URL multiple times
                test_url = urljoin(self.base_url, test_url) # Normalize
                
                response = self._send_request(test_url)
                # Look for content typical of sensitive files. This is error-prone.
                # Status code 200 is also a strong indicator if sensitive file content appears.
                sensitive_patterns = ["root:x:0:0", "[boot loader]", "Users\\Administrator", "Session TSL", "DOCUMENT_ROOT="]
                if response and response.status_code == 200 and any(pattern in response.text for pattern in sensitive_patterns):
                     self._add_finding("Directory Traversal", test_url, "Potential directory traversal detected (sensitive content).", payload, response.text)
                elif response and "include" in test_url.lower() and "failed to open stream" in response.text.lower():
                     self._add_finding("Directory Traversal / LFI", test_url, "Potential LFI detected (PHP stream error).", payload, response.text)

        logging.info("Directory Traversal test finished.")


    def test_weak_credentials(self):
        """Attempts login with common weak credentials."""
        logging.info("Starting Weak Credentials test...")
        login_paths = ['/login', '/admin', '/signin', '/wp-login.php'] # Common guesses
        
        discovered_login_forms = [f for f in self.discovered_forms if any(p in f['url'].lower() for p in login_paths)]
        
        if not discovered_login_forms:
            logging.warning("No typical login forms discovered. Testing common paths directly.")
            test_targets = [(urljoin(self.base_url, path), 'POST') for path in login_paths] # Assume POST
        else:
            logging.info(f"Found {len(discovered_login_forms)} potential login forms.")
            test_targets = [(form['url'], form['method']) for form in discovered_login_forms]

        success_indicators = ["logout", "dashboard", "welcome admin", "log out", "control panel", "administration"]
        
        found_weak_creds = False
        for target_url, method in test_targets:
             # Try to identify username/password fields (simple heuristics)
             form = next((f for f in discovered_login_forms if f['url'] == target_url), None)
             user_field, pass_field = None, None
             if form:
                 user_field = next((name for name, details in form['inputs'].items() if 'user' in name.lower() or 'log' in name.lower()), None)
                 pass_field = next((name for name, details in form['inputs'].items() if 'pass' in name.lower() or details.get('type') == 'password'), None)
             
             # Fallback if fields not found in form or no form discovered
             if not user_field: user_field = 'username' # Common defaults
             if not pass_field: pass_field = 'password'

             logging.info(f"Testing login on {target_url} (Method: {method}) with user field '{user_field}' and pass field '{pass_field}'")

             for username in self.weak_usernames:
                 for password in self.weak_passwords:
                     if found_weak_creds and self.args.stop_on_first: # Option to stop after first success
                          logging.info("Stopping weak credential test after finding first valid combination.")
                          return
                          
                     data = {user_field: username, pass_field: password}
                     # Include other potential hidden fields if form was discovered
                     if form:
                         for name, details in form['inputs'].items():
                              if name not in [user_field, pass_field] and details.get('type') == 'hidden':
                                   data[name] = details.get('value', '')
                     
                     response = self._send_request(target_url, method=method, data=data)
                     
                     # Check for success indicators AND ensure it's not the login page again (failed login)
                     if response and any(ind in response.text.lower() for ind in success_indicators) and "login" not in response.url.lower() and response.status_code != 401:
                          # Check if redirected away from login page, often a sign of success
                          if response.history: # Check if there was a redirect
                              final_url = response.url
                              if "login" not in final_url.lower():
                                   self._add_finding("Weak Credentials", target_url, f"Potential weak credentials found: Username='{username}', Password='{password}'", f"{username}:{password}", f"Redirected to {final_url}")
                                   found_weak_creds = True
                                   break # Move to next username
                          elif response.status_code == 200: # Check non-redirected success
                               self._add_finding("Weak Credentials", target_url, f"Potential weak credentials found: Username='{username}', Password='{password}'", f"{username}:{password}", f"Success indicator found on page.")
                               found_weak_creds = True
                               break # Move to next username
                               
                 if found_weak_creds and self.args.stop_on_first: break # Exit outer loop too
        
        if not found_weak_creds:
             logging.info("No obvious weak credentials found.")
        logging.info("Weak Credentials test finished.")


    def test_http_headers(self):
        """Checks for missing or insecurely configured security headers."""
        logging.info("Starting HTTP Security Headers test...")
        response = self._send_request(self.base_url)
        if not response:
            logging.error("Cannot test headers; initial request failed.")
            return

        headers = response.headers
        findings = [] # Collect header findings before logging/adding

        # Strict-Transport-Security (HSTS)
        if 'Strict-Transport-Security' not in headers:
            if self.base_url.startswith("https://"):
                findings.append(("Missing Header", "Strict-Transport-Security (HSTS)", "Header not set, vulnerable to downgrade attacks."))
        else:
            if 'max-age' not in headers['Strict-Transport-Security'] or int(headers['Strict-Transport-Security'].split('max-age=')[1].split(';')[0]) < 31536000: # Check for reasonable max-age (e.g., 1 year)
                 findings.append(("Insecure Header", "Strict-Transport-Security (HSTS)", f"Low max-age or missing max-age. Value: {headers['Strict-Transport-Security']}"))

        # Content-Security-Policy (CSP)
        if 'Content-Security-Policy' not in headers:
            findings.append(("Missing Header", "Content-Security-Policy (CSP)", "Header not set, increasing XSS risk."))
        else:
            csp = headers['Content-Security-Policy']
            if "'unsafe-inline'" in csp and ("script-src" in csp or "default-src" in csp):
                 findings.append(("Insecure Header", "Content-Security-Policy (CSP)", f"Allows 'unsafe-inline' scripts. Value: {csp}"))
            if "'unsafe-eval'" in csp and ("script-src" in csp or "default-src" in csp):
                 findings.append(("Insecure Header", "Content-Security-Policy (CSP)", f"Allows 'unsafe-eval'. Value: {csp}"))
            if "default-src *" in csp or "script-src *" in csp or "style-src *" in csp:
                 findings.append(("Insecure Header", "Content-Security-Policy (CSP)", f"Uses overly broad wildcard source (*). Value: {csp}"))

        # X-Frame-Options
        xfo = headers.get('X-Frame-Options', '').upper()
        if not xfo:
            # Check if CSP frame-ancestors is used instead
            csp = headers.get('Content-Security-Policy', '')
            if 'frame-ancestors' not in csp:
                 findings.append(("Missing Header", "X-Frame-Options", "Header not set and no CSP frame-ancestors, vulnerable to Clickjacking."))
        elif xfo not in ['DENY', 'SAMEORIGIN']:
            findings.append(("Insecure Header", "X-Frame-Options", f"Allows framing from potentially untrusted origins. Value: {xfo}"))

        # X-Content-Type-Options
        if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
            findings.append(("Missing/Insecure Header", "X-Content-Type-Options", f"Should be set to 'nosniff'. Value: {headers.get('X-Content-Type-Options', 'Not Set')}"))

        # Referrer-Policy
        if 'Referrer-Policy' not in headers:
             findings.append(("Missing Header", "Referrer-Policy", "Header not set, may leak sensitive information in Referer header."))
        # Add checks for weak policies if needed, e.g., 'unsafe-url'

        # Permissions-Policy (newer header replacing Feature-Policy)
        if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
             findings.append(("Missing Header", "Permissions-Policy / Feature-Policy", "Header not set, consider setting restrictive defaults."))

        # Server Information Leakage
        server_header = headers.get('Server')
        x_powered_by = headers.get('X-Powered-By')
        if server_header and server_header.lower() not in ['nginx', 'apache']: # Check for detailed version info
            if any(char.isdigit() for char in server_header):
                findings.append(("Information Leakage", "Server Header", f"Server header reveals specific version information. Value: {server_header}"))
        if x_powered_by:
             findings.append(("Information Leakage", "X-Powered-By Header", f"X-Powered-By header reveals technology information. Value: {x_powered_by}"))

        # Add findings to main list
        for finding_type, header_name, detail in findings:
            self._add_finding(f"{finding_type} ({header_name})", self.base_url, detail, None, headers.get(header_name))

        logging.info("HTTP Security Headers test finished.")

    def test_clickjacking(self):
        """Checks specifically for headers preventing clickjacking."""
        logging.info("Starting Clickjacking test...")
        response = self._send_request(self.base_url)
        if not response: return

        headers = response.headers
        xfo = headers.get('X-Frame-Options', '').upper()
        csp = headers.get('Content-Security-Policy', '')

        if not xfo and 'frame-ancestors' not in csp:
            self._add_finding("Clickjacking", self.base_url, "Missing X-Frame-Options and CSP frame-ancestors directives.", None, f"Headers: {dict(headers)}")
        elif xfo and xfo not in ['DENY', 'SAMEORIGIN']:
             self._add_finding("Clickjacking", self.base_url, f"X-Frame-Options allows framing from potentially untrusted origins: {xfo}", None, f"Header: X-Frame-Options: {xfo}")
        elif 'frame-ancestors' in csp and any(src in csp for src in ['*', 'http:', 'https:']): # Check for overly permissive frame-ancestors
              # More complex parsing needed for accurate check here
             logging.warning(f"CSP frame-ancestors found, but might be overly permissive: {csp}")

        logging.info("Clickjacking test finished.")

    def test_open_redirect(self):
        """Tests for open redirect vulnerabilities in common parameters."""
        logging.info("Starting Open Redirect test...")
        # Parameters commonly used for redirects
        redirect_params = ['redirect', 'url', 'next', 'destination', 'returnTo', 'goto']
        # Use a harmless, recognizable external URL. Avoid user-controlled input here.
        external_target = "https://example.com/scanner-test-redirect" 
        
        # Test against base URL with query parameters
        parsed = urlparse(self.base_url)
        base_for_redirect_test = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in redirect_params:
            test_url = f"{base_for_redirect_test}?{param}={external_target}"
            # Send request *without* allowing redirects to check the Location header
            response = self._send_request(test_url, allow_redirects=False)
            
            # Check for 3xx status code and Location header pointing to our external target
            if response and response.is_redirect: # Checks for 3xx status codes
                location_header = response.headers.get('Location', '')
                if external_target in location_header:
                     self._add_finding("Open Redirect", test_url, f"Potential open redirect vulnerability via '{param}' parameter.", external_target, f"Status: {response.status_code}, Location: {location_header}")

        # Could also test discovered forms if they seem redirect-related, but less common
        
        logging.info("Open Redirect test finished.")


    def test_insecure_communication(self):
        """Checks if the site uses HTTPS and if the certificate is valid."""
        logging.info("Starting Insecure Communication test...")
        
        if not self.base_url.startswith("https"):
            self._add_finding("Insecure Communication (HTTP)", self.base_url, "Website is served over HTTP, not HTTPS. Data is transmitted in plaintext.", None, None)
        else:
            # The verify=True/False is handled in _send_request based on --no-verify-ssl
            # We already logged SSL errors there. Here, we just note if verification was skipped.
             if not self.args.verify_ssl:
                  logging.warning("SSL certificate verification was skipped (--no-verify-ssl). Cannot confirm certificate validity.")
             else:
                 # Try a basic request again specifically to confirm validity if not already failed
                 try:
                     requests.get(self.base_url, verify=True, timeout=5)
                     logging.info("HTTPS is used and certificate verification seems successful.")
                 except requests.exceptions.SSLError as e:
                      # This duplicates the error log from _send_request but adds a finding
                      self._add_finding("Insecure Communication (SSL Error)", self.base_url, f"HTTPS used, but SSL certificate verification failed: {e}", None, str(e))
                 except requests.exceptions.RequestException as e:
                      logging.error(f"Could not verify HTTPS connection due to network error: {e}")

        logging.info("Insecure Communication test finished.")

    def test_cookie_security(self):
        """Checks security attributes of cookies set by the server."""
        logging.info("Starting Cookie Security test...")
        response = self._send_request(self.base_url) # Initial request to capture cookies
        if not response: 
             logging.error("Cannot test cookies; initial request failed.")
             return

        # Check cookies set by the server via Set-Cookie headers
        if not self.session.cookies:
            logging.info("No cookies were set by the server on the initial request.")
            return
            
        logging.info(f"Analyzing {len(self.session.cookies)} cookies...")
        for cookie in self.session.cookies:
            details = []
            if not cookie.secure:
                 # Secure flag missing is only relevant for HTTPS sites
                 if self.base_url.startswith("https"):
                     details.append("Cookie lacks 'Secure' flag (sent over HTTPS).")
            
            # HttpOnly flag check (especially important for session cookies)
            if not cookie.has_nonstandard_attr('httponly') or not cookie.get_nonstandard_attr('httponly'):
                  # Check if it looks like a session cookie
                  if 'sess' in cookie.name.lower() or 'auth' in cookie.name.lower() or 'token' in cookie.name.lower():
                       details.append("Potential session cookie lacks 'HttpOnly' flag (accessible to client-side scripts).")
                  else:
                       details.append("Cookie lacks 'HttpOnly' flag.")

            # SameSite flag check (already partially checked in CSRF test, more detailed here)
            samesite_val = cookie.get_nonstandard_attr('samesite', '').lower()
            if not samesite_val:
                 details.append("Cookie lacks 'SameSite' attribute (defaults vary by browser, potential CSRF risk).")
            elif samesite_val not in ['strict', 'lax']:
                 details.append(f"Cookie has weak 'SameSite' attribute: '{samesite_val}'.")

            if details:
                self._add_finding("Cookie Security Issue", self.base_url, f"Issues found with cookie '{cookie.name}': {'; '.join(details)}", cookie.value, f"Attributes: domain={cookie.domain}, path={cookie.path}, secure={cookie.secure}, httponly={cookie.has_nonstandard_attr('httponly')}, samesite={samesite_val}")

        logging.info("Cookie Security test finished.")
        
    # --- Add other test methods from the original code here, adapting them similarly ---
    # e.g., test_insufficient_logging_monitoring (hard to automate well)
    # e.g., test_brute_force_protection (needs refinement like weak creds test)
    # e.g., test_ssrf (highly context-dependent, hard to generalize)
    # e.g., test_cors (needs requests from a different origin, complex for basic script)
    # e.g., test_broken_access_control (requires knowledge of roles/paths)


    def run_scan(self):
        """Runs the selected vulnerability scans."""
        logging.info(f"Starting scan on {self.base_url}")
        
        # 1. Discover forms on the base page (can be expanded to crawl)
        self.discover_forms(self.base_url)

        # 2. Run individual tests (add more as they are implemented/updated)
        self.test_insecure_communication() # Check HTTPS first
        self.test_http_headers()
        self.test_clickjacking() # Partially covered by headers, specific check
        self.test_cookie_security()
        self.test_sql_injection()
        self.test_xss()
        self.test_csrf()
        self.test_directory_traversal()
        # self.test_insecure_file_upload() # Often needs specific knowledge/paths
        self.test_weak_credentials() # Can be noisy/slow
        self.test_open_redirect()
        # Add calls to other implemented tests here
        
        logging.info(f"Scan finished. Found {len(self.findings)} potential issues.")

    def report_findings(self, output_file=None):
        """Prints or saves the findings."""
        print("\n" + "="*20 + " SCAN RESULTS " + "="*20)
        if not self.findings:
            print("No potential vulnerabilities found.")
            return

        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.findings, f, indent=4)
                print(f"Findings saved to {output_file}")
            except Exception as e:
                logging.error(f"Failed to write findings to {output_file}: {e}")
                print("--- Findings ---")
                for finding in self.findings:
                    print(json.dumps(finding, indent=2)) # Fallback to printing
        else:
             print("--- Findings ---")
             for finding in self.findings:
                print(f"\nType: {finding['type']}")
                print(f"URL: {finding['url']}")
                print(f"Detail: {finding['detail']}")
                if finding.get('payload'):
                    print(f"Payload: {finding['payload']}")
                if finding.get('evidence'):
                    print(f"Evidence Snippet: {finding['evidence']}")
                print("-" * 10)
        
        print("="*54)

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Web Vulnerability Scanner. Use responsibly and ethically.")
    
    parser.add_argument("url", help="Target website URL (e.g., http://example.com)")
    parser.add_argument("--sqli-payloads", help="File containing SQL injection payloads (one per line)")
    parser.add_argument("--xss-payloads", help="File containing XSS payloads (one per line)")
    parser.add_argument("--dir-payloads", help="File containing Directory Traversal payloads (one per line)")
    parser.add_argument("--username-list", help="File containing usernames for weak credential checks")
    parser.add_argument("--password-list", help="File containing passwords for weak credential checks")
    parser.add_argument("-o", "--output", help="Output file to save findings in JSON format")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl", help="Disable SSL certificate verification (use with caution)")
    parser.add_argument("--stop-on-first", action="store_true", help="Stop weak credential test after finding the first valid login")
    # Add arguments for specific test toggles if needed
    
    args = parser.parse_args()

    scanner = WebVulnerabilityScanner(args.url, args)
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user.")
    except Exception as e:
        logging.critical(f"An critical error occurred during the scan: {e}", exc_info=True)
    finally:
        scanner.report_findings(args.output)

    # Note: For a production-grade tool, consider adding:
    # - More sophisticated detection logic (e.g., time-based SQLi, DOM XSS analysis)
    # - Concurrency (threading/asyncio) for speed
    # - Website crawling capabilities
    # - Authentication handling (login before testing protected areas)
    # - More robust state management
    # - Fuzzing capabilities
    # - Integration with external tools/databases (e.g., CVE databases)
    # - Better reporting formats (HTML, XML)
