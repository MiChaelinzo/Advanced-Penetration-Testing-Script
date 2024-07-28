import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

class WebVulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent": UserAgent(
                software_names=[SoftwareName.CHROME.value], 
                operating_systems=[OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
            ).get_random_user_agent()
        }

    def _send_request(self, url, method="GET", data=None, files=None):
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, verify=True, timeout=5)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, data=data, files=files, verify=True, timeout=5)
            else:
                print(f"Unsupported HTTP method: {method}")
                return None
            response.raise_for_status()  # Raise an exception for bad status codes
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return None

    def test_sql_injection(self, payloads=None):
        if payloads is None:
            payloads = ["'", "''",  "1=1", "--", "#"]
        for payload in payloads:
            test_url = urljoin(self.url, f"?username={payload}&password=test")
            response = self._send_request(test_url)
            if response and "error" not in response.text.lower():
                print(f"Potential SQL injection vulnerability found with payload: {payload}")

    def test_xss(self, payloads=None):
        if payloads is None:
            payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in payloads:
            test_data = {"username": payload, "password": "test"}
            response = self._send_request(self.url, method="POST", data=test_data)
            if response and payload in response.text:
                print(f"Potential XSS vulnerability found with payload: {payload}")

    def test_csrf(self):
        response = self._send_request(self.url)
        if response:
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                if form.get("method", "").upper() == "POST" and not form.find("input", {"name": "csrf_token"}):
                    print("Potential CSRF vulnerability found: Missing CSRF token in form.")

    def test_insecure_file_upload(self):
        test_url = urljoin(self.url, "/upload")  # Assuming a common upload path
        files = {"file": ("test.txt", "hello world")}
        response = self._send_request(test_url, method="POST", files=files)
        if response and "upload successful" in response.text.lower():
            print("Potential insecure file upload vulnerability found.")

    def test_directory_traversal(self, payloads=None):
        if payloads is None:
            payloads = ["../../etc/passwd", "..\\..\\Windows\\System32\\config\\SAM"]
        for payload in payloads:
            test_url = urljoin(self.url, payload)
            response = self._send_request(test_url)
            if response and ("root:" in response.text or "Administrator:" in response.text):
                print(f"Potential directory traversal vulnerability found with payload: {payload}")

  def test_weak_credentials(self, usernames=None, passwords=None):
        if usernames is None:
            usernames = ["admin", "root", "test"]
        if passwords is None:
            passwords = ["password", "123456", "admin"]
        test_url = urljoin(self.url, "/login")  # Assuming a common login path
        for username in usernames:
            for password in passwords:
                data = {"username": username, "password": password}
                response = self._send_request(test_url, method="POST", data=data)
                if response and "logged in" in response.text.lower():
                    print(f"Potential weak credentials found: Username={username}, Password={password}")

    def test_http_headers(self, headers_to_check=None):
        if headers_to_check is None:
            headers_to_check = ["X-XSS-Protection", "Content-Security-Policy", 
                                 "X-Frame-Options", "Strict-Transport-Security", 
                                 "Referrer-Policy"]  
        response = self._send_request(self.url)
        if response:
            for header in headers_to_check:
                if header not in response.headers:
                    print(f"Missing security header: {header}")
                else:
                    if header == "X-XSS-Protection" and response.headers[header] != "1; mode=block":
                        print("Weak X-XSS-Protection header. Should be '1; mode=block'.")
                    elif header == "Content-Security-Policy" and response.headers[header] == "'none'":
                        print("Weak Content-Security-Policy header. Using 'none' is not recommended.")
                    # Add more header-specific checks here as needed

    def test_clickjacking(self):
        response = self._send_request(self.url)
        if response and "X-Frame-Options" not in response.headers:
            print("Potential clickjacking vulnerability: Missing X-Frame-Options header.")

    def test_open_redirect(self, redirect_urls=None):
        if redirect_urls is None:
            redirect_urls = ["http://google.com", "https://facebook.com"]  # Use harmless external URLs
        for url in redirect_urls:
            test_url = urljoin(self.url, f"?redirect={url}")
            response = self._send_request(test_url, allow_redirects=False)  # Disable redirects
            if response and response.status_code in (301, 302) and url in response.headers.get("Location", ""):
                print(f"Potential open redirect vulnerability found with URL: {url}")

    def test_insecure_communication(self):
        if not self.url.startswith("https"):
            print("Insecure communication: Website is not using HTTPS.")
        else:
            try:
                requests.get(self.url, verify=True)  # Check for valid SSL certificate
            except requests.exceptions.SSLError as e:
                print(f"Insecure communication: Invalid SSL certificate - {e}")
     def test_insecure_session_management(self):
        """
        This test requires knowledge of:
        - How the application sets session cookies (cookie name, session ID structure).
        - A way to access a protected resource after login.
        """
        login_url = urljoin(self.url, "/login")  # Assuming a standard login path
        protected_resource_url = urljoin(self.url, "/profile")  # Assuming a protected page
        
        # 1. Login and get the session cookie:
        login_data = {"username": "testuser", "password": "testpassword"}
        login_response = self._send_request(login_url, method="POST", data=login_data)

        if login_response and "logged in" in login_response.text.lower():
            session_cookie_name = "sessionid"  # Replace with actual cookie name
            session_id = login_response.cookies.get(session_cookie_name)
            
            if session_id:
                # 2. Check for weak session ID structure:
                if session_id.isdigit() or session_id.isalnum() and len(session_id) < 32:
                    print("Potential insecure session management: Session ID appears weak (predictable).")
                
                # 3. Try accessing the protected resource with the session ID:
                cookies = {session_cookie_name: session_id}
                response = self._send_request(protected_resource_url, cookies=cookies)
                if response and "Welcome" in response.text:  # Check for successful access
                    # (Additional tests can be added here, 
                    #  e.g., tampering with the session ID, checking for expiration)
                    print("Potential insecure session management: Session fixation or hijacking might be possible.")

    def test_cookie_security(self):
        response = self._send_request(self.url)
        if response:
            for cookie in response.cookies:
                if not cookie.secure:
                    print(f"Potential cookie security issue: Cookie '{cookie.name}' is not set with the 'Secure' flag.")
                if cookie.name.lower() == "sessionid" and not cookie.httpOnly:
                    print(f"Potential cookie security issue: Session cookie '{cookie.name}' is not set with the 'HttpOnly' flag.")

    def test_insufficient_logging_monitoring(self):
        """
        This test is highly application-specific.
        It would require attempting to trigger errors/exceptions 
        and then checking if sensitive information is leaked in logs 
        (which you'd need access to).
        """
        # Example (needs adjustment based on the application):
        error_trigger_url = urljoin(self.url, "/?param=inject'error")
        response = self._send_request(error_trigger_url)
        if response and ("stack trace" in response.text.lower() or
                         "database error" in response.text.lower()):
            print("Potential insufficient logging/monitoring: Sensitive information might be exposed in error messages.")

    def test_brute_force_protection(self):
        """
        This test requires knowledge of:
        - The login form fields and how the application handles login attempts.
        """
        login_url = urljoin(self.url, "/login")  # Assuming a common login path
        test_username = "testuser" 
        for i in range(5):  # Attempt multiple logins
            data = {"username": test_username, "password": f"wrongpassword{i}"}
            response = self._send_request(login_url, method="POST", data=data)
            if response and ("account locked" in response.text.lower() or 
                             "too many attempts" in response.text.lower()):
                # Application likely has brute-force protection.
                return
        print("Potential brute-force vulnerability: No account lockout or rate limiting observed.")

    def test_content_security_policy(self):
        response = self._send_request(self.url)
        if response:
            csp_header = response.headers.get("Content-Security-Policy")
            if not csp_header:
                print("Content Security Policy (CSP) header not found.")
            else:
                # Add checks for specific CSP directives here if needed.
                if "script-src" not in csp_header or "'unsafe-inline'" in csp_header:
                    print("Potential CSP vulnerability: Inline scripts are allowed.")

    def test_ssrf(self):
        """
        This test requires knowledge of:
        - Application functionality that makes requests to user-supplied URLs.
        """
        # Example (needs adjustment based on the application):
        ssrf_test_url = urljoin(self.url, "/fetch?url=http://localhost:8080/") 
        response = self._send_request(ssrf_test_url)
        if response and ("127.0.0.1" in response.text or 
                         "localhost" in response.text or response.status_code == 500):
            print("Potential SSRF vulnerability detected!")

    def test_cors(self):
        response = self._send_request(self.url)
        if response:
            acao_header = response.headers.get("Access-Control-Allow-Origin")
            if acao_header:
                if acao_header == "*" and "Access-Control-Allow-Credentials" in response.headers:
                    print("Potential CORS vulnerability: Wildcard origin (*) used with Allow-Credentials.")
            else:
                print("Access-Control-Allow-Origin header not found.") 

    def test_broken_access_control(self):
        """
        This test requires knowledge of:
        - Application functionality that requires authentication and authorization.
        - Different user roles and their permitted actions.
        """
        # Example (needs adjustment based on the application):
        admin_url = urljoin(self.url, "/admin")

        # 1. Try accessing the admin page without authentication:
        response = self._send_request(admin_url)
        if response and response.status_code != 401:
            print(f"Potential access control issue: Unprotected access to {admin_url}")

if __name__ == "__main__":
    website_url = input("Enter the website URL: ")
    scanner = WebVulnerabilityScanner(website_url)
    
    scanner.test_sql_injection()
    scanner.test_xss()
    scanner.test_csrf()
    scanner.test_insecure_file_upload()
    scanner.test_directory_traversal()
    # Add calls to other test methods as needed
