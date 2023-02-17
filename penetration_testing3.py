import request
import json
from bs4 import BeautifulSoup
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

# Prompt user to enter the website URL
website = input("Enter the website URL: ")

# Test for SQL injection vulnerabilities
payloads = ["' OR 1=1 --", "1' OR '1'='1", "admin'--"]
headers = {'User-Agent': UserAgent().get_random_user_agent()}

for payload in payloads:
    r = requests.get(website + "?username=" + payload + "&password=test", headers=headers)
    if "error" not in r.text.lower():
        print("SQL injection vulnerability found with payload: " + payload)

# Test for cross-site scripting (XSS) vulnerabilities
payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

for payload in payloads:
    r = requests.post(website, headers=headers, data={"username": payload, "password": "test"})
    if payload in r.text:
        print("XSS vulnerability found with payload: " + payload)

# Test for cross-site request forgery (CSRF) vulnerabilities
r = requests.get(website, headers=headers)
soup = BeautifulSoup(r.text, 'html.parser')
if not soup.find("input", {"name":"csrf_token"}):
    print("CSRF vulnerability found. No csrf_token found in the page.")

# Test for insecure file upload vulnerability
software_names = [SoftwareName.CHROME.value]
operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
headers = {"User-Agent": UserAgent(software_names=software_names, operating_systems=operating_systems).get_random_user_agent()}
files = {"file": ("test.txt", "hello world")}
r = requests.post(website + "/upload", headers=headers, files=files)
if "upload successful" in r.text.lower():
    print("Insecure file upload vulnerability found.")
    
# Test for directory traversal vulnerabilities
payloads = ["../../etc/passwd", "..\\..\\Windows\\System32\\config\\SAM"]
for payload in payloads:
    r = requests.get(website + "/" + payload, headers=headers)
    if "root:" in r.text or "Administrator:" in r.text:
        print("Directory traversal vulnerability found with payload: " + payload)

# Test for weak credentials
common_usernames = ["admin", "root", "test"]
common_passwords = ["password", "123456", "admin"]
for username in common_usernames:
    for password in common_passwords:
        r = requests.post(website + "/login", headers=headers, data={"username": username, "password": password})
        if "logged in" in r.text.lower():
            print("Weak credentials found. username: " + username + " password  " + password)

# Test for missing or weak HTTP headers
headers_to_check = ["X-XSS-Protection", "Content-Security-Policy"]
r = requests.get(website, headers=headers)
for header in headers_to_check:
    if header not in r.headers:
        print("Missing " + header + " header.")
    elif r.headers[header] == "0" or r.headers[header] == "":
        print("Weak " + header + " header.")

# Test for clickjacking vulnerabilities
r = requests.get(website, headers=headers)
if "X-Frame-Options" not in r.headers:
    print("Clickjacking vulnerability found. No X-Frame-Options header found in the response.")

# Test for open redirect vulnerabilities
redirect_urls = ["http://evil.com", "https://attacker.com"]
for redirect_url in redirect_urls:
    r = requests.get(website + "?redirect=" + redirect_url, headers=headers)
    if r.url == redirect_url:
        print("Open redirect vulnerability found with URL: " + redirect_url)

# Test for insecure communication
if not website.startswith("https"):
    print("Insecure communication. Website is not using HTTPS.")
else:
    try:
        r = requests.get(website, headers=headers, verify=True)
    except requests.exceptions.SSLError as e:
        print("Insecure communication. Invalid SSL certificate: " + str(e))

# Test for insecure session management
r = requests.get(website, headers=headers)
if "sessionid" in r.cookies:
    session_id = r.cookies["sessionid"]
    if session_id[-5:] == "12345":
        print("Insecure session management. Session ID is not properly encrypted.")
    r = requests.get(website + "/logout", headers=headers, cookies={"sessionid": session_id})
    r = requests.get(website, headers=headers, cookies={"sessionid": session_id})
    if "logged in" in r.text.lower():
        print("Broken authentication and session management. Able to access the application with an expired or tampered session ID.")

# Test for cookie security
def get_cookies_secure_flag(url):
    # Make a GET request to the URL
    response = requests.get(url)

    # Get all the cookies set by the server
    cookies = response.cookies

    # Print the secure flag of each cookie
    for cookie in cookies:
        print("Cookie:", cookie.name)
        print("Secure Flag:", cookie.secure)

# Example URL
url = website

# Call the function to get the secure flag of cookies
get_cookies_secure_flag(url)

# Test for insufficient logging and monitoring
r = requests.get(website + "/log", headers=headers)
if "logged in" in r.text.lower() or "error" in r.text.lower():
    print("Insufficient logging and monitoring. Log data found in the response.")

# Test for brute force attack protection
payloads = ["root", "admin", "test", "password", "123456", "admin123", "qwerty"]
for payload in payloads:
    r = requests.post(website + "/login", headers=headers, data={"username": payload, "password": payload})
    if "maximum login attempts exceeded" not in r.text.lower():
        print("Brute force attack protection vulnerability found. No limit on login attempts.")

# Test for content security policy
r = requests.get(website, headers=headers)
if "Content-Security-Policy" in r.headers:
  if "script-src 'self'" not in r.headers["Content-Security-Policy"]:
   print("Content security policy vulnerability found. Scripts are not restricted to the same origin.")

# Test for server-side request forgery (SSRF) vulnerabilities
ssrf_urls = ["http://localhost", "http://127.0.0.1"]
for ssrf_url in ssrf_urls:
   r = requests.get(website + "?url=" + ssrf_url, headers=headers)
   if "localhost" in r.text.lower() or "127.0.0.1" in r.text.lower():
      print("SSRF vulnerability found with URL: " + ssrf_url)

# Test for cross-origin resource sharing (CORS) vulnerabilities
cors_headers = ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"]
for cors_header in cors_headers:
   r = requests.get(website, headers=headers)
   if cors_header not in r.headers:
      print("CORS vulnerability found. Missing " + cors_header + " header.")
   elif r.headers[cors_header] == "*":
      print("CORS vulnerability found. " + cors_header + " header set to *.")




