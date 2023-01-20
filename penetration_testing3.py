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
