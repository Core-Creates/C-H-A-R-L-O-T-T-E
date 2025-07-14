import requests

# Define scan types and payloads
vuln_scans = {
    "1": {
        "name": "Reflected XSS",
        "payload": "<script>alert('XSS')</script>",
        "description": "Injects basic XSS payload in query param"
    },
    "2": {
        "name": "SQL Injection",
        "payload": "' OR '1'='1",
        "description": "Tests for SQLi using tautology injection"
    },
    "3": {
        "name": "Command Injection",
        "payload": "; whoami",
        "description": "Tests for unsanitized OS commands"
    }
}

def show_menu():
    print("\nAvailable Vulnerability Scan Types:\n")
    for key, scan in vuln_scans.items():
        print(f"{key}. {scan['name']} - {scan['description']}")

def get_choice():
    choice = input("\nEnter the number of the scan you want to run: ").strip()
    if choice not in vuln_scans:
        print("[!] Invalid choice. Try again.")
        return get_choice()
    return vuln_scans[choice]

def run_scan(scan_type, target_url):
    test_url = target_url
    if "?" not in test_url:
        test_url += "?test=" + scan_type["payload"]
    else:
        test_url += "&test=" + scan_type["payload"]

    print(f"\n[+] Testing {scan_type['name']} at: {test_url}")
    
    try:
        response = requests.get(test_url, timeout=10)
        if scan_type["payload"] in response.text:
            print("[!] Potential vulnerability found: Payload reflected in response!")
        else:
            print("[+] No reflection found. May not be vulnerable.")
    except Exception as e:
        print(f"[!] Error scanning: {e}")

if __name__ == "__main__":
    show_menu()
    selected_scan = get_choice()
    target = input("\nEnter the target URL (e.g. http://example.com/page.php?id=1): ").strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    run_scan(selected_scan, target)
