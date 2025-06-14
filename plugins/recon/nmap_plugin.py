"""
nmap_scan.py - CHARLOTTE plugin for interactive Nmap scanning.

Supports multiple scan types (TCP SYN, Connect, UDP, OS detection, etc.)
and prints human-readable recon output.

Author: CHARLOTTE (network voyeur extraordinaire)
"""

import nmap

# ────────────────────────────────────────────────────────────────────────────────
# Define available scan types and their corresponding Nmap flags + descriptions
# ────────────────────────────────────────────────────────────────────────────────
SCAN_TYPES = {
    "1": {"name": "TCP SYN Scan", "arg": "-sS", "description": "Stealthy, fast TCP scan (default)"},
    "2": {"name": "TCP Connect Scan", "arg": "-sT", "description": "Standard TCP connect scan"},
    "3": {"name": "UDP Scan", "arg": "-sU", "description": "Scan for open UDP ports"},
    "4": {"name": "Service Version Detection", "arg": "-sV", "description": "Detect service versions"},
    "5": {"name": "OS Detection", "arg": "-O", "description": "Try to identify the target OS"},
    "6": {"name": "Aggressive Scan", "arg": "-A", "description": "All-in-one: OS, services, scripts"},
    "7": {"name": "Ping Scan", "arg": "-sn", "description": "Discover live hosts (no port scan)"}
}

# ────────────────────────────────────────────────────────────────────────────────
# Display all scan types to the user in a numbered menu
# ────────────────────────────────────────────────────────────────────────────────
def list_scan_options():
    print("\n[CHARLOTTE] Available Nmap Scan Types:\n")
    for key, scan in SCAN_TYPES.items():
        print(f"  {key}. {scan['name']} – {scan['description']}")

# ────────────────────────────────────────────────────────────────────────────────
# Prompt user to select a scan type by number (retries if invalid)
# ────────────────────────────────────────────────────────────────────────────────
def choose_scan():
    while True:
        choice = input("\nSelect scan type by number: ").strip()
        if choice in SCAN_TYPES:
            return SCAN_TYPES[choice]
        print("[!] Invalid choice. Try again.")

# ────────────────────────────────────────────────────────────────────────────────
# Core Nmap scanning logic using python-nmap wrapper
# Executes selected scan type on target with specified ports
# ────────────────────────────────────────────────────────────────────────────────
def run_nmap_scan(scan_type, target, ports):
    print(f"\n[+] Running {scan_type['name']} on {target}:{ports}")
    scanner = nmap.PortScanner()
    try:
        # Run the scan using provided scan type and port range
        scanner.scan(hosts=target, arguments=f"{scan_type['arg']} -p {ports}")
    except Exception as e:
        print(f"[ERROR] Nmap failed to run: {e}")
        return

    # ───── Parse and print scan results ─────
    for host in scanner.all_hosts():
        print(f"\nScan Results for {host}")
        print(f"  Host Status: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"  Protocol: {proto.upper()}")
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                state = scanner[host][proto][port]['state']
                print(f"    Port {port}: {state}")

# ────────────────────────────────────────────────────────────────────────────────
# CHARLOTTE plugin entry point for interactive CLI scan
# Prompts for scan type, target, and port range before running scan
# ────────────────────────────────────────────────────────────────────────────────
def run_plugin():
    list_scan_options()
    selected = choose_scan()
    target = input("\nEnter target IP or domain: ").strip()
    ports = input("Enter port(s) to scan (e.g. 22,80 or 1-1000): ").strip()
    run_nmap_scan(selected, target, ports)

# ────────────────────────────────────────────────────────────────────────────────
# If this file is run directly, activate interactive scan prompt
# ────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_plugin()
# ────────────────────────────────────────────────────────────────────────────────
# End of nmap_plugin.py