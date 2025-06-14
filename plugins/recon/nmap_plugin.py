"""
nmap_scan.py - CHARLOTTE plugin for interactive Nmap scanning.

Supports multiple scan types (TCP SYN, Connect, UDP, OS detection, etc.)
and prints human-readable recon output.

Author: CHARLOTTE (network voyeur extraordinaire)
"""

import nmap
import json
import os
from datetime import datetime
from core.logic_modules import recon_heuristics  # Assuming this module exists

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
# Logs results to JSON and runs recon heuristics scoring
# ────────────────────────────────────────────────────────────────────────────────
def run_nmap_scan(scan_type, target, ports):
    print(f"\n[+] Running {scan_type['name']} on {target}:{ports}")
    scanner = nmap.PortScanner()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join("data", f"nmap_results_{target}_{timestamp}.json")
    os.makedirs("data", exist_ok=True)

    scan_output = []

    try:
        scanner.scan(hosts=target, arguments=f"{scan_type['arg']} -p {ports}")
    except Exception as e:
        print(f"[ERROR] Nmap failed to run: {e}")
        return

    for host in scanner.all_hosts():
        print(f"\nScan Results for {host}")
        print(f"  Host Status: {scanner[host].state()}")

        host_record = []

        for proto in scanner[host].all_protocols():
            print(f"  Protocol: {proto.upper()}")
            port_list = scanner[host][proto].keys()

            for port in sorted(port_list):
                state = scanner[host][proto][port]['state']
                banner = scanner[host][proto][port].get('product', '') + ' ' + scanner[host][proto][port].get('version', '')
                print(f"    Port {port}: {state} - {banner.strip()}")

                host_record.append({"port": port, "banner": banner.strip()})

        # Run recon heuristics on the host record
        heuristic_result = recon_heuristics.triage_host(host_record)
        print(f"\n[⚙️  Heuristic Score: {heuristic_result['score']} - {heuristic_result['rating']}]")
        for finding in heuristic_result['findings']:
            print(f"  → {finding}")

        scan_output.append({
            "host": host,
            "state": scanner[host].state(),
            "ports": host_record,
            "heuristics": heuristic_result
        })

    # Save results to file
    with open(output_path, "w") as f:
        json.dump(scan_output, f, indent=4)

    print(f"\n[📁 Results saved to {output_path}]")

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
# This plugin is designed to be imported and used within a larger CHARLOTTE framework.
# It provides an interactive Nmap scanning experience with human-readable output.
# It can be integrated into the CHARLOTTE CLI or used as a standalone script.
# Ensure the plugin is loaded correctly in the CHARLOTTE framework  to access its functionality.
# This code is part of the CHARLOTTE project, a network reconnaissance tool.