"""
nmap_plugin.py - CHARLOTTE plugin for interactive and chained Nmap scanning.

Supports multiple scan types (TCP SYN, Connect, UDP, OS detection, etc.)
Handles plugin chaining and saves results to timestamped folders.

Author: CHARLOTTE (network voyeur extraordinaire)
"""

import nmap
import json
import os
from datetime import datetime
from core.logic_modules import recon_heuristics  # Optional: scoring module

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

def list_scan_options():
    print("\n[CHARLOTTE] Available Nmap Scan Types:\n")
    for key, scan in SCAN_TYPES.items():
        print(f"  {key}. {scan['name']} – {scan['description']}")

def choose_scan():
    while True:
        choice = input("\nSelect scan type by number: ").strip()
        if choice in SCAN_TYPES:
            return SCAN_TYPES[choice]
        print("[!] Invalid choice. Try again.")

def run_nmap_scan(scan_type, target, ports=None, output_dir="data/findings"):
    """
    Executes an Nmap scan with a given scan type and saves results.
    Supports both interactive and chained automation modes.
    """
    os.makedirs(output_dir, exist_ok=True)
    scanner = nmap.PortScanner()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"nmap_{target}_{timestamp}.json")
    port_arg = f"-p {ports}" if ports else ""

    try:
        print(f"\n[NMAP] Running {scan_type['name']} on {target} {f'ports: {ports}' if ports else ''}")
        scanner.scan(hosts=target, arguments=f"{scan_type['arg']} {port_arg}")
    except Exception as e:
        print(f"[ERROR] Nmap failed on {target}: {e}")
        return

    scan_output = []

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

        # Heuristics
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

    with open(output_path, "w") as f:
        json.dump(scan_output, f, indent=4)

    print(f"\n[📁 Results saved to: {output_path}]")

def run_plugin(targets=None, output_dir="data/findings"):
    """
    CHARLOTTE plugin entry point.
    - If `targets` provided: used for automated chaining (uses -sV).
    - Else: prompts user for scan type, target, ports.
    """
    os.makedirs(output_dir, exist_ok=True)

    if targets:
        # Automated mode: run quiet service version detection on each target
        default_scan = {"name": "Service Version Detection", "arg": "-sV"}
        for host in targets:
            run_nmap_scan(default_scan, host, ports=None, output_dir=output_dir)
    else:
        # Interactive mode
        list_scan_options()
        selected = choose_scan()
        target = input("\nEnter target IP or domain: ").strip()
        ports = input("Enter port(s) to scan (e.g. 22,80 or 1-1000): ").strip()
        run_nmap_scan(selected, target, ports)


if __name__ == "__main__":
    run_plugin()
# This code is part of the CHARLOTTE CLI application, a network reconnaissance tool.
# It provides an interactive interface for running Nmap scans and supports chaining with other plugins.