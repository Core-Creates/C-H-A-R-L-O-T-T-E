"""
nmap_plugin.py - CHARLOTTE plugin for interactive and chained Nmap scanning.

Supports multiple scan types (TCP SYN, Connect, UDP, OS detection, etc.)
Handles plugin chaining and saves results to timestamped folders.

Author: CHARLOTTE (network voyeur extraordinaire)
"""

import os
import sys
import json
import nmap
from datetime import datetime
from tabulate import tabulate  # Optional dependency for summary display
from core.logic_modules import recon_heuristics  # Optional: scoring module

# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Define available scan types and their corresponding Nmap flags + descriptions
# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
SCAN_TYPES = {
    "1": {"name": "TCP SYN Scan", "arg": "-sS", "description": "Stealthy, fast TCP scan (default)"},
    "2": {"name": "TCP Connect Scan", "arg": "-sT", "description": "Standard TCP connect scan"},
    "3": {"name": "UDP Scan", "arg": "-sU", "description": "Scan for open UDP ports"},
    "4": {"name": "Service Version Detection", "arg": "-sV", "description": "Detect service versions"},
    "5": {"name": "OS Detection", "arg": "-O", "description": "Try to identify the target OS"},
    "6": {"name": "Aggressive Scan", "arg": "-A", "description": "All-in-one: OS, services, scripts"},
    "7": {"name": "Ping Scan", "arg": "-sn", "description": "Discover live hosts (no port scan)"}
}

# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Device settings management
# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

DEVICE_SETTINGS_PATH = "data/device_settings.json"

# Load device settings from JSON file
# If file does not exist, return empty settings
def load_device_settings():
    if os.path.exists(DEVICE_SETTINGS_PATH):
        with open(DEVICE_SETTINGS_PATH, "r") as f:
            return json.load(f)
    return {}

# Save device settings to JSON file
# Creates directory if it doesn't exist and makes a backup before writing
def save_device_settings(settings):
    os.makedirs(os.path.dirname(DEVICE_SETTINGS_PATH), exist_ok=True)
    if os.path.exists(DEVICE_SETTINGS_PATH):
        backup_path = DEVICE_SETTINGS_PATH.replace(".json", "_backup.json")
        os.replace(DEVICE_SETTINGS_PATH, backup_path)
    with open(DEVICE_SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=4)

# Assign priority based on heuristic score (headless mode)
# Returns "High", "Medium", or "Low" based on score thresholds
def assign_priority_by_score(score):
    if score >= 80:
        return "High"
    elif score >= 50:
        return "Medium"
    return "Low"

# Prompt user to assign priority based on heuristic score
# Provides a suggested priority based on score
def prompt_device_priority(host, default_score):
    print(f"\n[🧠 CHARLOTTE says:] \"Let's rank {host} based on how juicy it looks...\"")
    print(f"  Heuristic Score: {default_score}")
    print("  Suggested Priority based on score:")
    
    if default_score >= 80:
        suggested = "High"
    elif default_score >= 50:
        suggested = "Medium"
    else:
        suggested = "Low"

    print(f"  → Suggested: {suggested}")
    priority = input(f"Enter priority for {host} [High/Medium/Low] (default: {suggested}): ").strip().capitalize()
    if priority not in ["High", "Medium", "Low"]:
        print(f"[!] Invalid input. Defaulting to {suggested}.")
        priority = suggested
    return priority

# Save device settings with assigned priority
def save_device_with_priority(host, priority, settings):
    if host not in settings:
        settings[host] = {}
    settings[host]['priority'] = priority
    save_device_settings(settings)
    print(f"[✔️] Device {host} saved with priority: {priority}")

def extract_services_for_msf(nmap_json_path):
    """Extracts ports and services useful for Metasploit."""
    with open(nmap_json_path, "r") as f:
        data = json.load(f)

    candidates = []
    for host, results in data.items():
        for port, svc in results.get("ports", {}).items():
            if "http" in svc["name"] or "smb" in svc["name"] or "ftp" in svc["name"]:
                candidates.append((host, svc["name"], port))
    return candidates

# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Plugin functions
# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# Nmap settings ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# List available scan options
def list_scan_options():
    print("\n[CHARLOTTE] Available Nmap Scan Types:\n")
    for key, scan in SCAN_TYPES.items():
        print(f"  {key}. {scan['name']} – {scan['description']}")

# Prompt user to select a scan type
def choose_scan():
    while True:
        choice = input("\nSelect scan type by number: ").strip()
        if choice in SCAN_TYPES:
            return SCAN_TYPES[choice]
        print("[!] Invalid choice. Try again.")

# Run Nmap scan with selected type and target
# Supports both interactive and automated chaining modes
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

    # Print scan details
    print(f"\n[CHARLOTTE] Preparing to run Nmap scan:")
    try:
        print(f"\n[NMAP] Running {scan_type['name']} on {target} {f'ports: {ports}' if ports else ''}")
        scanner.scan(hosts=target, arguments=f"{scan_type['arg']} {port_arg}")
    except Exception as e:
        print(f"[ERROR] Nmap failed on {target}: {e}")
        return

    scan_output = []
    device_settings = load_device_settings()

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

        # Prompt user for device priority or auto-assign if headless
        if os.environ.get("CHARLOTTE_HEADLESS") == "1" or not sys.stdin.isatty():
            priority = assign_priority_by_score(heuristic_result['score'])
            print(f"[AUTO] Assigned priority '{priority}' for {host}")
        else:
            priority = prompt_device_priority(host, heuristic_result['score'])

        # Update device settings file
        device_settings[host] = {
            "priority": priority,
            "last_scanned": timestamp,
            "heuristic_score": heuristic_result['score']
        }
        save_device_settings(device_settings)
        print(f"[💾 Saved priority '{priority}' for {host} to device_settings.json]")

        # Save heuristic results
        scan_output.append({
            "host": host,
            "state": scanner[host].state(),
            "ports": host_record,
            "heuristics": heuristic_result
        })

    with open(output_path, "w") as f:
        json.dump(scan_output, f, indent=4)

    print(f"\n[📁 Results saved to: {output_path}]")

# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Plugin entry point
# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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

    # Show final summary sorted by score (desc)
    device_settings = load_device_settings()
    summary = [(host, data['priority'], data['heuristic_score']) for host, data in device_settings.items()]
    print("\n[🔍 CHARLOTTE Device Priority Summary]")
    print(tabulate(sorted(summary, key=lambda x: x[2], reverse=True), headers=["Host", "Priority", "Score"]))

# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# If this script is run directly, execute the plugin
# ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_plugin()

# This code is part of the CHARLOTTE CLI application, a network reconnaissance tool.
# It provides an interactive interface for running Nmap scans and supports chaining with other plugins.
