"""
nmap_plugin.py - CHARLOTTE plugin for interactive and chained Nmap scanning.

Supports multiple scan types (TCP SYN, Connect, UDP, OS detection, etc.)
Handles plugin chaining and saves results to timestamped folders.

Author: CHARLOTTE (network voyeur extraordinaire)
"""

import os
import sys
import json
from datetime import datetime

# Optional dependencies
try:
    from tabulate import tabulate
except Exception:  # pragma: no cover
    tabulate = None

# Optional scoring/heuristics module
try:
    from core.logic_modules import recon_heuristics
except Exception:  # pragma: no cover
    recon_heuristics = None

# python-nmap
import nmap

# ──────────────────────────────────────────────────────────────────────────────
# Scan types (menu)
# ──────────────────────────────────────────────────────────────────────────────
SCAN_TYPES = {
    "1": {"name": "TCP SYN Scan", "arg": "-sS", "description": "Stealthy, fast TCP scan (default)"},
    "2": {"name": "TCP Connect Scan", "arg": "-sT", "description": "Standard TCP connect scan"},
    "3": {"name": "UDP Scan", "arg": "-sU", "description": "Scan for open UDP ports"},
    "4": {"name": "Service Version Detection", "arg": "-sV", "description": "Detect service versions"},
    "5": {"name": "OS Detection", "arg": "-O", "description": "Try to identify the target OS"},
    "6": {"name": "Aggressive Scan", "arg": "-A", "description": "All-in-one: OS, services, scripts"},
    "7": {"name": "Ping Scan", "arg": "-sn", "description": "Discover live hosts (no port scan)"},
}

# ──────────────────────────────────────────────────────────────────────────────
# Device settings management
# ──────────────────────────────────────────────────────────────────────────────
DEVICE_SETTINGS_PATH = "data/device_settings.json"

def load_device_settings():
    if os.path.exists(DEVICE_SETTINGS_PATH):
        with open(DEVICE_SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_device_settings(settings):
    os.makedirs(os.path.dirname(DEVICE_SETTINGS_PATH), exist_ok=True)
    # write atomically
    tmp_path = DEVICE_SETTINGS_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4)
    os.replace(tmp_path, DEVICE_SETTINGS_PATH)

def assign_priority_by_score(score: int) -> str:
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"

def prompt_device_priority(host: str, default_score: int) -> str:
    print(f"\n[🧠 CHARLOTTE says:] \"Let's rank {host} based on how juicy it looks...\"")
    print(f"  Heuristic Score: {default_score}")
    if default_score >= 80:
        suggested = "High"
    elif default_score >= 50:
        suggested = "Medium"
    else:
        suggested = "Low"
    print(f"  → Suggested: {suggested}")
    priority = input(f"Enter priority for {host} [High/Medium/Low] (default: {suggested}): ").strip().capitalize()
    if priority not in {"High", "Medium", "Low"}:
        print(f"[!] Invalid input. Defaulting to {suggested}.")
        priority = suggested
    return priority

def extract_services_for_msf(nmap_json_path):
    """Extract likely-exploitable services from our saved JSON (host → ports dict)."""
    with open(nmap_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    candidates = []
    for host, results in data.items():
        for port, svc in results.get("ports", {}).items():
            name = str(svc.get("name", "")).lower()
            if any(k in name for k in ("http", "smb", "ftp", "ssh", "rdp", "rpc")):
                candidates.append((host, name, int(port)))
    return candidates

# ──────────────────────────────────────────────────────────────────────────────
# UI helpers
# ──────────────────────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────────────────
# Core scan
# ──────────────────────────────────────────────────────────────────────────────
def _make_scanner():
    """
    Create a PortScanner. On Windows, allow override with NMAP_EXE env var:
      set NMAP_EXE=C:\\Program Files (x86)\\Nmap\\nmap.exe
    """
    nmap_path = os.environ.get("NMAP_EXE")
    if nmap_path:
        return nmap.PortScanner(nmap_search_path=nmap_path)
    return nmap.PortScanner()

def run_nmap_scan(scan_type, target, ports=None, output_dir="data/findings"):
    """
    Executes an Nmap scan with a given scan type and saves results.

    Output JSON shape:
    {
      "<host>": {
        "state": "up",
        "last_scanned": "<timestamp>",
        "ports": {
          "22": {"state":"open","name":"ssh","product":"OpenSSH","version":"8.4"},
          "80": {"state":"open","name":"http","product":"Apache httpd","version":"2.4.57"}
        },
        "heuristics": {"score": 73, "rating": "elevated", "findings": [...]}
      },
      ...
    }
    """
    os.makedirs(output_dir, exist_ok=True)
    scanner = _make_scanner()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"nmap_{target.replace('/', '_')}_{timestamp}.json")
    port_arg = f"-p {ports}" if ports else ""

    try:
        print(f"\n[NMAP] {scan_type['name']} on {target} {f'(ports: {ports})' if ports else ''}")
        scanner.scan(hosts=target, arguments=f"{scan_type['arg']} {port_arg}")
    except Exception as e:
        print(f"[ERROR] Nmap failed on {target}: {e}")
        return None

    results = {}
    device_settings = load_device_settings()

    for host in scanner.all_hosts():
        host_state = scanner[host].state()
        ports_dict = {}

        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                entry = scanner[host][proto][port]
                # Normalize
                ports_dict[str(port)] = {
                    "state": entry.get("state", ""),
                    "name": entry.get("name", ""),
                    "product": entry.get("product", ""),
                    "version": entry.get("version", ""),
                }

        # Heuristics (optional)
        if recon_heuristics and hasattr(recon_heuristics, "triage_host"):
            host_record = [
                {"port": int(p), "name": v.get("name", ""), "product": v.get("product", ""), "version": v.get("version", "")}
                for p, v in ports_dict.items()
            ]
            heuristic_result = recon_heuristics.triage_host(host_record)
        else:
            heuristic_result = {"score": 50, "rating": "baseline", "findings": ["Heuristics module not available"]}

        # Priority (interactive vs headless)
        interactive = sys.stdin.isatty() and os.environ.get("CHARLOTTE_HEADLESS") != "1"
        if interactive:
            priority = prompt_device_priority(host, heuristic_result["score"])
        else:
            priority = assign_priority_by_score(heuristic_result["score"])
            print(f"[AUTO] Assigned priority '{priority}' for {host}")

        # Persist device settings
        device_settings[host] = {
            "priority": priority,
            "last_scanned": timestamp,
            "heuristic_score": heuristic_result["score"],
        }
        save_device_settings(device_settings)
        print(f"[💾 Saved priority '{priority}' for {host} to device_settings.json]")

        # Assemble result for this host
        results[host] = {
            "state": host_state,
            "last_scanned": timestamp,
            "ports": ports_dict,
            "heuristics": heuristic_result,
        }

        # Pretty print summary to console
        print(f"\nScan Results for {host} ({host_state})")
        for p, v in sorted(ports_dict.items(), key=lambda kv: int(kv[0])):
            banner = f"{v.get('product','')} {v.get('version','')}".strip()
            print(f"  {p}/tcp: {v.get('state','')}  {v.get('name','')}  {banner}")

        print(f"\n[⚙️  Heuristic Score: {heuristic_result['score']} - {heuristic_result['rating']}]")
        for finding in heuristic_result.get("findings", []):
            print(f"  → {finding}")

    # Save to disk
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"\n[📁 Results saved to: {output_path}]")
    return output_path

# ──────────────────────────────────────────────────────────────────────────────
# Plugin entry point (manager-compatible)
# ──────────────────────────────────────────────────────────────────────────────
def run_plugin(args=None, output_dir="data/findings"):
    """
    CHARLOTTE plugin entry point. Signature is manager-compatible.

    Behavior:
      - Headless chaining:
          args = {"targets": ["10.0.0.5", "10.0.0.6"], "scan_type": "-sV", "ports": "1-1024"}
      - Interactive:
          no args or no 'targets' -> show menu + prompt user
    """
    os.makedirs(output_dir, exist_ok=True)

    # Extract args
    targets = None
    scan_flag = None
    ports = None
    if isinstance(args, dict):
        targets = args.get("targets")
        scan_flag = args.get("scan_type")  # e.g. "-sV"
        ports = args.get("ports")
        output_dir = args.get("output_dir", output_dir)

    output_paths = []

    if targets:
        # Headless: default to -sV unless caller overrides
        chosen = next((v for v in SCAN_TYPES.values() if v["arg"] == (scan_flag or "-sV")), None)
        if not chosen:
            chosen = SCAN_TYPES["4"]  # Service Version Detection
        for host in targets:
            path = run_nmap_scan(chosen, host, ports=ports, output_dir=output_dir)
            if path:
                output_paths.append(path)
    else:
        # Interactive mode
        list_scan_options()
        chosen = choose_scan()
        target = input("\nEnter target IP or domain (comma-separated for multiple): ").strip()
        ports = input("Enter port(s) to scan (e.g. 22,80 or 1-1000) [optional]: ").strip()
        targets = [t.strip() for t in target.split(",") if t.strip()]
        for host in targets:
            path = run_nmap_scan(chosen, host, ports=ports or None, output_dir=output_dir)
            if path:
                output_paths.append(path)

    # Final summary (optional)
    device_settings = load_device_settings()
    summary_rows = [
        (host, data.get("priority", "?"), data.get("heuristic_score", 0))
        for host, data in device_settings.items()
    ]
    print("\n[🔍 CHARLOTTE Device Priority Summary]")
    if tabulate:
        print(tabulate(sorted(summary_rows, key=lambda x: x[2], reverse=True), headers=["Host", "Priority", "Score"]))
    else:
        for row in sorted(summary_rows, key=lambda x: x[2], reverse=True):
            print(f"  {row[0]:<20} {row[1]:<6} {row[2]}")

    # Return paths so other plugins can chain outputs
    return output_paths

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_plugin()
    # For testing purposes, run a sample scan
    # run_nmap_scan(SCAN_TYPES["4"], "scanme.nmap.org", ports="22,80,443", output_dir="data/findings")
    # Note: This is just for manual testing, not part of the plugin's main functionality
    # run_nmap_scan(SCAN_TYPES["1"], "scanme.nmap.org", output_dir="data/findings")
    # This allows running the plugin directly for testing without needing a manager
