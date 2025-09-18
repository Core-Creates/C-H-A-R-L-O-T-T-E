"""
nessus_plugin.py - CHARLOTTE plugin for interactive and chained Nessus scanning.

This plugin integrates CHARLOTTE with Nessus, allowing scans to be created, launched,
and results retrieved directly from the Nessus API. It mirrors the structure and style
of the Nmap plugin, providing both interactive and headless modes.

Features:
- Lists available Nessus policies
- Creates and launches scans against chosen targets
- Polls Nessus until scans complete, then retrieves results
- Runs optional heuristics to triage findings
- Assigns host priority ratings (High/Medium/Low)
- Saves results to timestamped JSON files
- Updates device_settings.json for persistence
- Outputs a summary table of hosts, priorities, and scores

This provides a Nessus equivalent of the Nmap plugin within CHARLOTTE’s ecosystem,
ensuring consistency, automation, and an interactive user experience.

Author: CHARLOTTE (network voyeur extraordinaire) (Narooch)
"""

import os
import sys
import json
import time
from datetime import datetime
import requests

# Optional dependencies
try:
    from tabulate import tabulate
except Exception:  # pragma: no cover
    tabulate = None

try:
    from core.logic_modules import recon_heuristics
except Exception:  # pragma: no cover
    recon_heuristics = None

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


# ──────────────────────────────────────────────────────────────────────────────
# Nessus API client
# ──────────────────────────────────────────────────────────────────────────────
class NessusClient:
    def __init__(self, url, access_key, secret_key, verify_ssl=False):
        self.url = url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json"
        }

    def list_policies(self):
        r = requests.get(f"{self.url}/policies", headers=self.headers, verify=self.verify_ssl)
        return r.json() if r.ok else {"error": r.text}

    def create_scan(self, name, policy_id, targets):
        policies = self.list_policies().get("policies", [])
        policy = next((p for p in policies if p["id"] == policy_id), None)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")
        data = {
            "uuid": policy["uuid"],
            "settings": {"name": name, "policy_id": policy_id, "text_targets": targets}
        }
        r = requests.post(f"{self.url}/scans", headers=self.headers, json=data, verify=self.verify_ssl)
        return r.json() if r.ok else {"error": r.text}

    def launch_scan(self, scan_id):
        r = requests.post(f"{self.url}/scans/{scan_id}/launch", headers=self.headers, verify=self.verify_ssl)
        return r.json() if r.ok else {"error": r.text}

    def get_scan_results(self, scan_id):
        r = requests.get(f"{self.url}/scans/{scan_id}", headers=self.headers, verify=self.verify_ssl)
        return r.json() if r.ok else {"error": r.text}


# ──────────────────────────────────────────────────────────────────────────────
# Core scan workflow
# ──────────────────────────────────────────────────────────────────────────────
def run_nessus_scan(client, scan_id, output_dir="data/findings"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"nessus_scan_{scan_id}_{timestamp}.json")

    print(f"[NESSUS] Running scan {scan_id}... (this may take a while)")
    client.launch_scan(scan_id)

    # crude wait loop (poll until done)
    while True:
        results = client.get_scan_results(scan_id)
        status = results.get("info", {}).get("status", "unknown")
        print(f"  Status: {status}")
        if status == "completed":
            break
        time.sleep(10)

    findings = {}
    device_settings = load_device_settings()

    for host in results.get("hosts", []):
        hostname = host.get("hostname")
        vulns = host.get("vulnerabilities", [])

        heuristic_result = {"score": 50, "rating": "baseline", "findings": []}
        if recon_heuristics and hasattr(recon_heuristics, "triage_host"):
            heuristic_result = recon_heuristics.triage_host(vulns)

        interactive = sys.stdin.isatty() and os.environ.get("CHARLOTTE_HEADLESS") != "1"
        if interactive:
            priority = prompt_device_priority(hostname, heuristic_result["score"])
        else:
            priority = assign_priority_by_score(heuristic_result["score"])
            print(f"[AUTO] Assigned priority '{priority}' for {hostname}")

        device_settings[hostname] = {
            "priority": priority,
            "last_scanned": timestamp,
            "heuristic_score": heuristic_result["score"],
        }
        save_device_settings(device_settings)
        print(f"[💾 Saved priority '{priority}' for {hostname}]")

        findings[hostname] = {
            "last_scanned": timestamp,
            "vulnerabilities": vulns,
            "heuristics": heuristic_result,
        }

        print(f"\nScan Results for {hostname}")
        for v in vulns:
            print(f"  [{v.get('severity')}] {v.get('plugin_name')} (Plugin {v.get('plugin_id')})")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)

    print(f"[📁 Results saved to: {output_path}]")
    return output_path


# ──────────────────────────────────────────────────────────────────────────────
# Plugin entry point
# ──────────────────────────────────────────────────────────────────────────────
def run_plugin(args=None, output_dir="data/findings"):
    """Manager-compatible entry point for Nessus plugin."""
    url = os.environ.get("NESSUS_URL", "https://localhost:8834")
    access_key = os.environ.get("NESSUS_ACCESS_KEY", "")
    secret_key = os.environ.get("NESSUS_SECRET_KEY", "")
    client = NessusClient(url, access_key, secret_key, verify_ssl=False)

    scans = client.list_policies().get("policies", [])
    if not scans:
        print("[!] No Nessus policies found.")
        return []

    output_paths = []

    if isinstance(args, dict) and args.get("scan_id"):
        scan_id = args["scan_id"]
        path = run_nessus_scan(client, scan_id, output_dir=output_dir)
        if path:
            output_paths.append(path)
    else:
        print("\n[CHARLOTTE] Available Nessus Policies:")
        for p in scans:
            print(f"  {p['id']}. {p['name']}")
        choice = input("Select policy ID to run: ").strip()
        try:
            policy_id = int(choice)
        except ValueError:
            print("[!] Invalid policy ID.")
            return []
        targets = input("Enter target IP(s) or domain(s), comma-separated: ").strip()
        scan = client.create_scan("CHARLOTTE Scan", policy_id, targets)
        scan_id = scan.get("scan", {}).get("id")
        if not scan_id:
            print("[!] Failed to create scan.")
            return []
        path = run_nessus_scan(client, scan_id, output_dir=output_dir)
        if path:
            output_paths.append(path)

    # Summary
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

    return output_paths


if __name__ == "__main__":
    run_plugin()