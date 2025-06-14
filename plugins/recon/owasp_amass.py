"""
owasp_amass.py - CHARLOTTE plugin for OWASP Amass reconnaissance.

Performs subdomain enumeration, optionally passive only, and parses results.
Designed for use in self-contained or offline recon modules.

Author: CHARLOTTE (touched by shadows)
"""

import subprocess
import os
import json
from datetime import datetime

OUTPUT_DIR = "data/amass_results"

def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def run_amass_enum(domain, passive=True, output_format="json"):
    """
    Executes Amass for subdomain enumeration.
    
    Args:
        domain (str): The target domain (e.g. example.com)
        passive (bool): Whether to use passive-only mode
        output_format (str): One of 'json', 'txt', or 'csv'
    
    Returns:
        str: Path to output file
    """
    ensure_output_dir()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = os.path.join(OUTPUT_DIR, f"{domain}_{timestamp}.{output_format}")

    cmd = [
        "amass", "enum",
        "-d", domain,
        "-o", output_path if output_format == "txt" else "/dev/null",  # stdout redirected if not txt
    ]

    if output_format == "json":
        cmd += ["-json", output_path]
    elif output_format == "csv":
        cmd += ["-csv", output_path]
    if passive:
        cmd.append("-passive")

    try:
        print(f"[CHARLOTTE] Running Amass on {domain}...")
        subprocess.run(cmd, check=True)
        print(f"[CHARLOTTE] Amass output saved to: {output_path}")
        return output_path
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Amass failed: {e}")
        return None

def parse_amass_json(json_path):
    """
    Parses Amass JSON results and extracts useful data.
    
    Returns:
        list of dict: Parsed subdomain records
    """
    if not os.path.exists(json_path):
        print(f"[ERROR] File not found: {json_path}")
        return []

    results = []
    with open(json_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                if "name" in obj:
                    results.append({
                        "name": obj["name"],
                        "addresses": obj.get("addresses", []),
                        "sources": obj.get("sources", [])
                    })
            except json.JSONDecodeError:
                continue

    return results

def print_summary(records):
    print("\n🔍 CHARLOTTE Recon Summary:")
    print(f"  Total subdomains found: {len(records)}\n")
    for entry in records[:10]:
        name = entry['name']
        ips = ", ".join([addr['ip'] for addr in entry.get("addresses", [])])
        print(f"  • {name}  ➝  {ips}")

def run_plugin(domain):
    json_output = run_amass_enum(domain, passive=True, output_format="json")
    if json_output:
        results = parse_amass_json(json_output)
        print_summary(results)
    else:
        print("[CHARLOTTE] Amass did not produce usable output.")

# CLI entry point (for standalone runs)
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run OWASP Amass Plugin")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--active", action="store_true", help="Use active mode (default is passive)")
    args = parser.parse_args()

    run_amass_enum(args.domain, passive=not args.active)
