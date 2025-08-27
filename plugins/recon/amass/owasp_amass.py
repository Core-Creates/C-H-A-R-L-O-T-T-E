# ******************************************************************************************
# plugins/recon/amass/owasp_amass.py
# CHARLOTTE plugin for OWASP Amass - Subdomain Enumeration
# Supports passive and active modes, multiple output formats, and CHARLOTTE JSON parsing.
# Author: CHARLOTTE (touched by shadows)
# ******************************************************************************************

import subprocess
import os
import json
from datetime import datetime

OUTPUT_DIR = "data/findings"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_amass_enum(domain, passive=True, output_format="json"):
    """
    Executes Amass for subdomain enumeration.
    Returns both the file path and the containing output folder.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = os.path.join(OUTPUT_DIR, f"amass_{domain}_{timestamp}")
    os.makedirs(folder, exist_ok=True)

    output_path = os.path.join(folder, f"{domain}_{'passive' if passive else 'active'}.{output_format}")

    cmd = [
        "amass", "enum",
        "-d", domain,
        "-o", output_path if output_format == "txt" else "/dev/null"
    ]

    if output_format == "json":
        cmd += ["-json", output_path]
    elif output_format == "csv":
        cmd += ["-csv", output_path]

    if passive:
        cmd.append("-passive")

    try:
        print(f"[CHARLOTTE] Running Amass ({'passive' if passive else 'active'}) on {domain}...")
        subprocess.run(cmd, check=True)
        print(f"[CHARLOTTE] Output saved to: {output_path}")
        return output_path, folder
    except subprocess.CalledProcessError as e:
        print(f"[!] Amass execution failed: {e}")
        return None, None


def parse_amass_json(json_path):
    """
    Parses Amass JSON output to CHARLOTTE-compatible format.

    Args:
        json_path (str): Path to Amass JSON file

    Returns:
        list: List of parsed records
    """
    results = []
    if not os.path.exists(json_path):
        print(f"[!] File not found: {json_path}")
        return results

    with open(json_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
                results.append({
                    "plugin": "owasp_amass",
                    "type": "subdomain",
                    "domain": obj.get("name"),
                    "addresses": obj.get("addresses", []),
                    "source": obj.get("sources", [{}])[0].get("name", "unknown"),
                    "timestamp": obj.get("timestamp"),
                    "tags": obj.get("tag", []),
                })
            except json.JSONDecodeError:
                continue
    return results


def print_summary(records):
    """
    Prints a CHARLOTTE-styled summary table.

    Args:
        records (list): List of parsed subdomain results
    """
    print("\n🔍 CHARLOTTE Recon Summary:")
    print(f"  Total subdomains found: {len(records)}\n")
    for entry in records[:10]:  # Only show top 10 for brevity
        name = entry['domain']
        ips = ", ".join([addr['ip'] for addr in entry.get("addresses", [])])
        print(f"  • {name}  ➝  {ips}")


def run_plugin(chain_followups=True):
    """
    CHARLOTTE CLI interface for plugin execution.
    Supports optional chaining to Nmap and HTTP banner scan.
    """
    from InquirerPy import inquirer
    from core.plugin_manager import run_plugin as run_next_plugin

    domain = inquirer.text(message="🌐 Target domain to scan:").execute()
    mode = inquirer.select(message="🛠️ Amass mode:", choices=["passive", "active"]).execute()
    passive_mode = (mode == "passive")

    json_output, folder = run_amass_enum(domain, passive=passive_mode, output_format="json")
    if not json_output:
        print("[!] Amass did not produce usable output.")
        return

    results = parse_amass_json(json_output)
    print_summary(results)

    summary_path = os.path.join(folder, f"charlotte_subdomains_{domain}_{mode}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[✓] Results saved to: {summary_path}")

    # 🔗 CHAINING
    if chain_followups:
        confirm = inquirer.confirm(
            message="🔗 Chain results to Nmap and HTTP Banner plugins?", default=True
        ).execute()
        if confirm:
            unique_hosts = set()
            for item in results:
                if item.get("domain"):
                    unique_hosts.add(item["domain"])
                for addr in item.get("addresses", []):
                    ip = addr.get("ip")
                    if ip:
                        unique_hosts.add(ip)

            target_list = sorted(unique_hosts)
            print(f"\n🔗 Chaining {len(target_list)} hosts into Nmap and HTTP Banner plugins...")

            run_next_plugin("nmap_plugin", targets=target_list, output_dir=folder)
            run_next_plugin("http_banner", targets=target_list, output_dir=folder)
    else:
        print("\n[ℹ️] No follow-up plugins chained. You can run them manually later.")
        

# ******************************************************************************************
# Optional: standalone CLI usage
# ******************************************************************************************

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Run OWASP Amass Plugin")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--active", action="store_true", help="Use active mode (default is passive)")
    args = parser.parse_args()

    json_output, folder = run_amass_enum(
        args.domain,
        passive=not args.active,
        output_format="json",
    )

    if json_output:
        parsed = parse_amass_json(json_output)
        print_summary(parsed)

        summary_path = os.path.join(
            folder,
            f"charlotte_subdomains_{args.domain}_{'active' if args.active else 'passive'}.json"
        )
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=2)

        print(f"[✓] Results saved to: {summary_path}")
    else:
        print("[!] Amass execution failed or produced no output.")
        sys.exit(1)
