# ******************************************************************************************
# load_nmap_results.py
# Utility for loading and parsing CHARLOTTE's Nmap scan JSON output
# ******************************************************************************************

import os
import json

# ==========================================================================================
# FUNCTION: load_nmap_results()
# Loads Nmap scan data from CHARLOTTE-formatted JSON
# ==========================================================================================
def load_nmap_results(filepath):
    """
    Load CHARLOTTE-style Nmap scan JSON results.

    Args:
        filepath (str): Path to the JSON output from CHARLOTTE's Nmap plugin.

    Returns:
        List[Dict]: List of hosts with services and metadata, or None on failure.
    """
    if not os.path.exists(filepath):
        print(f"[!] Nmap results file not found: {filepath}")
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "hosts" not in data:
            print("[!] Unexpected format: missing 'hosts' key.")
            return None

        print(f"[+] Loaded Nmap results: {len(data['hosts'])} host(s) found.")
        return data["hosts"]

    except json.JSONDecodeError:
        print(f"[!] Failed to decode JSON in {filepath}")
    except Exception as e:
        print(f"[!] Error reading Nmap results: {e}")

    return None
# ==========================================================================================
# End of load_nmap_results.py
# ******************************************************************************************