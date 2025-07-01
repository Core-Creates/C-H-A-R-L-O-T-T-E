# ******************************************************************************************
# cve_lookup.py - HARLOTTE CVE Lookup Utility
# Supports NVD-based CVE ID lookups, batch queries, year filtering, and local caching.
# ******************************************************************************************

import os
import json
import requests
from datetime import datetime

# ------------------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------------------

CACHE_FILE = os.path.join("data", "cve_cache.json")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ------------------------------------------------------------------------------------------
# Cache Management
# ------------------------------------------------------------------------------------------

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[WARN] Cache file corrupted. Starting fresh.")
    return {}


def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


# ------------------------------------------------------------------------------------------
# Core Lookup Functions
# ------------------------------------------------------------------------------------------

def fetch_cve_data(cve_id):
    cache = load_cache()
    cve_id = cve_id.upper()

    if cve_id in cache:
        return cache[cve_id], True

    try:
        response = requests.get(NVD_API, params={"cveId": cve_id})
        response.raise_for_status()
        result = response.json()
        if "vulnerabilities" in result and result["vulnerabilities"]:
            cve_info = result["vulnerabilities"][0]
            cache[cve_id] = cve_info
            save_cache(cache)
            return cve_info, False
    except Exception as e:
        return {"error": str(e)}, False

    return {"error": "CVE not found"}, False


def fetch_cves_batch(cve_ids, year_filter=None):
    results = {}
    for cve_id in cve_ids:
        if year_filter and not cve_id.startswith(f"CVE-{year_filter}"):
            continue
        data, _ = fetch_cve_data(cve_id)
        results[cve_id] = data
    return results


# ------------------------------------------------------------------------------------------
# Summary Formatter
# ------------------------------------------------------------------------------------------

def summarize_cve(cve_data):
    try:
        if "error" in cve_data:
            return f"[!] Error: {cve_data['error']}"

        cve_id = cve_data["cve"]["id"]
        description = cve_data["cve"]["descriptions"][0]["value"]
        published = cve_data.get("published", "N/A")
        cvss = "N/A"

        metrics = cve_data["cve"].get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss = metrics[version][0]["cvssData"]["baseScore"]
                break

        return f"🔍 {cve_id}:\n📅 Published: {published}\n🎯 CVSS Score: {cvss}\n📝 {description}\n"
    except Exception as e:
        return f"[!] Failed to summarize CVE: {str(e)}"


# ------------------------------------------------------------------------------------------
# Optional CLI Entry Point
# ------------------------------------------------------------------------------------------

def run(args):
    cve_arg = args.get("cve")
    year = args.get("year")

    if not cve_arg:
        return "[!] Please provide one or more CVE IDs using the 'cve' argument."

    cve_ids = [cid.strip().upper() for cid in cve_arg.split(",") if cid.strip()]
    results = fetch_cves_batch(cve_ids, year_filter=year)
    output = []
    for cid, data in results.items():
        output.append("═" * 60)
        output.append(summarize_cve(data))
    return "\n".join(output)


# ------------------------------------------------------------------------------------------
# Standalone Test Mode
# ------------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------------
# Standalone Test Mode for CHARLOTTE CVE Lookup Tool
# Supports both full CVE IDs (e.g., CVE-2023-1234) and short IDs (e.g., 1234, if year is
# also supplied). Provides robust input handling, error messages, and clean output.
# ------------------------------------------------------------------------------------------
if __name__ == "__main__":
<<<<<<< HEAD
    print("🔎 CHARLOTTE CVE Lookup Tool")
    ids_input = input("Enter CVE ID(s) (comma-separated or just numbers): ").strip()
    year = input("Filter by year (optional, required if using just numbers): ").strip()

    cve_ids = []
    for c in ids_input.split(","):
        c = c.strip()
        if not c:
            continue
        if c.upper().startswith("CVE-"):
            # Already fully-qualified CVE ID
            cve_ids.append(c.upper())
        elif c.isdigit():
            # Short number, needs a year
            if not year:
                print(f"[!] Year required for short CVE ID '{c}'. Skipping.")
                continue
            cve_ids.append(f"CVE-{year}-{c.zfill(4)}")
        else:
            # Unrecognized format
            print(f"[!] Invalid CVE ID format: '{c}'. Skipping.")
=======
    print("🔎 HARLOTTE CVE Lookup Tool")
    ids_input = input("Enter CVE ID(s) (comma-separated): ").strip()
    year = input("Filter by year (optional): ").strip()
    cve_ids = [c.strip().upper() for c in ids_input.split(",") if c.strip()]
>>>>>>> parent of afee65d (edited misspelling of CHARLOTTE in cve lookup tool)

    results = fetch_cves_batch(cve_ids, year_filter=year or None)
    for cid, data in results.items():
        print("═" * 60)
        print(summarize_cve(data))

# ------------------------------------------------------------------------------------------
# This module is designed to be imported and used by the main application.