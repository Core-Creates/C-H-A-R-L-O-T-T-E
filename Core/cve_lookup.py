# ******************************************************************************************
# cve_lookup.py - CVE Lookup Utility for CHARLOTTE
# Supports online and offline queries, with batch and year filtering.
# ******************************************************************************************

import os
import json
import requests
from datetime import datetime

CACHE_FILE = os.path.join("data", "cve_cache.json")
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def fetch_cve_data(cve_id):
    cache = load_cache()
    cve_id = cve_id.upper()
    if cve_id in cache:
        return cache[cve_id], True

    params = {"cveId": cve_id}
    try:
        response = requests.get(API_URL, params=params)
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
        data, from_cache = fetch_cve_data(cve_id)
        results[cve_id] = data
    return results


def summarize_cve(cve_data):
    try:
        if "error" in cve_data:
            return f"[!] Error: {cve_data['error']}"

        cve_id = cve_data["cve"]["id"]
        description = cve_data["cve"]["descriptions"][0]["value"]
        published = cve_data.get("published", "N/A")
        cvss = "N/A"

        metrics = cve_data.get("cve", {}).get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss = metrics[version][0]["cvssData"]["baseScore"]
                break

        return f"🔍 {cve_id}:\n📅 Published: {published}\n🎯 CVSS Score: {cvss}\n📝 {description}\n"
    except Exception as e:
        return f"[!] Failed to summarize CVE: {str(e)}"


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


if __name__ == "__main__":
    print("🔎 CHARLOTTE CVE Lookup Tool")
    ids_input = input("Enter CVE ID(s) (comma-separated): ").strip()
    year = input("Filter by year (optional): ").strip()
    cve_ids = [c.strip() for c in ids_input.split(",") if c.strip()]

    results = fetch_cves_batch(cve_ids, year_filter=year or None)
    for cid, data in results.items():
        print("═" * 60)
        print(summarize_cve(data))
