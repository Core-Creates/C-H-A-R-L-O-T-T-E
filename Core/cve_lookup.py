# ******************************************************************************************
# cve_lookup.py - CVE Lookup Utility for CHARLOTTE
# Supports online and offline queries, with batch and year filtering.
# ******************************************************************************************

import os
import json
import requests

CACHE_FILE = os.path.join("data", "cve_cache.json")
REMOTE_API = "https://cve.circl.lu/api/cve/"


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=4)


def fetch_cve_online(cve_id):
    try:
        res = requests.get(REMOTE_API + cve_id)
        if res.status_code == 200:
            return res.json()
        else:
            return None
    except Exception:
        return None


def get_cve_info(cve_id, cache):
    cve_id = cve_id.upper()
    if cve_id in cache:
        return cache[cve_id], True

    data = fetch_cve_online(cve_id)
    if data:
        cache[cve_id] = data
        save_cache(cache)
    return data, False


def format_cve_data(cve_data):
    if not cve_data:
        return "[!] No data found."
    return f"""
🆔 {cve_data.get('id')}
📛 Summary: {cve_data.get('summary')}
🏷️  CVSS Score: {cve_data.get('cvss')}
🧪 Published: {cve_data.get('Published')}
🧪 Modified: {cve_data.get('Modified')}
🔗 Link: https://cve.circl.lu/api/cve/{cve_data.get('id')}
"""


def lookup_single(cve_id):
    cache = load_cache()
    cve_data, from_cache = get_cve_info(cve_id, cache)
    source = "[CACHE]" if from_cache else "[API]"
    return source + "\n" + format_cve_data(cve_data)


def lookup_batch(cve_ids):
    cache = load_cache()
    results = []
    for cve_id in cve_ids:
        cve_data, from_cache = get_cve_info(cve_id, cache)
        source = "[CACHE]" if from_cache else "[API]"
        results.append(source + "\n" + format_cve_data(cve_data))
    return "\n".join(results)


def filter_cves_by_year(cve_ids, year):
    cache = load_cache()
    year = str(year)
    filtered = []
    for cve_id in cve_ids:
        cve_data, _ = get_cve_info(cve_id, cache)
        if cve_data and cve_data.get("Published", "").startswith(year):
            filtered.append(cve_id)
    return filtered


# Example usage (you can integrate this into a plugin UI or CLI):
# print(lookup_single("CVE-2023-12345"))
# print(lookup_batch(["CVE-2023-12345", "CVE-2022-0001"]))
# print(filter_cves_by_year(["CVE-2023-12345", "CVE-2022-0001"], 2023))
# Note: The example usage is commented out. You can uncomment and use it in your application.
# This module can be imported and used in other parts of the CHARLOTTE application.