# ******************************************************************************************
# CHARLOTTE CVE Lookup Module
# Looks up Common Vulnerabilities and Exposures from local DB or remote API
# ******************************************************************************************

import json
import os
import requests
from datetime import datetime

# Optional local cache (if user wants offline mode)
CVE_DB_PATH = "data/cve_cache.json"
REMOTE_API = "https://cve.circl.lu/api/cve/"

# ******************************************************************************************
# Utility to Load Local CVE Cache (if available)
# ******************************************************************************************
def load_local_cve_db():
    if os.path.exists(CVE_DB_PATH):
        try:
            with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Failed to load local CVE DB: {e}")
    return {}

# ******************************************************************************************
# Query CVE by ID (e.g., CVE-2023-12345)
# ******************************************************************************************
def lookup_cve(cve_id):
    local_db = load_local_cve_db()
    if cve_id in local_db:
        return local_db[cve_id]

    try:
        response = requests.get(f"{REMOTE_API}{cve_id}", timeout=10)
        if response.status_code == 200:
            cve_data = response.json()
            return cve_data
        else:
            return {"error": f"Remote lookup failed (HTTP {response.status_code})"}
    except requests.RequestException as e:
        return {"error": f"Network error: {e}"}

# ******************************************************************************************
# Pretty Print CVE Summary
# ******************************************************************************************
def format_cve(cve_data):
    if "error" in cve_data:
        return f"[!] {cve_data['error']}"

    return f"""
🔐 CVE ID: {cve_data.get('id', 'N/A')}
📅 Published: {cve_data.get('Published', 'N/A')}
📝 Summary: {cve_data.get('summary', 'No summary available.')}
🎯 CVSS Score: {cve_data.get('cvss', 'N/A')}
📂 References:
  - {cve_data.get('references', ['None'])[0] if cve_data.get('references') else 'None'}
"""

# ******************************************************************************************
# Sample Usage (standalone)
# ******************************************************************************************
if __name__ == "__main__":
    cve_id = input("Enter CVE ID (e.g., CVE-2023-12345): ").strip()
    result = lookup_cve(cve_id)
    print(format_cve(result))
