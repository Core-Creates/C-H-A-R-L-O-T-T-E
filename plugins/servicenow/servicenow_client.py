# ******************************************************************************************
# plugins/integration/servicenow/servicenow_client.py
# ServiceNow API client for CHARLOTTE
# Supports incident creation and logic for determining critical issues
# ******************************************************************************************

import requests
import json
import os

SERVICENOW_CONFIG_PATH = "data/servicenow_config.json"

# ==========================================================================================
# FUNCTION: load_config()
# Loads ServiceNow credentials and instance URL
# ==========================================================================================
def load_config():
    if not os.path.exists(SERVICENOW_CONFIG_PATH):
        raise FileNotFoundError("ServiceNow configuration file not found. Please run setup.")
    with open(SERVICENOW_CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

# ==========================================================================================
# FUNCTION: should_create_ticket_for()
# Determines whether a finding meets criteria for ticketing
# ==========================================================================================
def should_create_ticket_for(vuln):
    return vuln.get("cvss", 0) >= 9.0 or vuln.get("impact", "").upper() == "RCE"

# ==========================================================================================
# FUNCTION: create_incident()
# Creates a ServiceNow incident from a given finding
# ==========================================================================================
def create_incident(short_description, description, urgency="2", impact="2"):
    config = load_config()
    instance_url = config.get("instance_url").rstrip("/")
    api_url = f"{instance_url}/api/now/table/incident"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "short_description": short_description,
        "description": description,
        "urgency": urgency,
        "impact": impact
    }

    try:
        response = requests.post(
            api_url,
            auth=(config["username"], config["password"]),
            headers=headers,
            json=payload
        )

        if response.status_code == 201:
            data = response.json()
            print(f"[✓] Created incident: {data['result']['number']}")
            return data['result']
        else:
            print(f"[!] Failed to create incident: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"[!] Exception during ticket creation: {e}")
        return None

# ==========================================================================================
# FUNCTION: maybe_create_tickets()
# Loops through triaged findings and creates tickets for critical ones
# ==========================================================================================
def maybe_create_tickets(findings):
    try:
        config = load_config()
    except FileNotFoundError:
        print("[!] ServiceNow config missing. Run setup before using this feature.")
        return

    print("[*] Checking for critical findings to ticket...")

    for vuln in findings:
        if should_create_ticket_for(vuln):
            short_desc = f"[CHARLOTTE] Critical: {vuln.get('id', 'Unknown ID')}"
            full_desc = (
                f"CHARLOTTE identified a critical vulnerability.\n\n"
                f"🧠 CVE: {vuln.get('id', 'N/A')}\n"
                f"📊 CVSS: {vuln.get('cvss', 'N/A')}\n"
                f"🔥 Impact: {vuln.get('impact', 'N/A')}\n"
                f"🪲 CWE: {vuln.get('cwe', 'N/A')}\n"
                f"📝 Description: {vuln.get('description', 'No details provided.')}"
            )
            create_incident(short_desc, full_desc)
    print("[*] Ticket creation process completed.")
# ==========================================================================================