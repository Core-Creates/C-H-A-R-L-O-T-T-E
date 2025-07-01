# ******************************************************************************************
# core/report_dispatcher.py
# Handles sending reports to analysts or ticketing systems (e.g., email, ServiceNow)
# Depends on user_config.py settings saved in data/user_settings.json
# ******************************************************************************************

import os
import json
import smtplib
import mimetypes
from email.message import EmailMessage
import requests

SETTINGS_FILE = os.path.join("data", "user_settings.json")

# ==========================================================================================
# FUNCTION: load_user_settings()
# Loads user-defined config from JSON
# ==========================================================================================
def load_user_settings():
    if not os.path.exists(SETTINGS_FILE):
        raise FileNotFoundError("User settings not found. Run user_config.py first.")
    with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

# ==========================================================================================
# FUNCTION: send_email_report()
# Sends triage report via email with file attachment
# ==========================================================================================
def send_email_report(file_path, subject="CHARLOTTE Triage Report"):
    config = load_user_settings().get("email", {})

    msg = EmailMessage()
    msg["From"] = config["from"]
    msg["To"] = config["to"]
    msg["Subject"] = subject
    msg.set_content("Attached is the latest triage report from CHARLOTTE.")

    ctype, encoding = mimetypes.guess_type(file_path)
    maintype, subtype = (ctype or "application/octet-stream").split("/", 1)

    with open(file_path, "rb") as f:
        msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(file_path))

    with smtplib.SMTP_SSL(config["smtp_server"], config["smtp_port"]) as smtp:
        smtp.login(config["username"], config["password"])
        smtp.send_message(msg)

    print(f"[+] Report sent to {config['to']} via email.")

# ==========================================================================================
# FUNCTION: send_servicenow_ticket()
# Creates a ServiceNow incident and uploads report
# ==========================================================================================
def send_servicenow_ticket(file_path, short_description="CHARLOTTE Triage Report"):
    config = load_user_settings().get("servicenow", {})

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    auth = (config["username"], config["password"])
    instance_url = config["instance_url"].rstrip("/")
    incident_api = f"{instance_url}/api/now/table/incident"

    payload = {
        "short_description": short_description,
        "description": "Attached is a CHARLOTTE triage report.",
        "category": config.get("category", "security"),
        "urgency": config.get("urgency", "2")
    }

    response = requests.post(incident_api, auth=auth, headers=headers, json=payload)
    response.raise_for_status()

    incident_sys_id = response.json()["result"]["sys_id"]
    print(f"[+] Created ServiceNow ticket: {incident_sys_id}")

    attachment_api = f"{instance_url}/api/now/attachment/file"
    with open(file_path, "rb") as file_data:
        files = {"file": (os.path.basename(file_path), file_data)}
        params = {"table_name": "incident", "table_sys_id": incident_sys_id}
        attach_response = requests.post(attachment_api, auth=auth, headers={}, params=params, files=files)
        attach_response.raise_for_status()

    print("[+] Report attached to ServiceNow incident.")

# ==========================================================================================
# FUNCTION: dispatch_report()
# Master dispatcher that checks config and sends to destination
# ==========================================================================================
def dispatch_report(file_path):
    settings = load_user_settings()
    destination = settings.get("default_dispatch")

    if destination == "email":
        send_email_report(file_path)
    elif destination == "servicenow":
        send_servicenow_ticket(file_path)
    else:
        print("[!] No valid dispatch method configured. Report saved locally.")
    print(f"[+] Report dispatched successfully: {file_path}")