# ******************************************************************************************
# core/report_dispatcher.py
# Handles sending reports to analysts or ticketing systems (e.g., email, ServiceNow)
# Depends on user_config.py settings saved in data/user_settings.json
# ******************************************************************************************

import os
import sys
import json
import smtplib
import requests
import mimetypes

# Dynamically locate CHARLOTTE root and add to Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
# Ensure CHARLOTTE core and plugins are importable
try:
    from email.message import EmailMessage
    from plugins.exploitation.metasploit.msf_mapper import find_exploit_for_cve
    from plugins.exploitation.metasploit.cve_autoscript import generate_exploit_script
except ImportError as e:
    print(f"[!] Import error: {e}")
    raise

# ==========================================================================================
# CONSTANTS

SETTINGS_FILE = os.path.join("data", "user_settings.json")


# ==========================================================================================
# FUNCTION: load_user_settings()
# Loads user-defined config from JSON
# ==========================================================================================
def load_user_settings():
    if not os.path.exists(SETTINGS_FILE):
        raise FileNotFoundError("User settings not found. Run user_config.py first.")
    with open(SETTINGS_FILE, encoding="utf-8") as f:
        return json.load(f)


# If Metasploit is connected, generate scripts for all CVEs with exploits
def autoscript_exploits(report_data, client, rhost, lhost, lport):
    for vuln in report_data.get("vulnerabilities", []):
        cve_id = vuln.get("cve_id")
        if vuln.get("metasploit_modules"):
            script_path = generate_exploit_script(cve_id, client, rhost, lhost, lport)
            if script_path:
                vuln["exploit_script"] = script_path


# ==========================================================================================
# FUNCTION: enrich_report_with_exploits()
# Attempts to enrich report with matching Metasploit modules and optionally generate scripts
# ==========================================================================================
def enrich_report_with_exploits(report_data, client):
    settings = load_user_settings()
    defaults = settings.get("exploit_defaults", {})

    if settings.get("auto_script_exploits") and client:
        autoscript_exploits(
            report_data,
            client,
            defaults.get("rhost"),
            defaults.get("lhost"),
            defaults.get("lport"),
        )

    for vuln in report_data.get("vulnerabilities", []):
        cve_id = vuln.get("cve_id")
        if cve_id:
            exploits = find_exploit_for_cve(client, cve_id)
            vuln["metasploit_modules"] = exploits


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
        msg.add_attachment(
            f.read(),
            maintype=maintype,
            subtype=subtype,
            filename=os.path.basename(file_path),
        )

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

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    auth = (config["username"], config["password"])
    instance_url = config["instance_url"].rstrip("/")
    incident_api = f"{instance_url}/api/now/table/incident"

    payload = {
        "short_description": short_description,
        "description": "Attached is a CHARLOTTE triage report.",
        "category": config.get("category", "security"),
        "urgency": config.get("urgency", "2"),
    }

    response = requests.post(incident_api, auth=auth, headers=headers, json=payload)
    response.raise_for_status()

    incident_sys_id = response.json()["result"]["sys_id"]
    print(f"[+] Created ServiceNow ticket: {incident_sys_id}")

    attachment_api = f"{instance_url}/api/now/attachment/file"
    with open(file_path, "rb") as file_data:
        files = {"file": (os.path.basename(file_path), file_data)}
        params = {"table_name": "incident", "table_sys_id": incident_sys_id}
        attach_response = requests.post(
            attachment_api, auth=auth, headers={}, params=params, files=files
        )
        attach_response.raise_for_status()

    print("[+] Report attached to ServiceNow incident.")


def show_report_summary(report_data):
    print("\n--- Triage Report Summary ---")
    print(f"Total Vulnerabilities: {len(report_data.get('vulnerabilities', []))}")
    for vuln in report_data.get("vulnerabilities", []):
        print(
            f"- {vuln.get('cve_id', 'Unknown CVE')}: {vuln.get('description', 'No description')}"
        )
    print("------------------------------")


# ==========================================================================================
# FUNCTION: save_report_locally()
# Saves the report data to a local file
# ==========================================================================================


def save_report_locally(report_data, file_path=None, interactive=True):
    if interactive:
        save_report = input("Save report locally? (y/n): ").strip().lower() == "y"
        if not save_report:
            print("[*] Report not saved locally.")
            return None
        file_name = (
            input("Enter file name (default: triage_report.json): ").strip()
            or "triage_report.json"
        )
    else:
        file_name = "triage_report.json"

    if not file_name.endswith(".json"):
        file_name += ".json"
    file_path = file_path or os.path.join("data/reports", file_name)
    os.makedirs("data/reports", exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    print(f"[+] Report saved locally to {file_path}")
    show_report_summary(report_data)
    return file_path


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


# ==========================================================================================
# FUNCTION: resend_queued_reports()
# Resends any reports that failed to dispatch previously
# ==========================================================================================
def resend_queued_reports():
    settings = load_user_settings()
    queue_file = settings.get("report_queue_file", "data/report_queue.json")

    if not os.path.exists(queue_file):
        print("[*] No queued reports to resend.")
        return

    with open(queue_file, encoding="utf-8") as f:
        queued_reports = json.load(f)

    for report in queued_reports:
        try:
            dispatch_report(report["file_path"])
            print(f"[+] Successfully resent report: {report['file_path']}")
        except Exception as e:
            print(f"[!] Failed to resend report {report['file_path']}: {e}")

    # Clear the queue after processing
    os.remove(queue_file)
    print("[+] Cleared report queue after resending.")
