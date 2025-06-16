# ******************************************************************************************
# core/report_dispatcher.py
# Handles sending reports to analysts or ticketing systems (e.g., email, ServiceNow, Slack/Teams)
# Depends on user_config.py settings saved in data/user_settings.json
# ******************************************************************************************

import os
import json
import smtplib
import argparse
import mimetypes
from email.message import EmailMessage
import requests

SETTINGS_FILE = os.path.join("data", "user_settings.json")
QUEUE_FILE = os.path.join("data", "queued_reports.json")

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
# FUNCTION: send_webhook()
# Sends report notification to Slack or Teams via webhook
# ==========================================================================================
def send_webhook(file_path):
    config = load_user_settings().get("webhook", {})
    if not config.get("url"):
        print("[!] Webhook URL not configured.")
        return

    message = {
        "text": f"CHARLOTTE Triage Report generated: {os.path.basename(file_path)}. Please review the attached file in the local reports directory or dashboard."
    }

    try:
        response = requests.post(config["url"], json=message)
        response.raise_for_status()
        print("[+] Webhook notification sent.")
    except Exception as e:
        print(f"[!] Webhook dispatch failed: {e}")
        raise

# ==========================================================================================
# FUNCTION: queue_report()
# Appends failed dispatch file path to a JSON-based queue
# ==========================================================================================
def queue_report(file_path):
    queue = []
    if os.path.exists(QUEUE_FILE):
        try:
            with open(QUEUE_FILE, "r", encoding="utf-8") as f:
                queue = json.load(f)
        except Exception:
            pass  # Assume corrupted or empty queue

    if file_path not in queue:
        queue.append(file_path)

    with open(QUEUE_FILE, "w", encoding="utf-8") as f:
        json.dump(queue, f, indent=4)

    print(f"[!] Report queued for later dispatch: {file_path}")

# ==========================================================================================
# FUNCTION: dispatch_report()
# Master dispatcher that checks config and sends to destination with fallback
# ==========================================================================================
def dispatch_report(file_path):
    try:
        settings = load_user_settings()
        destination = settings.get("default_dispatch")

        if destination == "email":
            send_email_report(file_path)
        elif destination == "servicenow":
            send_servicenow_ticket(file_path)
        else:
            print("[!] No valid dispatch method configured. Report saved locally.")

        # Always try webhook if enabled
        if settings.get("webhook", {}).get("enabled"):
            send_webhook(file_path)

        print(f"[+] Report dispatched successfully: {file_path}")

    except Exception as e:
        print(f"[!] Dispatch failed: {e}")
        queue_report(file_path)
        print("[i] You can reattempt dispatch via the CLI queue resend option.")
# ==========================================================================================
# ==========================================================================================
# FUNCTION: resend_queued_reports()
# Attempts to resend any failed reports stored in the queue
# ==========================================================================================
def resend_queued_reports():
    if not os.path.exists(QUEUE_FILE):
        print("[*] No queued reports to resend.")
        return

    try:
        with open(QUEUE_FILE, "r", encoding="utf-8") as f:
            queue = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read queue: {e}")
        return

    if not queue:
        print("[*] Report queue is empty.")
        return

    failed = []
    print(f"[*] Attempting to resend {len(queue)} reports...")

    for path in queue:
        if os.path.exists(path):
            try:
                dispatch_report(path)
            except Exception as e:
                print(f"[!] Failed to resend: {path} | {e}")
                failed.append(path)
        else:
            print(f"[!] Missing file: {path}")
            failed.append(path)

    if failed:
        with open(QUEUE_FILE, "w", encoding="utf-8") as f:
            json.dump(failed, f, indent=4)
        print(f"[!] {len(failed)} reports remain in the queue.")
    else:
        os.remove(QUEUE_FILE)
        print("[+] All queued reports resent successfully.")
        
# ==========================================================================================
# ==========================================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHARLOTTE Report Dispatcher CLI")
    parser.add_argument("file_path", nargs="?", help="Path to the report file to dispatch")
    parser.add_argument("--resend", action="store_true", help="Resend all queued reports instead of dispatching a new one")
    args = parser.parse_args()

    if args.resend:
        resend_queued_reports()
    elif args.file_path and os.path.exists(args.file_path):
        dispatch_report(args.file_path)
    else:
        print("[!] Please provide a valid report path or use --resend")
# or ensure the queue file exists for resending reports.")
# """