# ******************************************************************************************
# core/user_config.py
# First-run wizard to configure CHARLOTTE's analyst reporting + integration behavior
# ******************************************************************************************

import os
import json
from InquirerPy import inquirer
from getpass import getpass

CONFIG_FILE = os.path.join("config", "user_settings.json")

DEFAULT_SETTINGS = {
    "report_format": "PDF",
    "auto_send": False,
    "email_enabled": False,
    "email": {
        "smtp_server": "",
        "smtp_port": 587,
        "sender_email": "",
        "recipient_email": "",
        "auth_token": ""
    },
    "servicenow_enabled": False,
    "servicenow": {
        "instance_url": "",
        "api_token": "",
        "default_assignment_group": "Security Operations"
    }
}

def run_initial_setup():
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

    print("\n⚙️  CHARLOTTE First-Time Setup Wizard")
    settings = DEFAULT_SETTINGS.copy()

    # Preferred Report Format
    format_choice = inquirer.select(
        message="Preferred report format:",
        choices=["PDF", "Markdown", "HTML"]
    ).execute()
    settings["report_format"] = format_choice

    # Auto-send?
    auto_send = inquirer.confirm(
        message="Automatically send report after triage?",
        default=False
    ).execute()
    settings["auto_send"] = auto_send

    # Email Config
    email_enabled = inquirer.confirm(
        message="Send reports via email?",
        default=False
    ).execute()
    if email_enabled:
        settings["email_enabled"] = True
        settings["email"]["smtp_server"] = inquirer.text(message="SMTP Server:").execute()
        settings["email"]["smtp_port"] = int(inquirer.text(message="SMTP Port (default 587):", default="587").execute())
        settings["email"]["sender_email"] = inquirer.text(message="Sender Email:").execute()
        settings["email"]["recipient_email"] = inquirer.text(message="Recipient Email:").execute()
        settings["email"]["auth_token"] = getpass("SMTP Password or App Token: ")

    # ServiceNow Config
    servicenow_enabled = inquirer.confirm(
        message="Integrate with ServiceNow?",
        default=False
    ).execute()
    if servicenow_enabled:
        settings["servicenow_enabled"] = True
        settings["servicenow"]["instance_url"] = inquirer.text(message="ServiceNow Instance URL:").execute()
        settings["servicenow"]["api_token"] = getpass("ServiceNow API Token: ")
        settings["servicenow"]["default_assignment_group"] = inquirer.text(
            message="Default Assignment Group:",
            default="Security Operations"
        ).execute()

    # Save to file
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4)
    print(f"\n✅ Configuration saved to {CONFIG_FILE}\n")


if __name__ == "__main__":
    run_initial_setup()
# This script is intended to be run as a standalone module to configure CHARLOTTE's user settings.
# It initializes the configuration file with user preferences for reporting and integrations.