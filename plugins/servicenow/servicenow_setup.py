# ******************************************************************************************
# plugins/integration/servicenow/servicenow_setup.py
# Handles first-time ServiceNow configuration for CHARLOTTE
# Prompts user and stores credentials in a local JSON file
# ******************************************************************************************

import os
import json
from InquirerPy import inquirer

CONFIG_PATH = "data/servicenow_config.json"

# ==========================================================================================
# FUNCTION: configure_servicenow()
# Prompts user for ServiceNow credentials and writes them to local config file
# ==========================================================================================
def configure_servicenow():
    print("🔧 CHARLOTTE ServiceNow Integration Setup")

    instance_url = inquirer.text(
        message="Enter your ServiceNow instance URL (e.g., https://dev12345.service-now.com):"
    ).execute().strip()

    username = inquirer.text(
        message="Enter your ServiceNow username:"
    ).execute().strip()

    password = inquirer.secret(
        message="Enter your ServiceNow password (input hidden):"
    ).execute().strip()

    config = {
        "instance_url": instance_url,
        "username": username,
        "password": password
    }

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    print(f"[✓] ServiceNow configuration saved to {CONFIG_PATH}")

# ==========================================================================================
# FUNCTION: main()
# Entry point for the ServiceNow setup script
# ==========================================================================================
def main():
    if not os.path.exists(CONFIG_PATH):
        configure_servicenow()
    else:
        print("[i] ServiceNow configuration already exists. No changes made.")

if __name__ == "__main__":
    main()