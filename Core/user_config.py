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
    },
    "slack_enabled": False,
    "slack": {
        "webhook_url": "",
        "channel": "#general"
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
    slack_enabled = inquirer.confirm(
        message="Send alerts to Slack via webhook?",
        default=False
    ).execute()
    if slack_enabled:
        settings["slack_enabled"] = True
        settings["slack"]["webhook_url"] = inquirer.text(message="Slack Incoming Webhook URL:").execute()
        settings["slack"]["channel"] = inquirer.text(message="Default Slack channel (e.g. #general):", default="#general").execute()
        settings["slack"]["username"] = inquirer.text(
            message="Slack Bot Username (optional):",
            default="CHARLOTTE"
        ).execute()
        settings["slack"]["icon_emoji"] = inquirer.text(
            message="Slack Bot Icon Emoji (optional):",
            default=":robot_face:"
        ).execute()
        settings["slack"]["channel"] = inquirer.text(
            message="Slack Channel Name (optional, for direct messages):",
            default="#general"
        ).execute()
        settings["slack"]["channel_id"] = inquirer.text(
            message="Slack Channel ID (optional, for direct messages):",
            default=""
        ).execute()
        settings["slack"]["team_name"] = inquirer.text(
            message="Slack Team Name (optional, for direct messages):",
            default=""
        ).execute()
        settings["slack"]["team_id"] = inquirer.text(
            message="Slack Team ID (optional, for direct messages):",
            default=""
        ).execute()
        settings["slack"]["thread_ts"] = inquirer.text(
            message="Slack Thread Timestamp (optional, for threaded messages):",
            default=""
        ).execute()
        settings["slack"]["attachments"] = inquirer.confirm(
            message="Include attachments in Slack messages?",
            default=True
        ).execute()
        settings["slack"]["markdown"] = inquirer.confirm(
            message="Use Markdown formatting in Slack messages?",
            default=True
        ).execute()
        settings["slack"]["notify"] = inquirer.confirm(
            message="Notify users with @here or @channel?",
            default=False
        ).execute()
        settings["slack"]["notify_users"] = inquirer.text(
            message="Comma-separated list of user IDs to notify (optional):",
            default=""
        ).execute().split(",")
        settings["slack"]["notify_groups"] = inquirer.text(
            message="Comma-separated list of group IDs to notify (optional):",
            default=""
        ).execute().split(",")
        settings["slack"]["notify_roles"] = inquirer.text(
            message="Comma-separated list of role IDs to notify (optional):",
            default=""
        ).execute().split(",")
        settings["slack"]["notify_channels"] = inquirer.text(
            message="Comma-separated list of channel IDs to notify (optional):",
            default=""
        ).execute().split(",")
        settings["slack"]["notify_everyone"] = inquirer.confirm(
            message="Notify @everyone in the channel?",
            default=False
        ).execute()
        settings["slack"]["configuration_url"] = inquirer.text(
            message="Slack Configuration URL (optional, for more settings):",
            default="https://api.slack.com/apps"
        ).execute()
        settings["slack"]["configuration_token"] = getpass(
            "Slack Configuration Token (optional, for API access):"
        )
        settings["slack"]["configuration_client_id"] = inquirer.text(
            message="Slack Configuration Client ID (optional, for OAuth):",
            default=""
        ).execute()
    
    # Confirm settings
    print("\n🔧 Configuration Summary:"
          f"\n- Report Format: {settings['report_format']}"
          f"\n- Auto-send: {'Enabled' if settings['auto_send'] else 'Disabled'}"
          f"\n- Email: {'Enabled' if settings['email_enabled'] else 'Disabled'}"
          f"\n- ServiceNow: {'Enabled' if settings['servicenow_enabled'] else 'Disabled'}"
          f"\n- Slack: {'Enabled' if settings['slack_enabled'] else 'Disabled'}")
    
    # Prompt to save settings
    save = inquirer.confirm(
        message="Save these settings?",
        default=True
    ).execute()
    if not save:
        print("\n❌ Configuration not saved. Exiting setup.")
        return
    print("\n✅ Configuration saved successfully!")
    # Ensure config directory exists
    if not os.path.exists("config"):
        os.makedirs("config")

    # Save settings to JSON file
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4)
    print(f"\n✅ Configuration saved to {CONFIG_FILE}\n")
    # Print final confirmation
    print("CHARLOTTE is now configured and ready to assist you with CVE triage and reporting!")
    print("You can always modify these settings later in the config/user_settings.json file.\n")
    # Exit the setup
    print("Thank you for setting up CHARLOTTE! Happy triaging! 🎉"
          "\n\nYou can now run CHARLOTTE with your configured settings.\n"
          "Use the command `python charlotte.py` to start the application.\n"
          "\n\nIf you need to reconfigure, just run this script again.\n"
            "\n\nFor any issues or feedback, please visit our GitHub repository:\n"
          "Exiting setup. Have a great day! 😊"
          "\n\n- The CHARLOTTE Team")


if __name__ == "__main__":
    run_initial_setup()
# This script is intended to be run as a standalone module to configure CHARLOTTE's user settings.
# It initializes the configuration file with user preferences for reporting and integrations.