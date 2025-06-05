"""
cli.py

Interactive CLI interface for C.H.A.R.L.O.T.T.E. using InquirerPy.
Allows users to choose a task and run plugins dynamically.
"""

from InquirerPy import inquirer
from InquirerPy.separator import Separator
from core.plugin_manager import run_plugin

# Define available tasks from plugin manager
PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📡 Port Scan": "port_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🧼 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
}


def launch_cli():
    print("\n👾 Welcome to C.H.A.R.L.O.T.T.E. — Choose your task:\n")

    # Main task selection
    task_label = inquirer.select(
        message="Select a task:",
        choices=[
            *[name for name in PLUGIN_TASKS],
            Separator(),
            "❌ Exit"
        ],
    ).execute()

    if task_label == "❌ Exit":
        print("Goodbye, bestie 🖤")
        return

    task = PLUGIN_TASKS[task_label]

    # Prompt for arguments (basic version)
    raw_args = inquirer.text(
        message="Enter args as key=value (comma separated, leave blank for none):",
    ).execute()

    args = {}
    if raw_args:
        try:
            for pair in raw_args.split(","):
                key, value = pair.strip().split("=")
                args[key.strip()] = value.strip()
        except:
            print("[!] Malformed argument input. Please use key=value format.")

    print("\n🔧 Running Plugin...\n")
    output = run_plugin(task, args)
    print("\n📤 Output:\n", output)


if __name__ == "__main__":
    launch_cli()
