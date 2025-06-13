# ******************************************************************************************
# CHARLOTTE CLI - Interactive Interface for the Cybernetic Heuristic Assistant
# Provides task selection, personality configuration, and scan execution via plugin engine.
# ******************************************************************************************

import random
import os
import json
import argparse
from datetime import datetime
from InquirerPy import inquirer
from core.logger import log_session
from InquirerPy.separator import Separator
from core.plugin_manager import run_plugin
from core.charlotte_personality import CharlottePersonality

# ******************************************************************************************
# Plugin Task + Argument Setup
# Maps human-readable labels to internal plugin keys and defines required input arguments.
# ******************************************************************************************

PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📡 Port Scan": "port_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🧼 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
}

REQUIRED_ARGS = {
    "reverse_engineering": ["file"],
    "binary_strings": ["file"],
    "web_recon": ["domain"],
    "port_scan": ["target"],
    "sql_injection": ["url"],
    "xss_scan": ["url"],
    "exploit_generation": ["vuln_description"],
}

# List of CHARLOTTE's predefined mood+tone profiles available to the user
PREDEFINED_MODES = ["goth_queen", "mischief", "gremlin_mode", "professional", "apathetic_ai"]

# ******************************************************************************************
# Personality Configuration
# Loads, saves, and instantiates CHARLOTTE's sass/sarcasm/chaos settings from JSON config.
# ******************************************************************************************

def load_personality_config(path="personality_config.json"):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_personality_config(config, path="personality_config.json"):
    with open(path, "w") as f:
        json.dump(config, f, indent=4)

def create_charlotte_from_config(config):
    mode = config.get("mode", "goth_queen")
    sass = config.get("sass", 0.5)
    sarcasm = config.get("sarcasm", 0.5)
    chaos = config.get("chaos", 0.5)
    return CharlottePersonality(sass=sass, sarcasm=sarcasm, chaos=chaos, mode=mode)

# ******************************************************************************************
# Validation & Logging Helpers
# Check task arguments and maintain timestamped logs of CHARLOTTE's sessions.
# ******************************************************************************************

def validate_args(task, args_dict):
    required = REQUIRED_ARGS.get(task, [])
    return [key for key in required if key not in args_dict or not args_dict[key].strip()]

def log_session(task, args, mood, output):
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H:%M:%S")
    log_dir = "logs/charlotte_sessions"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{date_str}.txt")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("═" * 60 + "\n")
        f.write(f"[🕒 {time_str}] Mood: {mood.upper()}\n")
        f.write(f"🛠️ Task: {task}\n")
        f.write(f"📥 Args: {args}\n")
        f.write("📤 Output:\n")
        f.write(output + "\n")
        f.write("═" * 60 + "\n\n")

# ******************************************************************************************
# Main Interactive CLI Handler
# Presents interactive menus for mode selection, input collection, validation, and scanning.
# ******************************************************************************************

def launch_cli():
    # 🌙 User selects CHARLOTTE's personality configuration
    selected_mode = inquirer.select(
        message="Select CHARLOTTE's personality mode:",
        choices=PREDEFINED_MODES + ["custom"],
        default="goth_queen"
    ).execute()

    if selected_mode != "custom":
        config = {"mode": selected_mode}
    else:
        # 🎛️ Manually configure sass/sarcasm/chaos sliders
        sass = float(inquirer.text(message="Sass level (0.0–1.0):", default="0.5").execute())
        sarcasm = float(inquirer.text(message="Sarcasm level (0.0–1.0):", default="0.5").execute())
        chaos = float(inquirer.text(message="Chaos level (0.0–1.0):", default="0.5").execute())
        config = {"sass": sass, "sarcasm": sarcasm, "chaos": chaos}

    # 💾 Persist mode settings to config file
    save_personality_config(config)

    # 🧠 Spin up CHARLOTTE instance based on mood profile
    charlotte = create_charlotte_from_config(config)

    # 🎭 Determine CHARLOTTE's daily attitude
    mood, phrase = charlotte.get_daily_mood()
    print(f"\n👾 Welcome to C.H.A.R.L.O.T.T.E. [Mood: {mood.upper()}]")
    print(f"💬 {phrase}\n")

    # 🧩 Ask user to select a plugin task
    task_label = inquirer.select(
        message="Select a task:",
        choices=[*PLUGIN_TASKS, Separator(), "❌ Exit"],
    ).execute()

    if task_label == "❌ Exit":
        print("Goodbye, bestie 🖤")
        return

    task = PLUGIN_TASKS[task_label]

    # 🧠 CHARLOTTE explains each task (with mood-specific entropy logic)
    if task == "binary_strings":
        print("\n🧪 CHARLOTTE says:")

        if mood == "sassy":
            print("  Honey, entropy is just chaos — measured mathematically.")
            print("  If it looks random and sus, it probably is. Let’s dig in.\n")

        elif mood == "brooding":
            print("  Entropy... the measure of disorder. Like code. Like people.\n")

        elif mood == "manic":
            print("  OMG! High entropy = ENCRYPTION! SECRETS! CHAOS! I love it!! 🤩\n")

        elif mood == "apathetic":
            print("  Entropy is a number. It’s whatever. Just run the scan.\n")

        else:
            print("  Entropy measures how *random* or *unstructured* a string is.")
            print("  Higher entropy often means encryption, encoding, or something suspicious.\n")

    elif task == "reverse_engineering":
        print("\n🧪 CHARLOTTE says:")
        print("  Symbolic tracing helps analyze binary behavior without execution.")
        print("  Useful for malware analysis or understanding complex binaries.\n")
    elif task == "web_recon":
        print("\n🧪 CHARLOTTE says:")
        print("  Web recon helps discover hidden subdomains and potential attack surfaces.\n")
    elif task == "port_scan":
        print("\n🧪 CHARLOTTE says:")
        print("  Port scanning identifies open ports and services on a target system.\n")
    elif task == "sql_injection":
        print("\n🧪 CHARLOTTE says:")
        print("  SQL injection scans look for vulnerabilities in web applications.\n")
    elif task == "xss_scan":
        print("\n🧪 CHARLOTTE says:")
        print("  XSS scans detect cross-site scripting vulnerabilities in web apps.\n")
    elif task == "exploit_generation":
        print("\n🧪 CHARLOTTE says:")
        print("  Exploit generation creates payloads based on vulnerability descriptions.\n")

    # ✍️ Collect key=value args required by plugin
    raw_args = inquirer.text(
        message="Enter args as key=value (comma separated, leave blank for none):",
    ).execute()

    args = {}
    if raw_args:
        try:
            for pair in raw_args.split(","):
                if "=" in pair:
                    key, value = pair.strip().split("=", 1)
                    args[key.strip()] = value.strip()
        except Exception as e:
            print(f"[!] Malformed argument input: {e}")
            print("⚠️ Use key=value pairs separated by commas, e.g. file=binary.elf")
            return

    # 🚫 Alert if arguments are missing
    missing = validate_args(task, args)
    if missing:
        print("\n🚫 CHARLOTTE has *notes* for you:\n")
        for m in missing:
            print("🗯️ ", charlotte.sass(task, m))
        print("\n🔁 Try again — this time with feeling.\n")
        return

    # 🚀 Run the selected plugin with validated input
    print("\n🔧 Running Plugin...\n")
    output = run_plugin(task, args)
    print("\n📤 Output:\n", output)

    # 🧾 Save results to the log
    log_session(task, args, mood, output)

# Entry point to launch CLI
if __name__ == "__main__":
    launch_cli()

# ******************************************************************************************
# End of CHARLOTTE CLI - Interactive Interface for the Cybernetic Heuristic Assistant
# ******************************************************************************************
# This code provides an interactive command-line interface for CHARLOTTE, allowing users to select tasks,
# configure personality settings, and execute various security-related plugins. It includes