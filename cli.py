import random
import os
import json
import argparse
from datetime import datetime
from InquirerPy import inquirer
from InquirerPy.separator import Separator
from core.plugin_manager import run_plugin
from core.charlotte_personality import CharlottePersonality

#=======================================================================================================
# Plugin Task + Argument Setup
#=======================================================================================================

# Maps friendly task names to internal plugin keys
PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📡 Port Scan": "port_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🧼 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
}

# Defines required arguments for each plugin
REQUIRED_ARGS = {
    "reverse_engineering": ["file"],
    "binary_strings": ["file"],
    "web_recon": ["domain"],
    "port_scan": ["target"],
    "sql_injection": ["url"],
    "xss_scan": ["url"],
    "exploit_generation": ["vuln_description"],
}

# List of predefined CHARLOTTE personality modes
PREDEFINED_MODES = ["goth_queen", "mischief", "gremlin_mode", "professional", "apathetic_ai"]

# ========================================================================================
# Personality Mode Configuration
# Personality Initialization
# ========================================================================================

# Load JSON config (if available)
def load_personality_config(path="personality_config.json"):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Create a CHARLOTTE instance based on mode or sliders
def create_charlotte_from_config(config):
    mode = config.get("mode", "goth_queen")
    sass = config.get("sass", 0.5)
    sarcasm = config.get("sarcasm", 0.5)
    chaos = config.get("chaos", 0.5)
    return CharlottePersonality(sass=sass, sarcasm=sarcasm, chaos=chaos, mode=mode)

# ========================================================================================
# Main Task Execution & Validation
# Validation & Logging Helpers
# ========================================================================================

# Ensure all required arguments for a task are present
def validate_args(task, args_dict):
    required = REQUIRED_ARGS.get(task, [])
    return [key for key in required if key not in args_dict or not args_dict[key].strip()]

# Append task execution to log file by date
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

# ================================================================================================
# Main Interactive CLI Handler
# ================================================================================================

def launch_cli():
    # ✨ Ask user to select a personality mode or enter custom sliders
    selected_mode = inquirer.select(
        message="Select CHARLOTTE's personality mode:",
        choices=PREDEFINED_MODES + ["custom"],
        default="goth_queen"
    ).execute()

    # If a mode is chosen, build config from it
    if selected_mode != "custom":
        config = {"mode": selected_mode}
    else:
        # Otherwise ask for sass/sarcasm/chaos manually
        sass = float(inquirer.text(message="Sass level (0.0–1.0):", default="0.5").execute())
        sarcasm = float(inquirer.text(message="Sarcasm level (0.0–1.0):", default="0.5").execute())
        chaos = float(inquirer.text(message="Chaos level (0.0–1.0):", default="0.5").execute())
        config = {"sass": sass, "sarcasm": sarcasm, "chaos": chaos}

    # 🔧 Build CHARLOTTE from provided configuration
    charlotte = create_charlotte_from_config(config)

    # 🌡️ Get CHARLOTTE’s mood of the day and greeting phrase
    mood, phrase = charlotte.get_daily_mood()
    print(f"\n👾 Welcome to C.H.A.R.L.O.T.T.E. [Mood: {mood.upper()}]")
    print(f"💬 {phrase}\n")

    # 🧩 Task selection
    task_label = inquirer.select(
        message="Select a task:",
        choices=[*PLUGIN_TASKS, Separator(), "❌ Exit"],
    ).execute()

    if task_label == "❌ Exit":
        print("Goodbye, bestie 🖤")
        return

    task = PLUGIN_TASKS[task_label]

    # 📝 Gather key=value args
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

    # ✅ Validate required arguments
    missing = validate_args(task, args)
    if missing:
        print("\n🚫 CHARLOTTE has *notes* for you:\n")
        for m in missing:
            print("🗯️ ", charlotte.sass(task, m))
        print("\n🔁 Try again — this time with feeling.\n")
        return

    # 🚀 Execute plugin and display output
    print("\n🔧 Running Plugin...\n")
    output = run_plugin(task, args)
    print("\n📤 Output:\n", output)

    # 🧾 Log this session
    log_session(task, args, mood, output)

# Entry point
if __name__ == "__main__":
    launch_cli()
# Ensure the script runs only when executed directly
# if __name__ == "__main__":