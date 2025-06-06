import random
from InquirerPy import inquirer
from InquirerPy.separator import Separator
from core.plugin_manager import run_plugin

# Define available tasks and their plugin keys
PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📡 Port Scan": "port_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🧼 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
}

# Define required arguments for each task
REQUIRED_ARGS = {
    "reverse_engineering": ["file"],
    "binary_strings": ["file"],
    "web_recon": ["domain"],
    "port_scan": ["target"],
    "sql_injection": ["url"],
    "xss_scan": ["url"],
    "exploit_generation": ["vuln_description"],
}

def charlotte_sass(task, missing):
    sass_responses = [
        f"Umm... you want me to run `{task}` *without* telling me where the '{missing}' is? Bold of you.",
        f"Missing '{missing}', darling. I'm an AI, not a mind reader — yet.",
        f"Excuse me, but you forgot: {missing}. I’m disappointed but not surprised.",
        f"No '{missing}'? No service. Try again, hacker.",
        f"CHARLOTTE requires '{missing}' to proceed. I suggest you try again — with less chaos.",
        f"You gave me nothing to work with. Missing: {missing}. I'm not conjuring exploits from the void.",
        f"I'm withholding judgment. But you really should’ve included '{missing}'.",
    ]
    return random.choice(sass_responses)

def validate_args(task, args_dict):
    """
    Validates that required arguments are present for the task.
    Returns a list of missing keys.
    """
    required = REQUIRED_ARGS.get(task, [])
    return [key for key in required if key not in args_dict or not args_dict[key].strip()]


def launch_cli():
    print("\n👾 Welcome to C.H.A.R.L.O.T.T.E. — Choose your task:\n")

    task_label = inquirer.select(
        message="Select a task:",
        choices=[*PLUGIN_TASKS, Separator(), "❌ Exit"],
    ).execute()

    if task_label == "❌ Exit":
        print("Goodbye, bestie 🖤")
        return

    task = PLUGIN_TASKS[task_label]

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
            print("[!] Malformed argument input. Use key=value pairs.")
            return

        # Validate required arguments
    missing = validate_args(task, args)
    if missing:
        print("\n🚫 CHARLOTTE has *notes* for you:\n")
        for m in missing:
            print("🗯️ ", charlotte_sass(task, m))
        print("\n🔁 Try again — this time with feeling.\n")
        return


    print("\n🔧 Running Plugin...\n")
    output = run_plugin(task, args)
    print("\n📤 Output:\n", output)


if __name__ == "__main__":
    launch_cli()
# This is the main entry point for the CLI application.
# It initializes the CLI, presents the task selection menu,