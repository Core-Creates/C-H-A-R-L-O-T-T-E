# ******************************************************************************************
# CHARLOTTE CLI - Interactive Interface for the Cybernetic Heuristic Assistant
# Provides task selection, personality configuration, and scan execution via plugin engine.
# ******************************************************************************************

import os
import sys
import json
import random
import argparse
from datetime import datetime
from InquirerPy import inquirer
from utils.logger import log_session
from InquirerPy.separator import Separator
from core.plugin_manager import run_plugin
from core import report_dispatcher # Handles report generation and dispatching 
from core.charlotte_personality import CharlottePersonality
from plugins.recon.amass.owasp_amass import run_plugin as run_amass_plugin  # Merged Amass plugin
from plugins.recon.nmap.nmap_plugin import run_plugin as run_nmap_plugin     # Merged Nmap plugin

# ******************************************************************************************
# Plugin Task + Argument Setup
# Maps human-readable labels to internal plugin keys and defines required input arguments.
# ******************************************************************************************

PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📱 Nmap Network Scanner": "nmap_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🩺 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
    "🔎 OWASP Amass Subdomain Recon": "owasp_amass",
    "🧮 Vulnerability Triage (Score + Prioritize)": "triage_agent"
}

REQUIRED_ARGS = {
    "reverse_engineering": ["file"],
    "binary_strings": ["file"],
    "web_recon": ["domain"],
    "nmap_scan": ["target", "ports"],
    "sql_injection": ["url"],
    "xss_scan": ["url"],
    "exploit_generation": ["vuln_description"],
    "owasp_amass": ["domain"],
}

PLUGIN_DOCS = {
    "binary_strings": "Extract printable ASCII strings from binaries and score them by entropy to highlight suspicious or encoded data.",
    "reverse_engineering": "Symbolically trace executable behavior without runtime execution to analyze malware or reverse binaries.",
    "web_recon": "Perform DNS recon to identify subdomains and expand attack surface for web targets.",
    "nmap_scan": "Run an interactive Nmap scan using various techniques like SYN, UDP, or Aggressive scan modes.",
    "sql_injection": "Test URLs for injectable parameters that can expose or manipulate database contents.",
    "xss_scan": "Identify reflected or stored cross-site scripting flaws in web applications.",
    "exploit_generation": "Use LLMs or rule-based templates to generate proof-of-concept exploits from vulnerability descriptions.",
    "owasp_amass": "Run OWASP Amass to enumerate subdomains using passive DNS and other sources.",
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
# Plugin Documentation Helper
# ******************************************************************************************

def check_plugin_doc():
    for arg in sys.argv:
        if arg.startswith("--doc"):
            try:
                plugin_key = sys.argv[sys.argv.index(arg) + 1]
                if plugin_key in PLUGIN_DOCS:
                    print(f"\n🗾 CHARLOTTE Plugin Help: {plugin_key}\n")
                    print(PLUGIN_DOCS[plugin_key])
                else:
                    print(f"\n[!] Unknown plugin '{plugin_key}'. Try one of: {', '.join(PLUGIN_DOCS.keys())}")
            except IndexError:
                print("[!] Please specify a plugin after --doc (e.g., --doc binary_strings)")
            sys.exit(0)

# ******************************************************************************************
# Report Helper
# ******************************************************************************************

def handle_report(report_data):
    if not report_data:
        print("[!] No report data returned.")
        return
    file_path = report_dispatcher.save_report_locally(report_data, interactive=False)
    report_dispatcher.dispatch_report(file_path)

# ******************************************************************************************
# Task Explanation Handler
# ******************************************************************************************

def explain_task(task, mood):
    print("\n🥪 CHARLOTTE says:")
    if task == "binary_strings":
        if mood == "sassy":
            print("  Honey, entropy is just chaos — measured mathematically.\n  If it looks random and sus, it probably is. Let’s dig in.\n")
        elif mood == "brooding":
            print("  Entropy... the measure of disorder. Like code. Like people.\n")
        elif mood == "manic":
            print("  OMG! High entropy = ENCRYPTION! SECRETS! CHAOS! I love it!! 🤩\n")
        elif mood == "apathetic":
            print("  Entropy is a number. It’s whatever. Just run the scan.\n")
        else:
            print("  Entropy measures how *random* or *unstructured* a string is.\n  Higher entropy often means encryption, encoding, or something suspicious.\n")
    elif task == "reverse_engineering":
        print("  Symbolic tracing helps analyze binary behavior without execution.\n  Useful for malware analysis or understanding complex binaries.\n")
    elif task == "web_recon":
        print("  Web recon helps discover hidden subdomains and potential attack surfaces.\n")
    elif task == "owasp_amass":
        print("  OWASP Amass performs passive or active subdomain enumeration.\n  Great for expanding your domain's footprint and finding weak spots.\n")
    elif task == "nmap_scan":
        print("  Nmap is my favorite. Classic recon, updated with heuristics.\n  Let’s scan and see what secrets your network is whispering.\n")
    elif task == "sql_injection":
        print("  SQL injection scans look for vulnerabilities in web applications.\n")
    elif task == "xss_scan":
        print("  XSS scans detect cross-site scripting vulnerabilities in web apps.\n")
    elif task == "exploit_generation":
        print("  Exploit generation creates payloads based on vulnerability descriptions.\n")

# ******************************************************************************************
# Entry Point Logic
# ******************************************************************************************

def main():
    check_plugin_doc()

    if __name__ != "__main__":
        return

    # Example test
    result = run_amass_plugin(domain="example.com")
    handle_report(result)

if __name__ == "__main__":
    main()
# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI.
# ******************************************************************************************
