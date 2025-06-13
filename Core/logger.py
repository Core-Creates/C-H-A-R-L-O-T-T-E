"""
logger.py

Handles logging for plugin execution and session summaries.
Includes CHARLOTTE's sass, mood commentary, and helpful glossaries.
"""

import os
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Basic Plugin Event Logger
# ─────────────────────────────────────────────────────────────────────────────

def log_plugin_event(plugin_name, message):
    """
    Logs basic events related to a specific plugin (e.g., errors, status).
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_dir = "logs/plugin_events"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{plugin_name}_{date_str}.log")

    with open(log_path, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        f.write(f"{timestamp} {message}\n")

# ─────────────────────────────────────────────────────────────────────────────
# Session Logger w/ Mood & Glossary Support
# ─────────────────────────────────────────────────────────────────────────────

def log_session(task, args, mood, output, sass_lines=None):
    """
    Logs an entire CHARLOTTE session, including mood, plugin output, and glossary.
    """
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

        # Inject sass commentary if CHARLOTTE had notes
        if sass_lines:
            f.write("\n🗯️ CHARLOTTE’s Sass:\n")
            for line in sass_lines:
                f.write(f" - {line}\n")

        glossary = get_glossary_for_plugin(task)
        if glossary:
            f.write("\n" + glossary.strip() + "\n")

        f.write("═" * 60 + "\n\n")

# ─────────────────────────────────────────────────────────────────────────────
# Glossary Definitions per Plugin
# ─────────────────────────────────────────────────────────────────────────────

def get_glossary_for_plugin(plugin_name):
    glossaries = {
        "binary_strings": """
📚 Glossary of Terms:

 • entropy: A measure of randomness or unpredictability in data. High entropy can indicate encryption or obfuscation.
 • offset: The position in the binary file where the string was found.
 • ASCII: A character encoding standard for electronic communication representing text in computers.
""",
        "reverse_engineering": """
📚 Glossary of Terms:

 • symbolic trace: A method of analyzing a program’s logic path using abstract variables instead of real input.
 • disassembly: The process of converting machine code into human-readable instructions.
 • basic block: A straight-line code sequence with no branches in except to the entry and no branches out except at the exit.
""",
        "web_recon": """
📚 Glossary of Terms:

 • subdomain: A child domain under a larger root domain, often used to host separate services (like api.example.com).
 • DNS: The Domain Name System, which maps human-readable names to IP addresses.
 • passive recon: Gathering intel without interacting with the target directly (e.g., using public records).
""",
        "port_scan": """
📚 Glossary of Terms:

 • port: A numerical label for specific services on a host (e.g., 80 for HTTP).
 • open port: A port that accepts connections—aka a potential attack surface.
 • TCP/UDP: Common transport layer protocols used in networking.
""",
        "sql_injection": """
📚 Glossary of Terms:

 • SQLi: SQL Injection—a code injection technique that exploits insecure database queries.
 • payload: Crafted input used to break, manipulate, or extract data from a system.
 • sanitization: The process of cleaning user input to prevent malicious behavior.
""",
        "xss_scan": """
📚 Glossary of Terms:

 • XSS: Cross-Site Scripting—an injection attack where malicious scripts are run in users' browsers.
 • reflected XSS: The script comes from the current HTTP request (e.g., URL).
 • stored XSS: The script is saved on the server and executed every time a page loads.
 • DOM-based XSS: The script is triggered by the browser’s JavaScript environment, not the server.
""",
        "exploit_generation": """
📚 Glossary of Terms:

 • exploit: A piece of code or data that takes advantage of a vulnerability.
 • PoC: Proof of Concept—a minimal working demonstration of an exploit.
 • CVSS: Common Vulnerability Scoring System—a standard for measuring vulnerability severity.
"""
    }

    return glossaries.get(plugin_name, "")
# ─────────────────────────────────────────────────────────────────────────────
# Example usage: