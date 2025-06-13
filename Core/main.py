# ******************************************************************************************
# main.py - Minimal Launcher for CHARLOTTE with Banner and Plugin Hook
# ******************************************************************************************

import os
import sys
import json
from core import cve_lookup
from datetime import datetime
from InquirerPy import inquirer
# ******************************************************************************************
# Utility Functions
# Ensure root project path is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from InquirerPy import inquirer
from InquirerPy.separator import Separator
from plugin_manager import run_plugin, load_plugins
from charlotte_personality import CharlottePersonality

# Initialize CHARLOTTE personality
charlotte = CharlottePersonality()

# ******************************************************************************************
# Banner Art
# ******************************************************************************************

def print_banner():
    PURPLE = "\033[35m"
    RESET = "\033[0m"
    skull_banner = f"""{PURPLE}
                              ..................
                        ...........................
                       ..............................
                    ...................................
                   .....................................
                  .......................................
                  .......................................                       ,,
                  .......................................                    .';;;;'.             ..     ........              ''''                          ...              ;'''''''''''';         ;'''''''''''';           ;''''''''''';
                  ......................................                ....        '           ....     ....             ......             ''.       ;;            '  '                      '..' '..'            ;            ;         ;            ;           ;  .........;            
                    ...................................                ....                     ....     ....            ..'  '..            ''..........            .  .                    ...'     '...               ....                   ....                ;  '''''''';            
                    ....        .....''.....       ....               .....           ........  ...''''''....  .......  .''''''''.   ....... '.........    .......   .  .          .......  ..,.      .,..  .......      ....      .......      ....       .......  ;  ,.......;               
                    .'..        ..'  .. '...      ....                '''''           ........  .............  ....... ...''''''...  ....... ',''''',.     .......   .  .          .......  ..,.      .,..  .......      ....      .......      ....       .......  ;  ;            
                   .....      ...'   ..   '..     ....                 .....        .;          ....     ....          ...      ...          '.'     ,.              '  '''''''''            ..',. .,.'..                ....                   ....                ;  ''''''''';                    
                  ..'''''....''''... . ....'............                ....'......'..          ....     ....          ...      ...          '.'      ...            '..........;             .........                  ....                   ....                ............;           
                 ........................................                '.........;'                                                                                                                    
                     ...............................                                                                                                                     
                         🔮  C - H - A - R - L - O - T - T - E  🔮
{RESET}"""
    print(skull_banner)

# ******************************************************************************************
# Plugin Task Selection Logic
# ******************************************************************************************

PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📡 Port Scan": "port_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🧼 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
    "🔓 Binary Exploit (ROP Chain)": "binary_exploit",
    "🕵️ CVE Lookup (HARLOTTE)": "cve_lookup"
}
# ******************************************************************************************
# CVE Lookup Plugin Logic


def run_cve_lookup():
    print("\n=== HARLOTTE CVE Intelligence Module ===")

    option = inquirer.select(
        message="Choose your CVE query method:",
        choices=[
            "🔎 Lookup by CVE ID",
            "🗂️ Search by Keyword",
            "📅 List CVEs by Product and Year",
            "❌ Back to Main Menu"
        ]
    ).execute()

    if option == "🔎 Lookup by CVE ID":
        cve_id = input("Enter CVE ID (e.g., CVE-2023-12345): ").strip().upper()
        if not cve_id.startswith("CVE-"):
            print("Invalid CVE ID format.")
            return
        result = fetch_and_cache(cve_id)
        show_and_export(result)

    elif option == "🗂️ Search by Keyword":
        keyword = input("Enter keyword (e.g., apache, buffer overflow): ").strip().lower()
        results = cve_lookup.search_by_keyword(keyword)
        show_and_export(results, multiple=True)

    elif option == "📅 List CVEs by Product and Year":
        product = input("Enter product name (e.g., chrome, openssl): ").strip().lower()
        year = input("Enter year (e.g., 2022): ").strip()
        results = cve_lookup.search_by_product_year(product, year)
        show_and_export(results, multiple=True)

    else:
        return

# ******************************************************************************************
# Main Application Logic

def main():
    print_banner()
    load_plugins()

    task = inquirer.select(
        message="What would you like CHARLOTTE to do?",
        choices=[
            Separator("=== Binary Ops ==="),
            *[k for k in PLUGIN_TASKS.keys() if "Binary" in k],
            Separator("=== Recon ==="),
            *[k for k in PLUGIN_TASKS.keys() if "Scan" in k or "Recon" in k],
            Separator("=== Exploitation ==="),
            *[k for k in PLUGIN_TASKS.keys() if "Exploit" in k],
            Separator("=== Intelligence ==="),
            "🕵️ CVE Lookup (CHARLOTTE)",
            Separator(),
            "❌ Exit",
        ],
    ).execute()

    if task == "❌ Exit":
        print("Goodbye, bestie 🖤")
        return
    
    # Handle CVE Lookup separately
    if task == "🕵️ CVE Lookup (CHARLOTTE)":
        run_cve_lookup()
        return

    plugin_key = PLUGIN_TASKS.get(task)
    if plugin_key:
        print(f"✨ CHARLOTTE is preparing to run: {plugin_key}")
        # Minimal placeholder — this should prompt args later or route to cli_handler
        run_plugin(plugin_key)

# ******************************************************************************************
# Entry Point
# ******************************************************************************************

if __name__ == "__main__":
    main()
