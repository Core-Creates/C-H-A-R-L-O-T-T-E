# ******************************************************************************************
# main.py - Minimal Launcher for CHARLOTTE with Banner and Plugin Hook
# ******************************************************************************************

import os
import sys
import json
import cve_lookup
from datetime import datetime
from InquirerPy import inquirer
from agents.triage_agent import run_triage_agent
from plugin_manager import run_plugin, load_plugins
from charlotte_personality import CharlottePersonality
from InquirerPy.separator import Separator

# ******************************************************************************************
# Utility Setup
# Ensure root project path is in sys.path for relative imports
# ******************************************************************************************
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Initialize CHARLOTTE personality
charlotte = CharlottePersonality()

# ******************************************************************************************
# Banner Art
# ******************************************************************************************

def print_banner():
    PURPLE = "\033[35m"
    RESET = "\033[0m"
    skull_banner = f"""{PURPLE}
                              ...............
                        ...........................
                      ...............................
                    ...................................
                   .....................................
                  .......................................
                  .......................................                    ,,,,,                                                             .......               ....
                  .......................................                 .';;;;';;;            ....     ....              ''''              ;;''''''';;             ;  ;                       .,;';,.             ;'''''''''''';        ;'''''''''''';         ;''''''''''';
                  .......................................               ....        '           ....     ....             ......             ''.       ;;            ;  ;                      '..' '..'            ;,,,,,,,,,,,,;        ;,,,,,,,,,,,,;         ;  .........;            
                  ......................................               ....                     ....     ....            ..'  '..            ''..........            ;  ;                    ...'     '...               ....                  ....              ;  '''''''';            
                   ....         .....''.....       ....               .....           ........  ...''''''....  .......  .''''''''.   ....... '.........    .......   ;  ;          .......  ..,.       .,..  .......     ....      .......     ....     .......  ;  ,.......;               
                    ....        ..'  .. '...      ....                '''''           ........  .............  ....... ...''''''...  ....... ',''''',.     .......   ;  ;          .......  ..,.       .,..  .......     ....      .......     ....     .......  ;  ;            
                     ....      ..'   ..   '..     ....                 .....        .;          ....     ....          ...      ...          '.'     ,.              ;  '''''''';            ..',.   .,'..               ....                  ....              ;  ''''''''';                    
                   ..........''''... . ....'............                ....'......'..          ....     ....          ...      ...          '.'      ...            '..........;             ...........                ....                  ....              ;...........;           
                  .......................................                '.........;'                                                                                                           ';;;;;;'
                  ;.....................................;                   '''''''
                     ..,'  ',,'  ',,'  ',,'  ',,'  ',..                 
                   ;  .;....;;....;;....;;....;;....;.  ;                                                                                                                      
                   ;;                                  ;;
                   ;;;;'''';''';''';''';'''';''';'''';;;;
                    ;;;',,,',,,',,,',,,',,,,',,,',,,,;;;
                     ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                      ';;;;;;;;;;;;;;;;;;;;;;;;;;;;;;'
                        ';;;;;;;;;;;;;;;;;;;;;;;;;;'
                           ''''''''''''''''''''''
                         🔮  C - H - A - R - L - O - T - T - E  🔮

                  {PURPLE}  CHARLOTTE - The Cybersecurity Assistant  {RESET}
                        {PURPLE}  Version: 0.1.0  {RESET}   
{RESET}"""
    print(skull_banner)

# ******************************************************************************************
# Plugin Task Mapping
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
    "🕵️ CVE Lookup (CHARLOTTE)": "cve_lookup",
    "🧪 Static Analysis (Binary)": "static_analysis",
    "📊 Vulnerability Assessment": "vulnerability_assessment",
    "🧮 Vulnerability Triage (Score + Prioritize)": "triage_agent",
}

# ******************************************************************************************
# CVE Lookup Menu Logic
# ******************************************************************************************

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
        result = cve_lookup.fetch_and_cache(cve_id)
        cve_lookup.show_and_export(result)

    elif option == "🗂️ Search by Keyword":
        keyword = input("Enter keyword (e.g., apache, buffer overflow): ").strip().lower()
        results = cve_lookup.search_by_keyword(keyword)
        cve_lookup.show_and_export(results, multiple=True)

    elif option == "📅 List CVEs by Product and Year":
        product = input("Enter product name (e.g., chrome, openssl): ").strip().lower()
        year = input("Enter year (e.g., 2022): ").strip()
        results = cve_lookup.search_by_product_year(product, year)
        cve_lookup.show_and_export(results, multiple=True)

    else:
        return

# ******************************************************************************************
# Main CLI Application Logic
# ******************************************************************************************

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
            Separator("=== Scoring & Analysis ==="),
            *[k for k in PLUGIN_TASKS.keys() if "Triage" in k or "Assessment" in k],
            Separator(),
            "❌ Exit",
        ],
    ).execute()

    if task == "❌ Exit":
        print("Goodbye, bestie 🖤")
        return

    if task == "🕵️ CVE Lookup (CHARLOTTE)":
        run_cve_lookup()
        return

    plugin_key = PLUGIN_TASKS.get(task)

    # --------------------------------------------------
    # Plugin/Agent Execution Logic
    # --------------------------------------------------
    if plugin_key == "triage_agent":
        run_triage_agent()  # 👈 Directly runs the agent logic
    else:
        run_plugin(plugin_key)  # 👈 Standard plugin handler

# ******************************************************************************************
# Entry Point
# ******************************************************************************************

if __name__ == "__main__":
    main()
