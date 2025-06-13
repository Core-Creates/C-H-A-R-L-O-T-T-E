# ******************************************************************************************
# main.py - Minimal Launcher for CHARLOTTE with Banner and Plugin Hook
# ******************************************************************************************

import os
import sys

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
}

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
            Separator(),
            "❌ Exit",
        ],
    ).execute()

    if task == "❌ Exit":
        print("Goodbye, bestie 🖤")
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
