import os
from InquirerPy import inquirer
from InquirerPy.separator import Separator
from core.plugin_manager import run_plugin
from core.charlotte_personality import CharlottePersonality

charlotte = CharlottePersonality()

def print_banner():
    PURPLE = "\033[35m"
    RESET = "\033[0m"
    skull_banner = f"""{PURPLE}
                                                                                                                                                                                                                                                                                                            
                              .........'''......                                                                                                                                                                                                                                                            
                        ..............''''''''.....                                                                                                                                                                                                                                                          
                       ..''......''''...........''...                                                                                                                                                                                                                                                        
              ..........'''...'''''''''''.'',,,''.....   ......                                                                                                                                                                                                                                              
             .''.  ....'''...........''''''............     .''.                                                                                                                                                                                                                                             
              ..  ...''...''..''.'''''''''''''''''''.....                                                                                                                                                                                                                                                    
                  ....'..'''.....''''''...'''.'''''......                   .......                                                                                                                                                                                                                          
                  ..''..''''''.'',,,,''''',,''''''.......                ..'''.......              ..      ...                .....                                                                                                                                                  ..........             
                  ....'''''',,,''''',,,''','''.'''..'''.                .','.                     .''.     .,.              .........             ..'''''''.                .'.                        ..'''.                .''''''''''''.             ..'''''''''''..             .''''..'.'..           
                    ..''........',,,,,'''''............                .','.                      .''.    ..,.             .,..    .''.           .''..........             .,.                      ...........              .....',.....                .....,.....               .''.                    
                    .''.        ..''',''''..       .'..                .',,.            ..'.'.'.  .','''''',,.  ..''..'..  .,''''''','.  .''.''.. .''.........    .......   .,.            .......  ..,.     .,.   .......        .',.        .......         .,.         .......   .''......               
                    .'..        ..'''..'','.       .'..                .',,.            ........  .',......',.   .......   .,'......,'.  .......  .',''''',.     ....'''..  .,.           .''.'''.  .',.     .,.  ..''''...        ',.        .'.'.''.        .,.        ...''''.   .''......               
                   .....      ...''.. ..''''..     .'..                 .','.                     .''.     .,.             .,.     .''.           .''.  ..,.                .,..                     ',.     .,.                  .',.                        .,.                   .''.                    
                  ..'''''....''''... .  .'''''.....'''..                  .'''.... .              ..'.     .'.             .'.     .'..           .''.    .....             .,'........              ..........                    .'.                        .,.                   .'''''''''..           
                 ...''''..''''''',''......''..''''..''...                   .......                                                                ..       ...             ...........                 .....                      ...                        ...                    ..........             
                   ..''''''''',,''........''..''''.......                                                                                                                                                                                                                                                    
                     ...''''..''...........'''.......                                                                                                                                                                                                                                                        
                       ..','''''''''...'..''''....   .                                                                                                                                                                                                                                                      
                     .  ..''..,....''..'..'......   ..                                                                                                                                                                                                                                                      
                     ...   .  .    .. ..  ....     ...                                                                                                                                                                                                                                                      
                 ..  ........ ...  .   .       . .....                                                                                                                                                                                                                                                      
              ...       ...'...'...,'..'...'...'......      ...                                                                                                                                                                                                                                             
             .''.         .....'..''''''''''......          .''.                                                                                                                                                                                                                                            
             ......        ....'......'',,'''....         ...'..        

                         🔮  C - H - A - R - L - 0 - T - T - E  🔮
{RESET}"""
    print(skull_banner)

def main():
    print_banner()

    task = inquirer.select(
        message="What would you like CHARLOTTE to do?",
        choices=[
            Separator("=== Binary Ops ==="),
            "🧠 Reverse Engineer Binary (Symbolic Trace)",
            "🔍 Binary Strings + Entropy Analysis",
            Separator("=== Recon ==="),
            "🌐 Web Recon (Subdomains)",
            "📡 Port Scan",
            "💉 SQL Injection Scan",
            "🧼 XSS Scan",
            Separator("=== Exploitation ==="),
            "🚨 Exploit Generator",
        ],
    ).execute()

    # Map human-readable task to plugin key
    PLUGIN_TASKS = {
        "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
        "🔍 Binary Strings + Entropy Analysis": "binary_strings",
        "🌐 Web Recon (Subdomains)": "web_recon",
        "📡 Port Scan": "port_scan",
        "💉 SQL Injection Scan": "sql_injection",
        "🧼 XSS Scan": "xss_scan",
        "🚨 Exploit Generator": "exploit_generation",
    }

    plugin_key = PLUGIN_TASKS.get(task)
    if plugin_key:
        run_plugin(plugin_key)

if __name__ == "__main__":
    main()
# Ensure the plugins directory exists
if not os.path.exists("plugins"):
    os.makedirs("plugins")
# Ensure the plugins are loaded
from core.plugin_manager import load_plugins
load_plugins()