# ******************************************************************************************
# main.py - Minimal Launcher for CHARLOTTE with Banner and Plugin Hook
#
# PURPOSE:
#   CLI entry for CHARLOTTE. Displays a menu, dispatches tasks to plugins, and hosts
#   special flows (e.g., CVE Intelligence). Nmap gets a dedicated direct call so users
#   always see interactive prompts.
# ******************************************************************************************

import os
import sys

# ──────────────────────────────────────────────────────────────────────────────
# Third-party deps with friendly hints if missing
# ──────────────────────────────────────────────────────────────────────────────
try:
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator
except ModuleNotFoundError:
    print("[!] Missing dependency: InquirerPy\n    pip install InquirerPy")
    raise

# Make internal helpers importable by other modules
__all__ = ["run_plugin", "_call_plugin_entrypoint", "PLUGIN_REGISTRY", "ALIASES"]
# ──────────────────────────────────────────────────────────────────────────────
# Ensure project-local imports work (agents/, core/, plugins/, etc.)
# ──────────────────────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ──────────────────────────────────────────────────────────────────────────────
# CHARLOTTE internals
# ──────────────────────────────────────────────────────────────────────────────
try:
    from agents.triage_agent import run_triage_agent, load_findings, save_results
    from core.plugin_manager import run_plugin, load_plugins
    from core.charlotte_personality import CharlottePersonality
    import core.cve_lookup
except ModuleNotFoundError as e:
    print(f"[!] Missing CHARLOTTE module: {e.name}\n    Did you activate the venv and install requirements?")
    raise


from utils.logger import start_session, append_session_event, end_session, log_error, log_plugin_event
import uuid
import os
# ──────────────────────────────────────────────────────────────────────────────
# Initialize personality (for future contextual use)
# ──────────────────────────────────────────────────────────────────────────────
charlotte = CharlottePersonality()

# ──────────────────────────────────────────────────────────────────────────────
# Banner (for ✨ vibes ✨)
# ──────────────────────────────────────────────────────────────────────────────
def print_banner():
    PURPLE = "\033[35m"
    RESET = "\033[0m"
    skull_banner = f"""{PURPLE}
        
           ......      
        ...........    🔮  C - H - A - R - L - O - T - T - E  🔮
       '.....,.....,
      '...... . . . .
      '.....'.'.^.'.'
           ;';';';';
           ''''''''

                  {PURPLE}  CHARLOTTE - The Cybersecurity Assistant  {RESET}
                        {PURPLE}  Version: 0.1.0  {RESET}   
{RESET}"""
    print(skull_banner)

# ──────────────────────────────────────────────────────────────────────────────
# Menu label → plugin key mapping
#
# NOTE: The Nmap loader registers as "port_scan" in your plugin system. We keep
#       that here, but will also directly import/call its module to guarantee
#       interactive prompts.
# ──────────────────────────────────────────────────────────────────────────────
PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🔓 Binary Exploit (ROP Chain)": "binary_exploit",
    "🕵️ CVE Lookup (CHARLOTTE)": "cve_lookup",
    "🚨 Exploit Generator": "exploit_generation",
    "🔗 Link Analysis": "link_analysis",
    "📡 NMAP Scan": "port_scan",  # Nmap
    "🧨 Predict Exploitability": "exploit_predictor",
    "🔎 Search Exploit DB": "exploit_search",
    "💉 SQL Injection Scan": "sql_injection",
    "🧪 Static Analysis (Binary)": "static_analysis",
    "📊 Vulnerability Assessment": "vulnerability_assessment",
    "🧮 Vulnerability Triage (Score + Prioritize)": "triage_agent",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "🧼 XSS Scan": "xss_scan",
    "🐝 OWASP ZAP Exploitability": "owasp_zap"
}

# ──────────────────────────────────────────────────────────────────────────────
# CVE Lookup sub-menu
# ──────────────────────────────────────────────────────────────────────────────
def run_cve_lookup():
    print("\n=== CHARLOTTE CVE Intelligence Module ===")

    option = inquirer.select(
        message="Choose your CVE query method:",
        choices=[
            "🔎 Lookup by CVE ID",
            "🗂️ Search by Keyword",
            "📅 List CVEs by Product and Year",
            "❌ Back to Main Menu",
        ],
    ).execute()

    if option == "🔎 Lookup by CVE ID":
        cve_id = input("Enter CVE ID (e.g., CVE-2023-12345): ").strip().upper()
        if not cve_id.startswith("CVE-"):
            print("[!] Invalid CVE ID format.")
            end_session(session_id, status="ok")
        return
        result = core.cve_lookup.fetch_and_cache(cve_id)
        core.cve_lookup.show_and_export(result)

    elif option == "🗂️ Search by Keyword":
        keyword = input("Enter keyword (e.g., apache, buffer overflow): ").strip().lower()
        results = core.cve_lookup.search_by_keyword(keyword)
        core.cve_lookup.show_and_export(results, multiple=True)

    elif option == "📅 List CVEs by Product and Year":
        product = input("Enter product name (e.g., chrome, openssl): ").strip().lower()
        year = input("Enter year (e.g., 2022): ").strip()
        results = core.cve_lookup.search_by_product_year(product, year)
        core.cve_lookup.show_and_export(results, multiple=True)

# ──────────────────────────────────────────────────────────────────────────────
# Main CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    session_id = start_session({"version": "0.1.0", "stage": "cli_start"})
    append_session_event(session_id, "BANNER_PRINT")
    print_banner()

    # Load plugins (note: many implementations do this via side-effects and return None)
    try:
        load_plugins()
    except Exception as e:
        print(f"[!] Failed to load plugins: {e}")
        end_session(session_id, status="ok")
        return

    # Top-level menu
    task = inquirer.select(
        message="What would you like CHARLOTTE to do?",
        choices=[
            Separator("=== Binary Ops ==="),
            *[k for k in PLUGIN_TASKS if "Binary" in k],
            Separator("=== Recon ==="),
            *[k for k in PLUGIN_TASKS if "Scan" in k or "Recon" in k],
            Separator("=== Exploitation ==="),
            *[k for k in PLUGIN_TASKS if "Exploit" in k],
            Separator("=== Intelligence ==="),
            "🕵️ CVE Lookup (CHARLOTTE)",
            Separator("=== Scoring & Analysis ==="),
            *[k for k in PLUGIN_TASKS if "Triage" in k or "Assessment" in k],
            Separator(),
            "❌ Exit",
        ],
    ).execute()

    if task == "❌ Exit":
        print("Goodbye, bestie 🖤")
        end_session(session_id, status="ok")
        return

    if task == "🕵️ CVE Lookup (CHARLOTTE)":
        run_cve_lookup()
        end_session(session_id, status="ok")
        return

    plugin_key = PLUGIN_TASKS.get(task)

    # Special handling: Nmap must always prompt interactively from menu
    if plugin_key == "port_scan":
        try:
            # Use the shared entrypoint logic from plugin_manager so behavior is consistent everywhere
            from core.plugin_manager import _call_plugin_entrypoint  # shared helper
            import importlib

            # Prompt for required args (same UX as before)
            append_session_event(session_id, "PROMPT_SELECTION", {"selected": "port_scan"})
            target = inquirer.text(message="Enter target IP or domain:").execute()
            ports = inquirer.text(message="Enter ports (e.g., 80,443 or leave blank):").execute()

            # Import the Nmap plugin module and invoke via the shared entrypoint helper
            nmap_module = importlib.import_module("plugins.recon.nmap.nmap_plugin")
            append_session_event(session_id, "ACTION_BEGIN", {"plugin": "port_scan"})
            result = _call_plugin_entrypoint(
                nmap_module,
                {"target": target, "ports": ports, "interactive": True}
            )

            # Save/dispatch report (unchanged)
            from core import report_dispatcher
            append_session_event(session_id, "ACTION_RESULT", {"plugin": "port_scan", "result_kind": type(result).__name__})
            if result:
                file_path = report_dispatcher.save_report_locally(result, interactive=False)
                append_session_event(session_id, "TRIAGE_DONE", {"report_path": display_path(file_path)})
                report_dispatcher.dispatch_report(file_path)
            else:
                print("[!] No report data returned.")
            end_session(session_id, status="ok")
            return
    
        except Exception as e:
            print(f"[!] Nmap plugin error: {e}")
            log_error(f"Nmap error: {e}")
            append_session_event(session_id, "ERROR", {"where": "nmap", "error": str(e)})
            # Optional fallback: plugin manager dispatch
            try:
                run_plugin(plugin_key, args=None)
            except Exception as e2:
                print(f"[!] Plugin manager also failed to run Nmap: {e2}")
            end_session(session_id, status="ok")
            return

    
    # Built-in triage flow
    if plugin_key == "triage_agent":
        scan_path = inquirer.text(
            message="Enter path to scan file (press Enter for default: data/findings.json):"
        ).execute()
        scan_path = (scan_path or "").strip() or "data/findings.json"
        run_triage_agent(scan_file=scan_path)
        end_session(session_id, status="ok")
        return

    # Exploit predictor flow
    if plugin_key == "exploit_predictor":
        from core.logic_modules.exploit_predictor import batch_predict

        scan_path = inquirer.text(
            message="Enter path to scan file (press Enter for default: data/findings.json):"
        ).execute()
        scan_path = (scan_path or "").strip() or "data/findings.json"

        try:
            findings = load_findings(scan_path)
            enriched = batch_predict(findings)
            output_path = "data/findings_with_predictions.json"
            save_results(enriched, output_file=output_path)

            print(f"\n[✔] Exploit predictions saved to {output_path}")
            print("Use '🧮 Vulnerability Triage' to further refine prioritization.\n")
        except Exception as e:
            print(f"[!] Error processing exploit prediction: {e}")
        end_session(session_id, status="ok")
        return

    # All other plugins — use the manager and request interactive mode
    try:
        print(f"\n[✔] Running plugin: {plugin_key}...\n")
        result = run_plugin(plugin_key, args=None)
        
        # Display the plugin result
        if result:
            print(result)
        else:
            print(f"[!] Plugin '{plugin_key}' returned no output")
            
    except TypeError as te:
        print(f"[!] Plugin '{plugin_key}' raised a TypeError: {te}")
        print("    Tip: Ensure its entrypoint is 'def run_plugin(args=None, ...):'")
    except ImportError as ie:
        print(f"[!] Plugin '{plugin_key}' failed to import: {ie}")
        print("    Tip: Check if the plugin module exists and has no syntax errors")
    except Exception as e:
        print(f"[!] Error running plugin '{plugin_key}': {e}")
        import traceback
        print(f"[!] Full error details:")
        traceback.print_exc()

# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI application.
# ──────────────────────────────────────────────────────────────────────────────
# Path display helper
# ──────────────────────────────────────────────────────────────────────────────
def display_path(p: str) -> str:
    import os as _os
    return _os.path.normpath(p)
# ──────────────────────────────────────────────────────────────────────────────
# End of main.py