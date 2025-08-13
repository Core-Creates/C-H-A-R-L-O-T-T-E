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
    print_banner()

    # Load plugins (note: many implementations do this via side-effects and return None)
    try:
        load_plugins()
    except Exception as e:
        print(f"[!] Failed to load plugins: {e}")
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
        return

    if task == "🕵️ CVE Lookup (CHARLOTTE)":
        run_cve_lookup()
        return

    plugin_key = PLUGIN_TASKS.get(task)

    # Special handling: Nmap must always prompt interactively from menu
    if plugin_key == "port_scan":
        try:
            # Try to reuse the flexible shim from cli.py
            try:
                from cli import safe_run_plugin  # uses signature introspection and arg mapping
            except Exception:
                # Fallback: minimal local shim
                import inspect
                def safe_run_plugin(func, **params):
                    sig = inspect.signature(func)
                    param_names = list(sig.parameters.keys())
                    mapped = dict(params)
                    if "domain" in mapped and "domain" not in sig.parameters and "target" in sig.parameters:
                        mapped["target"] = mapped["domain"]
                    if len(param_names) == 1:
                        try:
                            return func(mapped)
                        except TypeError:
                            return func({k: v for k, v in mapped.items()})
                    filtered = {k: v for k, v in mapped.items() if k in sig.parameters}
                    try:
                        return func(**filtered)
                    except TypeError:
                        ordered = [mapped[name] for name in param_names if name in mapped]
                        return func(*ordered)

            # Prompt for required args (mirrors cli.py behavior)
            target = inquirer.text(message="Enter target IP or domain:").execute()
            ports = inquirer.text(message="Enter ports (e.g., 80,443 or leave blank):").execute()

            # Call the plugin with interactive=True; the shim adapts its signature
            from plugins.recon.nmap.nmap_plugin import run_plugin as run_nmap_plugin
            result = safe_run_plugin(run_nmap_plugin, target=target, ports=ports, interactive=True)

            # Save/dispatch report like cli.py does
            from core import report_dispatcher
            if result:
                file_path = report_dispatcher.save_report_locally(result, interactive=False)
                report_dispatcher.dispatch_report(file_path)
            else:
                print("[!] No report data returned.")
            return

        except Exception as e:
            print(f"[!] Nmap plugin error: {e}")
            # Optional: fall back to the plugin manager
            try:
                run_plugin(plugin_key, args=None)
            except Exception as e2:
                print(f"[!] Plugin manager also failed to run Nmap: {e2}")
            return
    
    # Built-in triage flow
    if plugin_key == "triage_agent":
        scan_path = inquirer.text(
            message="Enter path to scan file (press Enter for default: data/findings.json):"
        ).execute()
        scan_path = (scan_path or "").strip() or "data/findings.json"
        run_triage_agent(scan_file=scan_path)
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
        return

    # All other plugins — use the manager and request interactive mode
    try:
        run_plugin(plugin_key, args=None)
        print(f"\n[✔] Running plugin: {plugin_key}...\n")
    except TypeError as te:
        print(f"[!] Plugin '{plugin_key}' raised a TypeError: {te}")
        print("    Tip: Ensure its entrypoint is 'def run_plugin(args=None, ...):'")
    except Exception as e:
        print(f"[!] Error running plugin '{plugin_key}': {e}")

# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI application.