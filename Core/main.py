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
    # ⬇️ import robust plugin loader + convenience runners
    from core.plugin_manager import load_plugins, run_plugin, _load_plugin_module, _call_plugin_entrypoint
    from agents.triage_agent import run_triage_agent, load_findings, save_results
    from core.charlotte_personality import CharlottePersonality
    from utils.paths import display_path
    import core.cve_lookup
except ModuleNotFoundError as e:
    print(f"[!] Missing CHARLOTTE module: {e.name}\n    Did you activate the venv and install requirements?")
    raise

from utils.logger import start_session, append_session_event, end_session, log_error, log_plugin_event
from pathlib import Path
import uuid

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
def run_cve_lookup(session_id):
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

# ── Helpers to fetch dynamic registry robustly ───────────────────────────────
def _get_dynamic_registry():
    """
    Try multiple fallbacks to retrieve the dynamic plugin registry regardless
    of how plugin_manager exposes it.
    """
    reg = {}
    try:
        plugins = load_plugins() or {}
        if isinstance(plugins, dict) and "dynamic" in plugins:
            reg = plugins.get("dynamic") or {}
    except Exception:
        pass
    if reg:
        return reg

    # Fallbacks via plugin_manager module
    try:
        from core import plugin_manager as _pm
        for attr in ("DYNAMIC_PLUGINS", "PLUGINS", "REGISTRY", "_PLUGINS"):
            obj = getattr(_pm, attr, None)
            if isinstance(obj, dict):
                if "dynamic" in obj and isinstance(obj["dynamic"], dict):
                    return obj["dynamic"]
                if obj and all(isinstance(v, dict) for v in obj.values()):
                    return obj
    except Exception:
        pass
    return {}

# ── Classifiers for dynamic plugin surfacing ─────────────────────────────────
def _is_recon_like(task_key: str, pretty: str, desc: str, tags: list[str]) -> bool:
    t = set(x.lower() for x in (tags or []))
    name_lc = (pretty or "").lower()
    desc_lc = (desc or "").lower()
    key_lc  = (task_key or "").lower()

    recon_tags = {"recon", "dns", "subdomains", "amass", "enumeration", "http", "web"}
    if t & recon_tags:
        return True

    needles = ("recon", "amass", "subdomain", "dns", "enum", "banner", "http", "nmap")
    return any(n in name_lc for n in needles) or any(n in desc_lc for n in needles) or any(n in key_lc for n in needles)

def _is_amass_like(task_key: str, pretty: str, desc: str, tags: list[str]) -> bool:
    t = set(x.lower() for x in (tags or []))
    if "amass" in t:
        return True
    name_lc = (pretty or "").lower()
    desc_lc = (desc or "").lower()
    key_lc  = (task_key or "").lower()
    return ("amass" in name_lc) or ("amass" in desc_lc) or ("amass" in key_lc)

# ──────────────────────────────────────────────────────────────────────────────
# Main CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    session_id = start_session({"version": "0.1.0", "stage": "cli_start"})
    append_session_event(session_id, "BANNER_PRINT")
    print_banner()

    # ── Load plugin registry (static is handled by PLUGIN_TASKS) ─────────────
    try:
        _ = load_plugins()  # side-effects populate registry inside plugin_manager
    except Exception as e:
        print(f"[!] Failed to load plugins: {e}")
        end_session(session_id, status="ok")
        return

    # ── Collect dynamic plugins robustly ─────────────────────────────────────
    dynamic_registry = _get_dynamic_registry()

    if os.environ.get("CHARLOTTE_DEBUG"):
        print("[debug] dynamic keys:", list((dynamic_registry or {}).keys()))
        for k, m in (dynamic_registry or {}).items():
            print(f"[debug] {k} meta:", m)

    # ── Build auto-surfaced Recon entries ────────────────────────────────────
    recon_dynamic_entries = []
    for task_key, meta in (dynamic_registry or {}).items():
        pretty = (meta.get("pretty_name") or meta.get("name") or meta.get("label") or task_key).strip()
        desc   = (meta.get("description") or meta.get("desc") or "")
        tags   = meta.get("tags") or meta.get("categories") or []

        if _is_recon_like(task_key, pretty, desc, tags):
            prefix = "🛰️" if _is_amass_like(task_key, pretty, desc, tags) else "🧭"
            recon_dynamic_entries.append({"name": f"{prefix} {pretty}", "value": ("dynamic", task_key)})

    show_dynamic_fallback = not bool(recon_dynamic_entries)
    dynamic_fallback_entries = []
    if show_dynamic_fallback:
        for task_key, meta in (dynamic_registry or {}).items():
            pretty = (meta.get("pretty_name") or meta.get("name") or meta.get("label") or task_key).strip()
            dynamic_fallback_entries.append({"name": f"🧩 {pretty}", "value": ("dynamic", task_key)})

    while True:
        menu_choices = [
            Separator("=== Binary Ops ==="),
            *[k for k in PLUGIN_TASKS if "Binary" in k],

            Separator("=== Recon ==="),
            *[k for k in PLUGIN_TASKS if ("Scan" in k or "Recon" in k)],
            *recon_dynamic_entries,

            *( [Separator("=== Dynamic (unclassified) ===")] + dynamic_fallback_entries
               if show_dynamic_fallback else [] ),

            Separator("=== Exploitation ==="),
            *[k for k in PLUGIN_TASKS if "Exploit" in k],

            Separator("=== Intelligence ==="),
            "🕵️ CVE Lookup (CHARLOTTE)",

            Separator("=== Scoring & Analysis ==="),
            *[k for k in PLUGIN_TASKS if ("Triage" in k or "Assessment" in k)],

            Separator(),
            "❌ Exit",
        ]

        task = inquirer.select(
            message="What would you like CHARLOTTE to do?",
            choices=menu_choices,
        ).execute()

        if task == "❌ Exit":
            print("Goodbye, bestie 🖤")
            end_session(session_id, status="ok")
            break

        if task == "🕵️ CVE Lookup (CHARLOTTE)":
            run_cve_lookup(session_id)
            continue

        if isinstance(task, tuple) and len(task) == 2 and task[0] == "dynamic":
            _, dyn_key = task
            try:
                append_session_event(session_id, "ACTION_BEGIN", {"plugin": dyn_key})
                result = run_plugin(dyn_key, args=None)
                from core import report_dispatcher
                if result:
                    file_path = report_dispatcher.save_report_locally(result, interactive=False)
                    append_session_event(session_id, "TRIAGE_DONE", {"report_path": file_path})
                    print(f"\n[📁 Saved] {file_path}")
            except Exception as e:
                log_error(session_id, f"Dynamic plugin '{dyn_key}' failed: {e}")
                print(f"[!] Error running dynamic plugin '{dyn_key}': {e}")
            again = inquirer.confirm(message="Would you like to run another plugin?", default=True).execute()
            if not again:
                print("Goodbye, bestie 🖤")
                end_session(session_id, status="ok")
                break
            continue

        plugin_key = PLUGIN_TASKS.get(task)

        # ── Special handling: Nmap always prompts interactively
        if plugin_key == "port_scan":
            try:
                append_session_event(session_id, "PROMPT_SELECTION", {"selected": "port_scan"})
                target = inquirer.text(message="Enter target IP or domain:").execute()
                ports = inquirer.text(message="Enter ports (e.g., 80,443 or leave blank):").execute()

                # 🔒 Robust load with nested category support
                nmap_module = _load_plugin_module("recon.nmap", "nmap_plugin")
                result = _call_plugin_entrypoint(
                    nmap_module,
                    {"target": target, "ports": ports, "interactive": True},
                )

                from core import report_dispatcher
                append_session_event(session_id, "ACTION_RESULT",
                                     {"plugin": "port_scan", "result_kind": type(result).__name__})
                if result:
                    file_path = report_dispatcher.save_report_locally(result, interactive=False)
                    append_session_event(session_id, "TRIAGE_DONE", {"report_path": display_path(file_path)})
                    report_dispatcher.dispatch_report(file_path)
                else:
                    print("[!] No report data returned.")
            except Exception as e:
                print(f"[!] Nmap plugin error: {e}")
                log_error(session_id, f"Nmap error: {e}")
                append_session_event(session_id, "ERROR", {"where": "nmap", "error": str(e)})
                try:
                    run_plugin(plugin_key, args=None)
                except Exception as e2:
                    print(f"[!] Plugin manager also failed to run Nmap: {e2}")
            again = inquirer.confirm(message="Would you like to run another plugin?", default=True).execute()
            if not again:
                print("Goodbye, bestie 🖤")
                end_session(session_id, status="ok")
                break
            continue

        # ── Special handling: triage
        if plugin_key == "triage_agent":
            scan_path = inquirer.text(
                message="Enter path to scan file (press Enter for default: data/findings.json):"
            ).execute()
            scan_path = (scan_path or "").strip() or "data/findings.json"
            run_triage_agent(scan_file=scan_path)
            again = inquirer.confirm(message="Would you like to run another plugin?", default=True).execute()
            if not again:
                print("Goodbye, bestie 🖤")
                end_session(session_id, status="ok")
                break
            continue

        # ── Special handling: exploit predictor
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
            again = inquirer.confirm(message="Would you like to run another plugin?", default=True).execute()
            if not again:
                print("Goodbye, bestie 🖤")
                end_session(session_id, status="ok")
                break
            continue

        # ── Generic static plugin execution
        try:
            run_plugin(plugin_key, args=None)
            print(f"\n[✔] Running plugin: {plugin_key}...\n")
        except TypeError as te:
            print(f"[!] Plugin '{plugin_key}' raised a TypeError: {te}")
            print("    Tip: Ensure its entrypoint is 'def run_plugin(args=None, ...):'")
        except Exception as e:
            print(f"[!] Error running plugin '{plugin_key}': {e}")

        again = inquirer.confirm(message="Would you like to run another plugin?", default=True).execute()
        if not again:
            print("Goodbye, bestie 🖤")
            end_session(session_id, status="ok")
            break

# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI application.
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()


# ******************************************************************************************
# End of main.py
# ******************************************************************************************#
# 
