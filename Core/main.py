# ******************************************************************************************
# main.py - Minimal Launcher for CHARLOTTE with Banner and Plugin Hook
#
# PURPOSE:
#   CLI entry for CHARLOTTE. Displays a menu, dispatches tasks to plugins, and hosts
#   special flows (e.g., CVE Intelligence). Nmap gets a dedicated direct call so users
#   always see interactive prompts.
#
# COMMENTING GOAL:
#   This file now includes detailed, trace-friendly comments that explain:
#     • Import paths and why they're arranged this way
#     • How dynamic vs static plugins are surfaced and executed
#     • How the CVE sub-flow prompts the user, parses date filters, and calls NVD
#     • Where session telemetry logs get written (start/append/end)
#   These comments should help future contributors quickly follow the control flow.
# ******************************************************************************************

import os
import sys
import re
from datetime import datetime, timedelta, timezone  # Used for date parsing in CVE flow

# ──────────────────────────────────────────────────────────────────────────────
# Third-party deps with friendly hints if missing
# We keep this try/except so the CLI can clearly tell the user how to fix env issues.
# ──────────────────────────────────────────────────────────────────────────────
try:
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator
except ModuleNotFoundError:
    # If InquirerPy isn't installed, fail fast with a helpful message.
    print("[!] Missing dependency: InquirerPy\n    pip install InquirerPy")
    raise


from core.plugin_manager import (
    run_plugin,
    _call_plugin_entrypoint,
    register_post_run,
    PLUGIN_REGISTRY,
    ALIASES,
    # run_dynamic_by_label,  # only keep if you actually use it later
)

from utils.logger import start_session, append_session_event, end_session, log_error

# Make internal helpers importable by other modules
# Exposing these names allows other modules/tests to import entries neatly.
__all__ = ["run_plugin", "_call_plugin_entrypoint", "PLUGIN_REGISTRY", "ALIASES"]

# ──────────────────────────────────────────────────────────────────────────────
# Ensure project-local imports work (agents/, core/, plugins/, etc.)
# We add the repo root (../) to sys.path so absolute imports like 'core.x' resolve
# consistently, regardless of how 'charlotte' is invoked (module vs script).
# ──────────────────────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ──────────────────────────────────────────────────────────────────────────────
# CHARLOTTE internals
# Import core systems (plugin loader, triage, personality, path utils).
# If any module is missing, surface a clear, actionable message.
# ──────────────────────────────────────────────────────────────────────────────
try:
    # ⬇️ import robust plugin loader + convenience runners
    from core.plugin_manager import (
        load_plugins,
        run_plugin,
        _load_plugin_module,
        _call_plugin_entrypoint,
        register_post_run,
        run_dynamic_by_label,
    )
    from agents.triage_agent import run_triage_agent, load_findings, save_results
    from core.charlotte_personality import CharlottePersonality
    from utils.paths import display_path
    import core.cve_lookup
except ModuleNotFoundError as e:
    print(
        f"[!] Missing CHARLOTTE module: {e.name}\n    Did you activate the venv and install requirements?"
    )
    raise


# ──────────────────────────────────────────────────────────────────────────────
# Initialize personality (for future contextual use)
# Currently used for theming + possible persona-based responses later.
# ──────────────────────────────────────────────────────────────────────────────
charlotte = CharlottePersonality()


# ──────────────────────────────────────────────────────────────────────────────
# Banner (for ✨ vibes ✨)
# Contains color codes + ASCII skull. Purely cosmetic but establishes identity.
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
# Menu label → plugin key mapping (static registry)
# These are the “built-ins” that the main menu always shows.
# Dynamic plugins are discovered at runtime and surfaced separately.
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
    "🐝 OWASP ZAP Exploitability": "owasp_zap",
}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers for special flows (CVE date filter parsing)
# These helpers live here (UI/orchestration layer) rather than in cve_lookup.py,
# keeping cve_lookup clean as a data-access layer that only expects ISO timestamps.
# ──────────────────────────────────────────────────────────────────────────────


def _iso_z(dt: datetime) -> str:
    """NVD wants ISO8601 with milliseconds and Z suffix: YYYY-MM-DDTHH:MM:SS.000Z"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_date_filter(filter_str: str) -> tuple[str | None, str | None]:
    """
    Translates a human-friendly filter string into NVD pubStartDate/pubEndDate.

    Returns:
      (pubStartDateISO, pubEndDateISO) or (None, None) if filter is empty/invalid.

    Supported patterns:
      • 'last 30 days' / 'last 2 weeks' / 'last 3 months' (months≈30 days)
      • 'since 2025-07-01'
      • 'between 2025-07-01 and 2025-07-31'
      • '2025-07-01..2025-07-31'  (shorthand)

    Rationale:
      We keep date interpretation here in the UI layer so cve_lookup.py remains
      reusable in other contexts (e.g., headless or API).
    """
    if not filter_str:
        return None, None

    s = filter_str.strip().lower()
    now = datetime.now(timezone.utc)

    # Pattern: last N units
    m = re.match(r"^last\s+(\d+)\s*(days?|d|weeks?|w|months?|m)\s*$", s)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit.startswith("day") or unit == "d":
            delta = timedelta(days=n)
        elif unit.startswith("week") or unit == "w":
            delta = timedelta(weeks=n)
        else:  # months (approximate as 30 days each)
            delta = timedelta(days=30 * n)
        start = now - delta
        return _iso_z(start), _iso_z(now)

    # Pattern: since YYYY-MM-DD
    m = re.match(r"^since\s+(\d{4}-\d{2}-\d{2})\s*$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            return _iso_z(start), _iso_z(now)
        except Exception:
            return None, None

    # Pattern: between YYYY-MM-DD and YYYY-MM-DD
    m = re.match(r"^between\s+(\d{4}-\d{2}-\d{2})\s+and\s+(\d{4}-\d{2}-\d{2})\s*$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            # End-of-day inclusive: add a day then subtract 1 ms
            end = (
                datetime.strptime(m.group(2), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                + timedelta(days=1)
                - timedelta(milliseconds=1)
            )
            return _iso_z(start), _iso_z(end)
        except Exception:
            return None, None

    # Pattern: YYYY-MM-DD..YYYY-MM-DD shorthand
    m = re.match(r"^(\d{4}-\d{2}-\d{2})\s*\.\.\s*(\d{4}-\d{2}-\d{2})$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            end = (
                datetime.strptime(m.group(2), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                + timedelta(days=1)
                - timedelta(milliseconds=1)
            )
            return _iso_z(start), _iso_z(end)
        except Exception:
            return None, None

    # Fallback: unrecognized expression
    return None, None


# These helpers live here (UI/orchestration layer) rather than in cve_lookup.py,
# keeping cve_lookup clean as a data-access layer that only expects ISO timestamps.
# ──────────────────────────────────────────────────────────────────────────────


def _iso_z(dt: datetime) -> str:
    """NVD wants ISO8601 with milliseconds and Z suffix: YYYY-MM-DDTHH:MM:SS.000Z"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_date_filter(filter_str: str) -> tuple[str | None, str | None]:
    """
    Translates a human-friendly filter string into NVD pubStartDate/pubEndDate.

    Returns:
      (pubStartDateISO, pubEndDateISO) or (None, None) if filter is empty/invalid.

    Supported patterns:
      • 'last 30 days' / 'last 2 weeks' / 'last 3 months' (months≈30 days)
      • 'since 2025-07-01'
      • 'between 2025-07-01 and 2025-07-31'
      • '2025-07-01..2025-07-31'  (shorthand)

    Rationale:
      We keep date interpretation here in the UI layer so cve_lookup.py remains
      reusable in other contexts (e.g., headless or API).
    """
    if not filter_str:
        return None, None

    s = filter_str.strip().lower()
    now = datetime.now(timezone.utc)

    # Pattern: last N units
    m = re.match(r"^last\s+(\d+)\s*(days?|d|weeks?|w|months?|m)\s*$", s)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit.startswith("day") or unit == "d":
            delta = timedelta(days=n)
        elif unit.startswith("week") or unit == "w":
            delta = timedelta(weeks=n)
        else:  # months (approximate as 30 days each)
            delta = timedelta(days=30 * n)
        start = now - delta
        return _iso_z(start), _iso_z(now)

    # Pattern: since YYYY-MM-DD
    m = re.match(r"^since\s+(\d{4}-\d{2}-\d{2})\s*$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            return _iso_z(start), _iso_z(now)
        except Exception:
            return None, None

    # Pattern: between YYYY-MM-DD and YYYY-MM-DD
    m = re.match(r"^between\s+(\d{4}-\d{2}-\d{2})\s+and\s+(\d{4}-\d{2}-\d{2})\s*$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            # End-of-day inclusive: add a day then subtract 1 ms
            end = (
                datetime.strptime(m.group(2), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                + timedelta(days=1)
                - timedelta(milliseconds=1)
            )
            return _iso_z(start), _iso_z(end)
        except Exception:
            return None, None

    # Pattern: YYYY-MM-DD..YYYY-MM-DD shorthand
    m = re.match(r"^(\d{4}-\d{2}-\d{2})\s*\.\.\s*(\d{4}-\d{2}-\d{2})$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            end = (
                datetime.strptime(m.group(2), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                + timedelta(days=1)
                - timedelta(milliseconds=1)
            )
            return _iso_z(start), _iso_z(end)
        except Exception:
            return None, None

    # Fallback: unrecognized expression
    return None, None


# ──────────────────────────────────────────────────────────────────────────────
# CVE Lookup sub-menu
# This function orchestrates the CVE workflow:
#  • Prompts user for mode (ID vs Keyword)
#  • For keyword, optionally parses a human date filter and forwards ISO dates
#  • Calls cve_lookup helpers and then show_and_export for CSV/JSON
# All logic here is "UI/controller"; data fetching lives in core.cve_lookup.
# ──────────────────────────────────────────────────────────────────────────────
def run_cve_lookup(session_id: str | None = None):
    print("\n=== CHARLOTTE CVE Intelligence Module ===")
    from InquirerPy import (
        inquirer,
    )  # local import keeps startup faster if CVE flow unused

    # Prompt for CVE lookup mode
    mode = inquirer.select(
        message="Choose your CVE query method:",
        choices=["🔎 Search by CVE ID", "🗂️ Search by Keyword"],
        default="🗂️ Search by Keyword",
    ).execute()

    if mode.startswith("🔎"):
        # ---- CVE ID path (unchanged) ----
        # Accepts a mix of full IDs and short numeric IDs (with optional year hint)
        ids = input(
            "Enter CVE ID(s) (comma-separated or short IDs with year): "
        ).strip()
        year_hint = input("Optional year hint for short IDs (YYYY): ").strip()

        # Normalize input to a list of full CVE IDs (CVE-YYYY-NNNN)
        cve_ids = []
        for raw in ids.split(","):
            c = raw.strip()
            if not c:
                continue
            if c.upper().startswith("CVE-"):
                cve_ids.append(c.upper())
            elif c.isdigit():
                if not year_hint:
                    print(f"[!] Year required for short CVE ID '{c}'. Skipping.")
                    continue
                cve_ids.append(f"CVE-{year_hint}-{c.zfill(4)}")
            else:
                print(f"[!] Invalid CVE ID format: '{c}'. Skipping.")

        # Fetch in batch and display/export via cve_lookup
        results = core.cve_lookup.fetch_cves_batch(
            cve_ids, year_filter=year_hint or None
        )
        core.cve_lookup.show_and_export(results, multiple=True)
        return

    # ---- Keyword path with optional date filter ----
    # Ask for keyword; required to proceed.
    keyword = input("Enter keyword (e.g., apache, buffer overflow): ").strip()
    if not keyword:
        print("[!] No keyword provided.")
        return

    # Offer examples to reduce user error in natural-language date filters.
    print(
        "\n(Date filter is optional. Examples: 'last 30 days', 'since 2025-07-01', "
        "'between 2025-07-01 and 2025-07-31', '2025-07-01..2025-07-31')"
    )
    filt = input("Date filter (press Enter to skip): ").strip()

    # Convert human text → NVD ISO window (pubStartDate/pubEndDate) if provided.
    pub_start, pub_end = _parse_date_filter(filt)

    # Optional results limit; keeps NVD responses fast/sane.
    lim_raw = input("Max results (default 20): ").strip()
    try:
        limit = max(1, min(2000, int(lim_raw))) if lim_raw else 20
    except ValueError:
        limit = 20

    # Delegate actual API query to cve_lookup (data layer).
    results = core.cve_lookup.search_by_keyword(
        keyword=keyword,
        results_limit=limit,
        pub_start_iso=pub_start,
        pub_end_iso=pub_end,
        start_index=0,
    )

    # Normalize + pretty print + export (CSV/JSON) for later pipelines.
    core.cve_lookup.show_and_export(results, multiple=True)


# ── Helpers to fetch dynamic registry robustly ───────────────────────────────
def _get_dynamic_registry():
    """
    Attempt to retrieve the dynamic plugin registry regardless of how
    core.plugin_manager exposes it. We try load_plugins() first, then
    several likely attribute names as fallbacks.

    Returns:
      A dict mapping dynamic task keys → metadata dicts (or {} if not found).
    """
    reg = {}
    try:
        # Primary path: rely on plugin_manager's public loader
        plugins = load_plugins() or {}
        if isinstance(plugins, dict) and "dynamic" in plugins:
            reg = plugins.get("dynamic") or {}
    except Exception:
        # We swallow here to remain resilient if plugin discovery changes.
        pass
    if reg:
        return reg

    # Fallbacks: probe for common attribute names exposed by plugin_manager
    try:
        from core import plugin_manager as _pm

        for attr in ("DYNAMIC_PLUGINS", "PLUGINS", "REGISTRY", "_PLUGINS"):
            obj = getattr(_pm, attr, None)
            if isinstance(obj, dict):
                # Some shapes nest dynamic under a 'dynamic' key; others are flat.
                if "dynamic" in obj and isinstance(obj["dynamic"], dict):
                    return obj["dynamic"]
                if obj and all(isinstance(v, dict) for v in obj.values()):
                    return obj
    except Exception:
        pass
    return {}


# ── Classifiers for dynamic plugin surfacing ─────────────────────────────────
def _is_recon_like(task_key: str, pretty: str, desc: str, tags: list[str]) -> bool:
    """
    Heuristically classify a dynamic plugin as 'Recon' so it appears with recon items.
    We check tags and fuzzy match against common recon-related keywords.
    """
    t = {x.lower() for x in (tags or [])}
    name_lc = (pretty or "").lower()
    desc_lc = (desc or "").lower()
    key_lc = (task_key or "").lower()

    recon_tags = {"recon", "dns", "subdomains", "amass", "enumeration", "http", "web"}
    if t & recon_tags:
        return True

    needles = ("recon", "amass", "subdomain", "dns", "enum", "banner", "http", "nmap")
    return (
        any(n in name_lc for n in needles)
        or any(n in desc_lc for n in needles)
        or any(n in key_lc for n in needles)
    )


def _is_amass_like(task_key: str, pretty: str, desc: str, tags: list[str]) -> bool:
    """Special check so we can add a neat satellite emoji for Amass-like entries."""
    t = {x.lower() for x in (tags or [])}
    if "amass" in t:
        return True
    name_lc = (pretty or "").lower()
    desc_lc = (desc or "").lower()
    key_lc = (task_key or "").lower()
    return ("amass" in name_lc) or ("amass" in desc_lc) or ("amass" in key_lc)


# ──────────────────────────────────────────────────────────────────────────────
# Special handling: OWASP ZAP with comprehensive parameter input
# Provides a user-friendly interface for configuring ZAP scans with validation
# ──────────────────────────────────────────────────────────────────────────────
def run_owasp_zap_interface(session_id: str | None = None):
    """
    Interactive interface for OWASP ZAP vulnerability scanning.
    Prompts user for target URL, ZAP server settings, and scan parameters.

    ⚠️  IMPORTANT DISCLAIMER:
    - Passive scan: Only analyzes responses without modifying target pages
    - Spider crawler: Actively requests pages by following links (may generate server logs)
    - Active scan: Sends malicious payloads to test for vulnerabilities (REQUIRES EXPLICIT PERMISSION)

    Testing websites or applications without proper authorization may violate laws in many
    countries and regions. Always ensure you have written permission from the target
    owner before conducting any security assessments.
    """
    print("\n=== 🐝 OWASP ZAP Vulnerability Scanner ===")
    print("⚠️  IMPORTANT: Only scan targets you have permission to test!")
    print("Configure your ZAP scan parameters below:\n")

    try:
        # Target URL input with validation
        target = inquirer.text(
            message="Enter target URL to scan:",
            default="https://public-firing-range.appspot.com",
            validate=lambda x: x.startswith(("http://", "https://")) if x else True,
        ).execute()

        if not target:
            target = "https://public-firing-range.appspot.com"
            print(f"[ℹ️] Using default target: {target}")

        # Scan type selection
        scan_type_tuple = inquirer.select(
            message="Select scan type:",
            choices=[
                ("Passive Scan (Spider + Analysis)", "passive"),
                ("Active Scan (Spider + Active Testing)", "active"),
            ],
            default="passive",
        ).execute()

        # Extract the actual value from the tuple
        scan_type = (
            scan_type_tuple[1]
            if isinstance(scan_type_tuple, tuple)
            else scan_type_tuple
        )

        # ZAP server configuration
        zap_host = inquirer.text(
            message="ZAP server host (press Enter for default):", default="127.0.0.1"
        ).execute()

        zap_port = inquirer.text(
            message="ZAP server port (press Enter for default):", default="8080"
        ).execute()

        # Scan configuration
        scan_timeout = inquirer.text(
            message="Scan timeout in seconds (press Enter for default):", default="900"
        ).execute()

        # API key (optional)
        api_key = inquirer.text(
            message="ZAP API key (press Enter if not required):", default=""
        ).execute()

        # HTTP timeout
        http_timeout = inquirer.text(
            message="HTTP timeout in seconds (press Enter for default):", default="5.0"
        ).execute()

        # Build arguments dictionary
        args = {
            "target": target,
            "zap_host": zap_host or "127.0.0.1",
            "zap_port": int(zap_port or "8080"),
            "scan_timeout": int(scan_timeout or "900"),
            "http_timeout": float(http_timeout or "5.0"),
        }

        # Add API key if provided
        if api_key:
            args["api_key"] = api_key

        # Add scan type to args
        args["scan_type"] = scan_type

        print("\n[🔧] Configuration:")
        print(f"  Target: {args['target']}")
        print(f"  Scan Type: {scan_type.upper()}")
        print(f"  ZAP Server: {args['zap_host']}:{args['zap_port']}")
        print(f"  Scan Timeout: {args['scan_timeout']}s")
        print(f"  HTTP Timeout: {args['http_timeout']}s")
        if api_key:
            print(f"  API Key: {'*' * min(len(api_key), 8)}...")

        # Special warning for active scans
        if scan_type == "active":
            print("\n🚨  ACTIVE SCAN WARNING 🚨")
            print(f"Active scanning will send malicious payloads to {target}")
            print(
                "This may trigger security alerts and could be illegal without permission!"
            )
            print(
                "By proceeding, you confirm you have explicit permission to test this target."
            )

            # Require explicit confirmation for active scans
            proceed = inquirer.confirm(
                message="⚠️  I understand the risks and have permission to perform active scanning. Proceed?",
                default=False,
            ).execute()
        else:
            # Confirm before proceeding for passive scans
            proceed = inquirer.confirm(
                message="Proceed with scan?", default=True
            ).execute()

        if not proceed:
            print("[❌] Scan cancelled by user.")
            return

        print(f"\n[🚀] Starting OWASP ZAP scan of {target}...")

        # Log the action
        if session_id:
            append_session_event(
                session_id, "ACTION_BEGIN", {"plugin": "owasp_zap", "target": target}
            )

        # Execute the scan
        result = run_plugin("owasp_zap", args)

        # Log the result
        if session_id:
            append_session_event(
                session_id, "ACTION_RESULT", {"plugin": "owasp_zap", "result": result}
            )

        print("\n[✅] OWASP ZAP scan completed!")
        print(f"\n{result}")

    except KeyboardInterrupt:
        print("\n[❌] Scan cancelled by user.")
    except Exception as e:
        error_msg = f"OWASP ZAP interface error: {e}"
        print(f"\n[!] {error_msg}")
        if session_id:
            log_error(session_id, error_msg)
        raise


# ──────────────────────────────────────────────────────────────────────────────
# Helper function to handle graceful exit with session logging
# Centralizes the repeated pattern of goodbye message + session cleanup
# ──────────────────────────────────────────────────────────────────────────────
def graceful_exit(session_id: str | None = None):
    """
    Handles graceful exit with goodbye message and session cleanup.
    Centralizes the repeated pattern used throughout the main loop.
    """
    print("Goodbye, bestie 🖤")
    if session_id:
        end_session(session_id, status="ok")


# ──────────────────────────────────────────────────────────────────────────────
# Main CLI
# Orchestrates:
#   • Session lifecycle logging (start/end, events)
#   • Plugin discovery (static + dynamic)
#   • Menu presentation and user choice handling
#   • Special-cased flows: CVE Lookup, Nmap, triage, exploit predictor
#   • Generic plugin execution path for everything else
# ──────────────────────────────────────────────────────────────────────────────
def main():
    # Start session logging early so we capture startup diagnostics.
    session_id = start_session({"version": "0.1.0", "stage": "cli_start"})
    append_session_event(session_id, "BANNER_PRINT")
    print_banner()

    # ── Load plugin registry (static is handled by PLUGIN_TASKS) ─────────────
    try:
        _ = load_plugins()  # side-effects: populate registry in plugin_manager
    except Exception as e:
        print(f"[!] Failed to load plugins: {e}")
        end_session(session_id, status="ok")
        return

    # ── Register post-run LLM hook so every plugin result gets analyzed ──
    try:
        from core.ai.postrun_llm import postrun_llm

        register_post_run(postrun_llm)
        print("[hooks] postrun_llm registered")
    except Exception as hook_err:
        print(f"[hook] postrun_llm not registered: {hook_err}")

    # ── Collect dynamic plugins robustly ─────────────────────────────────────
    dynamic_registry = _get_dynamic_registry()

    # Optional debug dump of discovered dynamic plugins
    if os.environ.get("CHARLOTTE_DEBUG"):
        print("[debug] dynamic keys:", list((dynamic_registry or {}).keys()))
        for k, m in (dynamic_registry or {}).items():
            print(f"[debug] {k} meta:", m)

    # ── Build auto-surfaced Recon entries ────────────────────────────────────
    # We attempt to group recon-ish plugins into the Recon section for UX polish.
    recon_dynamic_entries = []
    for task_key, meta in (dynamic_registry or {}).items():
        pretty = (
            meta.get("pretty_name") or meta.get("name") or meta.get("label") or task_key
        ).strip()
        desc = meta.get("description") or meta.get("desc") or ""
        tags = meta.get("tags") or meta.get("categories") or []

        if _is_recon_like(task_key, pretty, desc, tags):
            prefix = "🛰️" if _is_amass_like(task_key, pretty, desc, tags) else "🧭"
            recon_dynamic_entries.append(
                {
                    "name": f"{prefix} {pretty}",
                    "value": ("dynamic", (meta.get("label") or pretty)),
                }
            )

    # If nothing classified as Recon, we still show a catch-all dynamic section.
    show_dynamic_fallback = not bool(recon_dynamic_entries)
    dynamic_fallback_entries = []
    if show_dynamic_fallback:
        for task_key, meta in (dynamic_registry or {}).items():
            pretty = (
                meta.get("pretty_name")
                or meta.get("name")
                or meta.get("label")
                or task_key
            ).strip()
            dynamic_fallback_entries.append(
                {
                    "name": f"🧩 {pretty}",
                    "value": ("dynamic", (meta.get("label") or pretty)),
                }
            )

    # ── Main menu loop: keep letting the user run tasks until exit ───────────
    while True:
        # Construct menu with sections. We combine static tasks + surfaced dynamic.
        menu_choices = [
            Separator("=== Binary Ops ==="),
            *[k for k in PLUGIN_TASKS if "Binary" in k],
            Separator("=== Recon ==="),
            *[k for k in PLUGIN_TASKS if ("Scan" in k or "Recon" in k)],
            *recon_dynamic_entries,
            *(
                [Separator("=== Dynamic (unclassified) ===")] + dynamic_fallback_entries
                if show_dynamic_fallback
                else []
            ),
            Separator("=== Exploitation ==="),
            *[k for k in PLUGIN_TASKS if "Exploit" in k],
            Separator("=== Intelligence ==="),
            "🕵️ CVE Lookup (CHARLOTTE)",
            Separator("=== Scoring & Analysis ==="),
            *[k for k in PLUGIN_TASKS if ("Triage" in k or "Assessment" in k)],
            Separator(),
            "❌ Exit",
        ]

        # Present interactive selection and capture user choice.
        task = inquirer.select(
            message="What would you like CHARLOTTE to do?",
            choices=menu_choices,
        ).execute()

        # Graceful exit path with session end logging.
        if task == "❌ Exit":
            graceful_exit(session_id)
            break

        # Special route: CVE Intelligence flow (own sub-menu + exports)
        if task == "🕵️ CVE Lookup (CHARLOTTE)":
            run_cve_lookup(session_id)
            continue

        # Special route: Run a dynamic plugin (tuple value is ('dynamic', key))
        if isinstance(task, tuple) and len(task) == 2 and task[0] == "dynamic":
            _, dyn_key = task
            try:
                append_session_event(session_id, "ACTION_BEGIN", {"plugin": dyn_key})
                result = run_dynamic_by_label(dyn_key, args=None)
                # If plugin returned a structured result, hand it to report dispatcher.
                from core import report_dispatcher

                if result:
                    file_path = report_dispatcher.save_report_locally(
                        result, interactive=False
                    )
                    append_session_event(
                        session_id, "TRIAGE_DONE", {"report_path": file_path}
                    )
                    print(f"\n[📁 Saved] {file_path}")
            except Exception as e:
                # Log + surface the error without crashing the whole CLI.
                log_error(session_id, f"Dynamic plugin '{dyn_key}' failed: {e}")
                print(f"[!] Error running dynamic plugin '{dyn_key}': {e}")
            # Offer to run another task before we loop back.
            again = inquirer.confirm(
                message="Would you like to run another plugin?", default=True
            ).execute()
            if not again:
                graceful_exit(session_id)
                break
            continue

        # For static choices, map pretty label → plugin key.
        plugin_key = PLUGIN_TASKS.get(task)

        # ── Special handling: Nmap always prompts interactively
        # We bypass the generic path to ensure a great interactive UX.
        if plugin_key == "port_scan":
            try:
                append_session_event(
                    session_id, "PROMPT_SELECTION", {"selected": "port_scan"}
                )
                target = inquirer.text(message="Enter target IP or domain:").execute()
                ports = inquirer.text(
                    message="Enter ports (e.g., 80,443 or leave blank):"
                ).execute()

                # 🔒 Robust load with nested category support
                nmap_module = _load_plugin_module("recon.nmap", "nmap_plugin")
                result = _call_plugin_entrypoint(
                    nmap_module,
                    {"target": target, "ports": ports, "interactive": True},
                )

                # Dispatch result to report pipeline (local file + any downstream hooks)
                from core import report_dispatcher

                append_session_event(
                    session_id,
                    "ACTION_RESULT",
                    {"plugin": "port_scan", "result_kind": type(result).__name__},
                )
                if result:
                    file_path = report_dispatcher.save_report_locally(
                        result, interactive=False
                    )
                    append_session_event(
                        session_id,
                        "TRIAGE_DONE",
                        {"report_path": display_path(file_path)},
                    )
                    report_dispatcher.dispatch_report(file_path)
                else:
                    print("[!] No report data returned.")
            except Exception as e:
                # We attempt a graceful fallback even if the direct module path fails
                print(f"[!] Nmap plugin error: {e}")
                log_error(session_id, f"Nmap error: {e}")
                append_session_event(
                    session_id, "ERROR", {"where": "nmap", "error": str(e)}
                )
                try:
                    run_plugin(plugin_key, args=None)
                except Exception as e2:
                    print(f"[!] Plugin manager also failed to run Nmap: {e2}")
            # Offer to run another task after Nmap completes.
            again = inquirer.confirm(
                message="Would you like to run another plugin?", default=True
            ).execute()
            if not again:
                graceful_exit(session_id)
                break
            continue

        # ── Special handling: triage (interactive path for selecting scan file)
        if plugin_key == "triage_agent":
            scan_path = inquirer.text(
                message="Enter path to scan file (press Enter for default: data/findings.json):"
            ).execute()
            scan_path = (scan_path or "").strip() or "data/findings.json"
            run_triage_agent(scan_file=scan_path)
            again = inquirer.confirm(
                message="Would you like to run another plugin?", default=True
            ).execute()
            if not again:
                graceful_exit(session_id)
                break
            continue

        # ── Special handling: exploit predictor (batch model inference)
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
                print(
                    "Use '🧮 Vulnerability Triage' to further refine prioritization.\n"
                )
            except Exception as e:
                print(f"[!] Error processing exploit prediction: {e}")
            again = inquirer.confirm(
                message="Would you like to run another plugin?", default=True
            ).execute()
            if not again:
                graceful_exit(session_id)
                break
            continue

        # ── Special handling: OWASP ZAP (interactive interface)
        if plugin_key == "owasp_zap":
            run_owasp_zap_interface(session_id)
            # Offer to run another task after OWASP ZAP completes.
            again = inquirer.confirm(
                message="Would you like to run another plugin?", default=True
            ).execute()
            if not again:
                graceful_exit(session_id)
                break
            continue

        # ── Generic static plugin execution
        # For all other static items, defer to plugin_manager.run_plugin().
        try:
            run_plugin(plugin_key, args=None)
            print(f"\n[✔] Running plugin: {plugin_key}...\n")
        except TypeError as the:
            # Helpful tip if plugin signature doesn't match expectations.
            print(f"[!] Plugin '{plugin_key}' raised a TypeError: {the}")
            print("    Tip: Ensure its entrypoint is 'def run_plugin(args=None, ...):'")
        except Exception as e:
            print(f"[!] Error running plugin '{plugin_key}': {e}")

        # Post-run: ask if the user wants to continue; end session if not.
        again = inquirer.confirm(
            message="Would you like to run another plugin?", default=True
        ).execute()
        if not again:
            graceful_exit(session_id)
            break


# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI application.
# When executed as a script (python -m core.main or python charlotte), we enter main().
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()

# ******************************************************************************************
# End of main.py
# ******************************************************************************************#
#
