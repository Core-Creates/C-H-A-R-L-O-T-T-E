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

from __future__ import annotations

import os
import sys
import re
import json
from datetime import datetime, timedelta, timezone

# ──────────────────────────────────────────────────────────────────────────────
# Third-party deps with friendly hints if missing
# We keep this try/except so the CLI can clearly tell the user how to fix env issues.
# ──────────────────────────────────────────────────────────────────────────────
try:
    from InquirerPy import inquirer
    from InquirerPy.separator import Separator
except ModuleNotFoundError:
    print("[!] Missing dependency: InquirerPy\n    pip install InquirerPy")
    sys.exit(1)

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
    # ⬇️ robust plugin loader + convenience runners
    from core.plugin_manager import (
        load_plugins,
        run_plugin,
        _load_plugin_module,
        _call_plugin_entrypoint,
        register_post_run,
        run_dynamic_by_label,
        PLUGIN_REGISTRY,
        ALIASES,
    )
    from agents.triage_agent import run_triage_agent, load_findings, save_results
    from core.charlotte_personality import CharlottePersonality
    from utils.paths import display_path
    import core.cve_lookup

    # Make internal helpers importable by other modules/tests.
    __all__ = ["run_plugin", "_call_plugin_entrypoint", "PLUGIN_REGISTRY", "ALIASES"]

except ModuleNotFoundError as e:
    print(
        f"[!] Missing CHARLOTTE module: {e.name}\n"
        f"    Did you activate the venv and install requirements?"
    )
    raise

# ──────────────────────────────────────────────────────────────────────────────
# Session telemetry (safe fallbacks if service module is absent)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from service.charlotte_service import (
        start_session,
        append_session_event,
        end_session,
        log_error,
    )
except Exception:

    def start_session(meta: dict) -> str:
        # simple fallback session id
        return datetime.now().strftime("%Y%m%d%H%M%S")

    def append_session_event(session_id: str, event: str, data: dict | None = None):
        pass

    def end_session(session_id: str, status: str = "ok"):
        pass

    def log_error(session_id: str, error: str):
        print(f"[session:{session_id}] ERROR: {error}")


# ──────────────────────────────────────────────────────────────────────────────
# Initialize personality (for future contextual use)
# Currently used for theming + possible persona-based responses later.
# ──────────────────────────────────────────────────────────────────────────────
charlotte = CharlottePersonality()


# ──────────────────────────────────────────────────────────────────────────────
# Banner (for ✨ vibes ✨)
# ──────────────────────────────────────────────────────────────────────────────
def print_banner() -> None:
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
# keeping that module clean as a data-access layer that expects ISO timestamps.
# ──────────────────────────────────────────────────────────────────────────────
def _iso_z(dt: datetime) -> str:
    """NVD wants ISO8601 with milliseconds and Z suffix: YYYY-MM-DDTHH:MM:SS.000Z"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_date_filter(filter_str: str) -> tuple[str | None, str | None]:
    """
    Translate a human-friendly filter string into NVD pubStartDate/pubEndDate.

    Supported:
      • 'last 30 days' / 'last 2 weeks' / 'last 3 months' (months≈30 days)
      • 'since 2025-07-01'
      • 'between 2025-07-01 and 2025-07-31'
      • '2025-07-01..2025-07-31'
    """
    if not filter_str:
        return None, None

    s = filter_str.strip().lower()
    now = datetime.now(timezone.utc)

    m = re.match(r"^last\s+(\d+)\s*(days?|d|weeks?|w|months?|m)\s*$", s)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit.startswith("day") or unit == "d":
            delta = timedelta(days=n)
        elif unit.startswith("week") or unit == "w":
            delta = timedelta(weeks=n)
        else:
            delta = timedelta(days=30 * n)
        start = now - delta
        return _iso_z(start), _iso_z(now)

    m = re.match(r"^since\s+(\d{4}-\d{2}-\d{2})\s*$", s)
    if m:
        try:
            start = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            return _iso_z(start), _iso_z(now)
        except Exception:
            return None, None

    m = re.match(r"^between\s+(\d{4}-\d{2}-\d{2})\s+and\s+(\d{4}-\d{2}-\d{2})\s*$", s)
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

    return None, None


# ──────────────────────────────────────────────────────────────────────────────
# LLM Router: analyze result & recommend next plugin
# ──────────────────────────────────────────────────────────────────────────────
def _llm_recommend_next(
    session_id: str, current_result: dict | str
) -> tuple[str | None, str]:
    """Return (next_label, analysis_markdown). If LLM is not configured, return (None, '')."""
    try:
        from core.ai.llm import analyze_plugin_output, redact_for_prompt
    except Exception:
        return None, ""
    try:
        # Build candidate labels from dynamic discovery
        try:
            from core.plugin_manager import dynamic_index_by_label

            dyn_map = dynamic_index_by_label()
            labels = sorted(list(dyn_map.keys()))
        except Exception:
            labels = []
        payload = {
            "session_id": session_id,
            "result": current_result,
            "available_dynamic_labels": labels,
            "instruction": "Summarize concisely, then pick exactly ONE label from available_dynamic_labels to run next. "
            'Respond with a JSON block: {"summary_md": str, "next_label": str}. '
            "The next_label MUST match one item from available_dynamic_labels. Keep summary short.",
        }
        safe = redact_for_prompt(payload)
        md = analyze_plugin_output("post-run router", safe, model=None, max_tokens=700)

        next_label = None
        summary_md = ""
        m = re.search(r"\{[\s\S]*\}", md)
        if m:
            try:
                j = json.loads(m.group(0))
                summary_md = j.get("summary_md", "") or ""
                nl = j.get("next_label")
                if isinstance(nl, str):
                    next_label = nl.strip()
            except Exception:
                pass
        return next_label, (summary_md or md or "")
    except Exception as e:
        return None, f"_LLM router error: {e}_"


# ──────────────────────────────────────────────────────────────────────────────
# CVE Intelligence flow
# ──────────────────────────────────────────────────────────────────────────────
def run_cve_lookup(session_id: str | None = None):
    print("\n=== CHARLOTTE CVE Intelligence Module ===")
    from InquirerPy import (
        inquirer,
    )  # local import keeps startup faster if CVE flow unused

    mode = inquirer.select(
        message="Choose your CVE query method:",
        choices=["🔎 Search by CVE ID", "🗂️ Search by Keyword"],
        default="🗂️ Search by Keyword",
    ).execute()

    if mode.startswith("🔎"):
        ids = input(
            "Enter CVE ID(s) (comma-separated or short IDs with year): "
        ).strip()
        year_hint = input("Optional year hint for short IDs (YYYY): ").strip()

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

        results = core.cve_lookup.fetch_cves_batch(
            cve_ids, year_filter=year_hint or None
        )
        core.cve_lookup.show_and_export(results, multiple=True)
        return

    keyword = input("Enter keyword (e.g., apache, buffer overflow): ").strip()
    if not keyword:
        print("[!] No keyword provided.")
        return

    print(
        "\n(Date filter is optional. Examples: 'last 30 days', 'since 2025-07-01', "
        "'between 2025-07-01 and 2025-07-31', '2025-07-01..2025-07-31')"
    )
    filt = input("Date filter (press Enter to skip): ").strip()

    pub_start, pub_end = _parse_date_filter(filt)

    lim_raw = input("Max results (default 20): ").strip()
    try:
        limit = max(1, min(2000, int(lim_raw))) if lim_raw else 20
    except ValueError:
        limit = 20

    results = core.cve_lookup.search_by_keyword(
        keyword=keyword,
        results_limit=limit,
        pub_start_iso=pub_start,
        pub_end_iso=pub_end,
        start_index=0,
    )
    core.cve_lookup.show_and_export(results, multiple=True)


# ──────────────────────────────────────────────────────────────────────────────
# Dynamic plugin registry fetch (robust)
# ──────────────────────────────────────────────────────────────────────────────
def _get_dynamic_registry() -> dict:
    """
    Attempt to retrieve the dynamic plugin registry regardless of how
    core.plugin_manager exposes it.
    """
    reg: dict = {}
    try:
        plugins = load_plugins() or {}
        if isinstance(plugins, dict) and "dynamic" in plugins:
            reg = plugins.get("dynamic") or {}
    except Exception:
        pass
    if reg:
        return reg

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


# ──────────────────────────────────────────────────────────────────────────────
# Recon classifiers for dynamic surfacing
# ──────────────────────────────────────────────────────────────────────────────
def _is_recon_like(task_key: str, pretty: str, desc: str, tags: list[str]) -> bool:
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
    t = {x.lower() for x in (tags or [])}
    if "amass" in t:
        return True
    name_lc = (pretty or "").lower()
    desc_lc = (desc or "").lower()
    key_lc = (task_key or "").lower()
    return ("amass" in name_lc) or ("amass" in desc_lc) or ("amass" in key_lc)


# ──────────────────────────────────────────────────────────────────────────────
# Special handling: OWASP ZAP with comprehensive parameter input
# ──────────────────────────────────────────────────────────────────────────────
def run_owasp_zap_interface(session_id: str | None = None):
    """
    Interactive interface for OWASP ZAP vulnerability scanning.
    """
    print("\n=== 🐝 OWASP ZAP Vulnerability Scanner ===")
    print("⚠️  IMPORTANT: Only scan targets you have permission to test!")
    print("Configure your ZAP scan parameters below:\n")

    try:
        target = inquirer.text(
            message="Enter target URL to scan:",
            default="https://public-firing-range.appspot.com",
            validate=lambda x: x.startswith(("http://", "https://")) if x else True,
        ).execute()

        if not target:
            target = "https://public-firing-range.appspot.com"
            print(f"[ℹ️] Using default target: {target}")

        scan_type_tuple = inquirer.select(
            message="Select scan type:",
            choices=[
                ("Passive Scan (Spider + Analysis)", "passive"),
                ("Active Scan (Spider + Active Testing)", "active"),
            ],
            default="passive",
        ).execute()
        scan_type = (
            scan_type_tuple[1]
            if isinstance(scan_type_tuple, tuple)
            else scan_type_tuple
        )

        zap_host = inquirer.text(
            message="ZAP server host (press Enter for default):", default="127.0.0.1"
        ).execute()
        zap_port = inquirer.text(
            message="ZAP server port (press Enter for default):", default="8080"
        ).execute()
        scan_timeout = inquirer.text(
            message="Scan timeout in seconds (press Enter for default):", default="900"
        ).execute()
        api_key = inquirer.text(
            message="ZAP API key (press Enter if not required):", default=""
        ).execute()
        http_timeout = inquirer.text(
            message="HTTP timeout in seconds (press Enter for default):", default="5.0"
        ).execute()

        args = {
            "target": target,
            "zap_host": zap_host or "127.0.0.1",
            "zap_port": int(zap_port or "8080"),
            "scan_timeout": int(scan_timeout or "900"),
            "http_timeout": float(http_timeout or "5.0"),
            "scan_type": scan_type,
        }
        if api_key:
            args["api_key"] = api_key

        print("\n[🔧] Configuration:")
        print(f"  Target: {args['target']}")
        print(f"  Scan Type: {scan_type.upper()}")
        print(f"  ZAP Server: {args['zap_host']}:{args['zap_port']}")
        print(f"  Scan Timeout: {args['scan_timeout']}s")
        print(f"  HTTP Timeout: {args['http_timeout']}s")
        if api_key:
            print(f"  API Key: {'*' * min(len(api_key), 8)}...")

        if scan_type == "active":
            print("\n🚨  ACTIVE SCAN WARNING 🚨")
            print(f"Active scanning will send malicious payloads to {target}")
            print(
                "This may trigger security alerts and could be illegal without permission!"
            )
            print(
                "By proceeding, you confirm you have explicit permission to test this target."
            )
            proceed = inquirer.confirm(
                message="⚠️  I understand the risks and have permission to perform active scanning. Proceed?",
                default=False,
            ).execute()
        else:
            proceed = inquirer.confirm(
                message="Proceed with scan?", default=True
            ).execute()

        if not proceed:
            print("[❌] Scan cancelled by user.")
            return

        print(f"\n[🚀] Starting OWASP ZAP scan of {target}...")

        if session_id:
            append_session_event(
                session_id, "ACTION_BEGIN", {"plugin": "owasp_zap", "target": target}
            )

        result = run_plugin("owasp_zap", args)

        if session_id:
            append_session_event(
                session_id, "ACTION_RESULT", {"plugin": "owasp_zap", "result": result}
            )

        print("\n[✅] OWASP ZAP scan completed!")
        print(f"\n{result}")

        return result

    except KeyboardInterrupt:
        print("\n[❌] Scan cancelled by user.")
        return None
    except Exception as e:
        error_msg = f"OWASP ZAP interface error: {e}"
        print(f"\n[!] {error_msg}")
        if session_id:
            log_error(session_id, error_msg)
        raise


# ──────────────────────────────────────────────────────────────────────────────
# Graceful exit helper
# ──────────────────────────────────────────────────────────────────────────────
def graceful_exit(session_id: str | None = None) -> None:
    print("Goodbye, bestie 🖤")
    if session_id:
        end_session(session_id, status="ok")


# ──────────────────────────────────────────────────────────────────────────────
# Main CLI
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    session_id = start_session({"version": "0.1.0", "stage": "cli_start"})
    append_session_event(session_id, "BANNER_PRINT")
    print_banner()

    try:
        _ = load_plugins()
    except Exception as e:
        print(f"[!] Failed to load plugins: {e}")
        end_session(session_id, status="ok")
        return

    try:
        from core.ai.postrun_llm import postrun_llm

        register_post_run(postrun_llm)
        print("[hooks] postrun_llm registered")
    except Exception as hook_err:
        print(f"[hook] postrun_llm not registered: {hook_err}")

    dynamic_registry = _get_dynamic_registry()

    if os.environ.get("CHARLOTTE_DEBUG"):
        print("[debug] dynamic keys:", list((dynamic_registry or {}).keys()))
        for k, m in (dynamic_registry or {}).items():
            print(f"[debug] {k} meta:", m)

    # Build auto-surfaced Recon entries
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

    while True:
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

        task = inquirer.select(
            message="What would you like CHARLOTTE to do?",
            choices=menu_choices,
        ).execute()

        if task == "❌ Exit":
            graceful_exit(session_id)
            break

        if task == "🕵️ CVE Lookup (CHARLOTTE)":
            run_cve_lookup(session_id)
            continue

        if isinstance(task, tuple) and len(task) == 2 and task[0] == "dynamic":
            _, dyn_key = task
            result = None
            try:
                append_session_event(session_id, "ACTION_BEGIN", {"plugin": dyn_key})
                result = run_dynamic_by_label(dyn_key, args=None)
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
                log_error(session_id, f"Dynamic plugin '{dyn_key}' failed: {e}")
                print(f"[!] Error running dynamic plugin '{dyn_key}': {e}")

            next_label, analysis_md = _llm_recommend_next(
                session_id, result if result is not None else {}
            )
            if analysis_md:
                print("\n[🧠 LLM Analysis]\n" + analysis_md + "\n")

            try:
                from core.plugin_manager import dynamic_index_by_label

                dyn_map = dynamic_index_by_label()
            except Exception:
                dyn_map = {}
            dyn_labels = list(dyn_map.keys())
            default_label = (
                next_label
                if next_label and next_label in dyn_labels
                else (dyn_labels[0] if dyn_labels else None)
            )

            if dyn_labels:
                ordered = [lbl for lbl in [default_label] if lbl] + [
                    lbl for lbl in dyn_labels if lbl != default_label
                ]
                choice = inquirer.select(
                    message="Choose next plugin to run (LLM suggested first):",
                    choices=ordered,
                    default=default_label,
                ).execute()
                use_prev = inquirer.confirm(
                    message="Pass previous output to the next plugin as chain_input?",
                    default=True,
                ).execute()
                chain_args = {"chain_input": result} if use_prev else None
                try:
                    append_session_event(
                        session_id,
                        "CHAIN_DECISION",
                        {"use_prev": bool(use_prev), "next": choice},
                    )
                except Exception:
                    pass
                try:
                    result = run_dynamic_by_label(choice, args=chain_args)
                except Exception as e:
                    log_error(
                        session_id, f"Chained dynamic plugin '{choice}' failed: {e}"
                    )
                    print(f"[!] Error running dynamic plugin '{choice}': {e}")
            else:
                again = inquirer.confirm(
                    message="Would you like to run another plugin?", default=True
                ).execute()
                if not again:
                    graceful_exit(session_id)
                    break
            continue

        plugin_key = PLUGIN_TASKS.get(task)

        if plugin_key == "port_scan":
            try:
                append_session_event(
                    session_id, "PROMPT_SELECTION", {"selected": "port_scan"}
                )
                target = inquirer.text(message="Enter target IP or domain:").execute()
                ports = inquirer.text(
                    message="Enter ports (e.g., 80,443 or leave blank):"
                ).execute()

                nmap_module = _load_plugin_module("recon.nmap", "nmap_plugin")
                result = _call_plugin_entrypoint(
                    nmap_module,
                    {"target": target, "ports": ports, "interactive": True},
                )

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
                print(f"[!] Nmap plugin error: {e}")
                log_error(session_id, f"Nmap error: {e}")
                append_session_event(
                    session_id, "ERROR", {"where": "nmap", "error": str(e)}
                )
                try:
                    result = run_plugin(plugin_key, args=None)
                except Exception as e2:
                    print(f"[!] Plugin manager also failed to run Nmap: {e2}")
                    result = None

            next_label, analysis_md = _llm_recommend_next(
                session_id, result if result is not None else {}
            )
            if analysis_md:
                print("\n[🧠 LLM Analysis]\n" + analysis_md + "\n")

            try:
                from core.plugin_manager import dynamic_index_by_label

                dyn_map = dynamic_index_by_label()
            except Exception:
                dyn_map = {}
            dyn_labels = list(dyn_map.keys())
            default_label = (
                next_label
                if next_label and next_label in dyn_labels
                else (dyn_labels[0] if dyn_labels else None)
            )

            if dyn_labels:
                ordered = [lbl for lbl in [default_label] if lbl] + [
                    lbl for lbl in dyn_labels if lbl != default_label
                ]
                choice = inquirer.select(
                    message="Choose next plugin to run (LLM suggested first):",
                    choices=ordered,
                    default=default_label,
                ).execute()
                use_prev = inquirer.confirm(
                    message="Pass previous output to the next plugin as chain_input?",
                    default=True,
                ).execute()
                chain_args = {"chain_input": result} if use_prev else None
                try:
                    append_session_event(
                        session_id,
                        "CHAIN_DECISION",
                        {"use_prev": bool(use_prev), "next": choice},
                    )
                except Exception:
                    pass
                try:
                    result = run_dynamic_by_label(choice, args=chain_args)
                except Exception as e:
                    log_error(
                        session_id, f"Chained dynamic plugin '{choice}' failed: {e}"
                    )
                    print(f"[!] Error running dynamic plugin '{choice}': {e}")
            else:
                again = inquirer.confirm(
                    message="Would you like to run another plugin?", default=True
                ).execute()
                if not again:
                    graceful_exit(session_id)
                    break
            continue

        if plugin_key == "triage_agent":
            scan_path = inquirer.text(
                message="Enter path to scan file (press Enter for default: data/findings.json):"
            ).execute()
            scan_path = (scan_path or "").strip() or "data/findings.json"
            run_triage_agent(scan_file=scan_path)
            result = {"task": "triage_agent", "scan_file": scan_path}

            next_label, analysis_md = _llm_recommend_next(
                session_id, result if result is not None else {}
            )
            if analysis_md:
                print("\n[🧠 LLM Analysis]\n" + analysis_md + "\n")

            try:
                from core.plugin_manager import dynamic_index_by_label

                dyn_map = dynamic_index_by_label()
            except Exception:
                dyn_map = {}
            dyn_labels = list(dyn_map.keys())
            default_label = (
                next_label
                if next_label and next_label in dyn_labels
                else (dyn_labels[0] if dyn_labels else None)
            )

            if dyn_labels:
                ordered = [lbl for lbl in [default_label] if lbl] + [
                    lbl for lbl in dyn_labels if lbl != default_label
                ]
                choice = inquirer.select(
                    message="Choose next plugin to run (LLM suggested first):",
                    choices=ordered,
                    default=default_label,
                ).execute()
                use_prev = inquirer.confirm(
                    message="Pass previous output to the next plugin as chain_input?",
                    default=True,
                ).execute()
                chain_args = {"chain_input": result} if use_prev else None
                try:
                    append_session_event(
                        session_id,
                        "CHAIN_DECISION",
                        {"use_prev": bool(use_prev), "next": choice},
                    )
                except Exception:
                    pass
                try:
                    result = run_dynamic_by_label(choice, args=chain_args)
                except Exception as e:
                    log_error(
                        session_id, f"Chained dynamic plugin '{choice}' failed: {e}"
                    )
                    print(f"[!] Error running dynamic plugin '{choice}': {e}")
            else:
                again = inquirer.confirm(
                    message="Would you like to run another plugin?", default=True
                ).execute()
                if not again:
                    graceful_exit(session_id)
                    break
            continue

        if plugin_key == "exploit_predictor":
            from core.logic_modules.exploit_predictor import batch_predict

            scan_path = inquirer.text(
                message="Enter path to scan file (press Enter for default: data/findings.json):"
            ).execute()
            scan_path = (scan_path or "").strip() or "data/findings.json"
            result = None
            try:
                findings = load_findings(scan_path)
                enriched = batch_predict(findings)
                output_path = "data/findings_with_predictions.json"
                save_results(enriched, output_file=output_path)
                print(f"\n[✔] Exploit predictions saved to {output_path}")
                print(
                    "Use '🧮 Vulnerability Triage' to further refine prioritization.\n"
                )
                result = {"task": "exploit_predictor", "output_path": output_path}
            except Exception as e:
                print(f"[!] Error processing exploit prediction: {e}")

            next_label, analysis_md = _llm_recommend_next(
                session_id, result if result is not None else {}
            )
            if analysis_md:
                print("\n[🧠 LLM Analysis]\n" + analysis_md + "\n")

            try:
                from core.plugin_manager import dynamic_index_by_label

                dyn_map = dynamic_index_by_label()
            except Exception:
                dyn_map = {}
            dyn_labels = list(dyn_map.keys())
            default_label = (
                next_label
                if next_label and next_label in dyn_labels
                else (dyn_labels[0] if dyn_labels else None)
            )

            if dyn_labels:
                ordered = [lbl for lbl in [default_label] if lbl] + [
                    lbl for lbl in dyn_labels if lbl != default_label
                ]
                choice = inquirer.select(
                    message="Choose next plugin to run (LLM suggested first):",
                    choices=ordered,
                    default=default_label,
                ).execute()
                use_prev = inquirer.confirm(
                    message="Pass previous output to the next plugin as chain_input?",
                    default=True,
                ).execute()
                chain_args = {"chain_input": result} if use_prev else None
                try:
                    append_session_event(
                        session_id,
                        "CHAIN_DECISION",
                        {"use_prev": bool(use_prev), "next": choice},
                    )
                except Exception:
                    pass
                try:
                    result = run_dynamic_by_label(choice, args=chain_args)
                except Exception as e:
                    log_error(
                        session_id, f"Chained dynamic plugin '{choice}' failed: {e}"
                    )
                    print(f"[!] Error running dynamic plugin '{choice}': {e}")
            else:
                again = inquirer.confirm(
                    message="Would you like to run another plugin?", default=True
                ).execute()
                if not again:
                    graceful_exit(session_id)
                    break
            continue

        if plugin_key == "owasp_zap":
            result = run_owasp_zap_interface(session_id)
            next_label, analysis_md = _llm_recommend_next(
                session_id, result if result is not None else {}
            )
            if analysis_md:
                print("\n[🧠 LLM Analysis]\n" + analysis_md + "\n")

            try:
                from core.plugin_manager import dynamic_index_by_label

                dyn_map = dynamic_index_by_label()
            except Exception:
                dyn_map = {}
            dyn_labels = list(dyn_map.keys())
            default_label = (
                next_label
                if next_label and next_label in dyn_labels
                else (dyn_labels[0] if dyn_labels else None)
            )

            if dyn_labels:
                ordered = [lbl for lbl in [default_label] if lbl] + [
                    lbl for lbl in dyn_labels if lbl != default_label
                ]
                choice = inquirer.select(
                    message="Choose next plugin to run (LLM suggested first):",
                    choices=ordered,
                    default=default_label,
                ).execute()
                use_prev = inquirer.confirm(
                    message="Pass previous output to the next plugin as chain_input?",
                    default=True,
                ).execute()
                chain_args = {"chain_input": result} if use_prev else None
                try:
                    append_session_event(
                        session_id,
                        "CHAIN_DECISION",
                        {"use_prev": bool(use_prev), "next": choice},
                    )
                except Exception:
                    pass
                try:
                    result = run_dynamic_by_label(choice, args=chain_args)
                except Exception as e:
                    log_error(
                        session_id, f"Chained dynamic plugin '{choice}' failed: {e}"
                    )
                    print(f"[!] Error running dynamic plugin '{choice}': {e}")
            else:
                again = inquirer.confirm(
                    message="Would you like to run another plugin?", default=True
                ).execute()
                if not again:
                    graceful_exit(session_id)
                    break
            continue

        # Generic static plugin execution
        try:
            print(f"[✔] Running plugin: {plugin_key}...")
            result = run_plugin(plugin_key, args=None)
        except TypeError as the:
            print(f"[!] Plugin '{plugin_key}' raised a TypeError: {the}")
            print("    Tip: Ensure its entrypoint is 'def run_plugin(args=None, ...):'")
            result = None
        except Exception as e:
            print(f"[!] Error running plugin '{plugin_key}': {e}")
            result = None

        next_label, analysis_md = _llm_recommend_next(
            session_id, result if result is not None else {}
        )
        if analysis_md:
            print("\n[🧠 LLM Analysis]\n" + analysis_md + "\n")

        try:
            from core.plugin_manager import dynamic_index_by_label

            dyn_map = dynamic_index_by_label()
        except Exception:
            dyn_map = {}
        dyn_labels = list(dyn_map.keys())
        default_label = (
            next_label
            if next_label and next_label in dyn_labels
            else (dyn_labels[0] if dyn_labels else None)
        )

        if dyn_labels:
            ordered = [lbl for lbl in [default_label] if lbl] + [
                lbl for lbl in dyn_labels if lbl != default_label
            ]
            choice = inquirer.select(
                message="Choose next plugin to run (LLM suggested first):",
                choices=ordered,
                default=default_label,
            ).execute()
            use_prev = inquirer.confirm(
                message="Pass previous output to the next plugin as chain_input?",
                default=True,
            ).execute()
            chain_args = {"chain_input": result} if use_prev else None
            try:
                append_session_event(
                    session_id,
                    "CHAIN_DECISION",
                    {"use_prev": bool(use_prev), "next": choice},
                )
            except Exception:
                pass
            try:
                result = run_dynamic_by_label(choice, args=chain_args)
            except Exception as e:
                log_error(session_id, f"Chained dynamic plugin '{choice}' failed: {e}")
                print(f"[!] Error running dynamic plugin '{choice}': {e}")
        else:
            again = inquirer.confirm(
                message="Would you like to run another plugin?", default=True
            ).execute()
            if not again:
                graceful_exit(session_id)
                break


# ******************************************************************************************
# Entrypoint
# ******************************************************************************************
if __name__ == "__main__":
    main()
