# ******************************************************************************************
# agents/triage_agent.py
# Handles triage of vulnerabilities using rule-based scoring and classification.
# Supports optional Markdown, PDF, and HTML report generation.
# Depends on core/logic_modules/triage_rules.py and report_utils.py
# ******************************************************************************************

import os
import sys
import json
import csv
from typing import Any
from collections.abc import Iterable

# Optional CLI interactivity; fall back to non-interactive if not present/TTY
try:
    from InquirerPy import inquirer  # type: ignore

    _HAS_INQUIRER = True
except Exception:
    _HAS_INQUIRER = False

# Add project root to sys.path for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.logic_modules.triage_rules import triage  # type: ignore
from core.logic_modules.exploit_predictor import predict_exploitability  # type: ignore
from core.logic_modules.report_utils import (  # type: ignore
    generate_markdown_report,
    generate_pdf_report,
    generate_html_report,
)
from core.report_dispatcher import dispatch_report, resend_queued_reports  # type: ignore
from core.cve_data_loader import load_cve_data  # type: ignore

# ServiceNow integration
from plugins.servicenow.servicenow_client import maybe_create_tickets  # type: ignore

# Action recommender (optional, used for dataset rows)
try:
    from models.action_recommender import (
        recommend_decision,
        Context as RecoContext,
    )  # type: ignore

    _HAS_RECO = True
except Exception:
    _HAS_RECO = False

# Path helper (robust import)
try:
    from utils.paths import display_path  # preferred location
except Exception:
    try:
        from paths import display_path  # fallback if you keep paths.py at repo root
    except Exception:

        def display_path(path: str, base: str | None = None) -> str:
            return str(path).replace("\\", "/")


SERVICENOW_CONFIG_PATH = "data/servicenow_config.json"


# ==========================================================================================
# INPUT LOADERS
# ==========================================================================================
def _load_json_file(file_path: str) -> list[dict[str, Any]]:
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        # allow {"findings":[...]} wrapper
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise ValueError(
            "Input JSON must be a list of records or an object with 'findings' list."
        )
    return data


def _load_jsonl_file(file_path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _load_csv_file(file_path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k: v for k, v in r.items()})
    return rows


def load_findings(file_path: str) -> list[dict[str, Any]]:
    """
    Load vulnerability scan data OR alert dataset records from a file.
    - .json → legacy findings format
    - .jsonl → CHARLOTTE triage dataset rows
    - .csv → CHARLOTTE triage dataset rows
    """
    if not os.path.exists(file_path):
        print(f"[!] Scan file not found: {file_path}")
        return []

    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext == ".json":
            return _load_json_file(file_path)
        elif ext in (".jsonl", ".ndjson"):
            return _load_jsonl_file(file_path)
        elif ext == ".csv":
            return _load_csv_file(file_path)
        else:
            print(f"[!] Unsupported file type: {ext}")
            return []
    except Exception as e:
        print(f"[!] Failed to read {file_path}: {e}")
        return []


# ==========================================================================================
# DETECT DATASET SHAPE
# ==========================================================================================
def _is_charlotte_dataset(rows: Iterable[dict[str, Any]]) -> bool:
    probe = next(iter(rows), None)
    if not probe:
        return False
    required = {"alert_id", "timestamp", "label", "category", "mitre_technique_id"}
    return required.issubset(set(map(str.lower, probe.keys()))) or required.issubset(
        probe.keys()
    )


# ==========================================================================================
# TRIAGE FLOW FOR LEGACY FINDINGS (UNCHANGED BEHAVIOR)
# ==========================================================================================
def _triage_findings_legacy(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    print("[*] Enriching findings with CVE metadata...")
    cve_map = load_cve_data()  # Load once for performance
    enriched: list[dict[str, Any]] = []
    for vuln in findings:
        result = triage(vuln)
        vuln.update(result)
        prediction = predict_exploitability(vuln)
        vuln.update(prediction)

        # CVE enrichment block
        cve_id = vuln.get("id")
        cve_info = cve_map.get(cve_id) if cve_id else None
        if cve_info:
            vuln["cve_description"] = cve_info.get(
                "description", "No description available."
            )
            vuln["tags"] = cve_info.get("tags", [])
            vuln["source_dataset"] = "Bouquets/Cybersecurity-LLM-CVE"
        else:
            vuln["cve_description"] = "No CVE enrichment found."
            vuln["tags"] = []

        # Auto-tagging
        desc = str(vuln.get("cve_description", "")).lower()
        emoji_tags = []
        if "wormable" in desc:
            emoji_tags.append("🚨 wormable")
        if "remote code execution" in desc or "rce" in desc:
            emoji_tags.append("🔥 critical RCE")
        if "buffer overflow" in desc:
            emoji_tags.append("🧠 buffer overflow")
        if "privilege escalation" in desc:
            emoji_tags.append("🔐 privilege escalation")
        vuln["emoji_tags"] = emoji_tags

        enriched.append(vuln)
    return enriched


# ==========================================================================================
# NEW: TRIAGE FLOW FOR CHARLOTTE TRIAGE DATASET (CSV/JSONL)
# ==========================================================================================
def _map_severity_1to5(x: Any) -> str:
    try:
        v = int(float(x))
    except Exception:
        return "medium"
    return {1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(v, "medium")


def _map_stage_from_category(cat: str) -> str:
    cat = (cat or "").strip().lower()
    if "exfil" in cat or "exfiltration" in cat:
        return "data_exfil"
    if "persistence" in cat:
        return "persistence"
    if "lateral" in cat:
        return "lateral_movement"
    if (
        "initial access" in cat
        or "execution" in cat
        or "command and control" in cat
        or "c2" in cat
    ):
        return "exploit_attempt"
    if "impact" in cat:
        return (
            "persistence"  # treat impact as requiring containment; policy can override
        )
    return "exploit_attempt"


def _row_is_remote(row: dict[str, Any]) -> bool:
    # Consider external geography or non-RFC1918 src as remote
    src = str(row.get("src_ip", ""))
    geo = str(row.get("src_geo", "")).upper()
    if geo and geo not in (
        "US",
        "CA",
        "DE",
        "FR",
        "GB",
        "NL",
        "PL",
        "JP",
        "KR",
        "BR",
        "IN",
        "AU",
        "LOCAL",
        "INTERNAL",
    ):
        return True
    # simple RFC1918 check
    return not (
        src.startswith("10.")
        or src.startswith("192.168.")
        or src.startswith("172.16.")
        or src.startswith("172.17.")
        or src.startswith("172.18.")
        or src.startswith("172.19.")
        or src.startswith("172.2")
    )


def _triage_findings_dataset(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not _HAS_RECO:
        print(
            "[!] models.action_recommender not available; proceeding without action recommendations."
        )
    enriched: list[dict[str, Any]] = []
    for r in rows:
        rec = dict(r)  # copy
        # Ensure recommended_action exists or compute via recommender
        if not rec.get("recommended_action") and _HAS_RECO:
            stage = _map_stage_from_category(rec.get("category", ""))
            sev = _map_severity_1to5(rec.get("severity", 3))
            ctx = RecoContext(
                is_remote=_row_is_remote(rec),
                asset_criticality="crown_jewel"
                if str(rec.get("asset_type", "")).lower() in ("server", "cloud-vm")
                and int(rec.get("severity", 3)) >= 4
                else "normal",
                data_classification="regulated"
                if "dlp" in str(rec.get("rule_name", "")).lower()
                else "internal",
                detection_confidence=float(rec.get("confidence", 0.8) or 0.8),
                repeat_attempts=0,
                has_mfa_bypass_indicators="mfa"
                in str(rec.get("description", "")).lower(),
                has_dlp_hit="dlp" in str(rec.get("description", "")).lower(),
                environment="prod",
                target_id=str(rec.get("asset_id", "")) or str(rec.get("dest_ip", "")),
                notes=str(rec.get("description", "")),
            )
            dec = recommend_decision(stage, sev, is_remote=ctx.is_remote, context=ctx)
            rec["recommended_action"] = dec.action
            rec["urgency"] = dec.urgency
            rec["decision_rationale"] = " | ".join(dec.rationale)
            rec["decision_notify"] = ",".join(dec.notify)
        enriched.append(rec)
    return enriched


# ==========================================================================================
# PUBLIC: TRIAGE DISPATCHERS
# ==========================================================================================
def triage_findings(records: list[dict[str, Any]]):
    """
    Unified entry that detects input shape and runs the appropriate enrichment flow.
    """
    if not records:
        return []
    if _is_charlotte_dataset(records):
        return _triage_findings_dataset(records)
    return _triage_findings_legacy(records)


def display_summary(findings: list[dict[str, Any]], limit: int = 10):
    # Sort by available score/evidence/severity
    def _key(f: dict[str, Any]):
        return (
            float(f.get("score", 0)),
            float(f.get("evidence_score", 0)),
            float(f.get("severity", 0)),
        )

    sorted_findings = sorted(findings, key=_key, reverse=True)
    print(f"\n===== 🧠 TRIAGE RESULTS (Top {limit}) =====")
    for vuln in sorted_findings[:limit]:
        vid = vuln.get("id") or vuln.get("alert_id") or "N/A"
        sev = vuln.get("severity")
        pri = vuln.get("priority", vuln.get("urgency", "N/A"))
        score = vuln.get("score", vuln.get("evidence_score", "N/A"))
        print(f"- {vid}: {pri} | Sev: {sev} | Score: {score}")
        if vuln.get("cwe"):
            print(f"  CWE: {vuln.get('cwe')} | Impact: {vuln.get('impact','N/A')}")
        if vuln.get("cve_description"):
            print(f"  Desc: {str(vuln['cve_description'])[:100]}...")
        if vuln.get("tags"):
            print(f"  Tags: {', '.join(vuln['tags'])}")
        if vuln.get("emoji_tags"):
            print(f"  🚩 {', '.join(vuln['emoji_tags'])}")
        if vuln.get("recommended_action"):
            print(
                f"  ▶ Action: {vuln['recommended_action']} ({vuln.get('urgency','')})"
            )
        print()


def save_results(findings, output_file="data/triaged_findings.json"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
    print(f"[+] Triaged results saved to {output_file}")


def _select_format_interactive() -> str | None:
    if not _HAS_INQUIRER or not sys.stdout.isatty():
        return None
    return inquirer.select(
        message="Select report output format:",
        choices=[
            "📄 Markdown (.md)",
            "🧾 PDF (.pdf)",
            "🌐 HTML (.html)",
            "♻️ Resend Queued Reports",
            "❌ Skip report",
        ],
    ).execute()


def run_triage_agent(
    scan_file="data/findings.json", dispatch=True, non_interactive: bool = False
):
    print(f"[*] Loading scan findings from: {scan_file}")
    findings = load_findings(scan_file)

    if not findings:
        print("[!] No findings to triage. Exiting.")
        return

    print("[*] Running triage logic...")
    enriched_findings = triage_findings(findings)

    display_summary(enriched_findings)
    save_results(enriched_findings)

    # Report selection (interactive if available; otherwise default to Markdown)
    fmt_choice = None if non_interactive is False else "📄 Markdown (.md)"
    if fmt_choice is None:
        fmt_choice = _select_format_interactive() or "📄 Markdown (.md)"

    if fmt_choice.startswith("♻️"):
        resend_queued_reports()
        return
    if fmt_choice.startswith("❌"):
        print("[*] Skipped report generation.")
        return

    report_file = None
    if fmt_choice.startswith("📄"):
        report_file = generate_markdown_report(
            enriched_findings,
            include_fields=[
                "cve_description",
                "tags",
                "emoji_tags",
                "recommended_action",
                "urgency",
            ],
        )
    elif fmt_choice.startswith("🧾"):
        report_file = generate_pdf_report(
            enriched_findings,
            include_fields=[
                "cve_description",
                "tags",
                "emoji_tags",
                "recommended_action",
                "urgency",
            ],
        )
    elif fmt_choice.startswith("🌐"):
        report_file = generate_html_report(
            enriched_findings,
            include_fields=[
                "cve_description",
                "tags",
                "emoji_tags",
                "recommended_action",
                "urgency",
            ],
        )

    if dispatch and report_file:
        dispatch_report(report_file)

    # Auto-ticket only for non-dataset legacy flow or when malicious/suspicious present
    if _HAS_INQUIRER and sys.stdout.isatty():
        auto_ticket = inquirer.confirm(
            message="Auto-create ServiceNow tickets for critical findings?",
            default=True,
        ).execute()
        if auto_ticket:
            maybe_create_tickets(enriched_findings)


if __name__ == "__main__":
    # Allow: python triage_agent.py /path/to/file.csv --non-interactive
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("scan_file", nargs="?", default="data/findings.json")
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip prompts; default to Markdown output.",
    )
    p.add_argument(
        "--no-dispatch",
        action="store_true",
        help="Do not dispatch report after generation.",
    )
    args = p.parse_args()
    run_triage_agent(
        args.scan_file,
        dispatch=not args.no_dispatch,
        non_interactive=args.non_interactive,
    )
