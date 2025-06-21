# ******************************************************************************************
# agents/triage_agent.py
# Handles triage of vulnerabilities using rule-based scoring and classification.
# Supports optional Markdown, PDF, and HTML report generation.
# Depends on core/logic_modules/triage_rules.py and report_utils.py
# ******************************************************************************************

import os
import json
from InquirerPy import inquirer
from core.logic_modules.triage_rules import triage
from core.logic_modules.exploit_predictor import predict_exploitability
from core.logic_modules.report_utils import (
    generate_markdown_report,
    generate_pdf_report,
    generate_html_report
)
from core.report_dispatcher import dispatch_report, resend_queued_reports
from core.cve_data_loader import load_cve_data  # Loads CVE dataset from Hugging Face

# ServiceNow integration
from plugins.servicenow.servicenow_client import create_incident, maybe_create_tickets
from plugins.servicenow.servicenow_setup import configure_servicenow

SERVICENOW_CONFIG_PATH = "data/servicenow_config.json"

# ==========================================================================================
# FUNCTION: load_findings()
# Loads vulnerability scan results from a local JSON file
# ==========================================================================================
def load_findings(file_path):
    """
    Load vulnerability scan data from a JSON file.

    --------------------------------------------
    Expected structure:
    --------------------------------------------
    [
        {
            "id": "CVE-2023-1234",
            "cvss": 8.1,
            "exploit_available": true,
            "asset_value": 4,
            "impact": "RCE",
            "cwe": "CWE-119: Buffer Overflow"
        },
        ...
    ]
    """
    if not os.path.exists(file_path):
        print(f"[!] Scan file not found: {file_path}")
        return []

    if not file_path.lower().endswith(".json"):
        print(f"[!] Invalid file type. Please provide a .json file.")
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to parse JSON: {e}")
        return []

# ==========================================================================================
# FUNCTION: triage_findings()
# Applies scoring logic to all findings using triage() from triage_rules.py
# Appends calculated 'severity', 'score', and 'priority' to each vuln entry
# Enriches findings with CVE description and tags from Hugging Face dataset
# ==========================================================================================
def triage_findings(findings):
    """
    Apply triage scoring, exploit prediction, and CVE enrichment.

    Enrichment adds:
    - cve_description: Text from the CVE dataset
    - tags: Any classification labels from the dataset
    - source_dataset: Indicates data origin
    - emoji_tags: Auto-tagged labels based on description keywords
    """
    print("[*] Enriching findings with CVE metadata...")
    cve_map = load_cve_data()  # Load once for performance

    enriched = []
    for vuln in findings:
        result = triage(vuln)
        vuln.update(result)

        prediction = predict_exploitability(vuln)
        vuln.update(prediction)

        # CVE enrichment block
        cve_id = vuln.get("id")
        cve_info = cve_map.get(cve_id)

        if cve_info:
            vuln["cve_description"] = cve_info.get("description", "No description available.")
            vuln["tags"] = cve_info.get("tags", [])
            vuln["source_dataset"] = "Bouquets/Cybersecurity-LLM-CVE"
        else:
            vuln["cve_description"] = "No CVE enrichment found."
            vuln["tags"] = []

        # Auto-tagging based on keywords
        desc = vuln["cve_description"].lower()
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
# FUNCTION: display_summary()
# CLI summary of top N triaged findings
# ==========================================================================================
def display_summary(findings, limit=10):
    sorted_findings = sorted(findings, key=lambda f: f["score"], reverse=True)
    print("\n===== 🧠 TRIAGE RESULTS (Top {0}) =====".format(limit))
    for vuln in sorted_findings[:limit]:
        print(f"- {vuln.get('id', 'N/A')}: {vuln['priority']} | {vuln['severity']} | Score: {vuln['score']}")
        print(f"  CWE: {vuln.get('cwe', 'N/A')} | Impact: {vuln.get('impact', 'N/A')} | Exploit: {vuln.get('exploit_prediction')} ({vuln.get('confidence')})")
        if vuln.get("cve_description"):
            print(f"  Desc: {vuln['cve_description'][:100]}...")
        if vuln.get("tags"):
            print(f"  Tags: {', '.join(vuln['tags'])}")
        if vuln.get("emoji_tags"):
            print(f"  🚩 {', '.join(vuln['emoji_tags'])}")
        print()

# ==========================================================================================
# FUNCTION: save_results()
# Writes enriched/triaged findings to an output file for downstream use
# ==========================================================================================
def save_results(findings, output_file="data/triaged_findings.json"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
    print(f"[+] Triaged results saved to {output_file}")

# ==========================================================================================
# FUNCTION: run_triage_agent()
# Full triage pipeline: Load -> Analyze -> Report -> Dispatch
# ==========================================================================================
def run_triage_agent(scan_file="data/findings.json", dispatch=True):
    print(f"[*] Loading scan findings from: {scan_file}")
    findings = load_findings(scan_file)

    if not findings:
        print("[!] No findings to triage. Exiting.")
        return

    print("[*] Running triage logic with exploit prediction...")
    enriched_findings = triage_findings(findings)

    display_summary(enriched_findings)
    save_results(enriched_findings)

    format_choice = inquirer.select(
        message="Select report output format:",
        choices=["📄 Markdown (.md)", "🧾 PDF (.pdf)", "🌐 HTML (.html)", "♻️ Resend Queued Reports", "❌ Skip report"]
    ).execute()

    report_file = None

    if format_choice.startswith("📄"):
        report_file = generate_markdown_report(enriched_findings, include_fields=["cve_description", "tags", "emoji_tags"])
    elif format_choice.startswith("🧾"):
        report_file = generate_pdf_report(enriched_findings, include_fields=["cve_description", "tags", "emoji_tags"])
    elif format_choice.startswith("🌐"):
        report_file = generate_html_report(enriched_findings, include_fields=["cve_description", "tags", "emoji_tags"])
    elif format_choice.startswith("♻️"):
        resend_queued_reports()
        return
    else:
        print("[*] Skipped report generation.")
        return

    if dispatch and report_file:
        dispatch_report(report_file)

    auto_ticket = inquirer.confirm(
        message="Auto-create ServiceNow tickets for critical findings?",
        default=True
    ).execute()

    if auto_ticket:
        maybe_create_tickets(enriched_findings)

# ==========================================================================================
# MAIN EXECUTION BLOCK
# ==========================================================================================
if __name__ == "__main__":
    run_triage_agent()

    # This block allows the script to be run directly from the command line.
    # It will execute the triage agent with the default scan file.
    # It can also be imported as a module in other scripts.
    # This modular design allows for easy integration into larger workflows.
    # This allows the script to be run directly for testing or standalone triage
    # purposes, without needing to go through the main CLI flow.

    # =================== CVE Lookup Example ====================
    # Useful for debugging or offline CVE validation
    cve_map = load_cve_data()
    finding = cve_map.get("CVE-2023-XXXX", None)
    if finding:
        print(f"Description: {finding['description']}")
