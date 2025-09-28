# ******************************************************************************************
# core/logic_modules/report_utils.py
# Centralized utility for generating Markdown and PDF reports with formatting
# Shared across triage_agent and other modules in CHARLOTTE
# ******************************************************************************************

import os
import csv
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from typing import Any


# ==========================================================================================
# FUNCTION: generate_html_report()
# Renders triage results as a basic HTML report with exploit and severity highlighting
# ==========================================================================================
def generate_html_report(
    findings: list[dict[str, Any]], output_file: str = "reports/triage_report.html"
) -> str:
    # Ensure directory exists (handle no-dir case)
    dirpath = os.path.dirname(output_file) or "."
    os.makedirs(dirpath, exist_ok=True)

    # Defensive: ensure we have list-like findings
    sorted_findings = sorted(
        list(findings or []), key=lambda f: float(f.get("score", 0)), reverse=True
    )

    html = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>CHARLOTTE Triage Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; background-color: #121212; color: #eee; padding: 20px; }",
        "h1 { color: #b45cff; } h2 { color: #ffffff; }",
        ".critical { color: red; font-weight: bold; }",
        ".section { margin-bottom: 2em; border-bottom: 1px solid #333; padding-bottom: 1em; }",
        "a { color: #9ad1ff; }",
        "</style></head><body>",
        "<h1>🧠 CHARLOTTE Vulnerability Triage Report</h1>",
    ]

    # Summary by severity
    html.append("<h2>📊 Summary by Severity</h2><ul>")
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in sorted_findings:
        sev = f.get("severity", "Unknown")
        if sev in severity_counts:
            severity_counts[sev] += 1
    for sev, count in severity_counts.items():
        html.append(f"<li>{sev}: {count}</li>")
    html.append("</ul>")

    # Critical exploitable list
    html.append("<h2>🔥 Critical Exploitable Vulnerabilities</h2><ul>")
    for vuln in sorted_findings:
        if (
            vuln.get("severity") == "Critical"
            and vuln.get("exploit_prediction") == "Exploit Likely"
        ):
            cve = str(vuln.get("id", "Unknown"))
            link = (
                f"https://nvd.nist.gov/vuln/detail/{cve}"
                if cve.startswith("CVE-")
                else "#"
            )
            impact = vuln.get("impact", "N/A")
            score = vuln.get("score", "N/A")
            confidence = vuln.get("confidence", "N/A")
            html.append(
                f"<li><a href='{link}'>{cve}</a> – {impact} | Score: {score} | {confidence}</li>"
            )
    html.append("</ul>")

    # Details per vuln
    for vuln in sorted_findings:
        cve = str(vuln.get("id", "Unknown"))
        severity = vuln.get("severity", "Unknown")
        priority = vuln.get("priority", "N/A")
        score = vuln.get("score", "N/A")
        impact = vuln.get("impact", "N/A")
        cwe = vuln.get("cwe", "N/A")
        exploit_prediction = vuln.get("exploit_prediction", "Unknown")
        confidence = vuln.get("confidence", "N/A")

        sev_class = "critical" if severity == "Critical" else ""
        html.append(f"<div class='section'><h2>{cve}</h2>")
        html.append(
            f"<p><strong>Severity:</strong> <span class='{sev_class}'>{severity}</span></p>"
        )
        html.append(f"<p><strong>Priority:</strong> {priority}</p>")
        html.append(f"<p><strong>Score:</strong> {score}</p>")
        html.append(f"<p><strong>Impact:</strong> {impact}</p>")
        html.append(f"<p><strong>CWE:</strong> {cwe}</p>")
        html.append(
            f"<p><strong>Exploitability:</strong> {exploit_prediction} ({confidence})</p></div>"
        )

    html.append("</body></html>")

    # Write with explicit UTF-8 encoding
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(html))

    print(f"[+] HTML report saved to {output_file}")
    return output_file


# ******************************************************************************************


# ==========================================================================================
# FUNCTION: generate_markdown_report()
# Generates a Markdown report from vulnerability data
# ==========================================================================================
def generate_markdown_report(
    findings: list[dict[str, Any]], output_file: str = "reports/triage_report.md"
) -> str:
    dirpath = os.path.dirname(output_file) or "."
    os.makedirs(dirpath, exist_ok=True)

    sorted_findings = sorted(
        list(findings or []), key=lambda f: float(f.get("score", 0)), reverse=True
    )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in sorted_findings:
        severity = f.get("severity", "Unknown")
        if severity in severity_counts:
            severity_counts[severity] += 1

    lines = ["# 🧠 CHARLOTTE Vulnerability Triage Report\n"]
    lines.append("## 📊 Summary by Severity")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for level in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {level} | {severity_counts[level]} |")
    lines.append("\n---\n")

    lines.append("## 🔥 Critical Exploitable Vulnerabilities")
    for vuln in sorted_findings:
        if (
            vuln.get("severity") == "Critical"
            and vuln.get("exploit_prediction") == "Exploit Likely"
        ):
            cve_id = str(vuln.get("id", "Unknown ID"))
            if cve_id.startswith("CVE-"):
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                lines.append(
                    f"- [{cve_id}]({link}) → {vuln.get('impact', 'N/A')} | Score: {vuln.get('score', 'N/A')} | {vuln.get('confidence', 'N/A')}"
                )
            else:
                lines.append(
                    f"- {cve_id} → {vuln.get('impact', 'N/A')} | Score: {vuln.get('score', 'N/A')} | {vuln.get('confidence', 'N/A')}"
                )
    lines.append("\n---\n")

    for vuln in sorted_findings:
        cve_id = str(vuln.get("id", "Unknown ID"))
        if cve_id.startswith("CVE-"):
            cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            lines.append(f"## [{cve_id}]({cve_link})")
        else:
            lines.append(f"## {cve_id}")

        lines.append(f"- **Priority**: {vuln.get('priority', 'N/A')}")
        lines.append(f"- **Severity**: {vuln.get('severity', 'N/A')}")
        lines.append(f"- **Score**: {vuln.get('score', 'N/A')}")
        lines.append(f"- **CWE**: {vuln.get('cwe', 'N/A')}")
        lines.append(f"- **Impact**: {vuln.get('impact', 'N/A')}")
        lines.append(
            f"- **Exploitability**: {vuln.get('exploit_prediction', 'N/A')} ({vuln.get('confidence', 'N/A')})"
        )
        lines.append("\n---\n")

    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved to {output_file}")
    return output_file


# ==========================================================================================
# FUNCTION: generate_csv_report()
# Minimal CSV export of findings (UTF-8). Columns chosen for broad compatibility with tests.
# ==========================================================================================
def generate_csv_report(
    findings: list[dict[str, Any]], output_file: str = "reports/triage_report.csv"
) -> str:
    dirpath = os.path.dirname(output_file) or "."
    os.makedirs(dirpath, exist_ok=True)

    fieldnames = [
        "id",
        "title",
        "severity",
        "priority",
        "score",
        "component",
        "cwe",
        "impact",
        "exploitability",
        "confidence",
    ]

    with open(output_file, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in list(findings or []):
            writer.writerow(
                {
                    "id": f.get("id") or f.get("cve") or "",
                    "title": f.get("title") or "",
                    "severity": f.get("severity") or "",
                    "priority": f.get("priority") or "",
                    "score": f.get("score") or "",
                    "component": (
                        f.get("component", {}).get("name")
                        if isinstance(f.get("component"), dict)
                        else f.get("component", "")
                    ),
                    "cwe": f.get("cwe") or "",
                    "impact": f.get("impact") or "",
                    "exploitability": f.get("exploit_prediction") or "",
                    "confidence": f.get("confidence") or "",
                }
            )

    print(f"[+] CSV report saved to {output_file}")
    return output_file


# ==========================================================================================
# FUNCTION: generate_pdf_report()
# Generates a color-coded PDF vulnerability report
# ==========================================================================================
def generate_pdf_report(
    findings: list[dict[str, Any]], output_file: str = "reports/triage_report.pdf"
) -> str:
    dirpath = os.path.dirname(output_file) or "."
    os.makedirs(dirpath, exist_ok=True)

    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter
    text = c.beginText(40, height - 50)
    text.setFont("Helvetica-Bold", 14)
    text.textLine("🧠 CHARLOTTE Vulnerability Triage Report")
    text.setFont("Helvetica", 12)
    text.textLine("")

    sorted_findings = sorted(
        list(findings or []), key=lambda f: float(f.get("score", 0)), reverse=True
    )
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in sorted_findings:
        severity = f.get("severity", "Unknown")
        if severity in severity_counts:
            severity_counts[severity] += 1

    text.textLine("📊 Summary by Severity:")
    for level in ["Critical", "High", "Medium", "Low"]:
        text.textLine(f"  {level}: {severity_counts[level]}")
    text.textLine("-" * 70)

    for vuln in sorted_findings:
        severity = (vuln.get("severity") or "").lower()
        exploit_likely = vuln.get("exploit_prediction") == "Exploit Likely"
        is_critical = severity == "critical"

        if is_critical and exploit_likely:
            c.setFillColor(colors.red)
            text.setFont("Helvetica-Bold", 12)
        else:
            c.setFillColor(colors.black)
            text.setFont("Helvetica", 12)

        cve_id = str(vuln.get("id", "Unknown ID"))
        text.textLine(f"\nID: {cve_id}")
        if cve_id.startswith("CVE-"):
            text.textLine(f"Link: https://nvd.nist.gov/vuln/detail/{cve_id}")

        text.textLine(
            f"  Priority: {vuln.get('priority', 'N/A')} | Severity: {vuln.get('severity', 'N/A')} | Score: {vuln.get('score', 'N/A')}"
        )
        text.textLine(
            f"  CWE: {vuln.get('cwe', 'N/A')} | Impact: {vuln.get('impact', 'N/A')}"
        )
        text.textLine(
            f"  Exploitability: {vuln.get('exploit_prediction', 'N/A')} ({vuln.get('confidence', 'N/A')})"
        )
        text.textLine("-" * 70)

    c.drawText(text)
    c.save()
    print(f"[+] PDF report saved to {output_file}")
    return output_file


# ==========================================================================================
# Standalone CLI usage for testing report generation
