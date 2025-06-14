# ******************************************************************************************
# report_utils.py
# Centralized utility for generating Markdown and PDF reports with formatting
# Shared across triage_agent and other modules in CHARLOTTE
# ******************************************************************************************

import os
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

# ==========================================================================================
# FUNCTION: generate_markdown_report()
# Generates a Markdown report from vulnerability data
# ==========================================================================================
def generate_markdown_report(findings, output_file="reports/triage_report.md"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    sorted_findings = sorted(findings, key=lambda f: f["score"], reverse=True)

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
        if vuln.get("severity") == "Critical" and vuln.get("exploit_prediction") == "Exploit Likely":
            cve_id = vuln.get('id', 'Unknown ID')
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else None
            lines.append(f"- [{cve_id}]({link}) → {vuln['impact']} | Score: {vuln['score']} | {vuln['confidence']}")
    lines.append("\n---\n")

    for vuln in sorted_findings:
        cve_id = vuln.get('id', 'Unknown ID')
        cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else None
        lines.append(f"## [{cve_id}]({cve_link})" if cve_link else f"## {cve_id}")
        lines.append(f"- **Priority**: {vuln['priority']}")
        lines.append(f"- **Severity**: {vuln['severity']}")
        lines.append(f"- **Score**: {vuln['score']}")
        lines.append(f"- **CWE**: {vuln.get('cwe', 'N/A')}")
        lines.append(f"- **Impact**: {vuln.get('impact', 'N/A')}")
        lines.append(f"- **Exploitability**: {vuln.get('exploit_prediction')} ({vuln.get('confidence')})")
        lines.append("\n---\n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved to {output_file}")
    return output_file

# ==========================================================================================
# FUNCTION: generate_pdf_report()
# Generates a color-coded PDF vulnerability report
# ==========================================================================================
def generate_pdf_report(findings, output_file="reports/triage_report.pdf"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter
    text = c.beginText(40, height - 50)
    text.setFont("Helvetica-Bold", 14)
    text.textLine("🧠 CHARLOTTE Vulnerability Triage Report")
    text.setFont("Helvetica", 12)
    text.textLine("")

    sorted_findings = sorted(findings, key=lambda f: f["score"], reverse=True)
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
        severity = vuln.get("severity", "").lower()
        exploit_likely = vuln.get("exploit_prediction", "") == "Exploit Likely"
        is_critical = severity == "critical"

        if is_critical and exploit_likely:
            c.setFillColor(colors.red)
            text.setFont("Helvetica-Bold", 12)
        else:
            c.setFillColor(colors.black)
            text.setFont("Helvetica", 12)

        cve_id = vuln.get('id', 'Unknown ID')
        text.textLine(f"\nID: {cve_id}")
        if cve_id.startswith("CVE-"):
            text.textLine(f"Link: https://nvd.nist.gov/vuln/detail/{cve_id}")

        text.textLine(f"  Priority: {vuln.get('priority')} | Severity: {vuln.get('severity')} | Score: {vuln.get('score')}")
        text.textLine(f"  CWE: {vuln.get('cwe', 'N/A')} | Impact: {vuln.get('impact', 'N/A')}")
        text.textLine(f"  Exploitability: {vuln.get('exploit_prediction')} ({vuln.get('confidence')})")
        text.textLine("-" * 70)

    c.drawText(text)
    c.save()
    print(f"[+] PDF report saved to {output_file}")
    return output_file
# ==========================================================================================
# Standalone CLI usage for testing report generation