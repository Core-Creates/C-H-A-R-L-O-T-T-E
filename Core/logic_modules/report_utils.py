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
# FUNCTION: generate_html_report()
# Renders triage results as a basic HTML report with exploit and severity highlighting
# ==========================================================================================
def generate_html_report(findings, output_file="reports/triage_report.html", include_fields=None):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    sorted_findings = sorted(findings, key=lambda f: f["score"], reverse=True)

    html = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>CHARLOTTE Triage Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; background-color: #121212; color: #eee; padding: 20px; }",
        "h1 { color: #b45cff; } h2 { color: #ffffff; }",
        ".critical { color: red; font-weight: bold; }",
        ".section { margin-bottom: 2em; border-bottom: 1px solid #333; padding-bottom: 1em; }",
        "</style></head><body>",
        "<h1>🧠 CHARLOTTE Vulnerability Triage Report</h1>",
    ]

    html.append("<h2>📊 Summary by Severity</h2><ul>")
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in sorted_findings:
        sev = f.get("severity", "Unknown")
        if sev in severity_counts:
            severity_counts[sev] += 1
    for sev, count in severity_counts.items():
        html.append(f"<li>{sev}: {count}</li>")
    html.append("</ul>")

    html.append("<h2>🔥 Critical Exploitable Vulnerabilities</h2><ul>")
    for vuln in sorted_findings:
        if vuln.get("severity") == "Critical" and vuln.get("exploit_prediction") == "Exploit Likely":
            cve = vuln.get("id", "Unknown")
            link = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else "#"
            html.append(f"<li><a href='{link}'>{cve}</a> – {vuln.get('impact')} | Score: {vuln.get('score')} | {vuln.get('confidence')}</li>")
    html.append("</ul>")

    for vuln in sorted_findings:
        cve = vuln.get("id", "Unknown")
        html.append(f"<div class='section'><h2>{cve}</h2>")
        html.append(f"<p><strong>Severity:</strong> <span class='{ 'critical' if vuln.get('severity') == 'Critical' else '' }'>{vuln.get('severity')}</span></p>")
        html.append(f"<p><strong>Priority:</strong> {vuln.get('priority')}</p>")
        html.append(f"<p><strong>Score:</strong> {vuln.get('score')}</p>")
        html.append(f"<p><strong>Impact:</strong> {vuln.get('impact')}</p>")
        html.append(f"<p><strong>CWE:</strong> {vuln.get('cwe')}</p>")
        html.append(f"<p><strong>Exploitability:</strong> {vuln.get('exploit_prediction')} ({vuln.get('confidence')})</p>")
        if include_fields:
            if "cve_description" in include_fields and vuln.get("cve_description"):
                html.append(f"<p><strong>Description:</strong> {vuln['cve_description']}</p>")
            if "tags" in include_fields and vuln.get("tags"):
                html.append(f"<p><strong>Tags:</strong> {', '.join(vuln['tags'])}</p>")
            if "emoji_tags" in include_fields and vuln.get("emoji_tags"):
                html.append(f"<p><strong>🚩 Auto Tags:</strong> {', '.join(vuln['emoji_tags'])}</p>")
        html.append("</div>")

    html.append("</body></html>")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print(f"[+] HTML report saved to {output_file}")
    return output_file

# ==========================================================================================
# FUNCTION: generate_markdown_report()
# Generates a Markdown report from vulnerability data
# ==========================================================================================
def generate_markdown_report(findings, output_file="reports/triage_report.md", include_fields=None):
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
        if include_fields:
            if "cve_description" in include_fields and vuln.get("cve_description"):
                lines.append(f"- **Description**: {vuln['cve_description']}")
            if "tags" in include_fields and vuln.get("tags"):
                lines.append(f"- **Tags**: {', '.join(vuln['tags'])}")
            if "emoji_tags" in include_fields and vuln.get("emoji_tags"):
                lines.append(f"- **🚩 Auto Tags**: {', '.join(vuln['emoji_tags'])}")
        lines.append("\n---\n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved to {output_file}")
    return output_file

# ==========================================================================================
# FUNCTION: generate_pdf_report()
# Generates a color-coded PDF vulnerability report
# ==========================================================================================
def generate_pdf_report(findings, output_file="reports/triage_report.pdf", include_fields=None):
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
        if include_fields:
            if "cve_description" in include_fields and vuln.get("cve_description"):
                text.textLine(f"  Description: {vuln['cve_description'][:200]}")
            if "tags" in include_fields and vuln.get("tags"):
                text.textLine(f"  Tags: {', '.join(vuln['tags'])}")
            if "emoji_tags" in include_fields and vuln.get("emoji_tags"):
                text.textLine(f"  🚩 Auto Tags: {', '.join(vuln['emoji_tags'])}")
        text.textLine("-" * 70)

    c.drawText(text)
    c.save()
    print(f"[+] PDF report saved to {output_file}")
    return output_file
# ==========================================================================================
# Standalone CLI usage for testing report generation