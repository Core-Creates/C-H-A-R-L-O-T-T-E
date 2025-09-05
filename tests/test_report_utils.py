from core.logic_modules import report_utils

mock_findings = [
    {
        "id": "CVE-2023-0001",
        "score": 9.8,
        "severity": "Critical",
        "priority": "🚨 High",
        "impact": "RCE",
        "cwe": "CWE-120",
        "exploit_prediction": "Exploit Likely",
        "confidence": "High",
    },
    {
        "id": "CVE-2023-0002",
        "score": 5.0,
        "severity": "Medium",
        "priority": "⚠️ Medium",
        "impact": "Privilege Escalation",
        "cwe": "CWE-287",
        "exploit_prediction": "Exploit Unlikely",
        "confidence": "Low",
    },
]


def test_generate_markdown(tmp_path):
    out = tmp_path / "report.md"
    report_utils.generate_markdown_report(mock_findings, str(out))
    assert out.exists()
    content = out.read_text()
    assert "CVE-2023-0001" in content


def test_generate_pdf(tmp_path):
    out = tmp_path / "report.pdf"
    report_utils.generate_pdf_report(mock_findings, str(out))
    assert out.exists()
    assert out.stat().st_size > 0


def test_generate_html(tmp_path):
    out = tmp_path / "report.html"
    report_utils.generate_html_report(mock_findings, str(out))
    assert out.exists()
    content = out.read_text()
    assert "CHARLOTTE Vulnerability Triage Report" in content
    assert "CVE-2023-0001" in content


def test_generate_csv(tmp_path):
    out = tmp_path / "report.csv"
    report_utils.generate_csv_report(mock_findings, str(out))
    assert out.exists()
    content = out.read_text()
    assert "CVE-2023-0001" in content
    assert "CVE-2023-0002" in content
    assert "9.8" in content
    assert "5.0" in content
