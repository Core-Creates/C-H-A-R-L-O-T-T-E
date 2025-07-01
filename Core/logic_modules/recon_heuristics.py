"""
recon_heuristics.py - CHARLOTTE's rule-based system for assessing recon data.
Used in offline or self-contained mode to triage hosts/services post-scan.

Author: CHARLOTTE (via human lackey)
"""

import re

# Heuristic service match rules
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "SMB",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy"
}

# Suspicious service banners / patterns
BANNER_PATTERNS = {
    "ftp": [r"vsftpd", r"ProFTPD", r"Anonymous login"],
    "ssh": [r"OpenSSH", r"Dropbear"],
    "http": [r"Apache", r"nginx", r"IIS", r"Tomcat"],
    "smb": [r"Windows", r"Samba"],
    "rdp": [r"Terminal Services", r"Remote Desktop"]
}

# Known bad versions
VULN_HINTS = {
    "vsftpd 2.3.4": "Possible backdoored FTP (CVE-2011-2523)",
    "Apache 2.4.49": "Path traversal (CVE-2021-41773)",
    "OpenSSH 7.2p2": "Privilege escalation known"
}


def score_port(port):
    """Assigns base score based on port value and typical use."""
    if port in [445, 139, 3389]:
        return 9  # High-value
    elif port in [21, 23, 25, 3306, 5900]:
        return 6
    elif port in [80, 443, 8080, 8000]:
        return 5
    return 3


def analyze_banner(port, banner):
    """Check banner string against regex patterns and known bad versions."""
    score = score_port(port)
    findings = []

    for service, patterns in BANNER_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                findings.append(f"{service.upper()} pattern matched: {pattern}")
                score += 2

    for vuln_str, vuln_note in VULN_HINTS.items():
        if vuln_str.lower() in banner.lower():
            findings.append(f"🚨 Vulnerable version detected: {vuln_note}")
            score += 5

    return score, findings


def triage_host(scan_results):
    """
    Analyze a single host's scan data.
    Input: scan_results = list of dicts with keys 'port', 'banner'
    Returns: dict with heuristic score and explanation
    """
    total_score = 0
    host_findings = []

    for service in scan_results:
        port = service.get("port")
        banner = service.get("banner", "")
        s, findings = analyze_banner(port, banner)
        total_score += s
        host_findings.extend([f"[Port {port}] {f}" for f in findings])

    rating = (
        "🔥 HIGH" if total_score > 20 else
        "⚠️  MEDIUM" if total_score > 10 else
        "✅ LOW"
    )

    return {
        "score": total_score,
        "rating": rating,
        "findings": host_findings
    }


# Example usage
if __name__ == "__main__":
    example_input = [
        {"port": 21, "banner": "220 (vsftpd 2.3.4)"},
        {"port": 80, "banner": "Server: Apache/2.4.49"},
        {"port": 22, "banner": "OpenSSH 7.2p2 Ubuntu"}
    ]

    result = triage_host(example_input)
    print(f"\nRecon Report:\nScore: {result['score']} ({result['rating']})")
    for finding in result['findings']:
        print(f" - {finding}")