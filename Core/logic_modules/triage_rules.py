# ******************************************************************************************
# core/logic_modules/triage_rules.py
# Contains scoring heuristics and triage classification logic for vulnerabilities.
# Designed for use by agents/triage_agent.py or similar modules.
# ******************************************************************************************


def calculate_severity(cvss_score):
    """
    Categorize CVSS score into human-readable severity labels.
    
    ----------------------
    CVSS Threshold Mapping:
    ----------------------
    - 9.0 to 10.0  → "Critical"
    - 7.0 to 8.9   → "High"
    - 4.0 to 6.9   → "Medium"
    - Below 4.0    → "Low"
    """
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"


def score_vulnerability(vuln):
    """
    Compute a composite triage score for a given vulnerability.

    --------------------------------------------
    INPUT FORMAT (dict):
    --------------------------------------------
    - "cvss": float (0–10 scale)
    - "exploit_available": bool
    - "asset_value": int (1–5, importance of affected asset)
    - "impact": str (keywords like "RCE", "DoS", etc.)
    - "cwe": str (CWE category, used for special-case boosts)
    
    --------------------------------------------
    SCORING STRATEGY (weightings):
    --------------------------------------------
    - CVSS score × 10
    - +30 if exploit is available
    - +5 × asset_value
    - +25 for RCE/Priv Escalation, +10 for DoS
    - +20 if CWE matches high-risk types
    """

    score = 0

    # ------------------------------
    # Step 1: Base CVSS weighting
    # ------------------------------
    cvss = vuln.get("cvss", 0)
    score += cvss * 10  # e.g., CVSS 8.1 → +81 pts

    # ------------------------------
    # Step 2: Exploit availability
    # ------------------------------
    if vuln.get("exploit_available"):
        score += 30  # Extra risk if exploit exists in wild

    # ------------------------------
    # Step 3: Asset importance
    # ------------------------------
    score += vuln.get("asset_value", 1) * 5  # Prioritize valuable assets

    # ------------------------------
    # Step 4: Impact-based boosts
    # ------------------------------
    impact = vuln.get("impact", "").lower()
    if "rce" in impact or "privilege escalation" in impact:
        score += 25  # Critical access manipulation
    elif "dos" in impact:
        score += 10  # Service availability disruption

    # ------------------------------
    # Step 5: CWE-based risk factors
    # ------------------------------
    cwe = vuln.get("cwe", "").lower()
    if any(keyword in cwe for keyword in ["sql injection", "buffer overflow", "use-after-free"]):
        score += 20  # High-profile vulnerability classes

    return score


def classify_priority(score):
    """
    Convert final numeric score into an actionable priority label.

    -----------------------------
    Priority Buckets:
    -----------------------------
    - 90+   → 🔥 Urgent
    - 70–89 → 🚨 High
    - 40–69 → ⚠️ Medium
    - <40   → 🧊 Low
    """
    if score >= 90:
        return "🔥 Urgent"
    elif score >= 70:
        return "🚨 High"
    elif score >= 40:
        return "⚠️ Medium"
    else:
        return "🧊 Low"


def triage(vuln):
    """
    Full triage pipeline:
    Runs CVSS classification, scoring, and priority labeling.

    -----------------------------
    OUTPUT FORMAT (dict):
    -----------------------------
    {
        "severity": str  → e.g., "High"
        "score": int     → e.g., 82
        "priority": str  → e.g., "🚨 High"
    }
    """
    cvss_severity = calculate_severity(vuln.get("cvss", 0))
    score = score_vulnerability(vuln)
    priority = classify_priority(score)

    return {
        "severity": cvss_severity,
        "score": score,
        "priority": priority
    }
