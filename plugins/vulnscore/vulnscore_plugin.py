
# ******************************************************************************************
# plugins/vulnscore/vulnscore_plugin.py
# Combines exploitability + severity prediction into a unified vulnerability score
# ******************************************************************************************

from core.logic_modules.exploit_predictor import predict_exploitability
from models.cve_severity_predictor import predict_severity

def run_vulnscore_plugin(cve_data):
    """
    Args:
        cve_data (dict): Dictionary with keys:
            - cvss_base
            - cvss_impact
            - exploitability_score
            - is_remote
            - cwe_id
    Returns:
        dict: Combined result with severity + exploitability
    """
    features = [
        cve_data.get("cvss_base", 0.0),
        cve_data.get("cvss_impact", 0.0),
        cve_data.get("exploitability_score", 0.0),
        int(cve_data.get("is_remote", 0)),
        int(cve_data.get("cwe_id", 0))
    ]

    severity = predict_severity(features)
    exploitability = predict_exploitability(cve_data)

    return {
        "severity_prediction": severity,
        "exploitability_prediction": exploitability,
        "recommended_action": "Generate PoC" if severity in ["High", "Critical"] and exploitability else "Triage Only"
    }

# Example standalone usage
if __name__ == "__main__":
    sample_cve = {
        "cvss_base": 8.8,
        "cvss_impact": 6.4,
        "exploitability_score": 2.2,
        "is_remote": 1,
        "cwe_id": 89
    }
    result = run_vulnscore_plugin(sample_cve)
    print("📊 Vulnerability Score Summary:")
    for key, val in result.items():
        print(f"{key}: {val}")
