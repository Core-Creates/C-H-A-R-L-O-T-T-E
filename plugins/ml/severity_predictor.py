
# ******************************************************************************************
# plugins/ml/predict_severity.py
# Plugin interface for CHARLOTTE to use the CVESeverityNet model
# ******************************************************************************************

from models.cve_severity_predictor import predict_severity

def run(args):
    """
    Entry point for CHARLOTTE's plugin system.

    Args:
        args (dict): Must include keys:
            - cvss_base
            - cvss_impact
            - exploitability_score
            - is_remote
            - cwe_id

    Returns:
        str: Predicted severity label (Low, Medium, High, Critical)
    """
    features = [
        args.get("cvss_base", 0.0),
        args.get("cvss_impact", 0.0),
        args.get("exploitability_score", 0.0),
        int(args.get("is_remote", 0)),
        int(args.get("cwe_id", 0))
    ]

    severity = predict_severity(features)
    return f"[🧠 Severity Predictor] Predicted Severity: {severity}"

# Optional CLI
if __name__ == "__main__":
    sample = {
        "cvss_base": 7.8,
        "cvss_impact": 6.4,
        "exploitability_score": 2.2,
        "is_remote": 1,
        "cwe_id": 89
    }
    print(run(sample))
