# ======================================================================
# models/__init__.py
# CHARLOTTE core models: convenient package exports
# ======================================================================

# Recommender (policy-driven)
from .action_recommender import (  # noqa: F401
    Stage,
    Severity,
    Context,
    Decision,
    recommend_action,
    recommend_decision,
    batch_recommend_actions,
    decision_as_dict,
    record_execution,
)

# Policy loader
from .policy_loader import (  # noqa: F401
    load_policy,
    LoadedPolicy,
)

# CVE severity model
from .cve_severity_predictor import (  # noqa: F401
    CVESeverityNet,
    load_model as load_severity_model,
    load_scaler as load_severity_scaler,
    predict_severity,
    predict_batch as predict_severity_batch,
)

# (Experimental) exploit report generator
from .exploit_report_generator import (  # noqa: F401
    ExploitReportGenerator,
)

__all__ = [
    # Recommender
    "Stage", "Severity", "Context", "Decision",
    "recommend_action", "recommend_decision", "batch_recommend_actions",
    "decision_as_dict", "record_execution",
    # Policy loader
    "load_policy", "LoadedPolicy",
    # CVE severity model
    "CVESeverityNet", "load_severity_model", "load_severity_scaler",
    "predict_severity", "predict_severity_batch",
    # Exploit report generator
    "ExploitReportGenerator",
]

__version__ = "0.1.0"
__author__ = "Corrina Alcoser"