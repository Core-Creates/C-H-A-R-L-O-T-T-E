# ======================================================================
# charlotte/models/__init__.py
# CHARLOTTE core models: convenient package exports (with lazy imports)
# ======================================================================

from __future__ import annotations
from typing import TYPE_CHECKING

# -- Eager, lightweight imports (fast, frequently used) ----------------
from .action_recommender import (  # noqa: F401
    Stage, Severity, Context, Decision,
    recommend_action, recommend_decision, batch_recommend_actions,
    decision_as_dict, record_execution,
)
from .policy_loader import (  # noqa: F401
    load_policy, LoadedPolicy,
)

# -- Optional / heavier modules are loaded lazily -----------------------
# Map attribute → (submodule, attribute)
_LAZY_EXPORTS = {
    # cve_severity_predictor (PyTorch etc.)
    "CVESeverityNet": ("charlotte.models.cve_severity_predictor", "CVESeverityNet"),
    "load_severity_model": ("charlotte.models.cve_severity_predictor", "load_model"),
    "load_severity_scaler": ("charlotte.models.cve_severity_predictor", "load_scaler"),
    "predict_severity": ("charlotte.models.cve_severity_predictor", "predict_severity"),
    "predict_severity_batch": ("charlotte.models.cve_severity_predictor", "predict_batch"),
    # exploit_report_generator (experimental)
    "ExploitReportGenerator": ("charlotte.models.exploit_report_generator", "ExploitReportGenerator"),
}

def __getattr__(name: str):
    """PEP 562: lazy attribute access so heavy deps aren’t imported unless used."""
    if name in _LAZY_EXPORTS:
        mod_name, attr = _LAZY_EXPORTS[name]
        import importlib
        mod = importlib.import_module(mod_name)
        val = getattr(mod, attr)
        globals()[name] = val  # cache for future lookups
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

if TYPE_CHECKING:
    # Help type checkers resolve lazy exports without importing at runtime
    from .cve_severity_predictor import (  # noqa: F401
        CVESeverityNet, load_model as load_severity_model,
        load_scaler as load_severity_scaler,
        predict_severity, predict_batch as predict_severity_batch,
    )
    from .exploit_report_generator import ExploitReportGenerator  # noqa: F401

# Public API
__all__ = [
    # Recommender
    "Stage", "Severity", "Context", "Decision",
    "recommend_action", "recommend_decision", "batch_recommend_actions",
    "decision_as_dict", "record_execution",
    # Policy loader
    "load_policy", "LoadedPolicy",
    # Lazy exports (resolved on first access)
    "CVESeverityNet", "load_severity_model", "load_severity_scaler",
    "predict_severity", "predict_severity_batch",
    "ExploitReportGenerator",
]

__version__ = "0.1.0"
__author__ = "Corrina Alcoser"
__license__ = "AGPL-3.0"
# ======================================================================