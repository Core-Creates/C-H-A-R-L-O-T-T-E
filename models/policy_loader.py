# ======================================================================
# models/policy_loader.py
# Load policy (YAML/JSON) into a runtime object for the recommender
# ======================================================================
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


@dataclass
class LoadedPolicy:
    actions: Dict[str, str]
    base_matrix: Dict[Tuple["Stage", "Severity"], str]
    urgency_by_severity: Dict["Severity", str]
    followups_by_stage: Dict["Stage", List[str]]
    modifiers: Dict[str, Any]
    fallbacks: Dict[str, Any]
    cooldowns: List[Dict[str, Any]]
    approvals: Dict[str, Any]
    dry_run: Dict[str, Any]
    version: int = 1


# ----------------------------- helpers --------------------------------
def _norm_key(s: str) -> str:
    return str(s).strip().replace("-", "_").replace(" ", "_").upper()


def _resolve_action_expr(expr: str, actions: Dict[str, str]) -> str:
    """
    Resolve expressions like "KILL_PROC + OPEN_TICKET_HIGH" using actions map.
    Unknown tokens are passed through as-is.
    """
    parts = [p.strip() for p in str(expr).split("+")]
    labels = [actions.get(_norm_key(p), p) for p in parts if p]
    return " + ".join(labels)


# ------------------------------ loader --------------------------------
def load_policy(path: str | Path) -> LoadedPolicy:
    """
    Load a YAML/JSON policy file. Supports:
      base_matrix:
        exploit_attempt:
          high: "KILL_PROC + OPEN_TICKET_HIGH"
        data_exfil:
          critical: ISOLATE
    OR:
      base_matrix:
        - {stage: exploit_attempt, severity: high, action: "KILL_PROC + OPEN_TICKET_HIGH"}
        - {stage: data_exfil, severity: critical, action: ISOLATE}
    """
    from models.action_recommender import Stage, Severity  # local import to avoid circulars

    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    version = int(raw.get("version", 1))
    actions_map: Dict[str, str] = {
        _norm_key(k): str(v) for k, v in (raw.get("actions", {}) or {}).items()
    }

    # --- base_matrix ---
    base_matrix: Dict[Tuple[Stage, Severity], str] = {}
    bm = raw.get("base_matrix", {}) or {}

    def _to_stage(x: str) -> Stage:
        try:
            return Stage(str(x).lower().strip())
        except Exception:
            return Stage.EXPLOIT_ATTEMPT

    def _to_sev(x: str) -> Severity:
        try:
            return Severity(str(x).lower().strip())
        except Exception:
            return Severity.MEDIUM

    if isinstance(bm, dict):
        # dict-of-dicts shape
        for stg_key, sev_map in bm.items():
            stg = _to_stage(stg_key)
            if isinstance(sev_map, dict):
                for sev_key, action_expr in sev_map.items():
                    sev = _to_sev(sev_key)
                    base_matrix[(stg, sev)] = _resolve_action_expr(action_expr, actions_map)
    elif isinstance(bm, list):
        # list-of-rows shape
        for row in bm:
            if not isinstance(row, dict):
                continue
            stg = _to_stage(row.get("stage", "exploit_attempt"))
            sev = _to_sev(row.get("severity", "medium"))
            action_expr = row.get("action", "OPEN_TICKET")
            base_matrix[(stg, sev)] = _resolve_action_expr(action_expr, actions_map)

    # --- urgency_by_severity ---
    urgency_by_sev: Dict[Severity, str] = {}
    for k, v in (raw.get("urgency_by_severity", {}) or {}).items():
        sev = _to_sev(k)
        urgency_by_sev[sev] = str(v)

    # --- followups_by_stage ---
    followups_by_stage: Dict[Stage, List[str]] = {}
    for k, v in (raw.get("followups_by_stage", {}) or {}).items():
        stg = _to_stage(k)
        followups_by_stage[stg] = list(v or [])

    modifiers = dict(raw.get("modifiers", {}) or {})
    fallbacks = dict(raw.get("fallbacks", {}) or {})

    # NEW: cooldowns/approvals/dry_run (all optional)
    cooldowns = list(raw.get("cooldowns", []) or [])
    approvals = dict(raw.get("approvals", {}) or {})
    dry_run = dict(raw.get("dry_run", {}) or {})  # <-- fix: define this before returning

    return LoadedPolicy(
        actions=actions_map,
        base_matrix=base_matrix,
        urgency_by_severity=urgency_by_sev,
        followups_by_stage=followups_by_stage,
        modifiers=modifiers,
        fallbacks=fallbacks,
        cooldowns=cooldowns,
        approvals=approvals,
        dry_run=dry_run,
        version=version,
    )
# ======================================================================
# End of models/policy_loader.py
# ======================================================================