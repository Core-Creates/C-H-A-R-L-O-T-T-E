# ******************************************************************************************
# models/policy_loader.py - YAML/JSON policy loader for action recommender
# ******************************************************************************************
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import yaml

from models.action_recommender import Stage, Severity  # reuse enums

@dataclass
class LoadedPolicy:
    actions: Dict[str, str]  # key -> display label
    base_matrix: Dict[Tuple[Stage, Severity], str]  # (stage,severity) -> resolved action text
    urgency_by_severity: Dict[Severity, str]
    followups_by_stage: Dict[Stage, List[str]]
    modifiers: dict
    fallbacks: dict
    version: int

def _enum_stage(s: str) -> Stage:
    try:
        return Stage(s.strip().lower())
    except Exception:
        return Stage.EXPLOIT_ATTEMPT  # fallback; also exposed via fallbacks

def _enum_sev(s: str) -> Severity:
    try:
        return Severity(s.strip().lower())
    except Exception:
        return Severity.MEDIUM

def _resolve_action_expr(expr: str, actions_map: Dict[str, str]) -> str:
    """
    Supports simple expressions like 'KILL_PROC + OPEN_TICKET_HIGH'.
    Tokens that match keys in actions_map are replaced with their display labels.
    Other text is preserved.
    """
    parts = [p.strip() for p in expr.split("+")]
    resolved = []
    for p in parts:
        key = p.replace(" ", "_").upper()  # be forgiving with spacing
        resolved.append(actions_map.get(key, p))
    return " + ".join(resolved)

def load_policy(path: str | Path) -> LoadedPolicy:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    version = int(raw.get("version", 1))
    actions_map: Dict[str, str] = {k.upper(): str(v) for k, v in raw.get("actions", {}).items()}

    # Base matrix
    base_matrix: Dict[Tuple[Stage, Severity], str] = {}
    for row in raw.get("base_matrix", []):
        stg = _enum_stage(row["stage"])
        sev = _enum_sev(row["severity"])
        action_expr = str(row["action"])
        base_matrix[(stg, sev)] = _resolve_action_expr(action_expr, actions_map)

    # Urgency map
    urgency_by_sev = { _enum_sev(k): v for k, v in raw.get("urgency_by_severity", {}).items() }

    # Follow-ups
    followups_by_stage = { _enum_stage(k): list(v or []) for k, v in raw.get("followups_by_stage", {}).items() }

    modifiers = raw.get("modifiers", {})
    fallbacks = raw.get("fallbacks", {})

    return LoadedPolicy(
        actions=actions_map,
        base_matrix=base_matrix,
        urgency_by_severity=urgency_by_sev,
        followups_by_stage=followups_by_stage,
        modifiers=modifiers,
        fallbacks=fallbacks,
        version=version,
    )
# ******************************************************************************************
# End of File
# ******************************************************************************************