# ******************************************************************************************
# models/action_recommender.py
# Context-aware, auditable recommender with rule-matrix + ML blending
# ******************************************************************************************
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Enums & constants
# ──────────────────────────────────────────────────────────────────────────────
class Stage(str, Enum):
    BENIGN = "benign"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    DATA_EXFIL = "data_exfil"
    PERSISTENCE = "persistence"
    LATERAL_MOVE = "lateral_movement"  # easy future extension

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Canonical action labels used across CHARLOTTE
ISOLATE = "Isolate Host"
KILL_PROC = "Kill Process"
BLOCK_IP_MONITOR = "Block IP and Monitor Process"
THROTTLE_ALERT = "Throttle Outbound Traffic + Alert SOC"
KILL_MONITOR_REGROWTH = "Kill Process and Monitor for Regrowth"
OPEN_TICKET = "Open SOC Ticket for Review"
OPEN_TICKET_HIGH = "Open Incident Ticket (High Priority)"
NO_ACTION = "No Action Required"

# ──────────────────────────────────────────────────────────────────────────────
# Core data structures
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Context:
    is_remote: bool = True
    asset_criticality: str = "normal"   # "normal" | "high" | "crown_jewel"
    data_classification: str = "internal"  # "public" | "internal" | "confidential" | "regulated"
    detection_confidence: float = 0.9   # 0..1 (model or heuristic)
    repeat_attempts: int = 0            # prior similar events in lookback
    has_mfa_bypass_indicators: bool = False
    has_dlp_hit: bool = False           # for exfil scenarios
    notes: Optional[str] = None         # freeform

@dataclass
class Decision:
    action: str
    urgency: str
    rationale: List[str]
    notify: List[str]
    followups: List[str]

# ──────────────────────────────────────────────────────────────────────────────
# Baseline policy matrix (stage × severity → default action)
# Keep this tiny & opinionated; modifiers add nuance.
# ──────────────────────────────────────────────────────────────────────────────
BASE_POLICY: Dict[Tuple[Stage, Severity], str] = {
    (Stage.DATA_EXFIL, Severity.HIGH): ISOLATE,
    (Stage.DATA_EXFIL, Severity.CRITICAL): ISOLATE,
    (Stage.EXPLOIT_ATTEMPT, Severity.HIGH): f"{KILL_PROC} and Open Incident Ticket",
    (Stage.EXPLOIT_ATTEMPT, Severity.CRITICAL): f"{KILL_PROC} and Open Incident Ticket",
    (Stage.PERSISTENCE, Severity.MEDIUM): KILL_MONITOR_REGROWTH,
    (Stage.PERSISTENCE, Severity.HIGH): KILL_MONITOR_REGROWTH,
    (Stage.EXPLOIT_ATTEMPT, Severity.MEDIUM): BLOCK_IP_MONITOR,
    (Stage.DATA_EXFIL, Severity.MEDIUM): THROTTLE_ALERT,
    (Stage.PERSISTENCE, Severity.LOW): "Log and Monitor Registry Key",
    (Stage.BENIGN, Severity.LOW): NO_ACTION,
}

# ──────────────────────────────────────────────────────────────────────────────
# Helper: normalize inputs safely
# ──────────────────────────────────────────────────────────────────────────────
def _to_stage(x: str) -> Stage:
    try:
        return Stage(x.lower().strip())
    except Exception:
        # Unknown stage → treat as exploit attempt but low confidence
        return Stage.EXPLOIT_ATTEMPT

def _to_severity(x: str) -> Severity:
    try:
        return Severity(x.lower().strip())
    except Exception:
        return Severity.MEDIUM

# ──────────────────────────────────────────────────────────────────────────────
# Modifiers: context-aware adjustments to the base decision
# Each modifier can append rationale and adjust action/urgency/notifications.
# ──────────────────────────────────────────────────────────────────────────────
def _apply_modifiers(
    stage: Stage, severity: Severity, ctx: Context, decision: Decision
) -> Decision:
    # 1) Asset criticality escalation
    if ctx.asset_criticality in ("high", "crown_jewel"):
        decision.rationale.append(f"Asset criticality={ctx.asset_criticality}")
        if stage in (Stage.DATA_EXFIL, Stage.PERSISTENCE) or severity in (Severity.HIGH, Severity.CRITICAL):
            decision.urgency = "P1"
            if decision.action not in (ISOLATE,):
                decision.action = f"{decision.action} → {ISOLATE}"
                decision.rationale.append("Escalated to isolation due to asset importance")
        decision.notify.extend(["IncidentResponse", "ServiceOwner"])

    # 2) Data classification & DLP hits
    if ctx.data_classification in ("confidential", "regulated") or ctx.has_dlp_hit:
        decision.rationale.append(
            f"Sensitive data (class={ctx.data_classification}, dlp_hit={ctx.has_dlp_hit})"
        )
        if stage == Stage.DATA_EXFIL and decision.action != ISOLATE:
            decision.action = ISOLATE
            decision.urgency = "P1"

    # 3) Remote origin makes containment stronger on execution attempts
    if ctx.is_remote and stage == Stage.EXPLOIT_ATTEMPT and severity != Severity.LOW:
        if KILL_PROC in decision.action or BLOCK_IP_MONITOR in decision.action:
            decision.rationale.append("Remote origin → block network egress/ingress")
            decision.action = f"{decision.action} + Temporary Network Quarantine"
            decision.notify.append("NetworkOps")

    # 4) Repeated attempts within lookback → increase urgency
    if ctx.repeat_attempts >= 3 and severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        decision.rationale.append(f"Repeat attempts={ctx.repeat_attempts}")
        if decision.urgency not in ("P1",):
            decision.urgency = "P2"
        decision.notify.append("ThreatHunting")

    # 5) MFA bypass indicators → immediate isolation if privilege-risky
    if ctx.has_mfa_bypass_indicators and stage in (Stage.PERSISTENCE, Stage.EXPLOIT_ATTEMPT):
        decision.rationale.append("MFA bypass indicators present")
        decision.action = ISOLATE
        decision.urgency = "P1"
        decision.notify.append("IdentitySec")

    # Deduplicate notify & followups
    decision.notify = sorted(set(decision.notify))
    decision.followups = sorted(set(decision.followups))
    return decision

# ──────────────────────────────────────────────────────────────────────────────
# ML blending: optional probability dicts to modulate severity/stage/confidence
# Pass in: stage_probs={'exploit_attempt':0.7,...}, severity_probs={'high':0.55,...}
# ──────────────────────────────────────────────────────────────────────────────
def _blend_with_ml(
    stage: Stage,
    severity: Severity,
    ctx: Context,
    stage_probs: Optional[Dict[str, float]],
    severity_probs: Optional[Dict[str, float]],
) -> Tuple[Stage, Severity, Context, List[str]]:
    notes: List[str] = []
    if stage_probs:
        best_stage = max(stage_probs.items(), key=lambda kv: kv[1])[0]
        best_conf = stage_probs.get(best_stage, 0.0)
        if best_conf >= 0.6:
            stage = _to_stage(best_stage)
            ctx.detection_confidence = max(ctx.detection_confidence, best_conf)
            notes.append(f"ML stage={stage.value} (p={best_conf:.2f})")
    if severity_probs:
        best_sev = max(severity_probs.items(), key=lambda kv: kv[1])[0]
        best_conf = severity_probs.get(best_sev, 0.0)
        if best_conf >= 0.6:
            severity = _to_severity(best_sev)
            ctx.detection_confidence = max(ctx.detection_confidence, best_conf)
            notes.append(f"ML severity={severity.value} (p={best_conf:.2f})")
    return stage, severity, ctx, notes

# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────
def recommend_action(
    stage: str,
    severity: str,
    is_remote: bool = True,
    *,
    context: Optional[Context] = None,
    stage_probs: Optional[Dict[str, float]] = None,
    severity_probs: Optional[Dict[str, float]] = None,
) -> str:
    """
    Backward-compatible single-string action for quick uses.
    Prefer `recommend_decision` if you want rationale & metadata.
    """
    dec = recommend_decision(
        stage, severity, is_remote=is_remote, context=context, stage_probs=stage_probs, severity_probs=severity_probs
    )
    return dec.action

def recommend_decision(
    stage: str,
    severity: str,
    *,
    is_remote: bool = True,
    context: Optional[Context] = None,
    stage_probs: Optional[Dict[str, float]] = None,
    severity_probs: Optional[Dict[str, float]] = None,
) -> Decision:
    """
    Rich decision including urgency, rationale, notify targets, and follow-ups.
    """
    stg = _to_stage(stage)
    sev = _to_severity(severity)
    ctx = context or Context(is_remote=is_remote)
    ctx.is_remote = is_remote if context is None else ctx.is_remote

    # Blend with ML (optional)
    ml_notes: List[str] = []
    stg, sev, ctx, ml_notes = _blend_with_ml(stg, sev, ctx, stage_probs, severity_probs)

    # Low-confidence safeguard
    if ctx.detection_confidence < 0.4:
        return Decision(
            action=OPEN_TICKET,
            urgency="P3",
            rationale=["Low detection confidence (<0.4)"] + ml_notes,
            notify=["SOC"],
            followups=["Collect additional telemetry", "Run targeted hunt query"],
        )

    # Base action
    action = BASE_POLICY.get((stg, sev))
    rationale = [f"Base policy match: stage={stg.value}, severity={sev.value}"]
    notify = ["SOC"]
    followups = []  # fill below

    if action is None:
        # Fallback defaults (keeps behavior similar to original)
        action = NO_ACTION if stg == Stage.BENIGN else OPEN_TICKET
        rationale.append("No explicit matrix entry → fallback")

    # Default urgency derived from severity
    urgency = {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
    }[sev]

    # Suggested follow-ups by stage
    if stg == Stage.EXPLOIT_ATTEMPT:
        followups += ["Acquire process dump & indicators", "Block offending IOC", "Confirm patch level"]
    elif stg == Stage.PERSISTENCE:
        followups += ["List autoruns & scheduled tasks", "Baseline diffs for startup items", "EDR scan sweep"]
    elif stg == Stage.DATA_EXFIL:
        followups += ["Quantify data scope", "Revoke tokens/keys", "Rotate credentials", "Legal/GRC review"]

    decision = Decision(action=action, urgency=urgency, rationale=rationale + ml_notes, notify=notify, followups=followups)
    decision = _apply_modifiers(stg, sev, ctx, decision)

    return decision

def batch_recommend_actions(
    stages: List[str],
    severities: List[str],
    is_remote_flags: Optional[List[bool]] = None,
    *,
    contexts: Optional[List[Context]] = None,
) -> List[str]:
    """
    Backward-compatible vectorized interface returning string actions.
    For richer outputs, map `recommend_decision` instead.
    """
    if is_remote_flags is None:
        is_remote_flags = [True] * len(stages)
    results: List[str] = []
    for i, (stg, sev, rem) in enumerate(zip(stages, severities, is_remote_flags)):
        ctx = (contexts[i] if contexts and i < len(contexts) else None)
        results.append(recommend_action(stg, sev, rem, context=ctx))
    return results
