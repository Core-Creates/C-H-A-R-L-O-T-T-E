# ******************************************************************************************
# models/action_recommender.py
# Context-aware, auditable recommender with rule-matrix + ML blending (policy-driven)
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
# Hardcoded baseline (used only when no policy is provided)
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
# Policy support (optional)
# ──────────────────────────────────────────────────────────────────────────────
try:
    # These imports are optional; only used when policy is supplied
    from models.policy_loader import load_policy, LoadedPolicy
except Exception:  # pragma: no cover
    load_policy = None
    LoadedPolicy = None  # type: ignore

def _ensure_policy(policy_path: Optional[str], policy_obj: Optional["LoadedPolicy"]) -> Optional["LoadedPolicy"]:
    if policy_obj is not None:
        return policy_obj
    if policy_path and load_policy:
        return load_policy(policy_path)
    return None

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
    policy_path: Optional[str] = None,                 # NEW (1): path to YAML/JSON policy
    policy: Optional["LoadedPolicy"] = None,           # NEW (2): preloaded policy object
) -> str:
    """
    Backward-compatible single-string action for quick uses.
    Prefer `recommend_decision` if you want rationale & metadata.
    """
    dec = recommend_decision(
        stage,
        severity,
        is_remote=is_remote,
        context=context,
        stage_probs=stage_probs,
        severity_probs=severity_probs,
        policy_path=policy_path,
        policy=policy,
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
    policy_path: Optional[str] = None,                 # NEW (1)
    policy: Optional["LoadedPolicy"] = None,           # NEW (2)
) -> Decision:
    """
    Rich decision including urgency, rationale, notify targets, and follow-ups.
    Uses policy-driven tables when `policy` or `policy_path` is provided; otherwise
    falls back to built-in defaults.
    """
    # Normalize inputs
    stg = _to_stage(stage)
    sev = _to_severity(severity)
    ctx = context or Context(is_remote=is_remote)
    ctx.is_remote = is_remote if context is None else ctx.is_remote

    # Resolve policy (if any)
    pol = _ensure_policy(policy_path, policy)

    # ML blending (optional)
    ml_notes: List[str] = []
    stg, sev, ctx, ml_notes = _blend_with_ml(stg, sev, ctx, stage_probs, severity_probs)

    # Low-confidence safeguard (policy-aware)
    if ctx.detection_confidence < 0.4:
        low_conf_action = (
            (pol.actions.get(pol.fallbacks.get("low_confidence_action", "OPEN_TICKET"), OPEN_TICKET))
            if pol else OPEN_TICKET
        )
        low_conf_urgency = pol.fallbacks.get("low_confidence_urgency", "P3") if pol else "P3"
        return Decision(
            action=low_conf_action,
            urgency=low_conf_urgency,
            rationale=["Low detection confidence (<0.4)"] + ml_notes,
            notify=["SOC"],
            followups=["Collect additional telemetry", "Run targeted hunt query"],
        )

    # Base action (policy-driven first, otherwise hardcoded)
    if pol:
        action = pol.base_matrix.get((stg, sev))
    else:
        action = BASE_POLICY.get((stg, sev))

    rationale = [f"Base policy match: stage={stg.value}, severity={sev.value}"]
    notify = ["SOC"]
    followups: List[str] = []

    if action is None:
        # Fallback defaults (policy-aware)
        if stg == Stage.BENIGN:
            action = NO_ACTION
        else:
            action = (pol.actions.get("OPEN_TICKET", OPEN_TICKET) if pol else OPEN_TICKET)
        rationale.append("No explicit matrix entry → fallback")

    # Urgency mapping (policy-driven if available)
    if pol:
        urgency = pol.urgency_by_severity.get(sev, "P3")
    else:
        urgency = {
            Severity.CRITICAL: "P1",
            Severity.HIGH: "P2",
            Severity.MEDIUM: "P3",
            Severity.LOW: "P4",
        }[sev]

    # Follow-ups (policy-driven if available)
    if pol and stg in pol.followups_by_stage:
        followups.extend(pol.followups_by_stage[stg])
    else:
        if stg == Stage.EXPLOIT_ATTEMPT:
            followups += ["Acquire process dump & indicators", "Block offending IOC", "Confirm patch level"]
        elif stg == Stage.PERSISTENCE:
            followups += ["List autoruns & scheduled tasks", "Baseline diffs for startup items", "EDR scan sweep"]
        elif stg == Stage.DATA_EXFIL:
            followups += ["Quantify data scope", "Revoke tokens/keys", "Rotate credentials", "Legal/GRC review"]

    decision = Decision(action=action, urgency=urgency, rationale=rationale + ml_notes, notify=notify, followups=followups)

    # Apply modifiers:
    # - If a policy is supplied and you also want policy-tuned modifiers, you can either:
    #   (A) handle them in this function using `pol.modifiers` (as in the prior example), or
    #   (B) keep using your existing code-path below for now.
    #   Here we keep your original modifiers for simplicity & stability.
    decision = _apply_modifiers(stg, sev, ctx, decision)

    return decision

def batch_recommend_actions(
    stages: List[str],
    severities: List[str],
    is_remote_flags: Optional[List[bool]] = None,
    *,
    contexts: Optional[List[Context]] = None,
    policy_path: Optional[str] = None,                 # NEW (1)
    policy: Optional["LoadedPolicy"] = None,           # NEW (2)
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
        results.append(
            recommend_action(
                stg, sev, rem, context=ctx, policy_path=policy_path, policy=policy
            )
        )
    return results
