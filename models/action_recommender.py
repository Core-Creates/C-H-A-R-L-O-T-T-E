# ******************************************************************************************
# models/action_recommender.py
# Context-aware, auditable recommender with rule-matrix + ML blending (policy-driven)
# ******************************************************************************************
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple
import time

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
    environment: str = "prod"           # for approval gates (e.g., prod/stage/dev)
    target_id: Optional[str] = None     # entity for cooldown scope ("target")
    notes: Optional[str] = None         # freeform

@dataclass
class Decision:
    action: str
    urgency: str
    rationale: List[str]
    notify: List[str]
    followups: List[str]
    requires_approval: bool = False
    approval_reason: Optional[str] = None

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
# Helpers: normalization
# ──────────────────────────────────────────────────────────────────────────────
def _to_stage(x: str) -> Stage:
    try:
        return Stage(x.lower().strip())
    except Exception:
        return Stage.EXPLOIT_ATTEMPT

def _to_severity(x: str) -> Severity:
    try:
        return Severity(x.lower().strip())
    except Exception:
        return Severity.MEDIUM

# ──────────────────────────────────────────────────────────────────────────────
# Policy helpers (action resolution & policy-tunable modifiers)
# ──────────────────────────────────────────────────────────────────────────────

def _lc_set(values) -> Optional[set]:
    if not values:
        return None
    return {str(v).strip().lower() for v in values}

def _norm_key(s: str) -> str:
    return str(s).strip().replace("-", "_").replace(" ", "_").upper()

def _resolve_action_from_policy(pol, key_or_text: str) -> str:
    if not pol:
        return key_or_text
    if "+" in key_or_text:
        parts = [p.strip() for p in key_or_text.split("+")]
        return " + ".join(pol.actions.get(_norm_key(p), p) for p in parts)
    return pol.actions.get(_norm_key(key_or_text), key_or_text)

def _apply_modifiers_with_policy(
    stage: Stage, severity: Severity, ctx: Context, decision: Decision, pol
) -> Decision:
    mods = pol.modifiers if pol else {}

    # 1) Asset criticality escalation
    m = mods.get("asset_criticality_escalation", {})
    if m.get("enabled", False):
        levels = set(m.get("levels", []))
        if ctx.asset_criticality in levels:
            decision.rationale.append(f"Asset criticality={ctx.asset_criticality}")
            decision.urgency = "P1"
            escalate_to_key = m.get("escalate_to", "ISOLATE")
            escalate_to = _resolve_action_from_policy(pol, escalate_to_key)
            if decision.action != escalate_to:
                decision.action = f"{decision.action} → {escalate_to}"
                decision.rationale.append("Escalated due to asset importance")
            decision.notify += list(m.get("notify", []))

    # 2) Data sensitivity / DLP
    m = mods.get("data_sensitivity", {})
    if m.get("enabled", False):
        sensitive_classes = set(m.get("sensitive_classes", []))
        dlp_hit_triggers = bool(m.get("dlp_hit_triggers", True))
        if (ctx.data_classification in sensitive_classes) or (dlp_hit_triggers and ctx.has_dlp_hit):
            decision.rationale.append("Sensitive data condition")
            if m.get("urgency"):
                decision.urgency = str(m["urgency"])
            escalate_key = m.get("escalate_to")
            if escalate_key:
                escalate_to = _resolve_action_from_policy(pol, escalate_key)
                if stage == Stage.DATA_EXFIL and decision.action != escalate_to:
                    decision.action = escalate_to

    # 3) Remote origin quarantine
    m = mods.get("remote_origin_quarantine", {})
    if m.get("enabled", False) and ctx.is_remote:
        allowed_stages = set(m.get("stages", []))
        allowed_sevs = set(m.get("severities", []))
        if (stage.value in allowed_stages) and (severity.value in allowed_sevs):
            append_text = str(m.get("append_text", " + Temporary Network Quarantine"))
            if append_text and append_text not in decision.action:
                decision.action = decision.action + append_text
            decision.rationale.append("Remote origin → network quarantine applied")
            decision.notify += list(m.get("notify", []))

    # 4) Repeat attempts escalation (safe min_severity parse)
    m = mods.get("repeat_attempts", {})
    if m.get("enabled", False):
        threshold = int(m.get("threshold", 3))
        min_sev = _to_severity(str(m.get("min_severity", "medium")))
        sev_rank = ["low", "medium", "high", "critical"].index(severity.value)
        min_rank = ["low", "medium", "high", "critical"].index(min_sev.value)
        if ctx.repeat_attempts >= threshold and sev_rank >= min_rank:
            decision.rationale.append(f"Repeat attempts={ctx.repeat_attempts}")
            decision.urgency = str(m.get("raise_urgency_to", decision.urgency))
            decision.notify += list(m.get("notify", []))

    # 5) MFA bypass triggers isolation
    m = mods.get("mfa_bypass", {})
    if m.get("enabled", False) and ctx.has_mfa_bypass_indicators:
        allowed_stages = set(m.get("stages", []))
        if (not allowed_stages) or (stage.value in allowed_stages):
            escalate_to = _resolve_action_from_policy(pol, m.get("escalate_to", "ISOLATE"))
            decision.action = escalate_to
            decision.urgency = str(m.get("urgency", "P1"))
            decision.notify += list(m.get("notify", []))
            decision.rationale.append("MFA bypass indicators present")

    decision.notify = sorted(set(decision.notify))
    decision.followups = sorted(set(decision.followups))
    return decision

# (hardcoded fallback) modifiers
def _apply_modifiers(stage: Stage, severity: Severity, ctx: Context, decision: Decision) -> Decision:
    if ctx.asset_criticality in ("high", "crown_jewel"):
        decision.rationale.append(f"Asset criticality={ctx.asset_criticality}")
        if stage in (Stage.DATA_EXFIL, Stage.PERSISTENCE) or severity in (Severity.HIGH, Severity.CRITICAL):
            decision.urgency = "P1"
            if decision.action not in (ISOLATE,):
                decision.action = f"{decision.action} → {ISOLATE}"
                decision.rationale.append("Escalated to isolation due to asset importance")
        decision.notify.extend(["IncidentResponse", "ServiceOwner"])
    if ctx.data_classification in ("confidential", "regulated") or ctx.has_dlp_hit:
        decision.rationale.append(f"Sensitive data (class={ctx.data_classification}, dlp_hit={ctx.has_dlp_hit})")
        if stage == Stage.DATA_EXFIL and decision.action != ISOLATE:
            decision.action = ISOLATE
            decision.urgency = "P1"
    if ctx.is_remote and stage == Stage.EXPLOIT_ATTEMPT and severity != Severity.LOW:
        if KILL_PROC in decision.action or BLOCK_IP_MONITOR in decision.action:
            decision.rationale.append("Remote origin → block network egress/ingress")
            decision.action = f"{decision.action} + Temporary Network Quarantine"
            decision.notify.append("NetworkOps")
    if ctx.repeat_attempts >= 3 and severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        decision.rationale.append(f"Repeat attempts={ctx.repeat_attempts}")
        if decision.urgency not in ("P1",):
            decision.urgency = "P2"
        decision.notify.append("ThreatHunting")
    if ctx.has_mfa_bypass_indicators and stage in (Stage.PERSISTENCE, Stage.EXPLOIT_ATTEMPT):
        decision.rationale.append("MFA bypass indicators present")
        decision.action = ISOLATE
        decision.urgency = "P1"
        decision.notify.append("IdentitySec")
    decision.notify = sorted(set(decision.notify))
    decision.followups = sorted(set(decision.followups))
    return decision

# ──────────────────────────────────────────────────────────────────────────────
# ML blending
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
# ENFORCEMENT: cooldowns & approvals
# ──────────────────────────────────────────────────────────────────────────────
_URGENCY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

def _split_action_labels(action_text: str) -> List[str]:
    """
    Split a composite action string into normalized labels.
    e.g., "Kill Process + Open Incident Ticket (High Priority) + Temporary Network Quarantine"
    → ["kill process", "open incident ticket (high priority)", "temporary network quarantine"]
    """
    parts = action_text.replace("→", "+").split("+")
    return [p.strip().lower() for p in parts if p and p.strip()]

def _action_matches(decision_action: str, policy_action_key: str, pol) -> bool:
    """
    True if the decision's action contains the policy action (by label).
    First try exact token equality against split labels, then fall back to substring.
    """
    resolved = _resolve_action_from_policy(pol, policy_action_key).lower()
    tokens = _split_action_labels(decision_action)
    return any(resolved == t for t in tokens) or (resolved in decision_action.lower())


def _enforce_cooldowns(
    pol,
    decision: Decision,
    stg: Stage,
    sev: Severity,
    ctx: Context,
    *,
    recent_action_lookup: Optional[Callable[[str, str], Optional[float]]],
    now_ts: float,
) -> Decision:
    rules = getattr(pol, "cooldowns", []) if pol else []
    if not rules:
        return decision

    for rule in rules:
        match = rule.get("match", {}) or {}
        scope = match.get("scope", "target")
        stages = _lc_set(match.get("stages", []))
        severities = _lc_set(match.get("severities", []))
        actions = list(match.get("actions", []) or [])

        # Stage / severity narrowing
        if stages and stg.value not in stages:
            continue
        if severities and sev.value not in severities:
            continue

        # Scope support (target only for now)
        if scope == "target":
            if not ctx.target_id or not recent_action_lookup:
                continue
        else:
            continue

        window = int(rule.get("window_seconds", 0))
        on_v = str(rule.get("on_violation", "require_approval")).lower()
        reason = rule.get("reason", "Cooldown triggered")

        candidates: List[Tuple[str, str]] = []  # (akey_for_reason, label_for_lookup)

        if actions:
            matched_any_action = False
            for akey in actions:
                if not _action_matches(decision.action, akey, pol):
                    continue
                matched_any_action = True
                candidates.append((akey, _resolve_action_from_policy(pol, akey)))

            if not matched_any_action:
                # 🔧 Fallback: apply rule to current composite action tokens
                decision.rationale.append(
                    f"Cooldown rule actions {actions} did not explicitly match; "
                    "falling back to current action tokens"
                )
                for token in _split_action_labels(decision.action):
                    candidates.append(("current_action", token))
        else:
            # No actions specified → apply to current action tokens
            for token in _split_action_labels(decision.action):
                candidates.append(("current_action", token))

        # Evaluate window; first violating candidate wins
        for akey, label in candidates:
            last_ts = recent_action_lookup(ctx.target_id, label)
            if last_ts is None:
                continue
            delta = now_ts - float(last_ts)
            if delta < window:
                decision.rationale.append(
                    f"Cooldown violation ({akey}): {reason} (Δ={delta:.1f}s < window={window}s)"
                )
                decision.notify += list(rule.get("notify", []))
                if on_v == "defer_to_ticket":
                    decision.action = pol.actions.get("OPEN_TICKET", OPEN_TICKET) if pol else OPEN_TICKET
                else:
                    decision.requires_approval = True
                    decision.approval_reason = reason
                break

    decision.notify = sorted(set(decision.notify))
    return decision



def _enforce_approvals(pol, decision: Decision, stg: Stage, sev: Severity, ctx: Context) -> Decision:
    rules = (getattr(pol, "approvals", {}) or {}).get("rules", []) if pol else []
    if not rules:
        return decision

    for rule in rules:
        when = rule.get("when", {}) or {}
        min_urg = when.get("urgency_at_least")
        envs = _lc_set(when.get("environments", []))            # ← normalize
        assets = _lc_set(when.get("asset_criticality_in", []))  # ← normalize
        actions = _lc_set(when.get("actions", []))              # ← normalize keys safely
        stages = _lc_set(when.get("stages", []))                # ← normalize
        severities = _lc_set(when.get("severities", []))        # ← normalize

        if min_urg and _URGENCY_ORDER.get(decision.urgency, 99) > _URGENCY_ORDER.get(min_urg, 99):
            continue
        if envs and (ctx.environment not in envs):
            continue
        if assets and (ctx.asset_criticality not in assets):
            continue
        if stages and (stg.value not in stages):
            continue
        if severities and (sev.value not in severities):
            continue
        if actions and not any(_action_matches(decision.action, a, pol) for a in actions):
            continue

        req = rule.get("require", {}) or {}
        group = req.get("approver_group", "Security-Approvers")
        reason = req.get("reason", "Approval required by policy")
        decision.requires_approval = True
        decision.approval_reason = reason
        decision.rationale.append(f"Approval required: {reason} (group={group})")
        decision.notify += list(req.get("notify", []))

    decision.notify = sorted(set(decision.notify))
    return decision

def _enforce_dry_run(pol, decision: Decision) -> Decision:
    dr = (getattr(pol, "dry_run", {}) or {}) if pol else {}
    if not dr or not dr.get("enabled", False):
        return decision
    keys = set(dr.get("mark_actions", []))
    if keys and any(_action_matches(decision.action, k, pol) for k in keys):
        reason = dr.get("reason", "Dry run: approval required before enforcement")
        decision.requires_approval = True
        decision.approval_reason = reason
        decision.rationale.append(f"Dry-run: {reason}")
        decision.notify += list(dr.get("notify", []))
        decision.notify = sorted(set(decision.notify))
    return decision

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
    policy_path: Optional[str] = None,
    policy: Optional["LoadedPolicy"] = None,
    dry_run: bool = False,
    recent_action_lookup: Optional[Callable[[str, str], Optional[float]]] = None,
    now_ts: Optional[float] = None,
) -> str:
    dec = recommend_decision(
        stage,
        severity,
        is_remote=is_remote,
        context=context,
        stage_probs=stage_probs,
        severity_probs=severity_probs,
        policy_path=policy_path,
        policy=policy,
        dry_run=dry_run,
        recent_action_lookup=recent_action_lookup,
        now_ts=now_ts,
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
    policy_path: Optional[str] = None,
    policy: Optional["LoadedPolicy"] = None,
    dry_run: bool = False,
    recent_action_lookup: Optional[Callable[[str, str], Optional[float]]] = None,
    now_ts: Optional[float] = None,
) -> Decision:
    """
    Rich decision including urgency, rationale, notify targets, follow-ups,
    plus policy-driven cooldowns and approval gates when a policy is provided.

    recent_action_lookup(target_id, action_label) -> last_epoch_seconds or None
    now_ts: override time.time() for testing.
    """
    # Normalize inputs
    stg = _to_stage(stage)
    sev = _to_severity(severity)
    ctx = context or Context(is_remote=is_remote)
    ctx.is_remote = is_remote if context is None else ctx.is_remote

    pol = _ensure_policy(policy_path, policy)

    # ML blending
    ml_notes: List[str] = []
    stg, sev, ctx, ml_notes = _blend_with_ml(stg, sev, ctx, stage_probs, severity_probs)

    # Low-confidence safeguard
    if ctx.detection_confidence < 0.4:
        if pol:
            lc_key = pol.fallbacks.get("low_confidence_action", "OPEN_TICKET")
            low_conf_action = pol.actions.get(lc_key, OPEN_TICKET)
            low_conf_urgency = pol.fallbacks.get("low_confidence_urgency", "P3")
        else:
            low_conf_action, low_conf_urgency = OPEN_TICKET, "P3"
        return Decision(
            action=low_conf_action,
            urgency=low_conf_urgency,
            rationale=["Low detection confidence (<0.4)"] + ml_notes,
            notify=["SOC"],
            followups=["Collect additional telemetry", "Run targeted hunt query"],
        )

    # Base action
    action = pol.base_matrix.get((stg, sev)) if pol else BASE_POLICY.get((stg, sev))
    rationale = [f"Base policy match: stage={stg.value}, severity={sev.value}"]
    notify = ["SOC"]
    followups: List[str] = []

    if action is None:
        action = NO_ACTION if stg == Stage.BENIGN else (pol.actions.get("OPEN_TICKET", OPEN_TICKET) if pol else OPEN_TICKET)
        rationale.append("No explicit matrix entry → fallback")

    # Urgency
    urgency = (pol.urgency_by_severity.get(sev, "P3") if pol else {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
    }[sev])

    # Follow-ups
    if pol and stg in pol.followups_by_stage:
        followups.extend(pol.followups_by_stage[stg])
    else:
        if stg == Stage.EXPLOIT_ATTEMPT:
            followups += ["Acquire process dump & indicators", "Block offending IOC", "Confirm patch level"]
        elif stg == Stage.PERSISTENCE:
            followups += ["List autoruns & scheduled tasks", "Baseline diffs for startup items", "EDR scan sweep"]
        elif stg == Stage.DATA_EXFIL:
            followups += ["Quantify data scope", "Revoke tokens/keys", "Rotate credentials", "Legal/GRC review"]

    decision = Decision(
        action=action,
        urgency=urgency,
        rationale=rationale + ml_notes,
        notify=notify,
        followups=followups,
    )

    # Modifiers (policy-aware)
    if pol is not None:
        decision = _apply_modifiers_with_policy(stg, sev, ctx, decision, pol)
    else:
        decision = _apply_modifiers(stg, sev, ctx, decision)

    # ENFORCEMENT: cooldowns & approvals & dry-run (policy must be present for policy-driven pieces)
    if pol is not None:
        now = now_ts if now_ts is not None else time.time()
        decision = _enforce_cooldowns(pol, decision, stg, sev, ctx, recent_action_lookup=recent_action_lookup, now_ts=now)
        decision = _enforce_approvals(pol, decision, stg, sev, ctx)
        decision = _enforce_dry_run(pol, decision)
    # Global dry-run override (function arg)
    if dry_run and not decision.requires_approval:
        decision.requires_approval = True
        decision.approval_reason = "Global dry-run enabled"
        decision.rationale.append("Dry-run: Global override")

    return decision

def batch_recommend_actions(
    stages: List[str],
    severities: List[str],
    is_remote_flags: Optional[List[bool]] = None,
    *,
    contexts: Optional[List[Context]] = None,
    policy_path: Optional[str] = None,
    policy: Optional["LoadedPolicy"] = None,
    dry_run: bool = False,
    recent_action_lookup: Optional[Callable[[str, str], Optional[float]]] = None,
    now_ts: Optional[float] = None,
) -> List[str]:
    if is_remote_flags is None:
        is_remote_flags = [True] * len(stages)
    results: List[str] = []
    for i, (stg, sev, rem) in enumerate(zip(stages, severities, is_remote_flags)):
        ctx = (contexts[i] if contexts and i < len(contexts) else None)
        results.append(
            recommend_action(
                stg, sev, rem,
                context=ctx,
                policy_path=policy_path,
                policy=policy,
                dry_run=dry_run,
                recent_action_lookup=recent_action_lookup,
                now_ts=now_ts,
            )
        )
    return results

# ──────────────────────────────────────────────────────────────────────────────
# Optional: audit/export helper
# ──────────────────────────────────────────────────────────────────────────────
def decision_as_dict(dec: Decision, stage: str, severity: str, ctx: Context) -> Dict[str, str]:
    return {
        "stage": stage,
        "severity": severity,
        "action": dec.action,
        "urgency": dec.urgency,
        "requires_approval": str(dec.requires_approval),
        "approval_reason": dec.approval_reason or "",
        "rationale": " | ".join(dec.rationale),
        "notify": ",".join(dec.notify),
        "followups": ",".join(dec.followups),
        "remote": str(ctx.is_remote),
        "asset_criticality": ctx.asset_criticality,
        "data_classification": ctx.data_classification,
        "environment": ctx.environment,
        "target_id": ctx.target_id or "",
        "confidence": f"{ctx.detection_confidence:.2f}",
        "repeat_attempts": str(ctx.repeat_attempts),
        "mfa_bypass": str(ctx.has_mfa_bypass_indicators),
        "dlp_hit": str(ctx.has_dlp_hit),
        "notes": ctx.notes or "",
    }

# Optional helper: record executed actions for cooldown lookups
def record_execution(recorder_fn, ctx: Context, dec: Decision, *, now_ts: Optional[float] = None) -> None:
    """Call with a persistence function to store last-executed timestamps per action.
    recorder_fn(target_id: str, action_label: str, ts: float) -> None
    """
    if not recorder_fn or not ctx.target_id:
        return
    ts = now_ts if now_ts is not None else time.time()
    # Split compound actions like "Kill Process + Temporary Network Quarantine"
    parts = [p.strip() for p in dec.action.replace("→", "+").split("+") if p.strip()]
    for label in parts:
        recorder_fn(ctx.target_id, label, ts)
