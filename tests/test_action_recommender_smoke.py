# tests/test_action_recommender_smoke.py
from pathlib import Path
import pytest

from models.policy_loader import load_policy
from models.action_recommender import recommend_decision, Context

# Resolve the repo root and default policy path
REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "action_policy.yaml"

def _recent_action_lookup(_target_id: str, _action_label: str):
    # No recent actions by default (no cooldowns triggered)
    return None

def test_smoke_decision_basics():
    pol = load_policy(str(POLICY_PATH))
    ctx = Context(
        target_id="host-123",
        environment="prod",
        asset_criticality="normal",
        is_remote=True,
    )

    dec = recommend_decision(
        "data_exfil", "high",
        context=ctx,
        policy=pol,
        recent_action_lookup=_recent_action_lookup,
        dry_run=False,
    )

    # Basic shape assertions
    assert dec.action and isinstance(dec.action, str)
    assert dec.urgency in {"P1", "P2", "P3", "P4"}
    assert isinstance(dec.rationale, list) and dec.rationale
    assert "SOC" in dec.notify  # default notify path
    assert isinstance(dec.followups, list)

def test_global_dry_run_forces_approval():
    pol = load_policy(str(POLICY_PATH))
    ctx = Context(target_id="host-456", environment="prod", is_remote=True)

    dec = recommend_decision(
        "exploit_attempt", "high",
        context=ctx,
        policy=pol,
        recent_action_lookup=_recent_action_lookup,
        dry_run=True,  # global override should force approval
    )
    assert dec.requires_approval is True
    assert "Dry-run" in " ".join(dec.rationale)

@pytest.mark.skipif(
    not (load_policy(str(POLICY_PATH)).cooldowns),
    reason="No cooldown rules configured in policy",
)
def test_cooldown_block_or_approval_when_recent():
    pol = load_policy(str(POLICY_PATH))
    ctx = Context(target_id="host-789", environment="prod", is_remote=True)

    # Pretend the last matching action happened just now → should violate window
    def recent_action_lookup(_target_id: str, _action_label: str):
        import time
        return time.time()

    dec = recommend_decision(
        "exploit_attempt", "high",
        context=ctx,
        policy=pol,
        recent_action_lookup=recent_action_lookup,
        dry_run=False,
    )
    # Policy may either require approval or defer to ticket on violation.
    assert dec.requires_approval is True or dec.action.lower().startswith("open")
