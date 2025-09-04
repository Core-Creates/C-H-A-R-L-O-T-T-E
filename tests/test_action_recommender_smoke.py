# tests/test_action_recommender_smoke.py
import os
from pathlib import Path
import pytest

# Prefer the package path (charlotte.models), fall back to legacy (models)
try:
    from models import load_policy, recommend_decision, Context
except ImportError:
    from models import load_policy, recommend_decision, Context  # requires models/__init__.py exporting these

# Resolve policy path (env override supported)
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = REPO_ROOT / "policies" / "action_policy.yaml"
POLICY_PATH = Path(os.getenv("ACTION_POLICY_PATH", str(DEFAULT_POLICY)))

def _recent_action_lookup(_target_id: str, _action_label: str):
    # No recent actions by default (no cooldowns triggered)
    return None

@pytest.fixture(scope="session")
def policy():
    if not POLICY_PATH.exists():
        pytest.skip(f"Policy file not found: {POLICY_PATH}")
    return load_policy(str(POLICY_PATH))

def test_smoke_decision_basics(policy):
    ctx = Context(
        target_id="host-123",
        environment="prod",
        asset_criticality="normal",
        is_remote=True,
    )

    dec = recommend_decision(
        "data_exfil", "high",
        context=ctx,
        policy=policy,
        recent_action_lookup=_recent_action_lookup,
        dry_run=False,
    )

    # Basic shape assertions
    assert dec.action and isinstance(dec.action, str)
    assert dec.urgency in {"P1", "P2", "P3", "P4"}
    assert isinstance(dec.rationale, list) and dec.rationale
    assert "SOC" in dec.notify
    assert isinstance(dec.followups, list)

def test_global_dry_run_forces_approval(policy):
    ctx = Context(target_id="host-456", environment="prod", is_remote=True)

    dec = recommend_decision(
        "exploit_attempt", "high",
        context=ctx,
        policy=policy,
        recent_action_lookup=_recent_action_lookup,
        dry_run=True,  # global override should force approval
    )
    assert dec.requires_approval is True
    assert "Dry-run" in " ".join(dec.rationale)

def test_cooldown_block_or_approval_when_recent(policy):
    # Skip gracefully if the policy has no cooldowns configured
    if not getattr(policy, "cooldowns", None):
        pytest.skip("No cooldown rules configured in policy")

    ctx = Context(target_id="host-789", environment="prod", is_remote=True)

    # Pretend the last matching action happened just now → should violate window
    def recent_action_lookup(_target_id: str, _action_label: str):
        import time
        return time.time()

    dec = recommend_decision(
        "exploit_attempt", "high",
        context=ctx,
        policy=policy,
        recent_action_lookup=recent_action_lookup,
        dry_run=False,
    )
    # Policy may either require approval or defer to ticket on violation.
    assert dec.requires_approval is True or dec.action.lower().startswith("open")
