from models.action_recommender import recommend_decision, Context

def test_crown_jewel_exfil_escalates_to_isolation():
    dec = recommend_decision(
        "data_exfil","medium",
        context=Context(asset_criticality="crown_jewel", data_classification="regulated", has_dlp_hit=True)
    )
    assert dec.action == "Isolate Host"
    assert dec.urgency == "P1"
    assert any("Sensitive data" in r for r in dec.rationale)

def test_low_confidence_defers_to_ticket():
    dec = recommend_decision("exploit_attempt","critical", context=Context(detection_confidence=0.2))
    assert "Ticket" in dec.action or "Ticket" in dec.rationale[0]

def test_policy_repeat_attempts_threshold(pol):
    from models.action_recommender import recommend_decision, Context
    dec = recommend_decision(
        "exploit_attempt","medium",
        context=Context(repeat_attempts=4),
        policy=pol
    )
    assert dec.urgency in ("P2","P1")  # escalated by policy

def test_policy_action_key_forgiveness(pol):
    from models.action_recommender import _resolve_action_from_policy
    assert "Isolate Host" in _resolve_action_from_policy(pol, "isolate")
    assert "Isolate Host" in _resolve_action_from_policy(pol, "ISOLATE")
    assert "Isolate Host" in _resolve_action_from_policy(pol, "isolate-host")