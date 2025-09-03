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