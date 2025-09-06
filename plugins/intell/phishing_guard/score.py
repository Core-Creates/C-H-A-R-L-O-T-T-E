# plugins/intell/phishing_guard/score.py
import joblib
from .ruleset import score_rules, rules_total
from .features_url import url_features
from .features_page import page_features
from .tls_probe import tls_features
from .model import vectorize, FEATURE_KEYS

MODEL_PATH = "plugins/intell/phishing_guard/resources/phish_gbm.joblib"

def score_url(url: str, html: str | None) -> dict:
    uf = url_features(url)
    pf = page_features(html or "")
    tf = tls_features(uf["host_lower"]) if uf["scheme"]=="https" else {"cert_mismatch": True}

    # Rules
    rule_hits = score_rules(uf, tf, pf)
    rule_score = rules_total(rule_hits)

    # ML
    try:
        clf = joblib.load(MODEL_PATH)
        x = vectorize(uf, pf, tf).reshape(1,-1)
        ml_p = float(clf.predict_proba(x)[0,1])
    except Exception:
        ml_p = 0.0

    # Blend: 70% ML + 30% rules (clamped)
    blended = min(1.0, 0.3*(rule_score/100.0) + 0.7*ml_p)
    risk_0_100 = int(round(blended*100))

    recommendations = "block" if risk_0_100 >= 80 else "warn" if risk_0_100 >= 50 else "allow"
    reasons = [f"{h.id} (+{h.weight}) — {h.reason}" for h in rule_hits]
    return {
        "risk": risk_0_100,
        "recommendation": recommendations,
        "ml_prob": round(ml_p,3),
        "rule_score": rule_score,
        "reasons": reasons,
        "features_used": FEATURE_KEYS,
    }
