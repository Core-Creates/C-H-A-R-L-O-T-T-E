# plugins/intell/phishing_guard/ruleset.py
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class RuleHit:
    id: str
    weight: int
    reason: str

RISKY_TOKENS = {"login","verify","update","password","account","secure","support","billing","invoice"}
RISKY_TLDS = {"tk","ml","ga","cf","gq","xyz","top","click"}
MAX_SUBDOMAIN_DEPTH = 4

def score_rules(url_f: Dict, tls_f: Dict, page_f: Dict) -> List[RuleHit]:
    hits: List[RuleHit] = []
    host = url_f["host_lower"]
    domain = url_f["registered_domain"]
    tld = url_f["tld"]

    if url_f["has_ip_host"]:
        hits.append(RuleHit("ip_host", 20, "Hostname is a raw IP"))
    if url_f["subdomain_depth"] > MAX_SUBDOMAIN_DEPTH:
        hits.append(RuleHit("deep_subdomain", 12, "Excessive subdomain depth"))
    if tld in RISKY_TLDS:
        hits.append(RuleHit("risky_tld", 10, f"Risky TLD: .{tld}"))
    if any(tok in url_f["path_tokens"] for tok in RISKY_TOKENS):
        hits.append(RuleHit("phish_tokens_path", 14, "Suspicious path tokens"))
    if url_f["contains_at_symbol"]:
        hits.append(RuleHit("at_symbol", 10, "URL contains '@'"))
    if tls_f["cert_mismatch"]:
        hits.append(RuleHit("cert_mismatch", 18, "TLS CN/SAN mismatch"))
    if page_f["has_pwd_field"] and not page_f["has_visible_brand"]:
        hits.append(RuleHit("login_no_brand", 16, "Login form without clear brand"))
    if page_f["js_obfuscation_score"] >= 0.8:
        hits.append(RuleHit("obf_js", 12, "Heavily obfuscated JavaScript"))
    return hits

def rules_total(hits: List[RuleHit]) -> int:
    return min(100, sum(h.weight for h in hits))
