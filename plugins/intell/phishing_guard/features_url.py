# plugins/intell/phishing_guard/features_url.py
import re, math, idna
from urllib.parse import urlparse, parse_qs

HEX_RE = re.compile(r'%[0-9a-fA-F]{2}')
HOMOGLYPHISH = {'0':'o','1':'l','3':'e','5':'s','7':'t','@':'a','$':'s'}

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    p, n = Counter(s), len(s)
    return -sum((c/n) * math.log2(c/n) for c in p.values())

def tokenize_path(path: str):
    toks = re.split(r'[/\-\._\?\=&]', path.lower())
    return [t for t in toks if t]

def url_features(url: str) -> dict:
    u = urlparse(url)
    host = u.hostname or ""
    try:
        host_ascii = idna.encode(host).decode('ascii')
    except Exception:
        host_ascii = host
    host_lower = host_ascii.lower()
    path = u.path or "/"
    q = parse_qs(u.query)

    feats = {
        "scheme": u.scheme,
        "host_lower": host_lower,
        "registered_domain": host_lower.split('.')[-2] + '.' + host_lower.split('.')[-1] if host_lower.count('.')>=1 else host_lower,
        "tld": host_lower.split('.')[-1] if '.' in host_lower else "",
        "subdomain_depth": max(0, host_lower.count('.') - 1),
        "len_url": len(url),
        "len_path": len(path),
        "num_params": sum(len(v) for v in q.values()),
        "contains_at_symbol": '@' in url,
        "has_ip_host": bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host_lower)),
        "hex_escaped_ratio": len(HEX_RE.findall(url)) / max(1, len(url)),
        "entropy_host": shannon_entropy(host_lower),
        "entropy_path": shannon_entropy(path),
        "digit_ratio_host": sum(ch.isdigit() for ch in host_lower)/max(1,len(host_lower)),
        "path_tokens": tokenize_path(path),
        "port_specified": u.port is not None,
    }
    return feats
