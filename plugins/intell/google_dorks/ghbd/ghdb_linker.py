# plugins/intell/google_dorks/ghdb_linker.py
# Connect Nmap scan results to GHDB dorks via the ghdb provider

from __future__ import annotations

import os
import sys
import re
from typing import Dict, Any, List, Tuple, Iterable

# Dynamically locate CHARLOTTE root and add to Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Ensure CHARLOTTE core and plugins are importable
from plugins.intell.google_dorks.dorks.dorks import ghdb  # exposes ghdb.query(...)

# Prefer the real location
try:
    from utils.paths import display_path
except Exception:
    # Optional fallback if you ever relocate it in the future
    try:
        from utils.paths import display_path  # legacy
    except Exception:
        # Final safety: minimal inline shim so nothing crashes
        def display_path(path: str, base: str | None = None) -> str:
            return str(path).replace("\\", "/")

# Basic seeds per common service to boost useful dorks (non-exhaustive)
SERVICE_SEEDS: Dict[str, List[str]] = {
    "http": [
        r"intitle:\s*index\.of",
        r"inurl:admin",
        r"inurl:login",
        r"inurl:wp-login\.php",
        r"inurl:phpmyadmin",
        r"\"powered by\"",
    ],
    "https": [
        r"intitle:\s*index\.of",
        r"inurl:admin",
        r"inurl:login",
        r"inurl:wp-login\.php",
        r"inurl:phpmyadmin",
        r"\"powered by\"",
    ],
    "ftp": [
        r"intitle:\s*index\.of\s+ftp",
        r"inurl:ftp",
        r"anonymous ftp",
        r"vsftpd",
    ],
    "mysql": [
        r"inurl:phpmyadmin",
        r"intitle:phpmyadmin",
        r"intext:\"Welcome to phpMyAdmin\"",
    ],
    "postgresql": [
        r"inurl:pgadmin",
    ],
    "mongodb": [
        r"mongo express",
        r"inurl:8081",
    ],
    "rdp": [
        r"inurl:tsweb",
        r"Remote Desktop Web Connection",
    ],
    "telnet": [
        r"telnet",
        r"login",
    ],
    "rtsp": [
        r"rtsp",
        r"intitle:\"Network Camera\"",
        r"inurl:view/view\.shtml",
    ],
    "smtp": [
        r"Roundcube",
        r"SquirrelMail",
        r"RainLoop",
        r"inurl:webmail",
    ],
    "imap": [
        r"inurl:webmail",
        r"Roundcube",
        r"SquirrelMail",
    ],
    # add more as you like…
}

STOPWORDS = {
    "service", "server", "device", "unknown", "open",
    "ssl", "tls", "secure", "protocol", "daemon",
    "http", "https", "tcp", "udp",
}

def _tokenize(s: str) -> List[str]:
    if not s:
        return []
    # split on non-alphanum, lower, filter short/stop
    toks = re.split(r"[^A-Za-z0-9]+", s.lower())
    out = []
    for t in toks:
        if len(t) < 3:
            continue
        if t in STOPWORDS:
            continue
        out.append(t)
    return out

def _tokens_from_cpe(cpe: str) -> List[str]:
    # cpe:/a:apache:http_server:2.4.52 => ['apache', 'http', 'server', '2', '4', '52']
    if not cpe:
        return []
    # grab vendor and product segments
    parts = cpe.split(":")
    # cpe:/<part>:<vendor>:<product>:<version>...
    segs = []
    if len(parts) >= 4:
        segs.extend([parts[2], parts[3]])  # vendor, product
    if len(parts) >= 5 and parts[4]:
        segs.append(parts[4])  # version (may be dotted; tokens will handle)
    toks = []
    for s in segs:
        toks.extend(_tokenize(s.replace("_", " ")))
    return toks

def _build_grep_regex(tokens: Iterable[str], seeds: Iterable[str], port: int | None) -> str:
    """
    Build a case-insensitive OR-regex covering tokens and service seeds.
    We also drop in '8080' / '8443' style ports (these appear in some GHDB dorks).
    """
    alts = set()

    for t in tokens:
        if not t:
            continue
        # escape plain tokens
        alts.add(re.escape(t))

    for s in seeds:
        if not s:
            continue
        # seeds are mini-regexes already; keep as-is (wrapped)
        alts.add(s)

    if port and port in (81, 88, 8000, 8008, 8080, 8081, 8181, 8443, 8888):
        alts.add(str(port))

    if not alts:
        # fall back to a harmless catch-all that matches nothing
        return r"(?!)"
    return "(" + "|".join(sorted(alts)) + ")"

def _service_key(svc: str | None) -> str:
    return (svc or "").lower()

def _derive_service(port: int | None, name: str | None) -> str:
    # prefer banner-reported name; fallback by common ports
    if name:
        return name.lower()
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        80: "http", 81: "http", 88: "http", 110: "pop3",
        143: "imap", 443: "https", 465: "smtps", 554: "rtsp",
        587: "submission", 993: "imaps", 995: "pop3s",
        3306: "mysql", 3389: "rdp", 5432: "postgresql",
        6379: "redis", 8080: "http", 8081: "http", 8443: "https",
    }
    return common.get(port or -1, "unknown")

def suggest_from_nmap(
    scan_results: Dict[str, Any],
    source: str = "dump",
    limit_per_port: int = 20,
    extra_grep: str | None = None,
    debug: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Given a parsed Nmap scan result (your plugin's internal structure),
    return GHDB dork suggestions grouped by host:port.

    Expected shape (flexible):
    scan_results = {
      "hosts": [
        {"ip": "1.2.3.4",
         "ports": [
            {"port": 80, "proto": "tcp", "service": "http",
             "product": "Apache httpd", "version": "2.4.52",
             "extrainfo":"(Ubuntu)", "cpe": ["cpe:/a:apache:http_server:2.4.52"]},
            ...
         ]}
      ]
    }
    """
    # Preload GHDB rows once, then filter in-memory for each port
    # (ghdb.query will fetch dump each time; we want to avoid repeated fetches)
    # Grab everything once, then filter per port with our own grep.
    all_rows = ghdb.query(source=source, limit=None, grep=None, debug=debug)

    def filter_rows(rows, grep_regex: str) -> List[Dict[str, Any]]:
        try:
            rx = re.compile(grep_regex, re.IGNORECASE)
        except re.error:
            rx = re.compile(re.escape(grep_regex), re.IGNORECASE)
        out = []
        for r in rows:
            if rx.search(r.get("dork") or "") or rx.search(r.get("title") or ""):
                out.append(r)
        return out

    output: Dict[str, List[Dict[str, Any]]] = {}

    for host in (scan_results.get("hosts") or []):
        ip = host.get("ip") or host.get("host") or host.get("address") or "unknown"
        for p in (host.get("ports") or []):
            port = p.get("port") or p.get("portid")
            svc_name = _derive_service(port, p.get("service") or p.get("name"))
            product = p.get("product") or ""
            version = p.get("version") or ""
            extrainfo = p.get("extrainfo") or ""
            cpes = p.get("cpe") or p.get("cpes") or []

            # Build tokens
            tokens = set()
            tokens.update(_tokenize(svc_name))
            tokens.update(_tokenize(product))
            tokens.update(_tokenize(version))
            tokens.update(_tokenize(extrainfo))
            for c in (cpes if isinstance(cpes, list) else [cpes]):
                tokens.update(_tokens_from_cpe(c))

            seeds = SERVICE_SEEDS.get(_service_key(svc_name), [])
            grep_regex = _build_grep_regex(tokens, seeds, port)

            if extra_grep:
                # combine: (ours) | (user extra)
                grep_regex = f"(?:{grep_regex})|(?:{extra_grep})"

            matches = filter_rows(all_rows, grep_regex)
            # light ranking: prefer entries that match product tokens
            if product:
                prod_words = set(_tokenize(product))
                def score(row):
                    txt = (row.get("dork") or "") + " " + (row.get("title") or "")
                    txt_low = txt.lower()
                    s = 0
                    for w in prod_words:
                        if w and w in txt_low:
                            s += 1
                    return s
                matches.sort(key=score, reverse=True)

            key = f"{ip}:{port}/{p.get('proto','tcp')} {svc_name} {product} {version}".strip()
            output[key] = matches[:limit_per_port]

    return output
def suggest_from_cpe(
    cpe: str,
    source: str = "dump",
    limit: int = 20,
    extra_grep: str | None = None,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Suggest GHDB dorks based on a single CPE string.
    """
    tokens = _tokens_from_cpe(cpe)
    seeds = SERVICE_SEEDS.get(_service_key(tokens[0]), [])
    grep_regex = _build_grep_regex(tokens, seeds, None)

    if extra_grep:
        grep_regex = f"(?:{grep_regex})|(?:{extra_grep})"

    rows = ghdb.query(source=source, limit=limit, grep=grep_regex, debug=debug)
    return rows