# plugins/intell/google_dorks/ghbd/ghdb_linker.py
# Connect Nmap scan results to GHDB dorks via the ghdb provider

from __future__ import annotations

import os
import sys
import re
import importlib
from typing import Any
from collections.abc import Iterable

# ── Path bootstrap, then dynamic imports (avoids Ruff E402) ───────────────────
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    ghdb = importlib.import_module("plugins.intell.google_dorks.dorks.dorks").ghdb  # type: ignore[attr-defined]
except Exception:
    ghdb = None  # graceful fallback

try:
    display_path = importlib.import_module("utils.paths").display_path  # type: ignore[attr-defined]
except Exception:

    def display_path(path: str, base: str | None = None) -> str:
        return str(path).replace("\\", "/")


try:
    _shared_unique_dorks = importlib.import_module("utils.text").unique_dorks  # type: ignore[attr-defined]
except Exception:
    _shared_unique_dorks = None

# ── Seeds / stopwords ─────────────────────────────────────────────────────────
SERVICE_SEEDS: dict[str, list[str]] = {
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
    "ftp": [r"intitle:\s*index\.of\s+ftp", r"inurl:ftp", r"anonymous ftp", r"vsftpd"],
    "mysql": [
        r"inurl:phpmyadmin",
        r"intitle:phpmyadmin",
        r"intext:\"Welcome to phpMyAdmin\"",
    ],
    "postgresql": [r"inurl:pgadmin"],
    "mongodb": [r"mongo express", r"inurl:8081"],
    "rdp": [r"inurl:tsweb", r"Remote Desktop Web Connection"],
    "telnet": [r"telnet", r"login"],
    "rtsp": [r"rtsp", r"intitle:\"Network Camera\"", r"inurl:view/view\.shtml"],
    "smtp": [r"Roundcube", r"SquirrelMail", r"RainLoop", r"inurl:webmail"],
    "imap": [r"inurl:webmail", r"Roundcube", r"SquirrelMail"],
}
STOPWORDS = {
    "service",
    "server",
    "device",
    "unknown",
    "open",
    "ssl",
    "tls",
    "secure",
    "protocol",
    "daemon",
    "http",
    "https",
    "tcp",
    "udp",
}


# ── Local helpers ─────────────────────────────────────────────────────────────
def _collapse_ws(s: str) -> str:
    return " ".join((s or "").split())


def _clamp(s: str, max_len: int) -> str:
    s = s or ""
    return s if len(s) <= max_len else (s[: max_len - 1] + "…")


def _unique_dorks_local(dorks: list[str], max_items: int = 10) -> list[str]:
    seen, out = set(), []
    for d in dorks:
        d = _collapse_ws(d)
        if d and d not in seen:
            out.append(d)
            seen.add(d)
        if len(out) >= max_items:
            break
    return out


def _unique_dorks(dorks: list[str], max_items: int = 10) -> list[str]:
    if _shared_unique_dorks:
        try:
            return _shared_unique_dorks(dorks, max_items=max_items)  # type: ignore[misc]
        except TypeError:
            pass
    return _unique_dorks_local(dorks, max_items=max_items)


# ── Tokenization & query building ─────────────────────────────────────────────
def _tokenize(s: str) -> list[str]:
    if not s:
        return []
    toks = re.split(r"[^A-Za-z0-9]+", s.lower())
    return [t for t in toks if len(t) >= 3 and t not in STOPWORDS]


def _tokens_from_cpe(cpe: str) -> list[str]:
    if not cpe:
        return []
    parts = cpe.split(":")
    segs: list[str] = []
    if len(parts) >= 4:
        segs.extend([parts[2], parts[3]])
    if len(parts) >= 5 and parts[4]:
        segs.append(parts[4])
    out: list[str] = []
    for s in segs:
        out.extend(_tokenize(s.replace("_", " ")))
    return out


def _build_grep_regex(
    tokens: Iterable[str], seeds: Iterable[str], port: int | None
) -> str:
    alts = set()
    for t in tokens:
        if t:
            alts.add(re.escape(t))
    for s in seeds:
        if s:
            alts.add(s)
    if port and port in (81, 88, 8000, 8008, 8080, 8081, 8181, 8443, 8888):
        alts.add(str(port))
    return "(" + "|".join(sorted(alts)) + ")" if alts else r"(?!)"


def _service_key(svc: str | None) -> str:
    return (svc or "").lower()


def _derive_service(port: int | None, name: str | None) -> str:
    if name:
        return name.lower()
    common = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        80: "http",
        81: "http",
        88: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        465: "smtps",
        554: "rtsp",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        6379: "redis",
        8080: "http",
        8081: "http",
        8443: "https",
    }
    return common.get(port or -1, "unknown")


# ── Row cleanup / scoring ─────────────────────────────────────────────────────
def _row_key(r: dict[str, Any]) -> tuple[str, str]:
    return (_collapse_ws(r.get("dork") or ""), _collapse_ws(r.get("title") or ""))


def _dedupe_rows(
    rows: list[dict[str, Any]], limit: int | None = None
) -> list[dict[str, Any]]:
    seen, out = set(), []
    for r in rows:
        k = _row_key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
        if limit is not None and len(out) >= limit:
            break
    return out


def _score_row_by_tokens(row: dict[str, Any], tokens: Iterable[str]) -> int:
    txt = ((row.get("dork") or "") + " " + (row.get("title") or "")).lower()
    return sum(1 for w in set(tokens) if w and w in txt)


def _format_row_as_string(r: dict[str, Any], max_len: int = 120) -> str:
    d = _collapse_ws(r.get("dork") or "")
    t = _collapse_ws(r.get("title") or "")
    s = f"{d}  —  {t}" if (d and t) else (d or t or "")
    return _clamp(s, max_len)


# ── Public API ────────────────────────────────────────────────────────────────
def suggest_from_nmap(
    scan_results: dict[str, Any],
    source: str = "dump",
    limit_per_port: int = 20,
    extra_grep: str | None = None,
    debug: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    if ghdb is None:
        return {"error": "ghdb provider unavailable"}

    all_rows = ghdb.query(source=source, limit=None, grep=None, debug=debug)

    def filter_rows(
        rows: list[dict[str, Any]], grep_regex: str
    ) -> list[dict[str, Any]]:
        try:
            rx = re.compile(grep_regex, re.IGNORECASE)
        except re.error:
            rx = re.compile(re.escape(grep_regex), re.IGNORECASE)
        return [
            r
            for r in rows
            if rx.search(r.get("dork") or "") or rx.search(r.get("title") or "")
        ]

    output: dict[str, list[dict[str, Any]]] = {}
    for host in scan_results.get("hosts") or []:
        ip = host.get("ip") or host.get("host") or host.get("address") or "unknown"
        for p in host.get("ports") or []:
            port = p.get("port") or p.get("portid")
            svc_name = _derive_service(port, p.get("service") or p.get("name"))
            product = p.get("product") or ""
            version = p.get("version") or ""
            extrainfo = p.get("extrainfo") or ""
            cpes = p.get("cpe") or p.get("cpes") or []

            tokens = set()
            tokens.update(_tokenize(svc_name))
            tokens.update(_tokenize(product))
            tokens.update(_tokenize(version))
            tokens.update(_tokenize(extrainfo))
            for c in cpes if isinstance(cpes, list) else [cpes]:
                tokens.update(_tokens_from_cpe(c))

            seeds = SERVICE_SEEDS.get(_service_key(svc_name), [])
            grep_regex = _build_grep_regex(tokens, seeds, port)
            if extra_grep:
                grep_regex = f"(?:{grep_regex})|(?:{extra_grep})"

            matches = filter_rows(all_rows, grep_regex)
            if product:
                prod_words = set(_tokenize(product))
                matches.sort(
                    key=lambda r: _score_row_by_tokens(r, prod_words), reverse=True
                )

            output[
                f"{ip}:{port}/{p.get('proto','tcp')} {svc_name} {product} {version}".strip()
            ] = _dedupe_rows(matches, limit=limit_per_port)

    return output


def suggest_from_cpe(
    cpe: str,
    source: str = "dump",
    limit: int = 20,
    extra_grep: str | None = None,
    debug: bool = False,
) -> list[dict[str, Any]]:
    if ghdb is None:
        return []
    tokens = _tokens_from_cpe(cpe)
    seeds: list[str] = []
    for t in tokens:
        if t in SERVICE_SEEDS:
            seeds = SERVICE_SEEDS[t]
            break
    grep_regex = _build_grep_regex(tokens, seeds, None)
    if extra_grep:
        grep_regex = f"(?:{grep_regex})|(?:{extra_grep})"
    rows = ghdb.query(source=source, limit=limit, grep=grep_regex, debug=debug)
    return _dedupe_rows(rows, limit=limit)


def format_grouped_results_as_strings(
    grouped: dict[str, list[dict[str, Any]]],
    max_items_per_port: int = 10,
    max_line_len: int = 120,
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, rows in grouped.items():
        strings, seen = [], set()
        for r in rows:
            s = _format_row_as_string(r, max_len=max_line_len)
            if s not in seen:
                strings.append(s)
                seen.add(s)
            if len(strings) >= max_items_per_port:
                break
        out[key] = strings
    return out


def format_rows_as_strings(
    rows: list[dict[str, Any]], max_items: int = 10, max_line_len: int = 120
) -> list[str]:
    strings = [_format_row_as_string(r, max_len=max_line_len) for r in rows]
    return _unique_dorks(strings, max_items=max_items)


# ── End of ghdb_linker.py ─────────────────────────────────────────────────────
