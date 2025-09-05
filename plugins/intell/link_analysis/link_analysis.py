# plugins/intell/link_analysis.py
from __future__ import annotations

import re
import ipaddress
from urllib.parse import urlparse
from typing import Any

URL_RX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _classify(item: str) -> str:
    s = item.strip()
    if not s:
        return "unknown"
    if URL_RX.match(s):
        return "url"
    try:
        ipaddress.ip_address(s)
        return "ipv6" if ":" in s else "ipv4"
    except ValueError:
        pass
    # crude domain check: has a dot and allowed chars
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", s):
        return "domain"
    return "unknown"


def _normalize(item: str) -> dict[str, Any]:
    kind = _classify(item)
    out: dict[str, Any] = {"raw": item, "type": kind}

    if kind == "url":
        u = urlparse(item)
        host = u.hostname or ""
        port = u.port or (
            443 if u.scheme == "https" else 80 if u.scheme == "http" else None
        )
        out.update(
            {
                "scheme": u.scheme,
                "host": host,
                "port": port,
                "path": u.path or "/",
                "query": u.query or "",
                "fragment": u.fragment or "",
            }
        )
    elif kind in {"domain", "ipv4", "ipv6"}:
        out["host"] = item
    return out


def _edges_from_items(items: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """
    Very light relationship guesses:
      - url -> host (RESOLVES_TO)
      - explicit duplicates (ALIAS_OF)
    """
    edges: list[tuple[str, str, str]] = []
    seen_hosts: dict[str, str] = {}
    for it in items:
        rid = it["raw"]
        host = it.get("host")
        if it["type"] == "url" and host:
            edges.append((rid, host, "RESOLVES_TO"))
        if host:
            if host in seen_hosts and seen_hosts[host] != rid:
                edges.append((rid, seen_hosts[host], "ALIAS_OF"))
            else:
                seen_hosts[host] = rid
    return edges


def run(args=None):
    """
    args = {"target": "...", "seed": "..."} or None to prompt
    """
    if args is None:
        seed = input("URL/domain/IP (comma-separated allowed): ").strip()
    else:
        seed = (args or {}).get("target") or (args or {}).get("seed") or ""

    if not seed:
        return {
            "task": "link_analysis",
            "status": "error",
            "error": "No input provided.",
        }

    items = [s.strip() for s in seed.split(",") if s.strip()]
    nodes = [_normalize(s) for s in items]
    edges = _edges_from_items(nodes)

    return {
        "task": "link_analysis",
        "inputs": items,
        "status": "ok",
        "result": {
            "nodes": nodes,
            "edges": [{"src": s, "dst": d, "rel": r} for (s, d, r) in edges],
        },
        "notes": ["Heuristic graph; enrich with DNS/WHOIS/Cert transparency later."],
    }


def run_plugin(args=None):
    return run(args)


if __name__ == "__main__":
    # quick CLI
    print(run({"target": input("URL/domain/IP(s): ").strip()}))
