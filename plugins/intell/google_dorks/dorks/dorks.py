# plugins/intell/google_dorks/dorks.py
# GHDB (Google Hacking Database) fetcher for CHARLOTTE
# Provides: ghdb.query(source="dump"|"scrape", ..., grep=...) → List[dict]
from __future__ import annotations

import os
import re
import time
import json
import random
import argparse
import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from types import SimpleNamespace
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Paths (prefer utils.paths; safe fallback)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from utils.paths import p, ensure_parent
except Exception:

    def p(*parts) -> str:
        return os.path.abspath(os.path.join(*parts))

    def ensure_parent(*parts) -> str:
        path = p(*parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path


BASE = "https://www.exploit-db.com"
LIST_URL = f"{BASE}/google-hacking-database"

# Override if needed (PowerShell example):
#   setx GHDB_DUMP_URL "https://raw.githubusercontent.com/iphelix/seat/master/databases/GHDB.xml"
GHDB_DUMP_URL = os.environ.get(
    "GHDB_DUMP_URL",
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/ghdb.xml",
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": BASE,
}

GHDB_DETAIL_RX = re.compile(r"^/ghdb/\d+$")  # e.g., /ghdb/7129
CACHE_PATH = p("data", "cache", "ghdb.json")
CACHE_TTL_S = int(os.environ.get("GHDB_CACHE_TTL_S", "86400"))  # 24h default
ENABLE_CACHE = os.environ.get("GHDB_ENABLE_CACHE", "1") != "0"


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helper (simple retry with backoff)
# ──────────────────────────────────────────────────────────────────────────────
def _get(
    session: requests.Session,
    url: str,
    params: dict | None = None,
    max_retries: int = 5,
) -> requests.Response:
    delay = 1.0
    for _ in range(max_retries):
        r = session.get(url, params=params, headers=HEADERS, timeout=30)
        if r.status_code == 200:
            return r
        if r.status_code in (403, 429, 503):
            time.sleep(delay + random.uniform(0, 0.5))
            delay = min(delay * 2, 8)
            continue
        r.raise_for_status()
    r.raise_for_status()


# ──────────────────────────────────────────────────────────────────────────────
# Small utils
# ──────────────────────────────────────────────────────────────────────────────
def _title_from_dork(dork: str, maxlen: int = 80) -> str:
    if not dork:
        return "(no title)"
    t = " ".join(dork.split())
    return t if len(t) <= maxlen else t[: maxlen - 1] + "…"


def _find_ci(node: ET.Element, *names: str) -> str | None:
    """Case-insensitive findtext within node subtree across tag aliases."""
    wanted = {n.lower() for n in names}
    for elt in node.iter():
        if elt.tag.lower() in wanted:
            text = (elt.text or "").strip()
            if text:
                return text
    return None


def _find_id_near(node: ET.Element) -> str | None:
    """
    Try to find a numeric GHDB id near this node.
    Accept tags like <id>, <ghdbid>, <ghdb-id>, <entryid>, etc.
    Fallback: scan text/attributes for a 2–7 digit token.
    """
    id_text = _find_ci(node, "id", "ghdbid", "ghdb-id", "entryid", "eid")
    if id_text and id_text.isdigit():
        return id_text

    for elt in node.iter():
        if elt is node:
            continue
        if elt.text:
            m = re.search(r"\b(\d{2,7})\b", elt.text)
            if m:
                return m.group(1)
        for v in elt.attrib.values():
            m = re.search(r"\b(\d{2,7})\b", v)
            if m:
                return m.group(1)
    return None


def _load_cache() -> list[dict[str, Any]] | None:
    if not ENABLE_CACHE or not os.path.exists(CACHE_PATH):
        return None
    try:
        st = os.stat(CACHE_PATH)
        if (time.time() - st.st_mtime) > CACHE_TTL_S:
            return None
        with open(CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_cache(rows: list[dict[str, Any]]):
    try:
        ensure_parent(CACHE_PATH)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Source A: Official XML dump (preferred)
# ──────────────────────────────────────────────────────────────────────────────
def fetch_ghdb_dump(
    limit: int | None = None, use_cache: bool = True, debug: bool = False
) -> list[dict[str, Any]]:
    """
    Download & parse the GHDB XML dump.
    Returns list of dicts: {id,title,dork,category,author,date,url}
    """
    if use_cache:
        cached = _load_cache()
        if cached:
            return cached[: limit or None]

    with requests.Session() as s:
        r = _get(s, GHDB_DUMP_URL)
        if debug:
            print(
                f"[dbg] GET {GHDB_DUMP_URL} -> {r.status_code} {r.headers.get('Content-Type')}"
            )
        xml_bytes = r.content

    # Ensure it's XML (rate-limit or errors may return HTML)
    prefix = xml_bytes.lstrip()[:16]
    if not prefix.startswith(b"<"):
        preview = xml_bytes[:300].decode("utf-8", errors="replace")
        raise RuntimeError(
            "Expected XML from GHDB_DUMP_URL; got non-XML/HTML.\n"
            f"Preview (first 300 bytes):\n{preview}"
        )

    root = ET.fromstring(xml_bytes)
    parent = {child: p for p in root.iter() for child in p}

    # Accept multiple tag names for the dork field
    dork_nodes = [n for n in root.iter() if n.tag.lower() in {"dork", "query", "term"}]
    if debug:
        print(f"[dbg] found {len(dork_nodes)} candidate dork nodes")

    entries: list[dict[str, Any]] = []
    seen = set()

    for dn in dork_nodes:
        container = dn
        for _ in range(3):
            if container in parent:
                container = parent[container]
            else:
                break

        dork_text = (dn.text or "").strip()
        title = _find_ci(container, "title", "name")
        category = _find_ci(container, "category", "type")
        author = _find_ci(container, "author", "submittedby")
        date = _find_ci(container, "date", "published", "added")
        url = _find_ci(container, "url", "link", "href")

        ghdb_id = _find_id_near(dn) or _find_id_near(container)
        if ghdb_id and ghdb_id.isdigit():
            url = f"{BASE}/ghdb/{ghdb_id}"

        if not title:
            title = _title_from_dork(dork_text)

        rec = {
            "id": ghdb_id,
            "title": title or "(no title)",
            "dork": dork_text,
            "category": category,
            "author": author,
            "date": date,
            "url": url,
        }

        key = (rec["url"] or "", rec["dork"])
        if key in seen:
            continue
        seen.add(key)

        entries.append(rec)
        if limit and len(entries) >= limit:
            break

    if ENABLE_CACHE:
        _save_cache(entries)

    return entries


# ──────────────────────────────────────────────────────────────────────────────
# Source B: HTML scraping (fallback)
# ──────────────────────────────────────────────────────────────────────────────
def _fetch_ghdb_index_html(max_pages: int = 3) -> list[dict[str, Any]]:
    items, seen = [], set()
    with requests.Session() as s:
        for page in range(1, max_pages + 1):
            resp = _get(s, LIST_URL, params={"page": page})
            soup = BeautifulSoup(resp.text, "html.parser")
            # If site renders entries via JS, this will find 0.
            for a in soup.select('a[href^="/ghdb/"]'):
                href = a.get("href", "")
                if not GHDB_DETAIL_RX.match(href):
                    continue
                url = BASE + href
                title = " ".join(a.get_text(strip=True).split())
                if url in seen or not title:
                    continue
                seen.add(url)
                items.append({"title": title, "url": url})
            time.sleep(0.8 + random.uniform(0, 0.5))
    return items


def fetch_dork_text(session: requests.Session, detail_url: str) -> str | None:
    resp = _get(session, detail_url)
    soup = BeautifulSoup(resp.text, "html.parser")
    cand = soup.select_one("pre, code")
    return cand.get_text("\n", strip=True) if cand else None


def fetch_ghdb_scrape(
    max_pages: int = 1, enrich: bool = False, cap_enrich: int = 50
) -> list[dict[str, Any]]:
    items = _fetch_ghdb_index_html(max_pages=max_pages)
    if not enrich or not items:
        return items
    out: list[dict[str, Any]] = []
    with requests.Session() as s:
        for i, it in enumerate(items):
            if i >= cap_enrich:
                break
            dork = fetch_dork_text(s, it["url"])
            out.append({**it, "dork": dork})
            time.sleep(0.6 + random.uniform(0, 0.4))
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Filtering & Provider
# ──────────────────────────────────────────────────────────────────────────────
def _apply_filters(
    rows: list[dict[str, Any]],
    category: str | None = None,
    author: str | None = None,
    grep: str | None = None,
) -> list[dict[str, Any]]:
    if grep:
        try:
            rx = re.compile(grep, re.IGNORECASE)

            def grep_fn(s):
                return bool(rx.search(s or ""))
        except re.error:
            needle = (grep or "").lower()

            def grep_fn(s):
                return needle in (s or "").lower()
    else:

        def grep_fn(s):
            return True

    def has(sub: str | None, val: str | None) -> bool:
        return True if not sub else (sub.lower() in (val or "").lower())

    out: list[dict[str, Any]] = []
    for r in rows:
        if not has(category, r.get("category")):
            continue
        if not has(author, r.get("author")):
            continue
        if not (grep_fn(r.get("title")) or grep_fn(r.get("dork"))):
            continue
        out.append(r)
    return out


def ghdb_query(
    source: str = "dump",
    limit: int | None = None,
    pages: int = 1,
    enrich: bool = False,
    category: str | None = None,
    author: str | None = None,
    grep: str | None = None,
    debug: bool = False,
) -> list[dict[str, Any]]:
    if source == "dump":
        rows = fetch_ghdb_dump(limit=None, use_cache=True, debug=debug)
    else:
        rows = fetch_ghdb_scrape(max_pages=max(1, pages), enrich=enrich)

    rows = _apply_filters(rows, category=category, author=author, grep=grep)
    if limit:
        rows = rows[: max(0, int(limit))]
    return rows


# Expose as ghdb.query(...) for CHARLOTTE recon plugins
ghdb = SimpleNamespace(query=ghdb_query)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Fetch Google Dorks (GHDB) for CHARLOTTE")
    ap.add_argument("--source", choices=["dump", "scrape"], default="dump")
    ap.add_argument(
        "--limit", type=int, default=0, help="Cap AFTER filtering (0 = no cap)"
    )
    ap.add_argument(
        "--pages", type=int, default=1, help="Pages to scrape (scrape only)"
    )
    ap.add_argument(
        "--enrich", action="store_true", help="Fetch each detail’s dork (scrape only)"
    )
    ap.add_argument("--category", type=str, default=None)
    ap.add_argument("--author", type=str, default=None)
    ap.add_argument(
        "--grep", type=str, default=None, help="Regex/keyword matches title OR dork"
    )
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    rows = ghdb_query(
        source=args.source,
        limit=(args.limit or None),
        pages=args.pages,
        enrich=args.enrich,
        category=args.category,
        author=args.author,
        grep=args.grep,
        debug=args.debug,
    )

    print(f"[+] Collected {len(rows)} GHDB entries from {args.source}.")
    for r in rows[:10]:
        title = r.get("title") or "(no title)"
        url = r.get("url") or "(no url)"
        dork = r.get("dork")
        print(f"- {title} -> {url}" + (f" | dork: {dork[:80]}…" if dork else ""))


if __name__ == "__main__":
    main()
