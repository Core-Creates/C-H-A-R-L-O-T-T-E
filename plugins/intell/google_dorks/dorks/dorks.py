# plugins/intell/google_dorks/dorks.py
# GHDB (Google Hacking Database) fetcher for CHARLOTTE
# - Preferred source: Official XML dump (GHDB_DUMP_URL, override via env)
# - Fallback: HTML scraping (limited; site may be JS-rendered)
# - Filters: --category, --author, --grep (regex/keyword, case-insensitive)
# - Exposes provider: ghdb.query(...) for other plugins

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
from typing import Optional, List, Dict, Any

BASE = "https://www.exploit-db.com"
LIST_URL = f"{BASE}/google-hacking-database"

# Override if needed (PowerShell example):
#   setx GHDB_DUMP_URL "https://raw.githubusercontent.com/iphelix/seat/master/databases/GHDB.xml"
GHDB_DUMP_URL = os.environ.get(
    "GHDB_DUMP_URL",
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/ghdb.xml"
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
CACHE_PATH = os.path.join("data", "cache", "ghdb.json")


# -----------------------------
# HTTP helper
# -----------------------------
def _get(session: requests.Session, url: str, params: Optional[dict] = None, max_retries: int = 5) -> requests.Response:
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


# -----------------------------
# Small utils
# -----------------------------
def _title_from_dork(dork: str, maxlen: int = 80) -> str:
    if not dork:
        return "(no title)"
    t = " ".join(dork.split())  # collapse whitespace
    return t if len(t) <= maxlen else t[:maxlen - 1] + "…"


def _find_ci(node: ET.Element, *names: str) -> Optional[str]:
    """Case-insensitive findtext within node subtree across tag aliases."""
    wanted = {n.lower() for n in names}
    for elt in node.iter():
        if elt.tag.lower() in wanted:
            text = (elt.text or "").strip()
            if text:
                return text
    return None


def _find_id_near(node: ET.Element) -> Optional[str]:
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


# -----------------------------
# Source A: Official XML dump (preferred)
# -----------------------------
def fetch_ghdb_dump(limit: Optional[int] = None, save_cache: bool = True, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Download & parse the GHDB XML dump.
    Returns list of dicts: {id,title,dork,category,author,date,url}
    """
    with requests.Session() as s:
        r = s.get(GHDB_DUMP_URL, timeout=30)
        if debug:
            print(f"[dbg] GET {GHDB_DUMP_URL} -> {r.status_code} {r.headers.get('Content-Type')}")
        r.raise_for_status()
        xml_bytes = r.content

    # Ensure XML (rate-limit pages are HTML)
    if not xml_bytes.lstrip().startswith(b"<"):
        preview = xml_bytes[:300].decode("utf-8", errors="replace")
        raise RuntimeError(
            "Expected XML from GHDB_DUMP_URL, got non-XML/HTML.\n"
            f"Preview (first 300 bytes):\n{preview}"
        )

    root = ET.fromstring(xml_bytes)
    parent = {child: p for p in root.iter() for child in p}

    # Accept multiple tag names for the dork field
    dork_nodes = [n for n in root.iter() if n.tag.lower() in {"dork", "query", "term"}]
    if debug:
        print(f"[dbg] found {len(dork_nodes)} candidate dork nodes")

    entries: List[Dict[str, Any]] = []
    seen = set()

    for dn in dork_nodes:
        # Walk up a few levels to a likely record wrapper
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

        # De-dup by (url,dork) or just dork if no url
        key = (rec["url"] or "", rec["dork"])
        if key in seen:
            continue
        seen.add(key)

        entries.append(rec)
        if limit and len(entries) >= limit:
            break

    if save_cache:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)

    return entries


# -----------------------------
# Source B: HTML scraping (fallback)
# -----------------------------
def _fetch_ghdb_index_html(max_pages: int = 3) -> List[Dict[str, Any]]:
    items, seen = [], set()
    with requests.Session() as s:
        for page in range(1, max_pages + 1):
            resp = _get(s, LIST_URL, params={"page": page})
            soup = BeautifulSoup(resp.text, "html.parser")
            # NOTE: If site renders entries via JS, this will find 0.
            for a in soup.select('a[href^="/ghdb/"]'):
                href = a.get("href", "")
                if not GHDB_DETAIL_RX.match(href):
                    continue
                url = BASE + href
                title = a.get_text(strip=True)
                if url in seen or not title:
                    continue
                seen.add(url)
                items.append({"title": title, "url": url})
            time.sleep(0.8 + random.uniform(0, 0.5))
    return items


def fetch_dork_text(session: requests.Session, detail_url: str) -> Optional[str]:
    resp = _get(session, detail_url)
    soup = BeautifulSoup(resp.text, "html.parser")
    cand = soup.select_one("pre, code")
    return cand.get_text("\n", strip=True) if cand else None


def fetch_ghdb_scrape(max_pages: int = 1, enrich: bool = False, cap_enrich: int = 50) -> List[Dict[str, Any]]:
    """
    Fallback: scrape list pages; optionally fetch each detail’s dork string.
    """
    items = _fetch_ghdb_index_html(max_pages=max_pages)
    if not enrich or not items:
        return items
    out: List[Dict[str, Any]] = []
    with requests.Session() as s:
        for i, it in enumerate(items):
            if i >= cap_enrich:
                break
            dork = fetch_dork_text(s, it["url"])
            out.append({**it, "dork": dork})
            time.sleep(0.6 + random.uniform(0, 0.4))
    return out


# -----------------------------
# Filtering & Provider
# -----------------------------
def _apply_filters(
    rows: List[Dict[str, Any]],
    category: Optional[str] = None,
    author: Optional[str] = None,
    grep: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Case-insensitive filters:
      - category: substring match against row['category']
      - author:   substring match against row['author']
      - grep:     regex/keyword searched in title OR dork
    """
    if grep:
        try:
            rx = re.compile(grep, re.IGNORECASE)
            grep_fn = lambda s: bool(rx.search(s or ""))
        except re.error:
            needle = grep.lower()
            grep_fn = lambda s: needle in (s or "").lower()
    else:
        grep_fn = lambda s: True  # no-op

    def has(sub: Optional[str], val: Optional[str]) -> bool:
        return True if not sub else (sub.lower() in (val or "").lower())

    out: List[Dict[str, Any]] = []
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
    limit: Optional[int] = None,
    pages: int = 1,
    enrich: bool = False,
    category: Optional[str] = None,
    author: Optional[str] = None,
    grep: Optional[str] = None,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Programmatic entrypoint for CHARLOTTE plugins.

    Example:
        from plugins.intell.google_dorks.dorks import ghdb
        rows = ghdb.query(source="dump", grep="intitle:index.of", category="Files", limit=100)
    """
    if source == "dump":
        rows = fetch_ghdb_dump(limit=None, save_cache=True, debug=debug)
    else:
        rows = fetch_ghdb_scrape(max_pages=max(1, pages), enrich=enrich)

    rows = _apply_filters(rows, category=category, author=author, grep=grep)

    if limit:
        rows = rows[:max(0, int(limit))]
    return rows


# Expose as ghdb.query(...) for CHARLOTTE recon plugins
ghdb = SimpleNamespace(query=ghdb_query)


# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Fetch Google Dorks (GHDB) for CHARLOTTE")
    ap.add_argument("--source", choices=["dump", "scrape"], default="dump",
                    help="Preferred source. 'dump' uses OffSec GHDB XML (recommended).")
    ap.add_argument("--limit", type=int, default=0, help="Max items returned AFTER filtering (0 = no cap)")
    ap.add_argument("--pages", type=int, default=1, help="Pages to scrape (scrape only)")
    ap.add_argument("--enrich", action="store_true", help="Scrape detail pages for dork text (scrape only)")
    ap.add_argument("--category", type=str, default=None, help="Filter by category (substring, case-insensitive)")
    ap.add_argument("--author", type=str, default=None, help="Filter by author (substring, case-insensitive)")
    ap.add_argument("--grep", type=str, default=None, help="Regex/keyword to match title OR dork (case-insensitive)")
    ap.add_argument("--debug", action="store_true", help="Verbose diagnostics for dump/scrape")
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
