# ******************************************************************************************
# cve_lookup.py - C-H-A-R-L-O-T-T-E CVE Lookup Utility
# Supports NVD-based CVE ID lookups, batch queries, year filtering, keyword search,
# and local caching.
# ******************************************************************************************

import os
import sys
import csv
import json
import requests
from datetime import datetime
from typing import Any

# ------------------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------------------

CACHE_FILE = os.path.join("data", "cve_cache.json")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # optional; improves rate limits


# ------------------------------------------------------------------------------------------
# Cache Management
# ------------------------------------------------------------------------------------------


def load_cache() -> dict[str, Any]:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[WARN] Cache file corrupted. Starting fresh.")
    return {}


def save_cache(cache: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


# ------------------------------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------------------------------


def _nvd_get(params: dict[str, Any]) -> dict[str, Any]:
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()


def _extract_cvss(metrics: dict[str, Any]) -> float | None:
    """Return first available CVSS base score (prefers v3.1 -> v3.0 -> v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            try:
                return metrics[key][0]["cvssData"]["baseScore"]
            except Exception:
                continue
    return None


# ------------------------------------------------------------------------------------------
# Core Lookup Functions (by explicit CVE ID)
# ------------------------------------------------------------------------------------------


def fetch_cve_data(cve_id: str) -> tuple[dict[str, Any], bool]:
    cache = load_cache()
    cve_id = cve_id.upper()

    if cve_id in cache:
        return cache[cve_id], True

    try:
        result = _nvd_get({"cveId": cve_id})
        if "vulnerabilities" in result and result["vulnerabilities"]:
            cve_info = result["vulnerabilities"][0]
            cache[cve_id] = cve_info
            save_cache(cache)
            return cve_info, False
    except Exception as e:
        return {"error": str(e)}, False

    return {"error": "CVE not found"}, False


def fetch_cves_batch(
    cve_ids: list[str], year_filter: str | None = None
) -> dict[str, Any]:
    results = {}
    for cve_id in cve_ids:
        if year_filter and not cve_id.startswith(f"CVE-{year_filter}"):
            continue
        data, _ = fetch_cve_data(cve_id)
        results[cve_id] = data
    return results


# ------------------------------------------------------------------------------------------
# NEW: Keyword Search (used by core.main.run_cve_lookup)
# ------------------------------------------------------------------------------------------


def search_by_keyword(
    keyword: str,
    results_limit: int = 20,
    pub_start_iso: str | None = None,
    pub_end_iso: str | None = None,
    start_index: int = 0,
) -> list[dict[str, Any]]:
    """
    Search CVEs by keyword using the NVD 2.0 API.

    Args:
      keyword: e.g., "ssh", "openssl buffer overflow", "apache httpd"
      results_limit: max results to return (NVD allows up to 2000 per page; we default 20)
      pub_start_iso / pub_end_iso: optional ISO8601 timestamps ("YYYY-MM-DDTHH:MM:SS.000Z")
      start_index: for pagination

    Returns:
      List of dicts: {cve_id, description, published, cvss, url}
    """
    # Cache key for keyword queries (kept small/simple; no TTL logic here)
    cache = load_cache()
    cache_key = (
        f"KW:{keyword}:{results_limit}:{pub_start_iso}:{pub_end_iso}:{start_index}"
    )
    if cache_key in cache:
        return cache[cache_key]

    params: dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": max(1, min(int(results_limit), 2000)),
        "startIndex": max(0, int(start_index)),
    }
    if pub_start_iso:
        params["pubStartDate"] = pub_start_iso
    if pub_end_iso:
        params["pubEndDate"] = pub_end_iso

    try:
        data = _nvd_get(params)
    except Exception as e:
        return [{"error": f"NVD request failed: {e}"}]

    out: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id")
        if not cve_id:
            continue

        desc = ""
        try:
            # Prefer English description if present
            descs = c.get("descriptions", [])
            if descs:
                # find "en" or fallback to first
                d_en = next((d for d in descs if d.get("lang") == "en"), None)
                desc = (d_en or descs[0]).get("value", "")
        except Exception:
            pass

        published = item.get("published") or c.get("published")
        cvss = _extract_cvss(c.get("metrics", {}))
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        out.append(
            {
                "cve_id": cve_id,
                "description": desc,
                "published": published,
                "cvss": cvss,
                "url": url,
            }
        )

    # Save lightweight cache for keyword queries
    cache[cache_key] = out
    save_cache(cache)
    return out


# paste the following helpers anywhere below your other functions in cve_lookup.py


def _normalize_results_for_export(results):
    """
    Accepts either:
      - list of {'cve_id','description','published','cvss','url'} from search_by_keyword()
      - dict: { 'CVE-YYYY-NNNN': full_nvd_obj } from fetch_cves_batch()
    Returns a flat list of dict rows ready for CSV/JSON export & printing.
    """
    rows = []

    # Case 1: keyword search list
    if isinstance(results, list):
        for r in results:
            if not isinstance(r, dict):
                continue
            if "cve_id" in r:  # our keyword search format
                rows.append(
                    {
                        "cve_id": r.get("cve_id", ""),
                        "published": r.get("published", ""),
                        "cvss": r.get("cvss", ""),
                        "description": (r.get("description") or "")
                        .replace("\n", " ")
                        .strip(),
                        "url": r.get("url", ""),
                        "source": "keyword",
                    }
                )
        return rows

    # Case 2: batch dict from fetch_cves_batch()
    if isinstance(results, dict):
        for cve_id, data in results.items():
            if not isinstance(data, dict):
                continue
            if "error" in data:
                rows.append(
                    {
                        "cve_id": cve_id,
                        "published": "",
                        "cvss": "",
                        "description": f"ERROR: {data.get('error')}",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "source": "id_lookup",
                    }
                )
                continue

            cve = (data or {}).get("cve", {})
            desc = ""
            try:
                descs = cve.get("descriptions", [])
                if descs:
                    d_en = next((d for d in descs if d.get("lang") == "en"), None)
                    desc = (d_en or descs[0]).get("value", "")
            except Exception:
                pass

            published = data.get("published") or cve.get("published") or ""
            score = _extract_cvss(cve.get("metrics", {}))
            rows.append(
                {
                    "cve_id": cve.get("id", cve_id),
                    "published": published,
                    "cvss": score if score is not None else "",
                    "description": (desc or "").replace("\n", " ").strip(),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": "id_lookup",
                }
            )
        return rows

    # Fallback: unknown structure
    return rows


def show_and_export(
    results,
    multiple: bool = True,
    outdir: str | None = None,
    filename_prefix: str = "cve_search",
    open_after: bool = False,
) -> None:
    """
    Pretty-print results to console and export CSV/JSON for later pipelines.
    Signature matches how core.main calls it: show_and_export(results, multiple=True)

    Args:
      results: list (keyword search) or dict (id batch)
      multiple: retained for compatibility with your main.py; not used here
      outdir: output dir (default: reports/cve_lookup)
      filename_prefix: base filename used for exports
      open_after: if True on mac/linux/windows, try to open the CSV after writing
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = outdir or os.path.join("reports", "cve_lookup")
    os.makedirs(outdir, exist_ok=True)

    rows = _normalize_results_for_export(results)

    # --- Console table ---
    if not rows:
        print("[!] No results to display.")
    else:
        # column widths
        w_id = 18
        w_pub = 20
        w_cvss = 5
        w_url = 40
        print("=" * 100)
        print(
            f"{'CVE ID':<{w_id}}  {'Published':<{w_pub}}  {'CVSS':>{w_cvss}}  {'URL':<{w_url}}  Description"
        )
        print("-" * 100)
        for r in rows:
            cve_id = (r.get("cve_id") or "")[:w_id]
            published = str(r.get("published") or "")[:w_pub]
            cvss = "" if r.get("cvss") in (None, "") else str(r.get("cvss"))
            url = (r.get("url") or "")[:w_url]
            desc = r.get("description") or ""
            print(
                f"{cve_id:<{w_id}}  {published:<{w_pub}}  {cvss:>{w_cvss}}  {url:<{w_url}}  {desc}"
            )
        print("=" * 100)

    # --- Exports ---
    csv_path = os.path.join(outdir, f"{filename_prefix}_{ts}.csv")
    json_path = os.path.join(outdir, f"{filename_prefix}_{ts}.json")

    try:
        # CSV
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "cve_id",
                    "published",
                    "cvss",
                    "description",
                    "url",
                    "source",
                ],
            )
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        # JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)

        print(f"[✓] Exported {len(rows)} result(s)")
        print(f"    • CSV : {csv_path}")
        print(f"    • JSON: {json_path}")

        if open_after:
            try:
                if os.name == "nt":
                    os.startfile(csv_path)  # type: ignore[attr-defined]
                elif sys.platform == "darwin":
                    os.system(f'open "{csv_path}"')
                else:
                    os.system(f'xdg-open "{csv_path}"')
            except Exception:
                pass
    except Exception as e:
        print(f"[!] Export failed: {e}")


# ------------------------------------------------------------------------------------------
# Summary Formatter
# ------------------------------------------------------------------------------------------


def summarize_cve(cve_data: dict[str, Any]) -> str:
    try:
        if "error" in cve_data:
            return f"[!] Error: {cve_data['error']}"

        cve_id = cve_data["cve"]["id"]
        description = cve_data["cve"]["descriptions"][0]["value"]
        published = cve_data.get("published", "N/A")
        cvss = "N/A"

        metrics = cve_data["cve"].get("metrics", {})
        score = _extract_cvss(metrics)
        if score is not None:
            cvss = score

        return f"🔍 {cve_id}:\n📅 Published: {published}\n🎯 CVSS Score: {cvss}\n📝 {description}\n"
    except Exception as e:
        return f"[!] Failed to summarize CVE: {str(e)}"


# ------------------------------------------------------------------------------------------
# Optional CLI Entry Point
# ------------------------------------------------------------------------------------------


def run(args: dict[str, Any]):
    """
    CLI-compatible entry:
      - If 'keyword' in args: run keyword search
      - Else if 'cve' in args: fetch those CVE IDs (optionally filtered by 'year')
    """
    keyword = (args or {}).get("keyword")
    if keyword:
        limit = int((args or {}).get("limit", 20))
        # Default to open-ended range unless caller supplies timestamps
        results = search_by_keyword(keyword, results_limit=limit)
        if not results:
            return "[!] No results."
        lines = ["═" * 60]
        for r in results:
            if "error" in r:
                lines.append(f"[!] Error: {r['error']}")
                continue
            lines.append(f"{r['cve_id']}  (CVSS: {r.get('cvss', 'N/A')})")
            lines.append(f"Published: {r.get('published', 'N/A')}")
            lines.append(r.get("description", "").strip())
            lines.append(r.get("url", ""))
            lines.append("─" * 60)
        return "\n".join(lines)

    cve_arg = (args or {}).get("cve")
    year = (args or {}).get("year")

    if not cve_arg:
        return "[!] Provide 'keyword' or one/more CVE IDs using 'cve'."

    cve_ids = [cid.strip().upper() for cid in str(cve_arg).split(",") if cid.strip()]
    results = fetch_cves_batch(cve_ids, year_filter=year)
    output = []
    for cid, data in results.items():
        output.append("═" * 60)
        output.append(summarize_cve(data))
    return "\n".join(output)


# ------------------------------------------------------------------------------------------
# Standalone Test Mode
# ------------------------------------------------------------------------------------------

if __name__ == "__main__":
    print("🔎 CHARLOTTE CVE Lookup Tool")
    mode = input("Search mode? [id/keyword] ").strip().lower() or "id"

    if mode.startswith("k"):
        kw = input("Enter keyword (e.g., ssh, openssl): ").strip()
        limit = input("Limit (default 20): ").strip()
        limit = int(limit) if limit.isdigit() else 20
        results = search_by_keyword(kw, results_limit=limit)
        for r in results:
            print("═" * 60)
            if "error" in r:
                print(f"[!] Error: {r['error']}")
                continue
            print(f"{r['cve_id']}  (CVSS: {r.get('cvss', 'N/A')})")
            print(f"Published: {r.get('published', 'N/A')}")
            print(r.get("description", ""))
            print(r.get("url", ""))
    else:
        ids_input = input("Enter CVE ID(s) (comma-separated or just numbers): ").strip()
        year = input(
            "Filter by year (optional, required if using just numbers): "
        ).strip()

        cve_ids = []
        for c in ids_input.split(","):
            c = c.strip()
            if not c:
                continue
            if c.upper().startswith("CVE-"):
                cve_ids.append(c.upper())
            elif c.isdigit():
                if not year:
                    print(f"[!] Year required for short CVE ID '{c}'. Skipping.")
                    continue
                cve_ids.append(f"CVE-{year}-{c.zfill(4)}")
            else:
                print(f"[!] Invalid CVE ID format: '{c}'. Skipping.")

        results = fetch_cves_batch(cve_ids, year_filter=year or None)
        for cid, data in results.items():
            print("═" * 60)
            print(summarize_cve(data))

# ------------------------------------------------------------------------------------------
# This module is designed to be imported and used by the main application.
# The `run` function provides a CLI-compatible entry point.
# ------------------------------------------------------------------------------------------
