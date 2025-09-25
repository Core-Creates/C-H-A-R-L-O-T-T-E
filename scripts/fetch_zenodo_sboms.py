#!/usr/bin/env python3
"""
fetch_zenodo_sboms.py

Download SBOM archives (or any files) from Zenodo records.

Usage examples:
  # Download files attached to a single record
  python scripts/fetch_zenodo_sboms.py --record 1234567 --outdir data/zenodo

  # Search Zenodo for "sbom" and download the first 10 matching records' files (file types .json/.zip)
  python scripts/fetch_zenodo_sboms.py --query sbom --max-records 10 --file-ext json,zip --outdir data/zenodo

Notes:
- Zenodo API docs: https://developers.zenodo.org/ (the script uses the public zenodo.org API)
- Respect licensing for any SBOMs you download. This script does not change or redistribute licenses.
"""

from __future__ import annotations
import argparse
import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm

ZENODO_BASE = "https://zenodo.org"
ZENODO_API_RECORD = ZENODO_BASE + "/api/records/{id}"
ZENODO_API_SEARCH = ZENODO_BASE + "/api/records/"

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger(__name__)


def requests_session_with_retries(
    total_retries: int = 5, backoff: float = 0.3
) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=total_retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    return s


def fetch_record_metadata(
    record_id: str, session: requests.Session | None = None
) -> dict:
    """
    Fetch metadata for a given Zenodo record ID (numerical ID or doi-like).
    """
    s = session or requests_session_with_retries()
    url = ZENODO_API_RECORD.format(id=record_id)
    log.info("Fetching Zenodo record metadata: %s", url)
    resp = s.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def search_zenodo(
    query: str,
    page_size: int = 20,
    max_records: int = 100,
    session: requests.Session | None = None,
) -> list[dict]:
    """
    Search Zenodo for records matching `query`. Returns list of record metadata dicts (up to max_records).
    """
    s = session or requests_session_with_retries()
    results: list[dict] = []
    page = 1
    per_page = min(page_size, 100)
    while len(results) < max_records:
        params = {"q": query, "size": per_page, "page": page}
        log.info("Searching Zenodo: q=%s page=%d size=%d", query, page, per_page)
        resp = s.get(ZENODO_API_SEARCH, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break
        results.extend(hits)
        if len(hits) < per_page:
            break
        page += 1
    return results[:max_records]


def choose_files_from_record(
    record: dict, allowed_exts: list[str] | None = None
) -> list[dict]:
    """
    From a record metadata dict, return list of file dicts that match allowed_exts.
    Each file dict has keys like: 'key', 'links', 'checksum', 'id', 'files' etc.
    """
    files = record.get("files", []) or []
    if not allowed_exts:
        return files
    allowed_exts_lower = [e.lower().lstrip(".") for e in allowed_exts]
    chosen = []
    for f in files:
        fname = f.get("key", "")
        ext = Path(fname).suffix.lower().lstrip(".")
        if ext in allowed_exts_lower:
            chosen.append(f)
    return chosen


def parse_zenodo_checksum(checksum_str: str) -> tuple[str, str]:
    """
    Zenodo stores checksum strings like 'md5:abcd1234...' or 'sha256:...'
    Returns tuple (algo, hexdigest)
    """
    if not checksum_str:
        return ("", "")
    if ":" in checksum_str:
        algo, hexv = checksum_str.split(":", 1)
        return algo.lower(), hexv.lower()
    # default assume sha256 if unknown (not guaranteed)
    return ("sha256", checksum_str.lower())


def download_file(
    url: str,
    outpath: Path,
    session: requests.Session,
    checksum: tuple[str, str] | None = None,
    chunk_size: int = 1024 * 64,
    max_retries: int = 4,
) -> tuple[bool, str | None]:
    """
    Download a file with streaming, progress bar, and optional checksum verification.
    Returns (success, error_msg_or_none)
    """
    outpath.parent.mkdir(parents=True, exist_ok=True)
    # attempt with retries (simple loop)
    attempt = 0
    last_err = None
    while attempt < max_retries:
        attempt += 1
        try:
            with session.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                total = int(r.headers.get("Content-Length") or 0)
                # compute hash if requested
                hasher = None
                algo_name = None
                if checksum and checksum[0]:
                    algo_name = checksum[0].lower()
                    try:
                        hasher = hashlib.new(algo_name)
                    except Exception:
                        hasher = None
                        algo_name = None

                tmp_out = outpath.with_suffix(outpath.suffix + ".part")
                with open(tmp_out, "wb") as fh, tqdm(
                    total=total,
                    unit="B",
                    unit_scale=True,
                    desc=outpath.name,
                    leave=True,
                ) as pbar:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        pbar.update(len(chunk))
                        if hasher:
                            hasher.update(chunk)
                # finalize: verify checksum if present
                if hasher and checksum and checksum[1]:
                    hexdigest = hasher.hexdigest().lower()
                    expected = checksum[1].lower()
                    if hexdigest != expected:
                        last_err = f"checksum mismatch for {outpath.name}: expected {expected} got {hexdigest}"
                        log.warning(last_err)
                        tmp_out.unlink(missing_ok=True)
                        # retry after short backoff
                        time.sleep(2**attempt)
                        continue
                # move tmp to final
                tmp_out.replace(outpath)
                return (True, None)
        except requests.HTTPError as e:
            last_err = f"HTTP error: {e}"
            log.warning("Attempt %d/%d failed: %s", attempt, max_retries, last_err)
            time.sleep(2**attempt)
            continue
        except Exception as e:
            last_err = f"Error: {e}"
            log.warning("Attempt %d/%d failed: %s", attempt, max_retries, last_err)
            time.sleep(2**attempt)
            continue
    return (False, last_err)


def download_files_concurrent(
    items: list[tuple[dict, dict]], outdir: Path, workers: int = 4
) -> list[dict]:
    """
    items: list of (record_meta, file_meta) tuples
    outdir: base output dir
    Returns list of result dicts {record_id, filename, path, success, error}
    """
    session = requests_session_with_retries()
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for rec, fmeta in items:
            rec_id = (
                rec.get("id")
                or rec.get("conceptdoi")
                or rec.get("doi")
                or str(rec.get("record_id", "unknown"))
            )
            filename = fmeta.get("key")
            if not filename:
                continue
            outpath = outdir / f"{rec_id}" / filename
            checksum = None
            if fmeta.get("checksum"):
                checksum = parse_zenodo_checksum(fmeta.get("checksum"))
            url = fmeta.get("links", {}).get("download") or fmeta.get("links", {}).get(
                "self"
            )
            if not url:
                log.warning("No download link for %s in record %s", filename, rec_id)
                results.append(
                    {
                        "record": rec_id,
                        "filename": filename,
                        "path": None,
                        "success": False,
                        "error": "no-download-link",
                    }
                )
                continue
            fut = ex.submit(download_file, url, outpath, session, checksum)
            futures[fut] = {"record": rec_id, "filename": filename, "outpath": outpath}
        for fut in as_completed(futures):
            meta = futures[fut]
            ok, err = fut.result()
            results.append(
                {
                    "record": meta["record"],
                    "filename": meta["filename"],
                    "path": str(meta["outpath"]) if ok else None,
                    "success": ok,
                    "error": err,
                }
            )
            if ok:
                log.info("Downloaded: %s/%s", meta["record"], meta["filename"])
            else:
                log.error("Failed: %s/%s -> %s", meta["record"], meta["filename"], err)
    return results


def build_item_list_from_records(
    records: list[dict], allowed_exts: list[str] | None = None
) -> list[tuple[dict, dict]]:
    """
    From a list of record metadata dicts, collect (record, file_meta) pairs for files we want to download.
    """
    items = []
    for rec in records:
        files = choose_files_from_record(rec, allowed_exts)
        if not files:
            continue
        for f in files:
            items.append((rec, f))
    return items


def is_likely_sbom_filename(name: str) -> bool:
    name = name.lower()
    sbom_exts = (
        ".json",
        ".xml",
        ".spdx",
        ".cyclonedx",
        ".cdx",
        ".sbom",
        ".zip",
        ".tar.gz",
        ".tgz",
    )
    return (
        any(name.endswith(e) for e in sbom_exts)
        or "sbom" in name
        or "cyclonedx" in name
        or "spdx" in name
    )


def main():
    p = argparse.ArgumentParser(description="Fetch SBOM files from Zenodo records.")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--record", help="Zenodo record ID to fetch (numeric id).")
    grp.add_argument(
        "--query",
        help="Zenodo search query (e.g. 'sbom') to find records to download from.",
    )
    p.add_argument(
        "--max-records",
        type=int,
        default=20,
        help="Max number of records to process for search queries.",
    )
    p.add_argument(
        "--file-ext",
        help="Comma-separated list of file extensions to download (e.g. json,zip). If omitted, attempts to download files with SBOM-like names.",
    )
    p.add_argument(
        "--outdir", default="data/zenodo", help="Directory to save downloaded files."
    )
    p.add_argument("--workers", type=int, default=4, help="Parallel download workers.")
    p.add_argument(
        "--page-size",
        type=int,
        default=20,
        help="Zenodo search page size (when --query used).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Only list files that would be downloaded.",
    )
    p.add_argument(
        "--sandbox",
        action="store_true",
        help="Use Zenodo sandbox (developer/testing) - toggles base URL (not implemented for search).",
    )
    args = p.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    sess = requests_session_with_retries()

    records = []
    if args.record:
        # support passing DOI-like values too (Zenodo accepts numeric id in endpoint)
        try:
            rec_meta = fetch_record_metadata(args.record, session=sess)
            records = [rec_meta]
        except requests.HTTPError as e:
            log.error("Failed to fetch record %s: %s", args.record, e)
            return
    else:
        # search mode
        records = search_zenodo(
            args.query or "",
            page_size=args.page_size,
            max_records=args.max_records,
            session=sess,
        )
        log.info("Found %d records from search", len(records))

    # Decide allowed extensions
    allowed_exts = None
    if args.file_ext:
        allowed_exts = [
            e.strip().lstrip(".") for e in args.file_ext.split(",") if e.strip()
        ]

    # Build list of candidate files
    items = build_item_list_from_records(records, allowed_exts)
    # If file_ext not specified, filter by heuristic SBOM filenames
    if not allowed_exts:
        items = [
            (r, f) for (r, f) in items if is_likely_sbom_filename(f.get("key", ""))
        ]

    if not items:
        log.warning("No files found to download (try --file-ext or a different query).")
        return

    # dry run -> just print
    if args.dry_run:
        log.info("Dry run: listing candidate files:")
        for rec, f in items:
            rec_id = (
                rec.get("id") or rec.get("doi") or rec.get("conceptdoi") or "unknown"
            )
            print(f"{rec_id} -> {f.get('key')} ({f.get('links',{}).get('download')})")
        return

    log.info(
        "Preparing to download %d file(s) using %d workers", len(items), args.workers
    )
    results = download_files_concurrent(items, outdir, workers=args.workers)

    # Summary
    success = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    log.info("Download summary: %d succeeded, %d failed", len(success), len(failed))
    if failed:
        log.info("Failed downloads (sample):")
        for r in failed[:10]:
            log.info("  %s/%s -> %s", r["record"], r["filename"], r["error"])


if __name__ == "__main__":
    main()
