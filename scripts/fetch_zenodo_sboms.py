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
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

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
        allowed_methods=frozenset(["GET", "POST", "HEAD"]),
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
    Handles multi-part suffixes like '.tar.gz' and common shorthands like 'tgz'.
    Each file dict has keys like: 'key', 'links', 'checksum', 'id', 'files' etc.
    """
    files = record.get("files", []) or []
    if not allowed_exts:
        return files

    # Normalize allowed extensions: strip dots, lower-case
    requested = [e.lower().lstrip(".") for e in allowed_exts]
    norm = set()
    for e in requested:
        # map shorthand/synonyms and include related archive/container forms
        if e in {"tgz", "tar.gz"}:
            norm.update({"tgz", "tar.gz", "tar"})
        elif e == "tar":
            norm.update({"tar", "tgz", "tar.gz"})
        elif e in {"json", "xml", "cyclonedx", "spdx", "cdx"}:
            # SBOM-like formats may be distributed inside archives
            norm.update({e, "zip", "tgz", "tar.gz", "tar"})
        else:
            norm.add(e)

    chosen: list[dict] = []
    for f in files:
        fname = (f.get("key") or "").lower()

        # Build multi-suffix string (e.g. ['.tar', '.gz'] -> 'tar.gz')
        suffixes = "".join(Path(fname).suffixes).lower().lstrip(".")
        # last suffix (e.g. 'gz' from 'file.tar.gz' or 'zip' from file.zip)
        last = Path(fname).suffix.lower().lstrip(".")

        candidates = {suffixes, last}

        matched = False
        for a in norm:
            if a in candidates:
                matched = True
                break
            # fallback endswith check for robustness (handles weird filenames)
            if fname.endswith("." + a):
                matched = True
                break

        if matched:
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


def _probe_url_is_ok(url: str, session: requests.Session, timeout: int = 15) -> bool:
    """
    Probe a url with HEAD (or fallback GET) to check if it's likely usable for download.
    Returns True if we get HTTP 2xx/3xx or a bytes response from a lightweight GET.
    """
    try:
        head = session.head(url, allow_redirects=True, timeout=timeout)
        if 200 <= head.status_code < 400:
            return True
        # Some endpoints disallow HEAD and return 405; try a tiny GET
        if head.status_code in (405, 501):
            r = session.get(url, stream=True, timeout=timeout)
            # read one chunk then cancel
            for _ in r.iter_content(chunk_size=64):
                break
            r.close()
            if 200 <= r.status_code < 400:
                return True
    except Exception:
        # any exception counts as "not OK" here
        return False
    return False


def resolve_download_url(
    fmeta: dict, rec_id: str, session: requests.Session
) -> str | None:
    """
    Robustly determine a usable download URL for a file metadata object.
    Tries:
      1) fmeta['links']['download']
      2) fmeta['links']['self']
      3) constructed record-file public URL(s):
         - https://zenodo.org/record/{rec_id}/files/{filename}?download=1
         - https://zenodo.org/record/{rec_id}/files/{filename}
    Returns the usable URL (string) or None.
    """
    links = fmeta.get("links", {}) or {}
    # direct download link if present
    for key in ("download", "self"):
        url = links.get(key)
        if url:
            # quick probe to ensure it's usable
            if _probe_url_is_ok(url, session):
                return url

    # fallback: attempt the public record-file URL patterns
    filename = fmeta.get("key") or ""
    if not filename:
        return None
    # URL-encode filename to be safe
    quoted = quote(filename, safe="")
    candidates = [
        f"{ZENODO_BASE}/record/{rec_id}/files/{quoted}?download=1",
        f"{ZENODO_BASE}/record/{rec_id}/files/{quoted}",
    ]
    for cand in candidates:
        if _probe_url_is_ok(cand, session):
            return cand

    return None


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
                return True, None
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
    return False, last_err


def download_files_concurrent(
    items: list[tuple[dict, dict]], outdir: Path, workers: int = 4
) -> list[dict]:
    """
    items: list of (record_meta, file_meta) tuples
    outdir: base output dir
    Returns list of result dicts {record_id, filename, path, success, error}
    """
    session = requests_session_with_retries()
    results: list[dict] = []
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

            # Resolve a usable download URL (robust to missing 'download' key)
            url = resolve_download_url(fmeta, rec_id, session)
            if not url:
                log.warning(
                    "No download link (or fallback) for %s in record %s",
                    filename,
                    rec_id,
                )
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
    items: list[tuple[dict, dict]] = []
    for rec in records:
        files = choose_files_from_record(rec, allowed_exts)
        if not files:
            continue
        for f in files:
            items.append((rec, f))
    return items


def is_likely_sbom_filename(name: str) -> bool:
    name = (name or "").lower()
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
        ".tar",
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
    p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Assume yes to prompt and download without asking (useful for CI/non-interactive runs).",
    )
    args = p.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    sess = requests_session_with_retries()

    records: list[dict] = []
    if args.record:
        # support passing DOI-like values too (Zenodo accepts numeric id in endpoint)
        try:
            rec_meta = fetch_record_metadata(args.record, session=sess)
            records = [rec_meta]
        except requests.HTTPError as e:
            log.error("Failed to fetch record %s: %s", args.record, e)
            return
    else:
        # search mode: get lightweight hits first, then fetch full record metadata per hit
        hits = search_zenodo(
            args.query or "",
            page_size=args.page_size,
            max_records=args.max_records,
            session=sess,
        )
        log.info("Found %d search hits from Zenodo", len(hits))

        # Expand each hit to full record metadata so file download links are available.
        records = []
        for hit in hits:
            # Most hits contain numeric 'id'
            rec_id = hit.get("id") or hit.get("record_id") or hit.get("recordId")
            if not rec_id:
                # If the hit already looks like a full record, accept it
                records.append(hit)
                continue
            try:
                full = fetch_record_metadata(rec_id, session=sess)
                records.append(full)
                # be a little polite with the API
                time.sleep(0.05)
            except Exception as e:
                log.warning(
                    "Failed to fetch full metadata for record %s: %s", rec_id, e
                )
        log.info("Collected %d full record metadata objects", len(records))

    # Decide allowed extensions
    allowed_exts: list[str] | None = None
    if args.file_ext:
        # parse user-provided extensions and expand to include related archive/container forms
        requested = [
            e.strip().lstrip(".").lower() for e in args.file_ext.split(",") if e.strip()
        ]
        expanded = set()
        for r in requested:
            expanded.add(r)
            # If user asked for xml/json or SBOM-ish formats, also accept common archives that may contain SBOMs
            if r in {"json", "xml", "cyclonedx", "spdx", "cdx"}:
                expanded.update({"zip", "tgz", "tar.gz", "tar"})
            # map shorthand/synonyms for tar family
            if r == "tgz":
                expanded.update({"tar.gz", "tar", "tgz"})
            if r == "tar.gz":
                expanded.update({"tgz", "tar", "tar.gz"})
            if r == "tar":
                expanded.update({"tgz", "tar.gz", "tar"})
        allowed_exts = list(expanded)
        log.info(
            "Requesting extensions: %s -> expanded to: %s",
            ", ".join(requested),
            ", ".join(sorted(allowed_exts)),
        )

    # Build list of candidate files (respect explicit allowed_exts when they match)
    items = build_item_list_from_records(records, allowed_exts)

    # If caller didn't specify file-ext, apply the heuristic to filter SBOM-like names
    if not allowed_exts:
        items = [
            (r, f) for (r, f) in items if is_likely_sbom_filename(f.get("key", ""))
        ]

    # If user specified allowed_exts but nothing matched, fall back to heuristic
    if allowed_exts and not items:
        log.warning(
            "Requested extensions (%s) produced no matches. Falling back to filename heuristic to find likely SBOMs.",
            ", ".join(sorted(allowed_exts)),
        )
        all_items = build_item_list_from_records(records, None)
        heuristic_items = [
            (r, f) for (r, f) in all_items if is_likely_sbom_filename(f.get("key", ""))
        ]
        if heuristic_items:
            log.info(
                "Found %d candidate files via heuristic fallback.", len(heuristic_items)
            )
            items = heuristic_items
        else:
            log.warning(
                "Fallback heuristic also found no likely SBOM files. Example record file lists:"
            )
            for rec in records[:5]:
                rec_id = (
                    rec.get("id")
                    or rec.get("doi")
                    or rec.get("conceptdoi")
                    or "unknown"
                )
                filenames = [f.get("key") for f in (rec.get("files") or [])]
                log.info("  Record %s -> %s", rec_id, filenames[:8])
            # items remains empty and will trigger the no-files warning below

    if not items:
        log.warning("No files found to download (try --file-ext or a different query).")
        return

    # dry run -> just print (and show resolved download URL if available)
    if args.dry_run:
        log.info("Dry run: listing candidate files:")
        for rec, f in items:
            rec_id = (
                rec.get("id") or rec.get("doi") or rec.get("conceptdoi") or "unknown"
            )
            resolved = resolve_download_url(f, rec_id, sess)
            if resolved:
                print(f"{rec_id} -> {f.get('key')} ({resolved})")
            else:
                # show possible fallbacks to help troubleshooting
                filename = f.get("key") or ""
                quoted = quote(filename, safe="")
                candidates = [
                    f"{ZENODO_BASE}/record/{rec_id}/files/{quoted}?download=1",
                    f"{ZENODO_BASE}/record/{rec_id}/files/{quoted}",
                ]
                print(
                    f"{rec_id} -> {f.get('key')} (no direct link; tried: {candidates})"
                )
        return

    # Interactive confirmation before downloading (unless --yes/-y provided)
    if not args.yes:
        if sys.stdin.isatty():
            try:
                resp = (
                    input(
                        f"Found {len(items)} candidate file(s). Download now? [y/N]: "
                    )
                    .strip()
                    .lower()
                )
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                log.info("User declined download. Exiting.")
                return
        else:
            log.warning(
                "Non-interactive session and --yes not provided. Aborting without downloading."
            )
            return

    # Proceed to download
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


# ==============================================================================
# End of fetch_zenodo_sboms.py
# ===============================================================================
