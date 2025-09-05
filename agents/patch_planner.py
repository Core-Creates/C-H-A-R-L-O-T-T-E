# ==========================================================================================
# agents/patch_planner.py (portable) — Build ranked patch plans for Windows/Linux/macOS
#
# Backwards-compatible JSON schema; adds safer parsing, optional filters, CSV export,
# normalized maintenance windows, and deterministic ordering.
# ==========================================================================================
from __future__ import annotations

import argparse
import json
import math
import sys
import csv
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

ROOT_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT_DIR / "reports" / "patch_runs"
DATA_DIR = ROOT_DIR / "data"

DEFAULT_TRIAGE = DATA_DIR / "triaged_findings.json"
DEFAULT_ASSETS = (
    DATA_DIR / "assets.json"
)  # {host: {owner, tier, tags, os: 'windows|linux|macos', window: ISO8601|'+8h'}}

# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    cve: str
    asset: str
    epss: float = 0.0
    kev: bool = False
    cvss: float = 0.0
    exposure: str = "internal"
    criticality: str = "tier-2"
    package: str | None = None
    current_version: str | None = None
    fix_version: str | None = None

    @staticmethod
    def _to_float(v: Any, default: float = 0.0) -> float:
        try:
            x = float(v)
            # guard against NaN/inf from weird inputs
            if math.isnan(x) or math.isinf(x):
                return default
            return x
        except Exception:
            return default

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Finding:
        return Finding(
            cve=(d.get("cve") or d.get("CVE") or "").strip(),
            asset=(d.get("asset") or d.get("host") or "").strip(),
            epss=Finding._to_float(d.get("epss", 0.0), 0.0),
            kev=bool(d.get("kev", False)),
            cvss=Finding._to_float(d.get("cvss", 0.0), 0.0),
            exposure=str(d.get("exposure") or "internal").lower(),
            criticality=str(d.get("criticality") or "tier-2").lower(),
            package=d.get("package") or d.get("purl"),
            current_version=d.get("current_version") or d.get("version"),
            fix_version=d.get("fix_version"),
        )


@dataclass
class PlanItem:
    host: str
    cve: str
    kev: bool
    epss: float
    cvss: float
    exposure: str
    criticality: str
    package: str | None
    current_version: str | None
    fix_version: str | None
    ring: int
    window: str
    rollback: str
    os: str | None = None  # 'windows' | 'linux' | 'macos' | None


# ──────────────────────────────────────────────────────────────────────────────
# IO helpers
# ──────────────────────────────────────────────────────────────────────────────


def _read_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _read_json_or_inline(value: str) -> Any:
    """
    If value is a path to a file -> read JSON file; otherwise try to parse inline JSON string.
    """
    p = Path(value)
    if p.exists():
        return _read_json(p)
    return json.loads(value)


def _write_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)


def _write_csv(items: Iterable[PlanItem], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "host",
        "os",
        "cve",
        "ring",
        "window",
        "kev",
        "epss",
        "cvss",
        "exposure",
        "criticality",
        "package",
        "current_version",
        "fix_version",
        "rollback",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for it in items:
            row = asdict(it)
            # keep only listed fields, preserve order
            w.writerow({k: row.get(k) for k in fields})


def load_assets(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = _read_json(path)
    if not isinstance(data, dict):
        return {}
    # normalize keys to strings
    out: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, dict):
            out[k] = v
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Business logic
# ──────────────────────────────────────────────────────────────────────────────


def resolve_fix_version(f: Finding) -> str | None:
    # Stub: integrate OSV/vendor lookups here.
    return f.fix_version or None


def _parse_relative_window(expr: str) -> timedelta | None:
    """
    Accepts simple relative expressions like '+8h', '+2d', '+45m'
    """
    try:
        if not expr.startswith("+"):
            return None
        num = "".join(ch for ch in expr[1:] if ch.isdigit())
        unit = "".join(ch for ch in expr[1:] if not ch.isdigit()).lower()
        if not num or unit not in {"h", "d", "m"}:
            return None
        n = int(num)
        if unit == "h":
            return timedelta(hours=n)
        if unit == "d":
            return timedelta(days=n)
        if unit == "m":
            return timedelta(minutes=n)
    except Exception:
        pass
    return None


def _normalize_window(raw: Any, hours_ahead: int) -> str:
    """
    Return ISO-8601 UTC string. Accepts:
    - ISO 8601/RFC3339 strings (with or without timezone)
    - Relative strings like '+8h', '+2d', '+45m'
    - Otherwise: now + hours_ahead
    """
    now = datetime.now(timezone.utc)
    # Relative?
    if isinstance(raw, str):
        rel = _parse_relative_window(raw.strip())
        if rel is not None:
            return (now + rel).replace(second=0, microsecond=0).isoformat()

        # Try strict parsing via datetime.fromisoformat (Python accepts many RFC3339 forms)
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.replace(second=0, microsecond=0).isoformat()
        except Exception:
            pass

    # Fallback: default offset
    start = (now + timedelta(hours=hours_ahead)).replace(
        minute=0, second=0, microsecond=0
    )
    return start.isoformat()


def maintenance_window(
    host: str, assets: dict[str, dict[str, Any]], hours_ahead: int = 12
) -> str:
    raw = None
    if host in assets and isinstance(assets[host], dict):
        raw = assets[host].get("window")
    return _normalize_window(raw, hours_ahead)


RING_BY_TIER = {"tier-0": 0, "tier-1": 1, "tier-2": 2, "tier-3": 3}


def score_finding(f: Finding) -> float:
    score = 0.0
    score += 1.0 if f.kev else 0.0
    score += f.epss
    score += (max(0.0, min(10.0, f.cvss)) / 10.0) * 0.5
    score += 0.3 if f.exposure == "internet" else 0.0
    if f.criticality == "tier-0":
        score += 0.6
    elif f.criticality == "tier-1":
        score += 0.3
    return round(score, 6)


def assign_ring(f: Finding, ring_by_tier: dict[str, int] | None = None) -> int:
    mapping = ring_by_tier or RING_BY_TIER
    ring = mapping.get(f.criticality, 2)
    try:
        r = int(ring)
    except Exception:
        r = 2
    # keep rings within a sane range for downstream UIs
    return max(0, min(9, r))


def _infer_os(meta: dict[str, Any]) -> str | None:
    raw = str(meta.get("os") or meta.get("platform") or "").lower()
    if not raw:
        return None
    if raw.startswith("win"):
        return "windows"
    if raw in {"darwin", "mac", "macos", "osx"}:
        return "macos"
    return "linux"


def build_plan(
    findings: list[Finding],
    assets: dict[str, dict[str, Any]],
    min_epss: float = 0.0,
    kev_only: bool = False,
    ring_by_tier: dict[str, int] | None = None,
    hours_ahead: int = 12,
    dedupe: bool = True,
    exposure_filter: list[str] | None = None,  # e.g. ["internet","dmz"]
    tiers_filter: list[str] | None = None,  # e.g. ["tier-0","tier-1"]
) -> list[PlanItem]:
    exposure_set = {x.lower() for x in (exposure_filter or [])}
    tiers_set = {x.lower() for x in (tiers_filter or [])}

    filtered: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        if kev_only and not f.kev:
            continue
        if f.epss < min_epss:
            continue
        if exposure_set and f.exposure.lower() not in exposure_set:
            continue
        if tiers_set and f.criticality.lower() not in tiers_set:
            continue
        key = (f.asset, f.cve)
        if dedupe and key in seen:
            continue
        seen.add(key)
        filtered.append(f)

    # Resolve fix versions
    for f in filtered:
        f.fix_version = resolve_fix_version(f)

    # Deterministic ordering: primary score desc, then KEV desc, EPSS desc, CVSS desc, asset asc, CVE asc
    filtered.sort(
        key=lambda x: (
            -score_finding(x),
            -(1 if x.kev else 0),
            -x.epss,
            -x.cvss,
            x.asset or "",
            x.cve or "",
        )
    )

    plan: list[PlanItem] = []
    for f in filtered:
        ring = assign_ring(f, ring_by_tier)
        window = maintenance_window(f.asset, assets, hours_ahead=hours_ahead)
        rollback = f"snapshot-{f.asset}" if f.asset else "snapshot"
        host_os = None
        meta = assets.get(f.asset) or {}
        if isinstance(meta, dict):
            host_os = _infer_os(meta)
        plan.append(
            PlanItem(
                host=f.asset,
                cve=f.cve,
                kev=f.kev,
                epss=f.epss,
                cvss=f.cvss,
                exposure=f.exposure,
                criticality=f.criticality,
                package=f.package,
                current_version=f.current_version,
                fix_version=f.fix_version,
                ring=ring,
                window=window,
                rollback=rollback,
                os=host_os,
            )
        )
    return plan


def plan_to_dict(plan: list[PlanItem]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": 2,
        "items": [asdict(p) for p in plan],
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def _read_triage_arg(arg_val: str) -> Any:
    """
    Returns parsed JSON from a file, inline JSON, or STDIN if arg_val == '-'.
    Accepts list[...] or {"items":[...]} shapes.
    """
    try:
        if arg_val == "-":
            raw = sys.stdin.read()
            data = json.loads(raw)
        else:
            p = Path(arg_val)
            data = _read_json(p) if p.exists() else json.loads(arg_val)
    except Exception as e:
        raise SystemExit(f"[!] Failed to read triage data: {e}")

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "items" in data and isinstance(data["items"], list):
        return data["items"]
    # tolerate vendor-ish shapes that wrap under another key
    for k, v in data.items() if isinstance(data, dict) else []:
        if (
            isinstance(v, list)
            and v
            and isinstance(v[0], dict)
            and ("cve" in v[0] or "CVE" in v[0])
        ):
            return v
    raise SystemExit(
        "[!] Triaged data must be a list of findings or an object with 'items': [...]."
    )


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="CHARLOTTE Patch Planner (portable)")
    ap.add_argument(
        "--triage",
        default=str(DEFAULT_TRIAGE),
        help="Path to triaged_findings.json, inline JSON, or '-' for STDIN",
    )
    ap.add_argument(
        "--assets",
        default=str(DEFAULT_ASSETS),
        help="Optional assets.json with OS & windows",
    )
    ap.add_argument(
        "--kev-only", action="store_true", help="Only include CISA KEV items"
    )
    ap.add_argument(
        "--min-epss",
        type=float,
        default=0.0,
        help="Filter out items with EPSS below this",
    )
    ap.add_argument(
        "--ring-map",
        type=str,
        default=None,
        help="JSON mapping tier->ring override (file path or inline JSON)",
    )
    ap.add_argument(
        "--hours-ahead",
        type=int,
        default=12,
        help="Default maintenance window offset hours",
    )
    ap.add_argument(
        "--exposure",
        type=str,
        default=None,
        help="Comma-separated exposure filters (e.g., 'internet,dmz')",
    )
    ap.add_argument(
        "--tiers",
        type=str,
        default=None,
        help="Comma-separated tier filters (e.g., 'tier-0,tier-1')",
    )
    ap.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output path (.json). Default under reports/patch_runs/",
    )
    ap.add_argument(
        "--csv-out", type=str, default=None, help="Optional CSV summary output path"
    )
    ap.add_argument("--sass", action="store_true", help="Sassy console output")
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    # Triaged findings
    triage_items = _read_triage_arg(args.triage)
    findings = [Finding.from_dict(x) for x in triage_items if isinstance(x, dict)]

    # Assets
    assets_path = Path(args.assets)
    assets = load_assets(assets_path)

    # Ring map (file or inline JSON)
    ring_map = None
    if args.ring_map:
        try:
            rm = _read_json_or_inline(args.ring_map)
            if isinstance(rm, dict):
                ring_map = {str(k): int(v) for k, v in rm.items() if isinstance(k, str)}
        except Exception:
            ring_map = None

    exposure_filter = (
        [s.strip() for s in args.exposure.split(",")] if args.exposure else None
    )
    tiers_filter = [s.strip() for s in args.tiers.split(",")] if args.tiers else None

    plan_items = build_plan(
        findings,
        assets,
        min_epss=args.min_epss,
        kev_only=args.kev_only,
        ring_by_tier=ring_map,
        hours_ahead=args.hours_ahead,
        exposure_filter=exposure_filter,
        tiers_filter=tiers_filter,
    )
    plan_doc = plan_to_dict(plan_items)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.out) if args.out else (REPORTS_DIR / f"{ts}_patch_plan.json")
    _write_json(plan_doc, out_path)

    if args.csv_out:
        _write_csv(plan_items, Path(args.csv_out))

    if args.sass:
        print(f" CHARLOTTE conjured a cross-platform patch plan at: {out_path}")
        print(f" {len(plan_doc['items'])} targets queued, OS-aware.")
        if args.csv_out:
            print(f" CSV summary materialized at: {args.csv_out}")
    else:
        print(f"[✓] Patch plan written: {out_path}")
        print(f"[i] Items: {len(plan_doc['items'])}")
        if args.csv_out:
            print(f"[i] CSV summary: {args.csv_out}")


if __name__ == "__main__":
    main()
# ==========================================================================================
# End of file
# ==========================================================================================
