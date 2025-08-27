# ==========================================================================================
# agents/patch_planner.py  —  Build ranked patch plans from CHARLOTTE triage output
#
# PURPOSE
#   • Consume triage findings (CVEs, EPSS/KEV, asset criticality/exposure)
#   • Compute priority scores & assign rollout rings
#   • Attach maintenance windows & (optional) fix-version hints
#   • Emit a patch plan JSON consumable by patch_executor.py
#
# DESIGN NOTES
#   • Safe-by-default; won’t mutate anything. Produces plan files under reports/patch_runs/
#   • Plug points (stubs): resolve_fix_version(), maintenance_window(), load_assets()
#   • Compatible with CHARLOTTE repo layout; runnable as a standalone script too.
# ==========================================================================================

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Repo root helpers (tolerate running from anywhere)
# ──────────────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[1]  # .../C-H-A-R-L-O-T-T-E
REPORTS_DIR = ROOT_DIR / "reports" / "patch_runs"
DATA_DIR = ROOT_DIR / "data"

DEFAULT_TRIAGE = DATA_DIR / "triaged_findings.json"
DEFAULT_ASSETS = DATA_DIR / "assets.json"  # optional; structure: {host: {owner,tier,tags,...}}

# ──────────────────────────────────────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    cve: str
    asset: str
    epss: float = 0.0
    kev: bool = False
    cvss: float = 0.0
    exposure: str = "internal"   # "internet" | "internal"
    criticality: str = "tier-2"   # "tier-0" | "tier-1" | "tier-2" | "tier-3"
    package: Optional[str] = None  # purl or package name
    current_version: Optional[str] = None
    fix_version: Optional[str] = None  # may be filled by resolver

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Finding":
        return Finding(
            cve=d.get("cve") or d.get("CVE") or "",
            asset=d.get("asset") or d.get("host") or "",
            epss=float(d.get("epss", 0.0) or 0.0),
            kev=bool(d.get("kev", False)),
            cvss=float(d.get("cvss", 0.0) or 0.0),
            exposure=(d.get("exposure") or "internal").lower(),
            criticality=(d.get("criticality") or "tier-2").lower(),
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
    package: Optional[str]
    current_version: Optional[str]
    fix_version: Optional[str]
    ring: int
    window: str      # ISO8601
    rollback: str    # snapshot or backup handle (advisory)

# ──────────────────────────────────────────────────────────────────────────────
# I/O Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)


# ──────────────────────────────────────────────────────────────────────────────
# Asset & Fix Enrichment (stubs you can replace)
# ──────────────────────────────────────────────────────────────────────────────

def load_assets(path: Path) -> Dict[str, Dict[str, Any]]:
    """Optional CMDB/asset registry: {host: {owner, tier, tags, ...}}"""
    if not path.exists():
        return {}
    data = _read_json(path)
    return data if isinstance(data, dict) else {}


def resolve_fix_version(f: Finding) -> Optional[str]:
    """
    Stub: Resolve a fix version for a (package, cve) pair.
    Replace with:
      • OSV API lookup (purls in SBOM/lockfiles)
      • Vendor advisories (e.g., for Windows, RHEL, Ubuntu, etc.)
    Return a string like "openssl-3.0.15" or "apt:openssl>=1.1.1w-3".
    """
    return f.fix_version or None


def maintenance_window(host: str, assets: Dict[str, Dict[str, Any]], hours_ahead: int = 12) -> str:
    """Return next available window ISO time. Default: now + 12h at :00 minutes.
    If assets[host]['window'] exists, prefer that (ISO8601).
    """
    now = datetime.now(timezone.utc)
    if host in assets and isinstance(assets[host], dict):
        w = assets[host].get("window")
        if isinstance(w, str) and w:
            return w
    start = (now + timedelta(hours=hours_ahead)).replace(minute=0, second=0, microsecond=0)
    return start.isoformat()


# ──────────────────────────────────────────────────────────────────────────────
# Scoring & Ring Assignment
# ──────────────────────────────────────────────────────────────────────────────
RING_BY_TIER = {  # default mapping; override via CLI if desired
    "tier-0": 0,  # crown jewels → earliest but with manual gates
    "tier-1": 1,
    "tier-2": 2,
    "tier-3": 3,
}


def score_finding(f: Finding) -> float:
    # Simple, explainable score. Tweak weights as needed.
    score = 0.0
    score += 1.0 if f.kev else 0.0   # KEV gets a fixed boost
    score += f.epss                   # probability of exploitation
    score += (f.cvss / 10.0) * 0.5    # normalize CVSS weight
    score += 0.3 if f.exposure == "internet" else 0.0
    # Critical tiers bubble up (higher = more urgent)
    if f.criticality == "tier-0":
        score += 0.6
    elif f.criticality == "tier-1":
        score += 0.3
    return round(score, 6)


def assign_ring(f: Finding, ring_by_tier: Dict[str, int] = None) -> int:
    mapping = ring_by_tier or RING_BY_TIER
    return int(mapping.get(f.criticality, 2))


# ──────────────────────────────────────────────────────────────────────────────
# Planning
# ──────────────────────────────────────────────────────────────────────────────

def build_plan(
    findings: List[Finding],
    assets: Dict[str, Dict[str, Any]],
    min_epss: float = 0.0,
    kev_only: bool = False,
    ring_by_tier: Optional[Dict[str, int]] = None,
    hours_ahead: int = 12,
    dedupe: bool = True,
) -> List[PlanItem]:
    # Filter
    filtered: List[Finding] = []
    seen: set[Tuple[str, str]] = set()
    for f in findings:
        if kev_only and not f.kev:
            continue
        if f.epss < min_epss:
            continue
        key = (f.asset, f.cve)
        if dedupe and key in seen:
            continue
        seen.add(key)
        filtered.append(f)

    # Enrich fix versions & score
    for f in filtered:
        f.fix_version = resolve_fix_version(f)
    filtered.sort(key=score_finding, reverse=True)

    # Emit plan items
    plan: List[PlanItem] = []
    for f in filtered:
        ring = assign_ring(f, ring_by_tier)
        window = maintenance_window(f.asset, assets, hours_ahead=hours_ahead)
        rollback = f"snapshot-{f.asset}"
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
            )
        )
    return plan


def plan_to_dict(plan: List[PlanItem]) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "items": [p.__dict__ for p in plan],
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="CHARLOTTE Patch Planner")
    ap.add_argument("--triage", default=str(DEFAULT_TRIAGE), help="Path to triaged_findings.json")
    ap.add_argument("--assets", default=str(DEFAULT_ASSETS), help="Optional assets.json for windows/owners")
    ap.add_argument("--kev-only", action="store_true", help="Only include CISA KEV items")
    ap.add_argument("--min-epss", type=float, default=0.0, help="Filter out items with EPSS below this")
    ap.add_argument("--ring-map", type=str, default=None, help="JSON mapping of tier->ring to override defaults")
    ap.add_argument("--hours-ahead", type=int, default=12, help="Default maintenance window offset hours")
    ap.add_argument("--out", type=str, default=None, help="Output path (.json). Default under reports/patch_runs/")
    ap.add_argument("--sass", action="store_true", help="Add a little CHARLOTTE attitude to console output")
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    triage_path = Path(args.triage)
    assets_path = Path(args.assets)

    if not triage_path.exists():
        raise SystemExit(f"[!] Triaged findings not found: {triage_path}")

    triage_raw = _read_json(triage_path)
    findings = [Finding.from_dict(x) for x in (triage_raw if isinstance(triage_raw, list) else triage_raw.get("items", []))]

    assets = load_assets(assets_path)

    ring_map = None
    if args.ring_map:
        rm_path = Path(args.ring_map)
        ring_map = _read_json(rm_path)
        if not isinstance(ring_map, dict):
            ring_map = None

    plan_items = build_plan(findings, assets, min_epss=args.min_epss, kev_only=args.kev_only, ring_by_tier=ring_map, hours_ahead=args.hours_ahead)
    plan_doc = plan_to_dict(plan_items)

    # Where to write
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    default_out = REPORTS_DIR / f"{ts}_patch_plan.json"
    out_path = Path(args.out) if args.out else default_out

    _write_json(plan_doc, out_path)
    if args.sass:
        print(f"🔮 CHARLOTTE forged your patch ritual at: {out_path}")
        print(f"🧮 Counted {len(plan_doc['items'])} offerings to appease the CVE gods.")
    else:
        print(f"[✓] Patch plan written: {out_path}")
        print(f"[i] Items: {len(plan_doc['items'])}")


if __name__ == "__main__":
    main()
