# ==========================================================================================
# plugins/agents/patch_executor.py  —  Execute patch plans with canaries + rollback stubs
#
# PURPOSE
#   • Read a patch plan JSON produced by patch_planner.py
#   • Roll out by rings with a canary wave, bake period, and promotion
#   • Verify service health; auto-rollback stub on failure
#   • Respect per-item maintenance windows unless --ignore-windows
#   • Emit CSV/JSON run reports under reports/patch_runs/<ts>/
#
# BACKENDS (adapters)
#   • "noop"      : dry executor for demos/tests
#   • "ansible"   : shell out to ansible-playbook (stub call)
#   • "ssm"       : AWS SSM Patch Manager (stub call)
#   • "winupdate" : Windows Update API or PSRemoting (stub call)
#   • "shell"     : local shell commands on target (stub call)
#
#   NOTE: All adapters are stubs. Replace with real calls for your environment.
#   This is a skeleton. Replace adapter stubs with real calls for your environment.
# ==========================================================================================

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[2]  # .../C-H-A-R-L-O-T-T-E
REPORTS_DIR = ROOT_DIR / "reports" / "patch_runs"
PAUSE_FILE = "PAUSE"  # if this file exists in the run dir, stop before promoting

# ──────────────────────────────────────────────────────────────────────────────
# Pretty logger (w/ optional sass)
# ──────────────────────────────────────────────────────────────────────────────
class Log:
    def __init__(self, sass: bool = False):
        self.sass = sass
    def info(self, msg: str): print(f"{'🖤 ' if self.sass else ''}{msg}")
    def ok(self, msg: str): print(f"{'✅ ' if not self.sass else '🔮 '}{msg}")
    def warn(self, msg: str): print(f"{'⚠️  ' if not self.sass else '🕯️ '}"+msg)
    def err(self, msg: str): print(f"{'❌ ' if not self.sass else '☠️  '}"+msg)

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
    window: str
    rollback: str

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PlanItem":
        return PlanItem(
            host=d["host"],
            cve=d["cve"],
            kev=bool(d.get("kev", False)),
            epss=float(d.get("epss", 0.0) or 0.0),
            cvss=float(d.get("cvss", 0.0) or 0.0),
            exposure=d.get("exposure", "internal"),
            criticality=d.get("criticality", "tier-2"),
            package=d.get("package"),
            current_version=d.get("current_version"),
            fix_version=d.get("fix_version"),
            ring=int(d.get("ring", 2)),
            window=d.get("window"),
            rollback=d.get("rollback", f"snapshot-{d.get('host','host')}")
        )

# ──────────────────────────────────────────────────────────────────────────────
# I/O
# ──────────────────────────────────────────────────────────────────────────────

def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────────────

def _stable_canary_select(hosts: List[str], fraction: float, seed: str) -> List[str]:
    """Deterministic selection: hash(host+seed), pick lowest scores until quota."""
    n = max(1, int(round(len(hosts) * max(0.0, min(fraction, 1.0)))))
    scored = []
    for h in hosts:
        hv = hashlib.sha256((h + seed).encode("utf-8")).hexdigest()
        scored.append((int(hv[:8], 16), h))
    scored.sort(key=lambda x: x[0])
    return [h for _, h in scored[:n]]


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> str:
    return _now_dt().isoformat()


# ──────────────────────────────────────────────────────────────────────────────
# Health Checks (stubs)
# ──────────────────────────────────────────────────────────────────────────────

def run_health_checks(host: str, timeout_s: int = 60) -> bool:
    """Replace with real service probes, SLI checks, and log scans."""
    time.sleep(min(timeout_s, 2))  # simulate a quick probe
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Rollback (stub)
# ──────────────────────────────────────────────────────────────────────────────

def rollback_host(host: str, handle: str, backend: str) -> bool:
    # Implement snapshot revert, package downgrade, or AMI rollback here
    print(f"[↩] Rolling back {host} via {backend} using {handle} …")
    time.sleep(1)
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Adapters (stubs) — replace with your environment's real implementations
# ──────────────────────────────────────────────────────────────────────────────

def apply_patch(host: str, item: PlanItem, backend: str, dry_run: bool = False) -> Tuple[bool, str]:
    if dry_run or backend == "noop":
        return True, "noop"
    if backend == "ansible":
        # Example: ansible-playbook -l host patch.yml -e cve=CVE-... -e pkg=openssl-3.0.15
        print(f"[ansible] Would patch {host} pkg={item.package} fix={item.fix_version} cve={item.cve}")
        return True, "ansible-stub"
    if backend == "ssm":
        print(f"[ssm] Would start SSM Patch for {host} (baseline/override TBD)")
        return True, "ssm-stub"
    if backend == "winupdate":
        print(f"[winupdate] Would invoke Windows Update for {host} (KB mapping TBD)")
        return True, "winupdate-stub"
    if backend == "shell":
        print(f"[shell] Would run host-local commands to update {item.package}")
        return True, "shell-stub"
    return False, f"unknown-backend:{backend}"


# ──────────────────────────────────────────────────────────────────────────────
# Execution Engine
# ──────────────────────────────────────────────────────────────────────────────

def _items_for_host(items: List[PlanItem], host: str) -> List[PlanItem]:
    return [i for i in items if i.host == host]


def _sleep_minutes_responsive(minutes: int, pause_path: Path, log: Log):
    deadline = time.time() + (minutes * 60)
    while time.time() < deadline:
        if pause_path.exists():
            log.warn(f"Pause file detected: {pause_path}. Halting bake.")
            break
        time.sleep(5)


def _execute_hosts(hosts: List[str], items: List[PlanItem], backend: str, dry_run: bool, health_timeout: int, report_rows: List[Dict[str, Any]], log: Log) -> bool:
    all_ok = True
    for h in hosts:
        start = time.time()
        ok_all_findings = True
        for it in _items_for_host(items, h):
            ok, adapter = apply_patch(h, it, backend, dry_run)
            status = "success" if ok else "failed"
            report_rows.append({
                "ts": _now(), "host": h, "cve": it.cve, "ring": it.ring, "backend": adapter,
                "status": status, "kev": it.kev, "epss": it.epss, "fix_version": it.fix_version or "",
            })
            if not ok:
                ok_all_findings = False
        # Health check per-host after applying all items for that host
        if ok_all_findings:
            if not run_health_checks(h, timeout_s=health_timeout):
                ok_all_findings = False
                report_rows.append({"ts": _now(), "host": h, "cve": "*", "ring": it.ring, "backend": "health", "status": "failed"})
        dur = round(time.time() - start, 3)
        report_rows.append({"ts": _now(), "host": h, "metric": "apply_duration_s", "value": dur})
        if ok_all_findings:
            log.ok(f"Host {h} patched and healthy in {dur}s.")
        else:
            log.err(f"Host {h} failed health checks; marked for rollback.")
        all_ok = all_ok and ok_all_findings
    return all_ok


def _rollback_hosts(hosts: List[str], items: List[PlanItem], backend: str, report_rows: List[Dict[str, Any]], log: Log):
    for h in hosts:
        for it in _items_for_host(items, h):
            ok = rollback_host(h, it.rollback, backend)
            report_rows.append({
                "ts": _now(), "host": h, "cve": it.cve, "ring": it.ring, "backend": "rollback",
                "status": "success" if ok else "failed"
            })
            if ok:
                log.warn(f"Rolled back {h} for {it.cve}.")
            else:
                log.err(f"Rollback FAILED for {h} / {it.cve}. Investigate immediately.")


def _filter_by_window(items: List[PlanItem], ignore_windows: bool, log: Log) -> List[PlanItem]:
    if ignore_windows:
        return items
    now = _now_dt()
    ready = [i for i in items if not i.window or datetime.fromisoformat(i.window).astimezone(timezone.utc) <= now]
    skipped = [i for i in items if i not in ready]
    for it in skipped:
        log.info(f"Skipping {it.host} / {it.cve} until window {it.window}")
    return ready


def execute_ring(
    items: List[PlanItem],
    backend: str,
    dry_run: bool,
    canary_fraction: float,
    bake_minutes: int,
    health_timeout: int,
    pause_path: Path,
    report_rows: List[Dict[str, Any]],
    log: Log,
    ignore_windows: bool,
) -> bool:
    if not items:
        return True

    ring_id = items[0].ring
    items = _filter_by_window(items, ignore_windows, log)
    hosts = sorted({i.host for i in items})
    if not hosts:
        log.warn(f"Ring {ring_id}: no hosts ready within window.")
        return True

    seed = f"ring{ring_id}-{_now()}"
    canaries = _stable_canary_select(hosts, canary_fraction, seed)
    rest = [h for h in hosts if h not in canaries]

    log.info(f"Ring {ring_id}: hosts={len(hosts)}, canaries={len(canaries)} ({canary_fraction*100:.0f}%)")

    # 1) Canary wave
    if not _execute_hosts(canaries, items, backend, dry_run, health_timeout, report_rows, log):
        log.err(f"Canary failures in ring {ring_id}; aborting ring and initiating rollbacks.")
        _rollback_hosts(canaries, items, backend, report_rows, log)
        return False

    # Bake period before full promotion
    log.info(f"Bake for {bake_minutes} minutes before promoting ring {ring_id}… (create PAUSE file in run dir to halt)")
    _sleep_minutes_responsive(bake_minutes, pause_path, log)

    if pause_path.exists():
        log.warn(f"Pause file detected at {pause_path}. Aborting promotion.")
        return False

    # 2) Full ring
    ok = _execute_hosts(rest, items, backend, dry_run, health_timeout, report_rows, log)
    if not ok:
        log.err(f"Failures during ring {ring_id} promotion; initiating partial rollbacks.")
        _rollback_hosts(rest, items, backend, report_rows, log)
        return False

    return True


# ──────────────────────────────────────────────────────────────────────────────
# Run Wrapper
# ──────────────────────────────────────────────────────────────────────────────

def run(plan_path: Path, backend: str, dry_run: bool, canary: float, bake_minutes: int, health_timeout: int, ring_limit: Optional[List[int]] = None, sass: bool = False, ignore_windows: bool = False) -> Path:
    plan_doc = _read_json(plan_path)
    items = [PlanItem.from_dict(x) for x in plan_doc.get("items", [])]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = REPORTS_DIR / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    log = Log(sass=sass)
    pause_path = run_dir / PAUSE_FILE
    rows: List[Dict[str, Any]] = []
    success = True

    # Execute by ring order
    rings = sorted({i.ring for i in items})
    for r in rings:
        if ring_limit and r not in ring_limit:
            continue
        ring_items = [i for i in items if i.ring == r]
        ok = execute_ring(ring_items, backend, dry_run, canary, bake_minutes, health_timeout, pause_path, rows, log, ignore_windows)
        if not ok:
            success = False
            break

    # Write reports
    _write_json({"plan": plan_path.name, "success": success, "rows": rows}, run_dir / "run_report.json")
    with open(run_dir / "PATCH_REPORT.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=sorted({k for row in rows for k in row.keys()}))
        w.writeheader(); w.writerows(rows)

    if success:
        log.ok(f"Run complete. Artifacts: {run_dir}")
    else:
        log.err(f"Run completed with failures. Artifacts: {run_dir}")
    return run_dir


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="CHARLOTTE Patch Executor")
    ap.add_argument("--plan", required=True, help="Path to patch_plan.json from patch_planner.py")
    ap.add_argument("--backend", default="noop", choices=["noop", "ansible", "ssm", "winupdate", "shell"], help="Execution backend")
    ap.add_argument("--dry-run", action="store_true", help="Do not actually patch; simulate only")
    ap.add_argument("--canary", type=float, default=0.05, help="Fraction of hosts for canary wave (0.0-1.0)")
    ap.add_argument("--bake-minutes", type=int, default=30, help="Bake period between canary and promotion")
    ap.add_argument("--health-timeout", type=int, default=60, help="Per-host health check timeout seconds")
    ap.add_argument("--rings", type=str, default=None, help="Comma-separated subset of rings to run, e.g. 0,1")
    ap.add_argument("--sass", action="store_true", help="Enable CHARLOTTE’s no-nonsense sass in logs")
    ap.add_argument("--ignore-windows", action="store_true", help="Ignore maintenance windows in plan items")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    plan_path = Path(args.plan)
    if not plan_path.exists():
        raise SystemExit(f"[!] Plan not found: {plan_path}")
    ring_subset = [int(x) for x in args.rings.split(",")] if args.rings else None
    run(plan_path, backend=args.backend, dry_run=args.dry_run, canary=args.canary, bake_minutes=args.bake_minutes, health_timeout=args.health_timeout, ring_limit=ring_subset, sass=args.sass, ignore_windows=args.ignore_windows)


if __name__ == "__main__":
    main()
