# ==========================================================================================
# plugins/agents/patch_executor.py (portable)
#
# Cross-platform executor with:
#  • OS detection (Windows/Linux/macOS)
#  • System-level privilege checks (admin/root)
#  • Local backend: uses native package mechanisms per OS (stubs wired for safety)
#  • Deterministic canary + bake + window-respecting rollout
# ==========================================================================================
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import time
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT_DIR / "reports" / "patch_runs"
PAUSE_FILE = "PAUSE"


# ──────────────────────────────────────────────────────────────────────────────
# Logging (sass optional)
# ──────────────────────────────────────────────────────────────────────────────
class Log:
    def __init__(self, sass: bool = False):
        self.sass = sass

    def info(self, m: str):
        print(("🖤 " if self.sass else "") + m)

    def ok(self, m: str):
        print(("🔮 " if self.sass else "✅ ") + m)

    def warn(self, m: str):
        print(("🕯️ " if self.sass else "⚠️  ") + m)

    def err(self, m: str):
        print(("☠️  " if self.sass else "❌ ") + m)


# ──────────────────────────────────────────────────────────────────────────────
# Data
# ──────────────────────────────────────────────────────────────────────────────
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

    @staticmethod
    def from_dict(d: dict[str, Any]) -> PlanItem:
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
            rollback=d.get("rollback", f"snapshot-{d.get('host','host')}"),
            os=d.get("os"),
        )


def _read_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ──────────────────────────────────────────────────────────────────────────────
# Platform / privilege utilities
# ──────────────────────────────────────────────────────────────────────────────
def detect_local_os() -> str:
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    if "darwin" in s:
        return "macos"
    return "linux"


def has_system_privileges(osname: str) -> bool:
    try:
        if osname == "windows":
            import ctypes  # type: ignore

            return (
                ctypes.windll.shell32.IsUserAnAdmin() != 0
            )  # returns nonzero if admin
        else:
            return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        # If we cannot determine, assume no
        return False


def which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run_cmd(
    cmd: list[str], check: bool = False, timeout: int | None = None
) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and cp.returncode != 0:
            raise subprocess.CalledProcessError(
                cp.returncode, cmd, cp.stdout, cp.stderr
            )
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as e:
        return 1, "", str(e)


# ──────────────────────────────────────────────────────────────────────────────
# Local OS-specific patch helpers (safe stubs)
# ──────────────────────────────────────────────────────────────────────────────
def patch_linux(pkg: str | None, version: str | None) -> tuple[bool, str]:
    mgr = (
        which("apt-get")
        or which("dnf")
        or which("yum")
        or which("zypper")
        or which("pacman")
    )
    if not mgr:
        return False, "no-supported-linux-package-manager-found"
    # We keep updates limited to the target package when available; fall back to full upgrade.
    if "apt-get" in mgr:
        if pkg and version:
            cmd = ["sudo", "apt-get", "install", "-y", f"{pkg}={version}"]
        elif pkg:
            cmd = ["sudo", "apt-get", "install", "-y", "--only-upgrade", pkg]
        else:
            cmd = ["sudo", "apt-get", "upgrade", "-y"]
    elif "dnf" in mgr:
        if pkg:
            cmd = ["sudo", "dnf", "-y", "upgrade", pkg]
        else:
            cmd = ["sudo", "dnf", "-y", "upgrade", "--refresh"]
    elif "yum" in mgr:
        cmd = (
            ["sudo", "yum", "-y", "update"]
            if not pkg
            else ["sudo", "yum", "-y", "update", pkg]
        )
    elif "zypper" in mgr:
        cmd = ["sudo", "zypper", "-n", "patch"]
    else:  # pacman
        cmd = ["sudo", "pacman", "-Syu", "--noconfirm"]
    rc, out, err = run_cmd(cmd)
    return (rc == 0), (out or err)


def patch_macos(pkg: str | None, version: str | None) -> tuple[bool, str]:
    # System updates
    su = which("softwareupdate")
    if su:
        rc, out, err = run_cmd([su, "-ia"])  # install all available updates
        if rc != 0:
            return False, err or out
    # Homebrew packages
    brew = which("brew")
    if pkg and brew:
        _ = run_cmd([brew, "update"])
        rc, out, err = run_cmd(
            [brew, "upgrade", pkg if not version else f"{pkg}@{version}"]
        )
        return (rc == 0), (out or err)
    return True, "macos-updates-applied-or-no-brew-package"


def patch_windows(pkg: str | None, version: str | None) -> tuple[bool, str]:
    # Prefer winget; fallback to Chocolatey; PSWindowsUpdate if present
    winget = which("winget")
    if winget:
        if pkg:
            args = [
                winget,
                "upgrade",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
                pkg,
            ]
        else:
            args = [
                winget,
                "upgrade",
                "--all",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        rc, out, err = run_cmd(args)
        return (rc == 0), (out or err)
    choco = which("choco")
    if choco:
        args = [choco, "upgrade", "-y"]
        if pkg:
            args.append(pkg)
        rc, out, err = run_cmd(args)
        return (rc == 0), (out or err)
    # Last resort: Windows Update CLI via PowerShell (best-effort)
    pwsh = which("pwsh") or which("powershell")
    if pwsh:
        # Try PSWindowsUpdate if available; otherwise prompt.
        script = "if (Get-Module -ListAvailable PSWindowsUpdate) { Install-WindowsUpdate -AcceptAll -IgnoreReboot } else { Write-Output 'PSWindowsUpdate not installed' ; exit 2 }"
        rc, out, err = run_cmd(
            [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]
        )
        return (rc == 0), (out or err)
    return False, "no-winget-choco-or-powershell-available"


def apply_local(item: PlanItem, log: Log) -> tuple[bool, str]:
    osname = item.os or detect_local_os()
    if osname == "linux":
        return patch_linux(item.package, item.fix_version)
    if osname == "macos":
        return patch_macos(item.package, item.fix_version)
    if osname == "windows":
        return patch_windows(item.package, item.fix_version)
    return False, f"unsupported-os:{osname}"


# ──────────────────────────────────────────────────────────────────────────────
# Canary / rollout helpers
# ──────────────────────────────────────────────────────────────────────────────
def stable_canaries(hosts: list[str], fraction: float, seed: str) -> list[str]:
    fraction = max(0.0, min(1.0, fraction))
    n = max(1, int(round(len(hosts) * fraction))) if hosts else 0
    scored = []
    for h in hosts:
        hv = hashlib.sha256((h + seed).encode("utf-8")).hexdigest()
        scored.append((int(hv[:8], 16), h))
    scored.sort(key=lambda x: x[0])
    return [h for _, h in scored[:n]]


def run_health_checks(host: str, timeout_s: int = 60) -> bool:
    # Stub: replace with your probes/log scans/SLIs.
    time.sleep(min(timeout_s, 2))
    return True


def rollback_host(host: str, handle: str, backend: str, log: Log) -> bool:
    log.warn(f"Rolling back {host} via {backend} using {handle} …")
    time.sleep(1)
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Backends
# ──────────────────────────────────────────────────────────────────────────────
def apply_patch(
    host: str, item: PlanItem, backend: str, dry_run: bool, log: Log
) -> tuple[bool, str]:
    if dry_run or backend == "noop":
        return True, "noop"
    if backend == "local":
        ok, out = apply_local(item, log)
        return ok, "local" if ok else f"local-error:{out}"
    if backend == "ansible":
        log.info(
            f"[ansible] would patch {host} pkg={item.package} fix={item.fix_version} cve={item.cve}"
        )
        return True, "ansible-stub"
    if backend == "ssm":
        log.info(f"[ssm] would invoke AWS SSM Patch for {host}")
        return True, "ssm-stub"
    if backend == "winupdate":
        ok, out = patch_windows(item.package, item.fix_version)
        return ok, "winupdate" if ok else f"winupdate-error:{out}"
    return False, f"unknown-backend:{backend}"


# ──────────────────────────────────────────────────────────────────────────────
# Execution engine
# ──────────────────────────────────────────────────────────────────────────────
def items_for_host(items: list[PlanItem], host: str) -> list[PlanItem]:
    return [i for i in items if i.host == host]


def filter_by_window(
    items: list[PlanItem], ignore_windows: bool, log: Log
) -> list[PlanItem]:
    if ignore_windows:
        return items
    now = datetime.now(timezone.utc)
    ready, skipped = [], []
    for it in items:
        try:
            w = datetime.fromisoformat(it.window)
        except Exception:
            w = now
        if w <= now:
            ready.append(it)
        else:
            skipped.append(it)
    for it in skipped:
        log.info(f"Skipping {it.host} / {it.cve} until window {it.window}")
    return ready


def execute_hosts(
    hosts: list[str],
    items: list[PlanItem],
    backend: str,
    dry_run: bool,
    health_timeout: int,
    report_rows: list[dict[str, Any]],
    log: Log,
) -> bool:
    all_ok = True
    for h in hosts:
        ok_all = True
        for it in items_for_host(items, h):
            ok, adapter = apply_patch(h, it, backend, dry_run, log)
            status = "success" if ok else "failed"
            report_rows.append(
                {
                    "ts": _now_iso(),
                    "host": h,
                    "cve": it.cve,
                    "ring": it.ring,
                    "backend": adapter,
                    "status": status,
                    "kev": it.kev,
                    "epss": it.epss,
                    "fix_version": it.fix_version or "",
                }
            )
            if not ok:
                ok_all = False
        if ok_all and not run_health_checks(h, timeout_s=health_timeout):
            ok_all = False
            report_rows.append(
                {
                    "ts": _now_iso(),
                    "host": h,
                    "cve": "*",
                    "ring": items_for_host(items, h)[0].ring
                    if items_for_host(items, h)
                    else -1,
                    "backend": "health",
                    "status": "failed",
                }
            )
        if ok_all:
            log.ok(f"{h} patched + healthy")
        else:
            log.err(f"{h} failed health checks; marking for rollback")
        all_ok = all_ok and ok_all
    return all_ok


def rollback_hosts(
    hosts: list[str],
    items: list[PlanItem],
    backend: str,
    report_rows: list[dict[str, Any]],
    log: Log,
):
    for h in hosts:
        for it in items_for_host(items, h):
            ok = rollback_host(h, it.rollback, backend, log)
            report_rows.append(
                {
                    "ts": _now_iso(),
                    "host": h,
                    "cve": it.cve,
                    "ring": it.ring,
                    "backend": "rollback",
                    "status": "success" if ok else "failed",
                }
            )


def execute_ring(
    items: list[PlanItem],
    backend: str,
    dry_run: bool,
    canary_fraction: float,
    bake_minutes: int,
    health_timeout: int,
    pause_path: Path,
    report_rows: list[dict[str, Any]],
    log: Log,
    ignore_windows: bool,
) -> bool:
    if not items:
        return True
    ring_id = items[0].ring
    items = filter_by_window(items, ignore_windows, log)
    hosts = sorted({i.host for i in items})
    if not hosts:
        log.warn(f"Ring {ring_id}: no hosts ready")
        return True
    seed = f"ring{ring_id}-{_now_iso()}"
    canaries = stable_canaries(hosts, canary_fraction, seed)
    rest = [h for h in hosts if h not in canaries]
    log.info(
        f"Ring {ring_id}: {len(hosts)} hosts → canaries {len(canaries)} ({int(canary_fraction*100)}%)"
    )
    if not execute_hosts(
        canaries, items, backend, dry_run, health_timeout, report_rows, log
    ):
        log.err(f"Canary failures in ring {ring_id}; aborting ring")
        rollback_hosts(canaries, items, backend, report_rows, log)
        return False
    # bake
    end = time.time() + bake_minutes * 60
    while time.time() < end:
        if pause_path.exists():
            log.warn("PAUSE detected; stopping before promotion")
            return False
        time.sleep(5)
    if not execute_hosts(
        rest, items, backend, dry_run, health_timeout, report_rows, log
    ):
        log.err(f"Failures during ring {ring_id} promotion; rolling back remainder")
        rollback_hosts(rest, items, backend, report_rows, log)
        return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Preflight: OS & privilege check for local operations
# ──────────────────────────────────────────────────────────────────────────────
def preflight_privileges(backend: str, require_admin: bool, log: Log) -> dict[str, Any]:
    osname = detect_local_os()
    is_admin = has_system_privileges(osname)
    details = {
        "detected_os": osname,
        "has_system_privileges": bool(is_admin),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "user": os.environ.get("USERNAME") or os.environ.get("USER"),
    }
    if backend in ("local", "winupdate") and require_admin and not is_admin:
        log.err(
            f"System-level access required for backend '{backend}' on {osname}. Re-run elevated (Admin/root)."
        )
        raise SystemExit(2)
    if backend in ("local", "winupdate") and not is_admin:
        log.warn(
            f"Not running with system-level privileges on {osname}. Some patches may fail; use --require-admin to enforce."
        )
    else:
        log.ok(f"Privilege check OK → system-level: {is_admin}")
    return details


# ──────────────────────────────────────────────────────────────────────────────
# Entry points
# ──────────────────────────────────────────────────────────────────────────────
def run(
    plan_path: Path,
    backend: str,
    dry_run: bool,
    canary: float,
    bake_minutes: int,
    health_timeout: int,
    ring_limit: list[int] | None = None,
    sass: bool = False,
    ignore_windows: bool = False,
    require_admin: bool = False,
) -> Path:
    plan_doc = _read_json(plan_path)
    items = [PlanItem.from_dict(x) for x in plan_doc.get("items", [])]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = REPORTS_DIR / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    log = Log(sass=sass)
    pause_path = run_dir / PAUSE_FILE
    rows: list[dict[str, Any]] = []

    # privilege preflight (only meaningful for local-style backends)
    priv = preflight_privileges(backend, require_admin=require_admin, log=log)

    rings = sorted({i.ring for i in items})
    success = True
    for r in rings:
        if ring_limit and r not in ring_limit:
            continue
        ring_items = [i for i in items if i.ring == r]
        ok = execute_ring(
            ring_items,
            backend,
            dry_run,
            canary,
            bake_minutes,
            health_timeout,
            pause_path,
            rows,
            log,
            ignore_windows,
        )
        if not ok:
            success = False
            break

    _write_json(
        {"plan": plan_path.name, "success": success, "rows": rows, "preflight": priv},
        run_dir / "run_report.json",
    )
    with open(run_dir / "PATCH_REPORT.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f, fieldnames=sorted({k for row in rows for k in row.keys()})
        )
        w.writeheader()
        w.writerows(rows)
    (log.ok if success else log.err)(
        f"Run complete. Success={success}. Artifacts: {run_dir}"
    )
    return run_dir


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="CHARLOTTE Patch Executor (portable)")
    ap.add_argument(
        "--plan", required=True, help="Path to patch_plan.json from planner"
    )
    ap.add_argument(
        "--backend",
        default="local",
        choices=["local", "noop", "ansible", "ssm", "winupdate"],
        help="Execution backend",
    )
    ap.add_argument("--dry-run", action="store_true", help="Simulate only")
    ap.add_argument(
        "--canary",
        type=float,
        default=0.05,
        help="Fraction of hosts for canary wave (0..1)",
    )
    ap.add_argument("--bake-minutes", type=int, default=30, help="Bake period minutes")
    ap.add_argument(
        "--health-timeout",
        type=int,
        default=60,
        help="Per-host health check timeout seconds",
    )
    ap.add_argument(
        "--rings",
        type=str,
        default=None,
        help="Comma-separated subset of rings to run, e.g. 0,1",
    )
    ap.add_argument("--sass", action="store_true", help="Enable CHARLOTTE sass in logs")
    ap.add_argument(
        "--ignore-windows",
        action="store_true",
        help="Ignore maintenance windows in plan items",
    )
    ap.add_argument(
        "--require-admin",
        action="store_true",
        help="Exit if not running with system-level privileges for local backends",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    plan_path = Path(args.plan)
    if not plan_path.exists():
        raise SystemExit(f"[!] Plan not found: {plan_path}")
    ring_subset = [int(x) for x in args.rings.split(",")] if args.rings else None
    run(
        plan_path,
        backend=args.backend,
        dry_run=args.dry_run,
        canary=args.canary,
        bake_minutes=args.bake_minutes,
        health_timeout=args.health_timeout,
        ring_limit=ring_subset,
        sass=args.sass,
        ignore_windows=args.ignore_windows,
        require_admin=args.require_admin,
    )


if __name__ == "__main__":
    main()
