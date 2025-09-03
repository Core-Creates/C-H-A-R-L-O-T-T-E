# ******************************************************************************************
# netmon.py — Lightweight bandwidth & CPU monitor (optional psutil)
# ******************************************************************************************
from __future__ import annotations
import threading, time
from typing import Dict, Optional

try:
    import psutil  # type: ignore
except Exception:  # soft dep
    psutil = None  # type: ignore

class BandwidthMonitor:
    """
    Samples per-interface network usage and CPU% (if psutil is available).
    Exposes:
      - read() -> {"iface","bps_in","bps_out","idle_bps"}
      - utilization() -> float  (0..1)
      - cpu_percent() -> float
    Config keys (dict):
      - link_bps: int (default 100_000_000)
      - interfaces: [ { "name": "auto" | "<iface>" } ]
    """
    def __init__(self, cfg: Dict):
        self.cfg = cfg or {}
        self._lock = threading.Lock()
        self._run = False
        link_bps = int(self.cfg.get("link_bps", 100_000_000))
        self._state = {"iface": "unknown", "bps_in": 0, "bps_out": 0, "idle_bps": link_bps}
        self._cpu = 0.0

        # pick configured iface if provided (else 'auto')
        ifaces = self.cfg.get("interfaces", [])
        if ifaces and isinstance(ifaces, list):
            name = (ifaces[0] or {}).get("name")
            if name and name != "auto":
                self._state["iface"] = name

    def start(self):
        if not psutil:
            # degraded mode: keep static idle_bps, zero traffic; CPU stays 0.0
            return
        self._run = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self._run = False

    def read(self) -> Dict:
        with self._lock:
            return dict(self._state)

    def cpu_percent(self) -> float:
        return float(self._cpu)

    def utilization(self) -> float:
        s = self.read()
        total = (s["bps_in"] + s["bps_out"] + s["idle_bps"]) or 1
        return 1.0 - (s["idle_bps"] / total)

    # --------------------------------------------------------------------------------------
    def _loop(self):
        iface = self._state["iface"]
        if iface == "unknown":
            iface = self._pick_iface()

        pernic_prev = psutil.net_io_counters(pernic=True)
        prev = pernic_prev.get(iface)
        if prev is None:
            return
        prev_total = prev.bytes_recv + prev.bytes_sent

        link_bps = int(self.cfg.get("link_bps", 100_000_000))

        while self._run:
            time.sleep(1.0)
            try:
                self._cpu = psutil.cpu_percent(interval=None)
                pernic = psutil.net_io_counters(pernic=True)
                cur = pernic.get(iface)
                if cur is None:
                    continue
                cur_total = cur.bytes_recv + cur.bytes_sent
                delta = max(0, cur_total - prev_total)
                prev_total = cur_total
                bps = delta  # bytes/s at 1s cadence
                idle = max(0, link_bps - bps)
                with self._lock:
                    self._state = {
                        "iface": iface,
                        "bps_in": max(0, cur.bytes_recv - prev.bytes_recv),
                        "bps_out": max(0, cur.bytes_sent - prev.bytes_sent),
                        "idle_bps": idle,
                    }
                prev = cur
            except Exception:
                # keep thread alive; state will be from last good sample
                pass

    def _pick_iface(self) -> str:
        if not psutil:
            return "unknown"
        per = psutil.net_io_counters(pernic=True)
        best = "lo"
        best_bytes = -1
        for n, s in per.items():
            if n.lower() in ("lo", "loopback"):
                continue
            total = getattr(s, "bytes_sent", 0) + getattr(s, "bytes_recv", 0)
            if total > best_bytes:
                best = n
                best_bytes = total
        return best
