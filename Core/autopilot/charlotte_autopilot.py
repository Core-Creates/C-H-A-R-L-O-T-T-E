# ******************************************************************************************
# charlotte_autopilot.py — Bandwidth-aware autonomous Issue Finder
# ******************************************************************************************
from __future__ import annotations
import time, threading, concurrent.futures, logging
from typing import Dict, Any, List, Optional

from rate_limit import TokenBucketLimiter
from netmon import BandwidthMonitor
from issues import Issue

# Optional detectors; import if present
_DETECTOR_BUILDERS = []
try:
    from detectors.log_anomaly import LogAnomalyDetector  # type: ignore
    _DETECTOR_BUILDERS.append(("log_anomaly", LogAnomalyDetector))
except Exception:
    pass

try:
    from detectors.port_exposure import PortExposureDetector  # type: ignore
    _DETECTOR_BUILDERS.append(("port_exposure", PortExposureDetector))
except Exception:
    pass

try:
    from detectors.port_probe import PortProbeDetector  # type: ignore
    _DETECTOR_BUILDERS.append(("port_probe", PortProbeDetector))
except Exception:
    pass


class AutoPilot:
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.logger = logger.getChild("autopilot")
        self.cfg = cfg or {}

        self._running = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Scheduler
        self.tick_seconds = max(1, int(self.cfg.get("scheduler", {}).get("tick_seconds", 5)))
        self.max_workers = int(self.cfg.get("scheduler", {}).get("max_concurrent_detectors", 2))
        self.pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="ap-det"
        )

        # Bandwidth
        self.net_fraction = float(self.cfg.get("net_utilization_max", 0.35))
        self.netmon = BandwidthMonitor(self.cfg)
        self.limiter = TokenBucketLimiter(rate_bps=1_000_000, capacity_bytes=4_000_000)  # (re)set dynamically
        self._last_rate = 0

        # Adaptive backoff
        self.adaptive = self.cfg.get(
            "adaptive_backoff",
            {"cpu_hot_percent": 85, "net_hot_utilization": 0.70, "scale_factor": 2.0},
        )

        # Detectors
        dconf = self.cfg.get("detectors", {}) or {}
        self.detectors: Dict[str, Any] = {}
        for key, builder in _DETECTOR_BUILDERS:
            conf = dconf.get(key) or {}
            if conf.get("enabled"):
                try:
                    if "limiter" in builder.__init__.__code__.co_varnames:
                        det = builder(conf, limiter=self.limiter, netmon=self.netmon, logger=self.logger)
                    elif "logger" in builder.__init__.__code__.co_varnames:
                        det = builder(conf, logger=self.logger)
                    else:
                        det = builder(conf)
                    self.detectors[key] = det
                except Exception as e:
                    self.logger.warning("Skipping detector %s: %s", key, e)

        # timings per-detector
        self.intervals: Dict[str, float] = {
            name: self._parse_interval((dconf.get(name) or {}).get("interval", "5m"))
            for name in self.detectors
        }
        self.cd_spans: Dict[str, float] = {
            name: self._parse_interval((dconf.get(name) or {}).get("cooldown", "0s"))
            for name in self.detectors
        }
        self.cooldowns: Dict[str, float] = {name: 0.0 for name in self.detectors}

        self._last_cycle = 0.0

    # ------------------------------- Public API -------------------------------------------
    def start(self):
        if self._running.is_set():
            return
        self._stop.clear()
        self._running.set()
        self.netmon.start()
        self._thread = threading.Thread(target=self._loop, name="autopilot", daemon=True)
        self._thread.start()
        self.logger.info("Autopilot started")

    def stop(self):
        if not self._running.is_set():
            return
        self._stop.set()
        self._running.clear()
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.netmon.stop()
        self.logger.info("Autopilot stopped")

    def status(self) -> Dict[str, Any]:
        bw = self.netmon.read()
        return {
            "running": self._running.is_set(),
            "tick_seconds": self.tick_seconds,
            "max_workers": getattr(self.pool, "_max_workers", self.max_workers),
            "net_fraction": self.net_fraction,
            "limiter_rate_bps": self._last_rate,
            "iface": bw.get("iface", "unknown"),
            "idle_bps": bw.get("idle_bps", 0),
            "utilization": self.netmon.utilization(),
            "detectors": {k: (v.metrics() if hasattr(v, "metrics") else {}) for k, v in self.detectors.items()},
        }

    def metrics(self) -> Dict[str, Any]:
        return self.status()

    def set_net_fraction(self, f: float):
        self.net_fraction = max(0.05, min(0.9, float(f)))

    # ------------------------------- Loop --------------------------------------------------
    def _loop(self):
        try:
            while not self._stop.is_set():
                start = time.time()
                self._recalc_limiter()
                self._schedule_due()

                self._last_cycle = start
                elapsed = time.time() - start
                remaining = max(0.0, self.tick_seconds - elapsed)
                if remaining:
                    self._stop.wait(remaining)
        finally:
            # nothing to tear down here; netmon stopped in stop()
            pass

    def _recalc_limiter(self):
        bw = self.netmon.read() or {}
        headroom_bps = max(0, int(bw.get("idle_bps", 0)))
        rate = max(50_000, int(headroom_bps * float(self.net_fraction)))  # never below 50 kbps
        cap = max(rate * 4, 2_000_000)
        self.limiter.reset(rate_bps=rate, capacity_bytes=cap)
        self._last_rate = rate

    def _schedule_due(self):
        now = time.time()
        cpu_hot = self.netmon.cpu_percent() >= float(self.adaptive.get("cpu_hot_percent", 85))
        net_hot = self.netmon.utilization() >= float(self.adaptive.get("net_hot_utilization", 0.70))
        scale = float(self.adaptive.get("scale_factor", 2.0)) if (cpu_hot or net_hot) else 1.0

        for name, det in self.detectors.items():
            interval = float(self.intervals.get(name, 300.0)) * scale
            cooldown = float(self.cd_spans.get(name, 0.0))
            last = float(getattr(det, "_last_run", 0.0))
            if (now - last) < interval:
                continue
            if (now - float(self.cooldowns.get(name, 0.0))) < cooldown:
                continue

            self.cooldowns[name] = now
            try:
                self.pool.submit(self._run_detector_safe, name, det)
            except RuntimeError:
                break  # shutting down

    def _run_detector_safe(self, name: str, det):
        try:
            setattr(det, "_last_run", time.time())
            issues: List[Issue] = (det.run() or [])
            for issue in issues:
                self._handle_issue(name, issue)
        except Exception as e:
            self.logger.exception("Detector %s failed: %s", name, e)

    def _handle_issue(self, source: str, issue: Issue):
        self.logger.warning("[ISSUE] %s: %s (sev=%s) — hint=%s",
                            source, issue.title, issue.severity, issue.hint or "")

    # ------------------------------- Utils -------------------------------------------------
    @staticmethod
    def _parse_interval(s: str) -> float:
        s = (s or "").strip().lower()
        units = [("ms", 0.001), ("s", 1), ("m", 60), ("h", 3600)]
        for u, k in units:
            if s.endswith(u):
                return float(s[:-len(u)]) * k
        try:
            return float(s)
        except Exception:
            return 60.0
