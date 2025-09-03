# ==========================================================================================
# charlotte_service.py — CHARLOTTE system-wide daemon with health, metrics & autopilot
# Cross-platform: Windows / Linux / macOS
# - Long-lived background process (service/daemon)
# - /healthz, /metrics, /autopilot/*, /throttle, /shutdown on 127.0.0.1:<port>
# - Graceful signals where available (SIGTERM/SIGINT/SIGHUP/SIGBREAK)
# - No hard non-stdlib deps; optional psutil if installed for richer net metrics
# ==========================================================================================
from __future__ import annotations
import json, os, signal, sys, time, threading, logging, platform, socket, concurrent.futures
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
# Paths (relative to this file):
# repo/service/charlotte_service.py -> data/ and logs/ are one dir up by default
# Override with env: CHARLOTTE_CONFIG, CHARLOTTE_LOG_DIR
# ──────────────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[0]
DATA_DIR = (ROOT / ".." / "data").resolve()
DEFAULT_CONFIG = DATA_DIR / "config.json"

# OLD:
# DEFAULT_LOG_DIR = (ROOT / ".." / "logs").resolve()
# NEW:
DEFAULT_LOG_DIR = Path("/data/logs/charlotte_sessions")  # <- use your sessions path by default


STOP_EVENT = threading.Event()
RELOAD_EVENT = threading.Event()

METRICS_LOCK = threading.Lock()
METRICS_STATE: Dict[str, Any] = {
    "start_time": time.time(),         # unix epoch seconds
    "last_heartbeat": time.time(),     # unix epoch seconds
    "interval": 300,                   # seconds between heartbeats
    "autopilot": {
        "running": False,
        "net_fraction": 0.35,
        "limiter_rate_bps": 0,
        "iface": "unknown",
        "idle_bps": 0,
        "utilization": 0.0,
        "detectors": {}
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# Optional psutil for bandwidth/CPU (keeps stdlib baseline)
# ──────────────────────────────────────────────────────────────────────────────
try:
    import psutil  # type: ignore
except Exception:  # psutil remains optional
    psutil = None  # type: ignore

# ──────────────────────────────────────────────────────────────────────────────
# Token-bucket limiter (network bytes)
# ──────────────────────────────────────────────────────────────────────────────
class TokenBucketLimiter:
    def __init__(self, rate_bps: int, capacity_bytes: int):
        self._rate = max(1, rate_bps)
        self._cap = max(1, capacity_bytes)
        self._tokens = float(self._cap)
        self._lock = threading.Lock()
        self._last = time.time()

    def reset(self, rate_bps: int, capacity_bytes: int):
        with self._lock:
            self._rate = max(1, rate_bps)
            self._cap = max(1, capacity_bytes)
            self._tokens = min(self._tokens, float(self._cap))
            self._last = time.time()

    def acquire(self, cost_bytes: int):
        # Block until tokens available or STOP_EVENT set
        while not STOP_EVENT.is_set():
            with self._lock:
                now = time.time()
                elapsed = now - self._last
                self._last = now
                # add tokens
                self._tokens = min(float(self._cap), self._tokens + elapsed * self._rate)
                if self._tokens >= cost_bytes:
                    self._tokens -= cost_bytes
                    return
            # back off proportional to deficit (bounded)
            time.sleep(min(0.5, max(0.01, cost_bytes / max(1.0, self._rate))))

# ──────────────────────────────────────────────────────────────────────────────
# Lightweight bandwidth monitor
# - If psutil is present: samples per-interface counters + CPU
# - Else: uses a static link capacity heuristic and reports only configured headroom
# ──────────────────────────────────────────────────────────────────────────────
class BandwidthMonitor:
    def __init__(self, link_bps: int = 100_000_000, iface: Optional[str] = None):
        self._lock = threading.Lock()
        self._state = {"iface": iface or "unknown", "bps_in": 0, "bps_out": 0, "idle_bps": link_bps, "cpu": 0.0}
        self._run = False
        self._link_bps = int(link_bps)

    def start(self):
        if psutil is None:
            return  # degraded mode
        self._run = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self._run = False

    def _pick_iface(self) -> str:
        if psutil is None:
            return "unknown"
        # Choose busiest non-loopback if not configured
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

    def _loop(self):
        iface = self._state["iface"] if self._state["iface"] != "unknown" else self._pick_iface()
        pernic_prev = psutil.net_io_counters(pernic=True)
        prev = pernic_prev.get(iface)
        if prev is None:
            return
        prev_total = prev.bytes_recv + prev.bytes_sent
        while self._run and not STOP_EVENT.is_set():
            time.sleep(1.0)
            cpu = psutil.cpu_percent(interval=None)
            pernic = psutil.net_io_counters(pernic=True)
            cur = pernic.get(iface)
            if cur is None:
                continue
            cur_total = cur.bytes_recv + cur.bytes_sent
            delta = max(0, cur_total - prev_total)
            prev_total = cur_total
            bps = delta  # ~bytes/s at 1s cadence
            idle = max(0, self._link_bps - bps)
            with self._lock:
                self._state = {
                    "iface": iface,
                    "bps_in": max(0, cur.bytes_recv - prev.bytes_recv),
                    "bps_out": max(0, cur.bytes_sent - prev.bytes_sent),
                    "idle_bps": idle,
                    "cpu": float(cpu),
                }
            prev = cur

    def read(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def utilization(self) -> float:
        s = self.read()
        total = (s["bps_in"] + s["bps_out"] + s["idle_bps"]) or 1
        return 1.0 - (s["idle_bps"] / total)

    def cpu_percent(self) -> float:
        return float(self.read().get("cpu", 0.0))

# ──────────────────────────────────────────────────────────────────────────────
# Issue model + detectors (stdlib-only examples)
# - LogAnomalyDetector: scans last N lines for ERROR/Exception spikes
# - PortProbeDetector: attempts TCP connects to configured host:port list
#   (no sweeping scans; safe “known hosts” probe only)
# ──────────────────────────────────────────────────────────────────────────────
class Issue:
    def __init__(self, title: str, severity: str, details: Dict[str, Any], hint: Optional[str] = None):
        self.title = title
        self.severity = severity
        self.details = details
        self.hint = hint or ""

class LogAnomalyDetector:
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger.getChild("loganom")
        self._last_run = 0.0
        self._metrics = {"last_files": 0, "last_errors": 0}

    def metrics(self) -> Dict[str, Any]:
        return dict(self._metrics)

    def _tail(self, path: str, n: int) -> List[str]:
        avg_len = 120
        to_read = n * avg_len
        with open(path, "rb") as f:
            try:
                f.seek(-to_read, os.SEEK_END)
            except OSError:
                f.seek(0)
            data = f.read().decode("utf-8", errors="ignore")
        return data.splitlines()[-n:]

    def run(self) -> List[Issue]:
        import re, os
        patt = re.compile(r"ERROR|Exception|Traceback", re.IGNORECASE)
        files: List[str] = list(self.cfg.get("files", []))
        window = int(self.cfg.get("window_lines", 1000))
        thresh = int(self.cfg.get("error_threshold", 10))
        issues: List[Issue] = []
        total_err = 0
        for f in files:
            if not os.path.exists(f):
                continue
            lines = self._tail(f, window)
            cnt = sum(1 for ln in lines if patt.search(ln))
            total_err += cnt
            if cnt >= thresh:
                issues.append(Issue(
                    title=f"Error spike in {Path(f).name}: {cnt} hits / last {window} lines",
                    severity="medium",
                    details={"file": f, "count": cnt, "window_lines": window},
                    hint="Inspect recent errors; consider restart/escalation."
                ))
        self._metrics.update({"last_files": len(files), "last_errors": total_err})
        return issues

class PortProbeDetector:
    def __init__(self, cfg: Dict[str, Any], limiter: TokenBucketLimiter, netmon: BandwidthMonitor, logger: logging.Logger):
        self.cfg = cfg
        self.limiter = limiter
        self.netmon = netmon
        self.logger = logger.getChild("portprobe")
        self._last_run = 0.0
        self._metrics = {"last_probes": 0, "open_hits": 0}

    def metrics(self) -> Dict[str, Any]:
        return dict(self._metrics)

    def run(self) -> List[Issue]:
        hosts: List[str] = list(self.cfg.get("hosts", []))      # e.g., ["192.168.0.10","192.168.0.20"]
        ports: List[int] = list(self.cfg.get("ports", [22, 80, 443, 445, 3389, 5900]))
        timeout_s = float(self.cfg.get("timeout_seconds", 0.3))
        approx_cost = max(5_000, len(hosts) * len(ports) * 120)  # ~120 bytes/probe rough estimate
        self.limiter.acquire(approx_cost)

        open_hits = 0
        issues: List[Issue] = []
        for h in hosts:
            flagged: List[int] = []
            for p in ports:
                try:
                    with socket.create_connection((h, p), timeout=timeout_s):
                        flagged.append(p)
                        open_hits += 1
                except Exception:
                    pass
            if flagged:
                issues.append(Issue(
                    title=f"Host {h} has open ports: {flagged}",
                    severity="high",
                    details={"host": h, "open_ports": flagged},
                    hint="Verify necessity; restrict via firewall/ACL; segment to DMZ where appropriate."
                ))
        self._metrics.update({"last_probes": len(hosts) * max(1, len(ports)), "open_hits": open_hits})
        return issues

# ──────────────────────────────────────────────────────────────────────────────
# Autopilot (bandwidth-aware scheduler)
# ──────────────────────────────────────────────────────────────────────────────
class AutoPilot:
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.logger = logger.getChild("autopilot")
        self.cfg = cfg or {}
        self._running = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.tick_seconds = max(1, int(self.cfg.get("scheduler", {}).get("tick_seconds", 5)))
        self.max_workers = int(self.cfg.get("scheduler", {}).get("max_concurrent_detectors", 2))

        # bandwidth policy
        self.net_fraction = float(self.cfg.get("net_utilization_max", 0.35))
        link_bps = int(self.cfg.get("link_bps", 100_000_000))
        iface = None
        ifaces = self.cfg.get("interfaces", [])
        if ifaces and isinstance(ifaces, list):
            name = (ifaces[0] or {}).get("name")
            iface = None if (name in (None, "auto")) else name

        self.netmon = BandwidthMonitor(link_bps=link_bps, iface=iface)
        self.limiter = TokenBucketLimiter(rate_bps=1_000_000, capacity_bytes=4_000_000)

        # detectors registry
        dconf = self.cfg.get("detectors", {}) or {}
        self.detectors: Dict[str, Any] = {}
        if (dconf.get("log_anomaly") or {}).get("enabled", False):
            self.detectors["log_anomaly"] = LogAnomalyDetector(dconf["log_anomaly"], self.logger)
        if (dconf.get("port_probe") or {}).get("enabled", False):
            self.detectors["port_probe"] = PortProbeDetector(dconf["port_probe"], self.limiter, self.netmon, self.logger)

        # scheduling windows
        self.intervals: Dict[str, float] = {
            name: self._parse_interval(cfg.get("interval", "5m")) for name, cfg in dconf.items()
        }
        self.cooldowns: Dict[str, float] = {name: 0.0 for name in self.detectors}
        self.cd_spans: Dict[str, float] = {
            name: self._parse_interval(cfg.get("cooldown", "0s")) for name, cfg in dconf.items()
        }

        self.adaptive = self.cfg.get("adaptive_backoff", {"cpu_hot_percent": 85, "net_hot_utilization": 0.70, "scale_factor": 2.0})
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="ap-det")

    # timings
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

    # public API
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
            "max_workers": self.pool._max_workers if hasattr(self.pool, "_max_workers") else self.max_workers,
            "net_fraction": self.net_fraction,
            "limiter_rate_bps": getattr(self, "_last_rate", 0),
            "iface": bw.get("iface", "unknown"),
            "idle_bps": bw.get("idle_bps", 0),
            "utilization": self.netmon.utilization(),
            "detectors": {k: v.metrics() for k, v in self.detectors.items() if hasattr(v, "metrics")},
        }

    def set_net_fraction(self, f: float):
        self.net_fraction = max(0.05, min(0.9, float(f)))

    # internal loop
    def _loop(self):
        try:
            while not self._stop.is_set():
                start = time.time()
                self._recalc_limiter()
                self._publish_metrics()
                self._schedule_due()
                # sleep remainder of tick; respond promptly to stop()
                elapsed = time.time() - start
                remaining = max(0.0, self.tick_seconds - elapsed)
                if remaining:
                    self._stop.wait(remaining)
        finally:
            self._publish_metrics()

    def _recalc_limiter(self):
        bw = self.netmon.read() or {}
        headroom_bps = max(0, int(bw.get("idle_bps", 0)))
        rate = max(50_000, int(headroom_bps * float(self.net_fraction)))  # never below 50 kbps
        cap  = max(rate * 4, 2_000_000)
        self.limiter.reset(rate_bps=rate, capacity_bytes=cap)
        self._last_rate = rate

    def _schedule_due(self):
        now = time.time()
        cpu_hot = self.netmon.cpu_percent() >= float(self.adaptive.get("cpu_hot_percent", 85))
        net_hot = self.netmon.utilization() >= float(self.adaptive.get("net_hot_utilization", 0.70))
        scale   = float(self.adaptive.get("scale_factor", 2.0)) if (cpu_hot or net_hot) else 1.0

        for name, det in self.detectors.items():
            interval = float(self.intervals.get(name, 300.0)) * scale
            cooldown = float(self.cd_spans.get(name, 0.0))
            last     = float(getattr(det, "_last_run", 0.0))

            if (now - last) < interval:
                continue
            if (now - float(self.cooldowns.get(name, 0.0))) < cooldown:
                continue

            # schedule
            self.cooldowns[name] = now
            try:
                self.pool.submit(self._run_detector_safe, name, det)
            except RuntimeError:
                # pool may be shutting down
                break

    def _run_detector_safe(self, name: str, det):
        try:
            setattr(det, "_last_run", time.time())
            issues: List[Issue] = det.run() or []
            for issue in issues:
                # Currently just log the issue; integrate with triage/actions as needed
                self.logger.warning("[ISSUE] %s: %s (sev=%s) — hint=%s", name, issue.title, issue.severity, issue.hint)
        except Exception as e:
            self.logger.exception("Detector %s failed: %s", name, e)

    def _publish_metrics(self):
        st = self.status()
        with METRICS_LOCK:
            METRICS_STATE["autopilot"] = st

# ──────────────────────────────────────────────────────────────────────────────
# Health & Metrics server
# ──────────────────────────────────────────────────────────────────────────────
def _metrics_snapshot() -> str:
    with METRICS_LOCK:
        start = METRICS_STATE.get("start_time", time.time())
        last = METRICS_STATE.get("last_heartbeat", start)
        interval = METRICS_STATE.get("interval", 300)
        ap = METRICS_STATE.get("autopilot", {})
    now = time.time()
    uptime = max(0.0, now - float(start))
    # Prometheus text exposition format v0.0.4
    lines = [
        "# HELP charlotte_up Process liveness (1=up)",
        "# TYPE charlotte_up gauge",
        "charlotte_up 1",
        "# HELP charlotte_heartbeat_seconds Configured heartbeat interval in seconds",
        "# TYPE charlotte_heartbeat_seconds gauge",
        f"charlotte_heartbeat_seconds {float(interval)}",
        "# HELP charlotte_uptime_seconds Uptime of the process in seconds",
        "# TYPE charlotte_uptime_seconds counter",
        f"charlotte_uptime_seconds {uptime}",
        "# HELP charlotte_last_heartbeat_unixtime Seconds since epoch of the last heartbeat",
        "# TYPE charlotte_last_heartbeat_unixtime gauge",
        f"charlotte_last_heartbeat_unixtime {float(last)}",
        "# HELP charlotte_autopilot_running Autopilot state (1=running, 0=stopped)",
        "# TYPE charlotte_autopilot_running gauge",
        f"charlotte_autopilot_running {1 if ap.get('running') else 0}",
        "# HELP charlotte_autopilot_net_fraction Target fraction of idle bandwidth to use",
        "# TYPE charlotte_autopilot_net_fraction gauge",
        f"charlotte_autopilot_net_fraction {float(ap.get('net_fraction', 0.35))}",
        "# HELP charlotte_autopilot_limiter_rate_bps Current token-bucket fill rate (bytes/sec)",
        "# TYPE charlotte_autopilot_limiter_rate_bps gauge",
        f"charlotte_autopilot_limiter_rate_bps {int(ap.get('limiter_rate_bps', 0))}",
        "# HELP charlotte_autopilot_idle_bps Estimated idle bandwidth (bytes/sec)",
        "# TYPE charlotte_autopilot_idle_bps gauge",
        f"charlotte_autopilot_idle_bps {int(ap.get('idle_bps', 0))}",
        "# HELP charlotte_autopilot_utilization Current link utilization (0..1)",
        "# TYPE charlotte_autopilot_utilization gauge",
        f"charlotte_autopilot_utilization {float(ap.get('utilization', 0.0))}",
    ]
    return "\n".join(lines) + "\n"

# ──────────────────────────────────────────────────────────────────────────────
# HTTP handler factory (injects config/autopilot/logger)
# ──────────────────────────────────────────────────────────────────────────────
def make_handler(logger: logging.Logger, autopilot: AutoPilot, approval_token: str):
    token_env = os.getenv("CHARLOTTE_TOKEN", "")
    expected_token = token_env or approval_token or ""

    class Handler(BaseHTTPRequestHandler):
        def _authorized(self) -> bool:
            if not expected_token:
                # No token configured -> deny control endpoints for safety
                return False
            provided = self.headers.get("X-CHARLOTTE-Token", "")
            return provided == expected_token

        def _json(self, code: int, payload: dict):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            # quiet default HTTPServer stderr; centralize logging
            logger.info("HTTP %s %s", self.command, self.path)

        def do_GET(self):
            if self.path == "/healthz":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(b"ok")
                return

            if self.path == "/metrics":
                body = _metrics_snapshot().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path == "/autopilot/status":
                self._json(200, autopilot.status())
                return

            self._json(404, {"error": "not found"})

        def do_POST(self):
            # control endpoints require auth token
            if self.path == "/autopilot/start":
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                autopilot.start()
                return self._json(200, {"ok": True})

            if self.path == "/autopilot/stop":
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                autopilot.stop()
                return self._json(200, {"ok": True})

            if self.path.startswith("/throttle"):
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                try:
                    q = self.path.split("?", 1)[1]
                    params = dict([p.split("=", 1) for p in q.split("&") if "=" in p])
                    level = float(params.get("level", "0.35"))
                except Exception:
                    level = 0.35
                autopilot.set_net_fraction(level)
                return self._json(200, {"net_utilization_max": autopilot.net_fraction})

            if self.path == "/shutdown":
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                threading.Thread(target=lambda: STOP_EVENT.set(), daemon=True).start()
                return self._json(200, {"ok": True, "msg": "shutting down"})

            self._json(404, {"error": "not found"})

    return Handler

# ──────────────────────────────────────────────────────────────────────────────
# Health & control server
# ──────────────────────────────────────────────────────────────────────────────
def start_health_server(port: int, logger, handler_cls):
    try:
        srv = HTTPServer(("127.0.0.1", port), handler_cls)  # pass a class, not a factory
    except OSError as e:
        logger.error("failed to bind health/metrics server on 127.0.0.1:%d: %s", port, e)
        return None

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info("HTTP server on http://127.0.0.1:%d  endpoints: /healthz /metrics /autopilot/* /throttle /shutdown", port)
    return srv

# ──────────────────────────────────────────────────────────────────────────────
# Core helpers
# ──────────────────────────────────────────────────────────────────────────────
def load_config(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            assert isinstance(cfg, dict)
            return cfg
    except Exception:
        return {}

def setup_logger(log_dir: Path, level: str = "INFO") -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("charlotte-daemon")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = RotatingFileHandler(log_dir / "charlotte-daemon.log", maxBytes=5_000_000, backupCount=5)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.handlers.clear()
    logger.addHandler(handler)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

# ──────────────────────────────────────────────────────────────────────────────
# Signal handling (portable)
# ──────────────────────────────────────────────────────────────────────────────
def signal_handler(signum, frame):
    if signum in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        STOP_EVENT.set()
    elif signum == getattr(signal, "SIGHUP", None):
        RELOAD_EVENT.set()
    elif signum == getattr(signal, "SIGBREAK", None):  # Windows Ctrl+Break
        STOP_EVENT.set()

def _install_signal_handlers(logger: logging.Logger):
    for sig_name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, signal_handler)
            logger.debug("installed handler for %s", sig_name)
        except Exception:
            logger.debug("could not install handler for %s", sig_name)

# ──────────────────────────────────────────────────────────────────────────────
# Background work loop
# ──────────────────────────────────────────────────────────────────────────────
def heartbeat(logger: logging.Logger, interval: int):
    while not STOP_EVENT.is_set():
        try:
            logger.info("heartbeat | alive=%s", datetime.utcnow().isoformat()+"Z")
            with METRICS_LOCK:
                METRICS_STATE["last_heartbeat"] = time.time()
        except Exception as e:
            logger.exception("background loop error: %s", e)
        remaining = float(interval)
        while remaining > 0 and not STOP_EVENT.is_set():
            step = 1.0 if remaining > 1.0 else remaining
            STOP_EVENT.wait(step)
            remaining -= step

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    # Env overrides (work everywhere)
    config_path = Path(os.getenv("CHARLOTTE_CONFIG", str(DEFAULT_CONFIG))).resolve()
    log_dir = Path(os.getenv("CHARLOTTE_LOG_DIR", str(DEFAULT_LOG_DIR))).resolve()

    cfg = load_config(config_path)
    logger = setup_logger(log_dir, cfg.get("log_level", "INFO"))

    logger.info("CHARLOTTE daemon starting… (%s)", platform.platform())
    logger.info("config=%s", str(config_path))

    _install_signal_handlers(logger)

    # heartbeat
    interval = int(cfg.get("daemon", {}).get("heartbeat_seconds", 300))
    with METRICS_LOCK:
        METRICS_STATE["interval"] = interval
    t = threading.Thread(target=heartbeat, args=(logger, interval), daemon=True)
    t.start()

    # Autopilot wiring
    ap_cfg = cfg.get("autopilot", {}) or {}
    autopilot = AutoPilot(ap_cfg, logger=logger)
    approval_token = str(ap_cfg.get("approval_token", ""))

    # HTTP server (health/metrics + control)
    port = int(cfg.get("daemon", {}).get("health_port", 8787))
    handler_cls = make_handler(logger, autopilot, approval_token)   # build the class
    srv = start_health_server(port, logger, handler_cls) if port else None

    # Enable autopilot at boot if configured
    if ap_cfg.get("enabled", False):
        if os.getenv("CHARLOTTE_TOKEN", "") or approval_token:
            autopilot.start()
        else:
            logger.warning("Autopilot 'enabled' but no control token set; refusing to start for safety. "
                           "Set CHARLOTTE_TOKEN env or autopilot.approval_token in config.")

    # Supervision loop (config reload + graceful stop)
    try:
        while not STOP_EVENT.is_set():
            if RELOAD_EVENT.is_set():
                RELOAD_EVENT.clear()
                cfg = load_config(config_path)
                logger.info("reloaded config")
                # live-update heartbeat interval if it changed
                new_interval = int(cfg.get("daemon", {}).get("heartbeat_seconds", interval))
                if new_interval != interval:
                    with METRICS_LOCK:
                        METRICS_STATE["interval"] = new_interval
                    interval = new_interval
                    logger.info("updated heartbeat interval to %s seconds", interval)
            time.sleep(0.5)
    except KeyboardInterrupt:
        STOP_EVENT.set()

    logger.info("CHARLOTTE daemon stopping…")
    if srv is not None:
        try:
            srv.shutdown()
        except Exception:
            pass
    try:
        autopilot.stop()
    except Exception:
        pass
    t.join(timeout=10)
    logger.info("bye.")

if __name__ == "__main__":
    main()

# ==========================================================================================
# Config reference (config.json)
# {
#   "log_level": "INFO",
#   "daemon": { "health_port": 8787, "heartbeat_seconds": 300 },
#   "autopilot": {
#     "enabled": true,
#     "approval_token": "change-me-or-use-CHARLOTTE_TOKEN-env",
#     "net_utilization_max": 0.35,
#     "link_bps": 100000000,
#     "interfaces": [ { "name": "auto" } ],
#     "adaptive_backoff": { "cpu_hot_percent": 85, "net_hot_utilization": 0.70, "scale_factor": 2.0 },
#     "scheduler": { "tick_seconds": 5, "max_concurrent_detectors": 2 },
#     "detectors": {
#       "log_anomaly": {
#         "enabled": true,
#         "interval": "5m",
#         "cooldown": "2m",
#         "files": [ "/var/log/syslog", "C:\\\\ProgramData\\\\CHARLOTTE\\\\logs\\\\agent.log" ],
#         "window_lines": 1000,
#         "error_threshold": 10
#       },
#       "port_probe": {
#         "enabled": true,
#         "interval": "15m",
#         "cooldown": "5m",
#         "hosts": [ "192.168.0.10", "192.168.0.20" ],
#         "ports":  [ 22, 80, 443, 445, 3389, 5900 ],
#         "timeout_seconds": 0.3
#       }
#     }
#   }
# }
# Notes:
# - Set a control token via env CHARLOTTE_TOKEN (preferred) or autopilot.approval_token.
# - Install 'psutil' optionally for richer bandwidth/CPU sampling; otherwise we use a link_bps heuristic.
# - /throttle lets you change net_utilization_max on the fly: POST /throttle?level=0.2
# ==========================================================================================
# End of file