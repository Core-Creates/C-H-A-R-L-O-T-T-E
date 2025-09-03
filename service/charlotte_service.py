# ==========================================================================================
# charlotte_service.py — CHARLOTTE system-wide daemon with health & metrics endpoints
# Cross-platform: Windows / Linux / macOS
# - Runs as a long-lived background process (service/daemon)
# - Exposes /healthz and /metrics on 127.0.0.1:<port>
# - Gracefully handles signals where available (SIGTERM/SIGINT/SIGHUP/SIGBREAK)
# - No non-stdlib deps; works with systemd/launchd/NSSM/Task Scheduler
# ==========================================================================================
from __future__ import annotations
import json, os, signal, sys, time, threading, logging, platform
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any

# ──────────────────────────────────────────────────────────────────────────────
# Paths (relative to this file):
# repo/service/charlotte_service.py -> data/ and logs/ are one dir up by default
# Override with env: CHARLOTTE_CONFIG, CHARLOTTE_LOG_DIR
# ──────────────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[0]
DATA_DIR = (ROOT / ".." / "data").resolve()
DEFAULT_CONFIG = DATA_DIR / "config.json"
DEFAULT_LOG_DIR = (ROOT / ".." / "logs").resolve()

STOP_EVENT = threading.Event()
RELOAD_EVENT = threading.Event()
METRICS_LOCK = threading.Lock()
METRICS_STATE: Dict[str, Any] = {
    "start_time": time.time(),         # unix epoch seconds
    "last_heartbeat": time.time(),     # unix epoch seconds
    "interval": 300,                   # seconds between heartbeats
}

# ──────────────────────────────────────────────────────────────────────────────
# Health & Metrics server
# ──────────────────────────────────────────────────────────────────────────────

def _metrics_snapshot() -> str:
    with METRICS_LOCK:
        start = METRICS_STATE.get("start_time", time.time())
        last = METRICS_STATE.get("last_heartbeat", start)
        interval = METRICS_STATE.get("interval", 300)
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
    ]
    return "\n".join(lines) + "\n"


def start_health_server(port: int, logger):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(b"ok")
            elif self.path == "/metrics":
                body = _metrics_snapshot().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, fmt, *args):
            # Silence built-in HTTPServer stderr spam; we already log centrally
            return

    try:
        srv = HTTPServer(("127.0.0.1", port), H)
    except OSError as e:
        logger.error("failed to bind health/metrics server on 127.0.0.1:%d: %s", port, e)
        return None

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info("health/metrics server on http://127.0.0.1:%d/healthz and /metrics", port)
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
    # Not all signals exist on every OS; install what we can.
    for sig_name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, signal_handler)
            logger.debug("installed handler for %s", sig_name)
        except Exception:
            # Some contexts (threads, non-main thread, Windows limitations) may fail
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
        # Sleep in shorter chunks so we can react to STOP_EVENT quickly on Windows too
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

    interval = int(cfg.get("daemon", {}).get("heartbeat_seconds", 300))
    with METRICS_LOCK:
        METRICS_STATE["interval"] = interval

    t = threading.Thread(target=heartbeat, args=(logger, interval), daemon=True)
    t.start()

    # Start health/metrics server (optional)
    port = int(cfg.get("daemon", {}).get("health_port", 8787))
    srv = start_health_server(port, logger) if port else None

    # Main supervision loop
    try:
        while not STOP_EVENT.is_set():
            if RELOAD_EVENT.is_set():
                RELOAD_EVENT.clear()
                cfg = load_config(config_path)
                logger.info("reloaded config")
                # live-update interval if it changed
                new_interval = int(cfg.get("daemon", {}).get("heartbeat_seconds", interval))
                if new_interval != interval:
                    with METRICS_LOCK:
                        METRICS_STATE["interval"] = new_interval
                    interval = new_interval
                    logger.info("updated heartbeat interval to %s seconds", interval)
            time.sleep(0.5)
    except KeyboardInterrupt:
        # Windows/console-friendly stop
        STOP_EVENT.set()

    logger.info("CHARLOTTE daemon stopping…")
    if srv is not None:
        try:
            srv.shutdown()
        except Exception:
            pass
    t.join(timeout=10)
    logger.info("bye.")


if __name__ == "__main__":
    main()

# ==========================================================================================
# End of charlotte_service.py
# ==========================================================================================
