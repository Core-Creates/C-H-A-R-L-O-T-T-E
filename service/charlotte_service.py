# service/charlotte_daemon.py
from __future__ import annotations
import json, os, signal, sys, time, threading, logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DEFAULT_CONFIG = DATA_DIR / "config.json"
DEFAULT_LOG_DIR = ROOT / "logs"
STOP_EVENT = threading.Event()
RELOAD_EVENT = threading.Event()

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
    # Also log to stderr for service managers
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

def signal_handler(signum, frame):
    if signum in (signal.SIGINT, signal.SIGTERM):
        STOP_EVENT.set()
    elif signum in (getattr(signal, "SIGHUP", None),):
        RELOAD_EVENT.set()

def heartbeat(logger: logging.Logger, interval: int):
    """Your periodic background work goes here."""
    while not STOP_EVENT.is_set():
        try:
            # TODO: wire your tasks (triage, patch planner, schedulers, queues…)
            logger.info("heartbeat | alive=%s", datetime.utcnow().isoformat()+"Z")
            # example: run a lightweight healthcheck or queue poller
        except Exception as e:
            logger.exception("background loop error: %s", e)
        STOP_EVENT.wait(interval)

def main():
    # Read environment overrides set by service manager
    config_path = Path(os.getenv("CHARLOTTE_CONFIG", str(DEFAULT_CONFIG)))
    log_dir = Path(os.getenv("CHARLOTTE_LOG_DIR", str(DEFAULT_LOG_DIR)))

    cfg = load_config(config_path)
    logger = setup_logger(log_dir, cfg.get("log_level", "INFO"))

    logger.info("CHARLOTTE daemon starting…")
    logger.info("config=%s", str(config_path))

    # Wire signals (systemd passes SIGTERM; launchd too; Windows handled by manager)
    try:
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)
    except Exception:
        # Some platforms (Windows) have limited signal support
        pass

    interval = int(cfg.get("daemon", {}).get("heartbeat_seconds", 300))
    t = threading.Thread(target=heartbeat, args=(logger, interval), daemon=True)
    t.start()

    # Support config reload on SIGHUP
    while not STOP_EVENT.is_set():
        if RELOAD_EVENT.is_set():
            RELOAD_EVENT.clear()
            cfg = load_config(config_path)
            logger.info("reloaded config")
            # (optional) update runtime settings, intervals, feature flags…
        time.sleep(0.5)

    logger.info("CHARLOTTE daemon stopping…")
    t.join(timeout=10)
    logger.info("bye.")

if __name__ == "__main__":
    main()
# ==========================================================================================
# End of file
# ==========================================================================================
