"""
logger.py

Reusable logging module for C.H.A.R.L.O.T.T.E.
Supports session logs, plugin logs, and general event tracking.

Additions:
- start_session / append_session_event / end_session write NDJSON lines to logs/sessions.
- Backward-compatible helpers: log_session (pretty txt), log_plugin_event, log_error.
"""

import os
import json
from datetime import datetime
from typing import Optional, Dict, Any

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _timestamp() -> str:
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")


def _ts_utc_fs() -> str:
    # Filesystem-safe timestamp in UTC
    return datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")


# ──────────────────────────────────────────────────────────────────────────────
# New: Structured NDJSON session logging
# ──────────────────────────────────────────────────────────────────────────────
def start_session(meta: Optional[Dict[str, Any]] = None, log_dir: str = "logs/sessions") -> str:
    """Create a new session id and write a START record."""
    _ensure_dir(log_dir)
    session_id = _ts_utc_fs()
    path = os.path.join(log_dir, f"session_{session_id}.ndjson")
    rec = {"ts": _ts_utc_fs(), "event": "START", "payload": meta or {}}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return session_id


def append_session_event(session_id: str, event: str, payload: Optional[Dict[str, Any]] = None, log_dir: str = "logs/sessions") -> str:
    """Append an event line to the current session NDJSON file. Returns the path."""
    _ensure_dir(log_dir)
    path = os.path.join(log_dir, f"session_{session_id}.ndjson")
    rec = {"ts": _ts_utc_fs(), "event": event, "payload": payload or {}}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def end_session(session_id: str, status: str = "ok", log_dir: str = "logs/sessions") -> str:
    """Write END event and return the file path."""
    return append_session_event(session_id, "END", {"status": status}, log_dir=log_dir)


# ──────────────────────────────────────────────────────────────────────────────
# Existing: Pretty, human-readable session transcript
# ──────────────────────────────────────────────────────────────────────────────
def log_session(task: str, args: dict, mood: str, output: str, log_dir: str = "logs/charlotte_sessions"):
    """
    Logs a full CHARLOTTE CLI session to a dated TXT file.

    Args:
        task: The plugin task name.
        args: Dictionary of arguments used.
        mood: CHARLOTTE's mood during execution.
        output: Output returned from the plugin.
        log_dir: Where to store session logs.
    """
    _ensure_dir(log_dir)
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H:%M:%S")
    log_file = os.path.join(log_dir, f"{date_str}.txt")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("═" * 60 + "\n")
        f.write(f"[🕒 {time_str}] Mood: {mood.upper()}\n")
        f.write(f"🛠️ Task: {task}\n")
        f.write(f"📥 Args: {args}\n")
        f.write("📤 Output:\n")
        f.write(output + "\n")
        f.write("═" * 60 + "\n\n")


def log_plugin_event(plugin_name: str, message: str, log_dir: str = "logs/plugin_logs"):
    """Logs a single plugin-related event."""
    _ensure_dir(log_dir)
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"{plugin_name}_{date_str}.log")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{_timestamp()} {message}\n")


def log_error(error_msg: str, log_dir: str = "logs/errors"):
    """Logs a critical error to an error log."""
    _ensure_dir(log_dir)
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"errors_{date_str}.log")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{_timestamp()} {error_msg}\n")
