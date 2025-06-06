"""
logger.py

Reusable logging module for C.H.A.R.L.O.T.T.E.
Supports session logs, plugin logs, and general event tracking.
"""

import os
from datetime import datetime


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _timestamp():
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")


def log_session(task: str, args: dict, mood: str, output: str, log_dir: str = "logs/charlotte_sessions"):
    """
    Logs a full CHARLOTTE CLI session to a dated file.

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
    """
    Logs a single plugin-related event.

    Args:
        plugin_name: Name of the plugin.
        message: Log message.
        log_dir: Where to store plugin logs.
    """
    _ensure_dir(log_dir)
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"{plugin_name}_{date_str}.log")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{_timestamp()} {message}\n")


def log_error(error_msg: str, log_dir: str = "logs/errors"):
    """
    Logs a critical error to an error log.

    Args:
        error_msg: Description of the error or traceback.
        log_dir: Where to store error logs.
    """
    _ensure_dir(log_dir)
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"errors_{date_str}.log")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{_timestamp()} {error_msg}\n")
