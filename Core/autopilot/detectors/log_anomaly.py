# ******************************************************************************************
# LogAnomalyDetector — naive spike detector on ERROR/Traceback patterns
# ******************************************************************************************
from __future__ import annotations
import os
import re
import glob
from typing import Any

from ..issues import Issue

ERROR_PAT = re.compile(r"ERROR|Exception|Traceback", re.IGNORECASE)


class LogAnomalyDetector:
    """
    Config keys (all optional except threshold/window if you want different defaults):
      files:        ["/abs/file1.log", "/abs/file2.log"]  # explicit files win
      directory:    "/data/logs/charlotte_sessions"       # default when files not given
      pattern:      "*.log"                                # glob pattern inside directory
      recursive:    false                                  # enable ** patterns if true
      max_files:    20                                     # limit files per run (newest first)
      window_lines: 1000
      error_threshold: 10
    """

    def __init__(self, cfg: dict[str, Any], logger):
        self.cfg = cfg or {}
        self.logger = logger.getChild("loganom")
        self._last_run = 0.0
        self._metrics = {"last_files": 0, "last_errors": 0}

    def metrics(self) -> dict[str, Any]:
        return dict(self._metrics)

    def run(self) -> list[Issue]:
        files = self._resolve_files()
        window = int(self.cfg.get("window_lines", 1000))
        thresh = int(self.cfg.get("error_threshold", 10))

        issues: list[Issue] = []
        total_err = 0

        for f in files:
            try:
                if not os.path.exists(f) or not os.path.isfile(f):
                    continue
                lines = self._tail(f, window)
                cnt = sum(1 for ln in lines if ERROR_PAT.search(ln))
                total_err += cnt
                if cnt >= thresh:
                    issues.append(
                        Issue(
                            title=f"Error spike in {os.path.basename(f)}: {cnt} hits in last {window} lines",
                            severity="medium",
                            details={"file": f, "count": cnt, "window_lines": window},
                            hint="Open recent errors; consider restarting noisy service or escalating to triage.",
                        )
                    )
            except Exception as e:
                # keep going; one bad file shouldn't kill the run
                self.logger.warning("log scan failed for %s: %s", f, e)

        self._metrics.update({"last_files": len(files), "last_errors": total_err})
        return issues

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────
    def _resolve_files(self) -> list[str]:
        # If explicit files are provided, use them as-is
        files_cfg = self.cfg.get("files") or []
        if isinstance(files_cfg, list) and files_cfg:
            return [str(p) for p in files_cfg]

        # Otherwise, discover from a directory + pattern
        directory = str(self.cfg.get("directory") or "/data/logs/charlotte_sessions")
        pattern = str(self.cfg.get("pattern") or "*.log")
        recursive = bool(self.cfg.get("recursive", False))
        max_files = int(self.cfg.get("max_files", 20))

        search_glob = os.path.join(directory, pattern)
        candidates = glob.glob(search_glob, recursive=recursive)

        # Order by mtime (newest first) and take top N
        def _mt(p: str) -> float:
            try:
                return os.path.getmtime(p)
            except Exception:
                return 0.0

        candidates.sort(key=_mt, reverse=True)
        return candidates[:max_files]

    def _tail(self, path: str, n: int) -> list[str]:
        # Efficient tail without loading the full file into memory
        avg_len = 120
        to_read = max(1, n * avg_len)
        with open(path, "rb") as f:
            try:
                f.seek(-to_read, os.SEEK_END)
            except OSError:
                f.seek(0)
            data = f.read().decode("utf-8", errors="ignore")
        return data.splitlines()[-n:]


# ******************************************************************************************
# End of file
# ******************************************************************************************
