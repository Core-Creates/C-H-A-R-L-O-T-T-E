# ******************************************************************************************
# rate_limit.py — Token-bucket limiter for network bytes
# ******************************************************************************************
from __future__ import annotations
import threading, time

class TokenBucketLimiter:
    """
    Simple token-bucket limiter for bytes-per-second rate limiting.
    - rate_bps: token fill rate (bytes/sec)
    - capacity_bytes: bucket size (max burst)
    """
    def __init__(self, rate_bps: int, capacity_bytes: int):
        self._rate = max(1, int(rate_bps))
        self._cap = max(1, int(capacity_bytes))
        self._tokens = float(self._cap)
        self._lock = threading.Lock()
        self._last = time.time()

    def reset(self, rate_bps: int, capacity_bytes: int):
        with self._lock:
            self._rate = max(1, int(rate_bps))
            self._cap = max(1, int(capacity_bytes))
            self._tokens = min(self._tokens, float(self._cap))
            self._last = time.time()

    def acquire(self, cost_bytes: int):
        """Block until at least cost_bytes tokens are available."""
        need = max(0, int(cost_bytes))
        if need == 0:
            return
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self._last
                self._last = now
                # refill
                self._tokens = min(float(self._cap), self._tokens + elapsed * self._rate)
                if self._tokens >= need:
                    self._tokens -= need
                    return
            # back off proportional to deficit; keep it responsive
            time.sleep(min(0.5, max(0.01, need / max(1.0, self._rate))))
