"""Tiny per-IP token bucket. In-memory on purpose (single instance hackathon
demo); swap `_buckets` for Redis + a Lua script to go distributed."""
import time, threading

class TokenBucket:
    def __init__(self, rate_per_min=20, burst=8):
        self.rate = rate_per_min / 60.0
        self.burst = burst
        self._buckets = {}
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True
