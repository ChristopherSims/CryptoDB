"""In-memory sliding-window rate limiter.

For single-node deployments this is sufficient.
For clustered deployments, replace with a Redis-backed store.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

from cryptodb.config import settings


@dataclass
class _Window:
    requests: list[float] = field(default_factory=list)


class RateLimiter:
    """Sliding-window rate limiter per (key, window_seconds)."""

    def __init__(self) -> None:
        self._windows: dict[str, _Window] = defaultdict(_Window)
        self._lock = Lock()

    def is_allowed(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Return True if the request is within the rate limit."""
        now = time.monotonic()
        with self._lock:
            win = self._windows[key]
            # Evict expired entries
            cutoff = now - window_seconds
            win.requests = [t for t in win.requests if t > cutoff]
            if len(win.requests) >= limit:
                return False
            win.requests.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._windows.pop(key, None)


# Singleton
_limiter = RateLimiter()


def check_rate_limit(key: str, limit: int, window_seconds: int = 60) -> bool:
    return _limiter.is_allowed(key, limit, window_seconds)


def get_rate_limit_for_endpoint(endpoint: str) -> tuple[int, int]:
    """Return (limit, window_seconds) for an endpoint path."""
    if endpoint == "/auth/login":
        return (settings.rate_limit_login_rpm, 60)
    if endpoint in ("/auth/hardware/authenticate-begin", "/auth/hardware/authenticate-finish"):
        return (settings.rate_limit_hw_auth_rpm, 60)
    return (settings.rate_limit_rpm, 60)
