"""In-memory failed-login rate limiting (Phase 9).

Rule: at most :data:`MAX_FAILED_LOGINS` failed logins per identifier
(username or email, case-insensitive) per :data:`WINDOW_SECONDS`
(15 minutes). A successful login clears the counter. When the limit
is hit the login endpoint returns 429 instead of checking the
password — so a correct password cannot be used to probe whether the
account is locked, and a brute-force run is slowed to 10 guesses per
15 minutes per identifier.

This is intentionally in-memory: it needs no Redis and is correct
for a single-process deployment. It does NOT survive a restart and
does NOT share state across workers — a multi-worker production
deployment must move this to Redis (see ``docs/SECURITY.md``).
The store is keyed only by the login identifier, never by password
or token, and ``reset_login_rate_limits`` exists for tests.
"""

import threading
import time

MAX_FAILED_LOGINS = 10
WINDOW_SECONDS = 15 * 60

_attempts: dict[str, list[float]] = {}
_lock = threading.Lock()


def _key(identifier: str) -> str:
    return identifier.strip().lower()


def _prune(key: str, now: float) -> list[float]:
    cutoff = now - WINDOW_SECONDS
    kept = [t for t in _attempts.get(key, []) if t > cutoff]
    if kept:
        _attempts[key] = kept
    else:
        _attempts.pop(key, None)
    return kept


def is_login_blocked(identifier: str) -> bool:
    """True when ``identifier`` has hit the failed-login limit."""
    now = time.monotonic()
    with _lock:
        return len(_prune(_key(identifier), now)) >= MAX_FAILED_LOGINS


def record_failed_login(identifier: str) -> None:
    """Record one failed login attempt for ``identifier``."""
    now = time.monotonic()
    with _lock:
        attempts = _prune(_key(identifier), now)
        attempts.append(now)
        _attempts[_key(identifier)] = attempts


def clear_failed_logins(identifier: str) -> None:
    """Clear the failure counter (called on a successful login)."""
    with _lock:
        _attempts.pop(_key(identifier), None)


def reset_login_rate_limits() -> None:
    """Clear all counters. Tests only — never called in production."""
    with _lock:
        _attempts.clear()
