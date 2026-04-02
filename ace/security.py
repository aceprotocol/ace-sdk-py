"""ACE Protocol security: replay detection + timestamp freshness."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
import re

MAX_DRIFT_SECONDS = 300  # 5 minutes
_MESSAGE_ID_V4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def validate_message_id(message_id: str) -> None:
    """Validate that a message ID is a valid UUID v4."""
    if not _MESSAGE_ID_V4_PATTERN.match(message_id):
        raise ValueError(f"Invalid message_id: expected UUID v4, got '{message_id[:50]}'")


def check_timestamp_freshness(timestamp: int) -> None:
    """Check that a timestamp is within the 5-minute freshness window."""
    now = int(time.time())
    drift = abs(now - timestamp)
    if drift > MAX_DRIFT_SECONDS:
        raise ValueError(
            f"Timestamp not fresh: drift {drift}s exceeds max {MAX_DRIFT_SECONDS}s"
        )


class ReplayDetector:
    """Thread-safe in-memory replay detector with TTL-based eviction.

    Messages are evicted after ``ttl_seconds`` (default: matches the freshness
    window of 300 s).  A hard ``capacity`` cap prevents unbounded memory growth
    under burst traffic — when reached, the oldest entry is evicted regardless
    of TTL.

    Callers SHOULD persist state via ``export()`` / ``from_export()`` across
    restarts to avoid a replay window during the freshness period after restart.
    """

    def __init__(
        self,
        capacity: int = 100_000,
        ttl_seconds: int = MAX_DRIFT_SECONDS,
    ) -> None:
        self._capacity = capacity
        self._ttl = ttl_seconds
        # Stores message_id -> insertion_timestamp (monotonic)
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _evict_expired(self) -> None:
        """Remove entries older than TTL.  Caller must hold ``_lock``."""
        cutoff = time.monotonic() - self._ttl
        while self._seen:
            # Peek at the oldest entry
            _, ts = next(iter(self._seen.items()))
            if ts <= cutoff:
                self._seen.popitem(last=False)
            else:
                break

    def check_and_reserve(self, message_id: str) -> bool:
        """Atomically check if a messageId has been seen and reserve it.

        Returns True if the message is new (accepted), False if duplicate (rejected).
        Thread-safe: uses a lock to prevent TOCTOU race conditions.
        """
        with self._lock:
            self._evict_expired()

            if message_id in self._seen:
                return False

            # Hard capacity cap — evict oldest regardless of TTL
            if len(self._seen) >= self._capacity:
                self._seen.popitem(last=False)

            self._seen[message_id] = time.monotonic()
            return True

    def release(self, message_id: str) -> None:
        """Release a previously reserved message ID after processing failure."""
        with self._lock:
            self._seen.pop(message_id, None)

    def has_seen(self, message_id: str) -> bool:
        with self._lock:
            self._evict_expired()
            return message_id in self._seen

    def export(self) -> list[str]:
        with self._lock:
            self._evict_expired()
            return list(self._seen.keys())

    @classmethod
    def from_export(
        cls,
        message_ids: list[str],
        capacity: int = 100_000,
        ttl_seconds: int = MAX_DRIFT_SECONDS,
    ) -> "ReplayDetector":
        detector = cls(capacity, ttl_seconds)
        now = time.monotonic()
        for mid in message_ids[-capacity:]:
            detector._seen[mid] = now
        return detector
