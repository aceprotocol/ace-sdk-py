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
        raise ValueError(f"Invalid message_id: expected UUID v4, got '{message_id}'")


def check_timestamp_freshness(timestamp: int) -> None:
    """Check that a timestamp is within the 5-minute freshness window."""
    now = int(time.time())
    drift = abs(now - timestamp)
    if drift > MAX_DRIFT_SECONDS:
        raise ValueError(
            f"Timestamp not fresh: drift {drift}s exceeds max {MAX_DRIFT_SECONDS}s"
        )


class ReplayDetector:
    """Thread-safe in-memory replay detector with FIFO eviction."""

    def __init__(self, capacity: int = 100_000) -> None:
        self._capacity = capacity
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_reserve(self, message_id: str) -> bool:
        """Atomically check if a messageId has been seen and reserve it.

        Returns True if the message is new (accepted), False if duplicate (rejected).
        Thread-safe: uses a lock to prevent TOCTOU race conditions.
        """
        with self._lock:
            if message_id in self._seen:
                return False

            # Evict oldest if at capacity
            if len(self._seen) >= self._capacity:
                self._seen.popitem(last=False)

            self._seen[message_id] = None
            return True

    def release(self, message_id: str) -> None:
        """Release a previously reserved message ID after processing failure."""
        with self._lock:
            self._seen.pop(message_id, None)

    def has_seen(self, message_id: str) -> bool:
        with self._lock:
            return message_id in self._seen

    def export(self) -> list[str]:
        with self._lock:
            return list(self._seen.keys())

    @classmethod
    def from_export(cls, message_ids: list[str], capacity: int = 100_000) -> "ReplayDetector":
        detector = cls(capacity)
        for mid in message_ids[-capacity:]:
            detector._seen[mid] = None
        return detector
