"""ACE Protocol security: replay detection + timestamp freshness."""

from __future__ import annotations

import heapq
import re
import threading
import time

MAX_DRIFT_SECONDS = 300  # 5 minutes
_MESSAGE_ID_V4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def validate_message_id(message_id: str) -> None:
    """Validate that a message ID is a valid UUID v4."""
    if not _MESSAGE_ID_V4_PATTERN.match(message_id):
        raise ValueError(f"Invalid message_id: expected UUID v4, got '{message_id[:50]}'")


def check_timestamp_freshness(timestamp: int, oldest_timestamp: int | None = None) -> None:
    """Check ``floor <= timestamp <= now + 5 min``.

    The floor is ``now - 5 min``, or ``oldest_timestamp`` for offline delivery.
    """
    if not _is_timestamp(timestamp):
        raise ValueError("Invalid timestamp: must be a non-negative integer")
    now = int(time.time())
    if oldest_timestamp is not None and (not _is_timestamp(oldest_timestamp) or oldest_timestamp > now):
        raise ValueError("Invalid offline timestamp floor")
    floor = now - MAX_DRIFT_SECONDS if oldest_timestamp is None else oldest_timestamp
    if timestamp < floor or timestamp > now + MAX_DRIFT_SECONDS:
        drift = abs(now - timestamp)
        raise ValueError(
            f"Timestamp not fresh: drift {drift}s exceeds max {MAX_DRIFT_SECONDS}s"
        )


def _is_timestamp(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class ReplayDetector:
    """Thread-safe seen store with a replay horizon (06-security § Replay Protection).

    Holds ``(message_id, timestamp)`` for every message whose signature verified.
    Rejects any message with ``timestamp <= horizon``, so an entry can be removed
    once the horizon covers it: only the smallest-timestamp entry is removed, and
    the horizon moves up to its timestamp. Removal happens when the entry falls
    below the acceptance floor or the store exceeds ``capacity``.

    Callers MUST persist state via ``export()`` / ``from_export()`` across restarts.
    """

    def __init__(self, capacity: int = 100_000) -> None:
        if not _is_timestamp(capacity) or capacity < 1:
            raise ValueError("ReplayDetector capacity must be a positive integer")
        self._capacity = capacity
        self._ids: set[str] = set()
        self._heap: list[tuple[int, str]] = []  # min-heap of (timestamp, message_id)
        self._horizon = int(time.time()) - MAX_DRIFT_SECONDS
        self._lock = threading.Lock()

    @property
    def horizon(self) -> int:
        return self._horizon

    def accepts(self, message_id: str, timestamp: int) -> bool:
        """Pipeline steps 2–3: timestamp above the horizon and message_id unseen."""
        with self._lock:
            return self._accepts(message_id, timestamp)

    def commit(self, message_id: str, timestamp: int, floor: int | None = None) -> bool:
        """Pipeline step 4: record a message whose signature has verified.

        Returns False if it is a duplicate or at/below the horizon. ``floor`` is
        the acceptance floor (default ``now - 5 min``).
        """
        if floor is None:
            floor = int(time.time()) - MAX_DRIFT_SECONDS
        with self._lock:
            if not self._accepts(message_id, timestamp):
                return False
            self._ids.add(message_id)
            heapq.heappush(self._heap, (timestamp, message_id))
            self._evict(floor)
            return True

    def export(self) -> dict:
        with self._lock:
            return {"horizon": self._horizon, "entries": [[mid, ts] for ts, mid in self._heap]}

    @classmethod
    def from_export(cls, data: dict, capacity: int = 100_000) -> "ReplayDetector":
        detector = cls(capacity)
        horizon = data.get("horizon") if isinstance(data, dict) else None
        entries = data.get("entries") if isinstance(data, dict) else None
        if not _is_timestamp(horizon) or not isinstance(entries, list):
            raise ValueError("from_export: invalid replay state")
        detector._horizon = horizon
        for entry in entries:
            mid, ts = entry if isinstance(entry, (list, tuple)) and len(entry) == 2 else (None, None)
            if not isinstance(mid, str) or not _MESSAGE_ID_V4_PATTERN.match(mid):
                raise ValueError(f"from_export: invalid message_id '{str(mid)[:50]}'")
            if not _is_timestamp(ts) or ts <= horizon or mid in detector._ids:
                raise ValueError("from_export: invalid entry")
            detector._ids.add(mid)
            detector._heap.append((ts, mid))
        heapq.heapify(detector._heap)
        detector._evict(0)
        return detector

    def _accepts(self, message_id: str, timestamp: int) -> bool:
        return timestamp > self._horizon and message_id not in self._ids

    def _evict(self, floor: int) -> None:
        """Remove smallest-timestamp entries while below ``floor`` or over capacity."""
        while self._heap and (self._heap[0][0] < floor or len(self._heap) > self._capacity):
            ts, mid = heapq.heappop(self._heap)
            self._ids.discard(mid)
            self._horizon = ts
