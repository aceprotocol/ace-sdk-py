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

    Holds ``(message_id, sender, timestamp)`` for every message whose signature
    verified. Rejects any message with ``timestamp <= horizon``, or ``<=`` its
    sender's horizon, so an entry can be removed once a horizon covers it: only
    the smallest-timestamp entry is removed. Below the acceptance floor it raises
    the horizon; over ``capacity`` it raises only its sender's horizon, so a
    sender flooding the store cannot block anyone else.

    Callers MUST persist state via ``export()`` / ``from_export()`` across restarts.
    """

    def __init__(self, capacity: int = 100_000) -> None:
        if not _is_timestamp(capacity) or capacity < 1:
            raise ValueError("ReplayDetector capacity must be a positive integer")
        self._capacity = capacity
        self._ids: set[str] = set()
        self._heap: list[tuple[int, str, str]] = []  # min-heap of (timestamp, message_id, sender)
        self._horizon = int(time.time()) - MAX_DRIFT_SECONDS
        self._sender_horizons: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def horizon(self) -> int:
        return self._horizon

    def accepts(self, message_id: str, sender: str, timestamp: int) -> bool:
        """Pipeline steps 2–3: timestamp above both horizons and message_id unseen."""
        with self._lock:
            return self._accepts(message_id, sender, timestamp)

    def commit(self, message_id: str, sender: str, timestamp: int, floor: int | None = None) -> bool:
        """Pipeline step 4: record a message whose signature has verified.

        ``sender`` is the envelope ``from`` ACE ID. Returns False if it is a
        duplicate or at/below a horizon. ``floor`` is the acceptance floor
        (default ``now - 5 min``).
        """
        if floor is None:
            floor = int(time.time()) - MAX_DRIFT_SECONDS
        with self._lock:
            if not self._accepts(message_id, sender, timestamp):
                return False
            self._ids.add(message_id)
            heapq.heappush(self._heap, (timestamp, message_id, sender))
            self._evict(floor)
            return True

    def export(self) -> dict:
        with self._lock:
            return {
                "horizon": self._horizon,
                "senderHorizons": dict(self._sender_horizons),
                "entries": [[mid, sender, ts] for ts, mid, sender in self._heap],
            }

    @classmethod
    def from_export(cls, data: dict, capacity: int = 100_000) -> "ReplayDetector":
        detector = cls(capacity)
        horizon = data.get("horizon") if isinstance(data, dict) else None
        sender_horizons = data.get("senderHorizons", {}) if isinstance(data, dict) else None
        entries = data.get("entries") if isinstance(data, dict) else None
        if (
            not _is_timestamp(horizon)
            or not isinstance(sender_horizons, dict)
            or not all(isinstance(s, str) and s and _is_timestamp(h) for s, h in sender_horizons.items())
            or not isinstance(entries, list)
        ):
            raise ValueError("from_export: invalid replay state")
        detector._horizon = horizon
        detector._sender_horizons = dict(sender_horizons)
        for entry in entries:
            mid, sender, ts = entry if isinstance(entry, (list, tuple)) and len(entry) == 3 else (None, None, None)
            if not isinstance(mid, str) or not _MESSAGE_ID_V4_PATTERN.match(mid):
                raise ValueError(f"from_export: invalid message_id '{str(mid)[:50]}'")
            if (
                not isinstance(sender, str) or not sender or not _is_timestamp(ts)
                or not detector._accepts(mid, sender, ts)
            ):
                raise ValueError("from_export: invalid entry")
            detector._ids.add(mid)
            detector._heap.append((ts, mid, sender))
        heapq.heapify(detector._heap)
        detector._evict(0)
        return detector

    def _accepts(self, message_id: str, sender: str, timestamp: int) -> bool:
        return (
            timestamp > self._horizon
            and timestamp > self._sender_horizons.get(sender, self._horizon)
            and message_id not in self._ids
        )

    def _evict(self, floor: int) -> None:
        """Remove smallest-timestamp entries: below ``floor`` they raise the
        horizon, over capacity they raise only their sender's horizon."""
        while self._heap and self._heap[0][0] < floor:
            ts, mid, _ = heapq.heappop(self._heap)
            self._ids.discard(mid)
            self._horizon = max(self._horizon, ts)
        while len(self._heap) > self._capacity:
            ts, mid, sender = heapq.heappop(self._heap)
            self._ids.discard(mid)
            self._sender_horizons[sender] = max(self._sender_horizons.get(sender, ts), ts)
        self._compact_sender_horizons()

    def _compact_sender_horizons(self) -> None:
        """Keep at most ``capacity`` sender horizons: drop those the horizon
        already covers, then fold the lowest half into the horizon (amortized
        O(log n))."""
        if len(self._sender_horizons) <= self._capacity:
            return
        self._sender_horizons = {s: h for s, h in self._sender_horizons.items() if h > self._horizon}
        excess = len(self._sender_horizons) - self._capacity // 2
        if excess <= 0:
            return
        for sender, h in sorted(self._sender_horizons.items(), key=lambda kv: kv[1])[:excess]:
            del self._sender_horizons[sender]
            self._horizon = max(self._horizon, h)
