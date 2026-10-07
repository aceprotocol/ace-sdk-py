"""Seen store with replay horizons and a per-sender quota (06-security)."""

from __future__ import annotations

import copy
import heapq
import threading
from typing import Callable

from ._encoding import check_wire_int, is_message_id, unix_now, wire_int
from .errors import ACEError
from .limits import DEFAULT_REPLAY_CAPACITY, TIMESTAMP_WINDOW_SECONDS
from .types import ReplayState


class ReplayDetector:
    """Thread-safe seen store.

    A message ``(id, sender, ts)`` is accepted iff ``ts > H``, ``ts > SH[sender]`` and the
    pair is unseen. Entries are removed only once a horizon covers them:

    1. entries below the acceptance floor raise ``H``;
    2. a sender holding more than ``Q = max(1, capacity // 16)`` entries loses its
       smallest ones and raises only its own ``SH[sender]``;
    3. over capacity, the global smallest is removed and raises its sender's ``SH``;
    4. sender horizons covered by ``H`` are dropped; more than ``capacity`` of them
       fold the lowest into ``H``.

    Persist with ``export_state()`` / ``ReplayDetector.from_state()``.
    """

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_REPLAY_CAPACITY,
        horizon: int | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if type(capacity) is not int or capacity < 1:
            raise ACEError("invalid_argument", "capacity must be an integer >= 1")
        self._capacity = capacity
        self._quota = max(1, capacity // 16)
        self._clock = clock
        self._horizon = (
            max(0, unix_now(clock) - TIMESTAMP_WINDOW_SECONDS)
            if horizon is None
            else check_wire_int(horizon, "horizon")
        )
        self._sh: dict[str, int] = {}
        self._sh_heap: list[tuple[int, str]] = []  # lazy (h, sender)
        self._live: dict[tuple[str, str], int] = {}  # (sender, id) -> ts
        self._global: list[tuple[int, str, str]] = []  # lazy (ts, sender, id)
        self._per_sender: dict[str, list[tuple[int, str]]] = {}  # lazy (ts, id)
        self._counts: dict[str, int] = {}
        self._lock = threading.RLock()

    @property
    def horizon(self) -> int:
        return self._horizon

    @property
    def capacity(self) -> int:
        return self._capacity

    # --- public API ---

    def accepts(self, message_id: str, sender: str, timestamp: int) -> bool:
        self._check_args(message_id, sender, timestamp)
        with self._lock:
            return self._accepts(message_id, sender, timestamp)

    def _covered(self, sender: str, timestamp: int) -> bool:
        """True if a horizon (``H`` or ``SH[sender]``) covers ``timestamp`` (Inbox internal)."""
        with self._lock:
            return self._covers(sender, timestamp)

    def commit(
        self, message_id: str, sender: str, timestamp: int, floor: int | None = None
    ) -> bool:
        """Record a verified message. False if it is a duplicate or covered by a horizon."""
        self._check_args(message_id, sender, timestamp)
        floor = (
            max(0, unix_now(self._clock) - TIMESTAMP_WINDOW_SECONDS)
            if floor is None
            else check_wire_int(floor, "floor")
        )
        with self._lock:
            if not self._accepts(message_id, sender, timestamp):
                return False
            self._insert(timestamp, sender, message_id)
            # 1. floor eviction raises H
            while (m := self._peek_global()) is not None and m[0] < floor:
                self._remove(m[1], m[2])
                self._horizon = max(self._horizon, m[0])
            self._purge_global()
            # 2. sender quota
            self._enforce_quota(sender)
            # 3. capacity
            self._enforce_capacity()
            # 4. sender-horizon compaction
            self._compact()
            return True

    def clone(self) -> "ReplayDetector":
        with self._lock:
            other = copy.copy(self)
            other._sh = dict(self._sh)
            other._sh_heap = list(self._sh_heap)
            other._live = dict(self._live)
            other._global = list(self._global)
            other._per_sender = {s: list(h) for s, h in self._per_sender.items()}
            other._counts = dict(self._counts)
            other._lock = threading.RLock()
            return other

    def export_state(self) -> ReplayState:
        """Canonical state: entries sorted by (timestamp, sender, messageId), horizons sorted."""
        with self._lock:
            entries = sorted((ts, s, mid) for (s, mid), ts in self._live.items())
            return {
                "entries": [[mid, s, ts] for ts, s, mid in entries],
                "horizon": self._horizon,
                "senderHorizons": {s: h for s, h in sorted(self._sh.items()) if h > self._horizon},
                "version": 1,
            }

    @classmethod
    def from_state(
        cls,
        state: ReplayState,
        *,
        capacity: int = DEFAULT_REPLAY_CAPACITY,
        clock: Callable[[], int] | None = None,
    ) -> "ReplayDetector":
        """Validate (``invalid_argument``) and normalize a persisted state."""

        def bad(msg: str) -> ACEError:
            return ACEError("invalid_argument", f"from_state: {msg}")

        if not isinstance(state, dict):
            raise bad("state must be an object")
        version = state.get("version")
        if isinstance(version, bool) or version != 1:
            raise bad("version must be 1")
        horizon = wire_int(state.get("horizon"))
        sh = state.get("senderHorizons")
        entries = state.get("entries")
        if horizon is None or not isinstance(sh, dict) or not isinstance(entries, list):
            raise bad("horizon, senderHorizons and entries are required")
        det = cls(capacity=capacity, horizon=horizon, clock=clock)
        for s, h in sh.items():
            hv = wire_int(h)
            if not isinstance(s, str) or not s or hv is None:
                raise bad("invalid sender horizon")
            det._set_sh(s, hv)
        for entry in entries:
            if not isinstance(entry, list) or len(entry) != 3:
                raise bad("entries must be [messageId, sender, timestamp]")
            mid, s, ts = entry[0], entry[1], wire_int(entry[2])
            if not is_message_id(mid) or not isinstance(s, str) or not s or ts is None:
                raise bad("invalid entry")
            if not det._accepts(mid, s, ts):
                raise bad("entry is covered by a horizon or duplicated")
            det._insert(ts, s, mid)
        for s in sorted(det._counts):
            det._enforce_quota(s)
        det._enforce_capacity()
        det._compact()
        return det

    # --- internals (caller holds the lock) ---

    @staticmethod
    def _check_args(message_id: object, sender: object, timestamp: object) -> None:
        if (
            not isinstance(message_id, str)
            or not message_id
            or not isinstance(sender, str)
            or not sender
        ):
            raise ACEError("invalid_argument", "message_id and sender must be non-empty strings")
        check_wire_int(timestamp, "timestamp")

    def _covers(self, s: str, ts: int) -> bool:
        return ts <= self._horizon or ts <= self._sh.get(s, self._horizon)

    def _accepts(self, mid: str, s: str, ts: int) -> bool:
        return not self._covers(s, ts) and (s, mid) not in self._live

    def _insert(self, ts: int, s: str, mid: str) -> None:
        self._live[(s, mid)] = ts
        heapq.heappush(self._global, (ts, s, mid))
        heapq.heappush(self._per_sender.setdefault(s, []), (ts, mid))
        self._counts[s] = self._counts.get(s, 0) + 1

    def _remove(self, s: str, mid: str) -> None:
        del self._live[(s, mid)]
        c = self._counts[s] - 1
        if c:
            self._counts[s] = c
        else:
            del self._counts[s]
            self._per_sender.pop(s, None)

    def _peek_global(self) -> tuple[int, str, str] | None:
        g = self._global
        while g and self._live.get((g[0][1], g[0][2])) != g[0][0]:
            heapq.heappop(g)
        return g[0] if g else None

    def _peek_sender(self, s: str) -> tuple[int, str] | None:
        h = self._per_sender.get(s)
        while h and self._live.get((s, h[0][1])) != h[0][0]:
            heapq.heappop(h)
        return h[0] if h else None

    def _set_sh(self, s: str, h: int) -> None:
        self._sh[s] = h
        heapq.heappush(self._sh_heap, (h, s))

    def _raise_sh(self, s: str, ts: int) -> None:
        self._set_sh(s, max(self._sh.get(s, self._horizon), ts))
        limit = self._sh[s]
        while (m := self._peek_sender(s)) is not None and m[0] <= limit:
            self._remove(s, m[1])

    def _purge_global(self) -> None:
        while (m := self._peek_global()) is not None and m[0] <= self._horizon:
            self._remove(m[1], m[2])

    def _enforce_quota(self, s: str) -> None:
        while self._counts.get(s, 0) > self._quota:
            ts, mid = self._peek_sender(s)  # type: ignore[misc]
            self._remove(s, mid)
            self._raise_sh(s, ts)

    def _enforce_capacity(self) -> None:
        while len(self._live) > self._capacity:
            ts, s, mid = self._peek_global()  # type: ignore[misc]
            self._remove(s, mid)
            self._raise_sh(s, ts)

    def _drop_covered_sh(self) -> None:
        heap = self._sh_heap
        while heap and heap[0][0] <= self._horizon:
            h, s = heapq.heappop(heap)
            if self._sh.get(s) == h:
                del self._sh[s]

    def _compact(self) -> None:
        self._drop_covered_sh()
        if len(self._sh) <= self._capacity:
            return
        excess = len(self._sh) - self._capacity // 2
        for s, h in sorted(self._sh.items(), key=lambda kv: (kv[1], kv[0]))[:excess]:
            del self._sh[s]
            self._horizon = max(self._horizon, h)
        self._purge_global()
        self._drop_covered_sh()
        self._sh_heap = [(h, s) for s, h in self._sh.items()]
        heapq.heapify(self._sh_heap)
