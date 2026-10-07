"""Thread state machine with parties, roles and fixed reference positions (04)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Literal

from ._encoding import is_ace_id, is_conversation_id, is_message_id, is_thread_id, wire_int
from .errors import ACEError
from .types import ECONOMIC_TYPES, is_economic_type, is_message_type

ThreadState = Literal[
    "idle", "rfq", "offered", "accepted", "rejected", "invoiced", "paid", "delivered", "confirmed",
]

# (from_state, type) -> (to_state, required sender role)
TRANSITIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("idle", "rfq"): ("rfq", "buyer"),
    ("rfq", "offer"): ("offered", "seller"),
    ("rfq", "reject"): ("rejected", "seller"),
    ("offered", "offer"): ("offered", "seller"),
    ("offered", "accept"): ("accepted", "buyer"),
    ("offered", "reject"): ("rejected", "buyer"),
    ("accepted", "invoice"): ("invoiced", "seller"),
    ("accepted", "receipt"): ("paid", "buyer"),
    ("accepted", "deliver"): ("delivered", "seller"),
    ("invoiced", "receipt"): ("paid", "buyer"),
    ("paid", "deliver"): ("delivered", "seller"),
    ("delivered", "confirm"): ("confirmed", "buyer"),
}
TERMINAL_STATES: frozenset[str] = frozenset({"rejected", "confirmed"})

# type -> body field holding the reference
_REFERENCE_FIELDS = {
    "accept": "offerId",
    "invoice": "offerId",
    "receipt": "referenceId",
    "confirm": "deliverId",
}

DEFAULT_MAX_THREADS = 100_000
DEFAULT_MAX_HISTORY_PER_THREAD = 1_000


@dataclass(frozen=True)
class ThreadEvent:
    conversation_id: str
    thread_id: str | None
    type: str
    message_id: str
    timestamp: int
    from_id: str
    to_id: str


@dataclass(frozen=True)
class ThreadHistoryEntry:
    type: str
    message_id: str
    timestamp: int
    from_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "messageId": self.message_id,
            "timestamp": self.timestamp,
            "from": self.from_id,
        }


@dataclass(frozen=True)
class ThreadSnapshot:
    conversation_id: str
    thread_id: str
    local_ace_id: str
    peer_ace_id: str
    state: str
    history: tuple[ThreadHistoryEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversationId": self.conversation_id,
            "threadId": self.thread_id,
            "localAceId": self.local_ace_id,
            "peerAceId": self.peer_ace_id,
            "state": self.state,
            "history": [h.to_dict() for h in self.history],
        }

    @staticmethod
    def from_dict(d: object) -> "ThreadSnapshot":
        """Parse the JSON shape; structural errors raise ``invalid_argument``."""
        bad = ACEError("invalid_argument", "invalid thread snapshot")
        if not isinstance(d, dict) or not isinstance(d.get("history"), list):
            raise bad
        history = []
        for h in d["history"]:
            if not isinstance(h, dict):
                raise bad
            ts = wire_int(h.get("timestamp"))
            if ts is None:
                raise bad
            history.append(ThreadHistoryEntry(h.get("type"), h.get("messageId"), ts, h.get("from")))  # type: ignore[arg-type]
        return ThreadSnapshot(
            d.get("conversationId"),
            d.get("threadId"),
            d.get("localAceId"),  # type: ignore[arg-type]
            d.get("peerAceId"),
            d.get("state"),
            tuple(history),  # type: ignore[arg-type]
        )


@dataclass
class _Thread:
    peer: str
    state: str
    history: list[ThreadHistoryEntry]


def _positive_int(value: object, what: str) -> int:
    if type(value) is not int or value < 1:
        raise ACEError("invalid_argument", f"{what} must be a positive integer")
    return value


class ThreadStateMachine:
    """Per-(conversationId, threadId) economic flow seen from ``local_ace_id``.

    Bounds reject new work and never evict. ``remove()`` drops a thread explicitly.
    """

    def __init__(
        self,
        local_ace_id: str,
        *,
        max_threads: int = DEFAULT_MAX_THREADS,
        max_history_per_thread: int = DEFAULT_MAX_HISTORY_PER_THREAD,
    ) -> None:
        if not is_ace_id(local_ace_id):
            raise ACEError("invalid_argument", "local_ace_id must be an ACE ID")
        self.local_ace_id = local_ace_id
        self._max_threads = _positive_int(max_threads, "max_threads")
        self._max_history = _positive_int(max_history_per_thread, "max_history_per_thread")
        self._threads: dict[tuple[str, str], _Thread] = {}
        self._lock = threading.RLock()

    # --- core rules ---

    def _decide(
        self, e: ThreadEvent, body: object, *, check_refs: bool = True
    ) -> tuple[str, _Thread | None]:
        """Run check order 1-7 and return (next_state, existing thread). Caller holds the lock."""
        if not is_thread_id(e.thread_id):
            raise ACEError("invalid_envelope", "economic messages require a valid threadId")
        local = self.local_ace_id
        if local not in (e.from_id, e.to_id) or e.from_id == e.to_id:
            raise ACEError(
                "wrong_party", "the local identity is not exactly one party of this message"
            )
        thread = self._threads.get((e.conversation_id, e.thread_id))  # type: ignore[arg-type]
        if thread is not None and {local, thread.peer} != {e.from_id, e.to_id}:
            raise ACEError("wrong_party", "message is not between the thread's two parties")
        state = thread.state if thread else "idle"
        rule = None if state in TERMINAL_STATES else TRANSITIONS.get((state, e.type))
        if rule is None:
            raise ACEError(
                "transition_not_allowed", f"{e.type!r} is not allowed in state {state!r}"
            )
        next_state, role = rule
        if thread is not None:
            buyer = thread.history[0].from_id
            sender_role = "buyer" if e.from_id == buyer else "seller"
            if sender_role != role:
                raise ACEError(
                    "wrong_role", f"{e.type!r} in state {state!r} must come from the {role}"
                )
        if check_refs and e.type in _REFERENCE_FIELDS:
            field = _REFERENCE_FIELDS[e.type]
            ref = body.get(field) if isinstance(body, dict) else None
            if not isinstance(ref, str):
                raise ACEError("invalid_body", f"{e.type}.{field} is required")
            assert thread is not None
            expected = thread.history[-2 if e.type == "invoice" else -1].message_id
            if ref != expected:
                raise ACEError(
                    "bad_reference", f"{e.type}.{field} does not reference the required message"
                )
        if thread is None:
            if len(self._threads) >= self._max_threads:
                raise ACEError("limit_exceeded", f"thread limit {self._max_threads} reached")
        elif len(thread.history) >= self._max_history:
            raise ACEError("limit_exceeded", f"thread history limit {self._max_history} reached")
        return next_state, thread

    def _commit(self, e: ThreadEvent, next_state: str, thread: _Thread | None) -> None:
        entry = ThreadHistoryEntry(e.type, e.message_id, e.timestamp, e.from_id)
        if thread is None:
            peer = e.to_id if e.from_id == self.local_ace_id else e.from_id
            self._threads[(e.conversation_id, e.thread_id)] = _Thread(peer, next_state, [entry])  # type: ignore[index]
        else:
            thread.state = next_state
            thread.history.append(entry)

    @staticmethod
    def _check_event(e: object) -> ThreadEvent:
        if not isinstance(e, ThreadEvent):
            raise ACEError("invalid_argument", "expected a ThreadEvent")
        if not is_message_type(e.type):
            raise ACEError("invalid_envelope", "unknown message type")
        return e

    def check(self, e: ThreadEvent, body: object) -> None:
        """Raise the deterministic error ``apply`` would raise; never mutates."""
        e = self._check_event(e)
        if not is_economic_type(e.type):
            return
        with self._lock:
            self._decide(e, body)

    def apply(self, e: ThreadEvent, body: object) -> str:
        """Check and apply; returns the resulting state (non-economic: current state)."""
        e = self._check_event(e)
        with self._lock:
            if not is_economic_type(e.type):
                return self.get_state(e.conversation_id, e.thread_id) if e.thread_id else "idle"
            next_state, thread = self._decide(e, body)
            self._commit(e, next_state, thread)
            return next_state

    # --- queries ---

    def get_state(self, conversation_id: str, thread_id: str) -> str:
        with self._lock:
            t = self._threads.get((conversation_id, thread_id))
            return t.state if t else "idle"

    def get_snapshot(self, conversation_id: str, thread_id: str) -> ThreadSnapshot | None:
        with self._lock:
            t = self._threads.get((conversation_id, thread_id))
            if t is None:
                return None
            return ThreadSnapshot(
                conversation_id, thread_id, self.local_ace_id, t.peer, t.state, tuple(t.history)
            )

    def allowed_types(self, conversation_id: str, thread_id: str, sender_ace_id: str) -> list[str]:
        """Economic types ``sender_ace_id`` may send next (table order)."""
        with self._lock:
            t = self._threads.get((conversation_id, thread_id))
            if t is None:
                return ["rfq"]
            if sender_ace_id not in (self.local_ace_id, t.peer) or t.state in TERMINAL_STATES:
                return []
            role = "buyer" if sender_ace_id == t.history[0].from_id else "seller"
            return [
                typ
                for (state, typ), (_, r) in TRANSITIONS.items()
                if state == t.state and r == role
            ]

    def is_terminal(self, conversation_id: str, thread_id: str) -> bool:
        return self.get_state(conversation_id, thread_id) in TERMINAL_STATES

    def remove(self, conversation_id: str, thread_id: str) -> bool:
        with self._lock:
            return self._threads.pop((conversation_id, thread_id), None) is not None

    def export_state(self) -> list[ThreadSnapshot]:
        with self._lock:
            return [
                ThreadSnapshot(c, t, self.local_ace_id, th.peer, th.state, tuple(th.history))
                for (c, t), th in sorted(self._threads.items())
            ]

    @classmethod
    def from_state(
        cls,
        snapshots: list[ThreadSnapshot],
        local_ace_id: str,
        *,
        max_threads: int = DEFAULT_MAX_THREADS,
        max_history_per_thread: int = DEFAULT_MAX_HISTORY_PER_THREAD,
    ) -> "ThreadStateMachine":
        """Replay every snapshot's history under the party/role rules; any violation is
        ``invalid_argument``.

        Reference positions cannot be re-checked (bodies are not stored).
        """
        sm = cls(
            local_ace_id, max_threads=max_threads, max_history_per_thread=max_history_per_thread
        )

        def bad(msg: str) -> ACEError:
            return ACEError("invalid_argument", f"from_state: {msg}")

        if not isinstance(snapshots, (list, tuple)):
            raise bad("snapshots must be a list")
        for snap in snapshots:
            if not isinstance(snap, ThreadSnapshot):
                raise bad("expected ThreadSnapshot entries")
            if not is_conversation_id(snap.conversation_id) or not is_thread_id(snap.thread_id):
                raise bad("invalid conversationId or threadId")
            if snap.local_ace_id != local_ace_id:
                raise bad("snapshot belongs to another local identity")
            if not is_ace_id(snap.peer_ace_id) or snap.peer_ace_id == local_ace_id:
                raise bad("invalid peerAceId")
            if (snap.conversation_id, snap.thread_id) in sm._threads:
                raise bad("duplicate thread")
            if not snap.history:
                raise bad("history must not be empty")
            for h in snap.history:
                if (
                    not isinstance(h, ThreadHistoryEntry)
                    or h.type not in ECONOMIC_TYPES
                    or not is_message_id(h.message_id)
                    or wire_int(h.timestamp) is None
                    or isinstance(h.timestamp, float)
                    or h.from_id not in (local_ace_id, snap.peer_ace_id)
                ):
                    raise bad("invalid history entry")
                to_id = snap.peer_ace_id if h.from_id == local_ace_id else local_ace_id
                e = ThreadEvent(
                    snap.conversation_id,
                    snap.thread_id,
                    h.type,
                    h.message_id,
                    h.timestamp,
                    h.from_id,
                    to_id,
                )
                try:
                    next_state, thread = sm._decide(e, None, check_refs=False)
                except ACEError as exc:
                    raise bad(exc.message) from None
                sm._commit(e, next_state, thread)
            if sm.get_state(snap.conversation_id, snap.thread_id) != snap.state:
                raise bad("declared state does not match the replayed history")
        return sm
