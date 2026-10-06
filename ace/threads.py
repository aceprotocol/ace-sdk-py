"""Persistent thread records shared by Inbox and Outbox (lock ``threads``)."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal

from ._encoding import is_ace_id, wire_int
from .envelope import decode_envelope
from .errors import ACEError
from .state_machine import (
    TERMINAL_STATES,
    TRANSITIONS,
    ThreadHistoryEntry,
    ThreadSnapshot,
    ThreadStateMachine,
)
from .store import ACEStore, dump_record, load_record
from .types import ACEMessage

THREAD_RETENTION_SECONDS = 30 * 86400
_PRUNE_INTERVAL_SECONDS = 3600


def sha256_hex(*parts: str) -> str:
    """Lowercase hex SHA-256 over the UTF-8 parts joined by one zero byte."""
    return hashlib.sha256(b"\x00".join(p.encode("utf-8") for p in parts)).hexdigest()


def _now(clock: Callable[[], int] | None) -> int:
    return int(clock()) if clock is not None else int(time.time())


@dataclass(frozen=True)
class PendingSend:
    """A signed envelope staged by ``Outbox`` and not yet acknowledged."""

    request_id: str
    status: Literal["pending", "expired"]
    staged_at: int
    message: ACEMessage

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message.to_dict(), "requestId": self.request_id,
            "stagedAt": self.staged_at, "status": self.status,
        }

    @staticmethod
    def from_dict(d: object) -> "PendingSend":
        bad = ACEError("storage_failed", "invalid pending send")
        if not isinstance(d, dict):
            raise bad
        rid, status, staged = d.get("requestId"), d.get("status"), wire_int(d.get("stagedAt"))
        if not isinstance(rid, str) or not rid or status not in ("pending", "expired") or staged is None:
            raise bad
        try:
            message = decode_envelope(d.get("message"))
        except ACEError:
            raise bad from None
        return PendingSend(rid, status, staged, message)


@dataclass(frozen=True)
class ThreadRecord:
    snapshot: ThreadSnapshot
    pending: PendingSend | None

    def to_dict(self) -> dict[str, Any]:
        d = self.snapshot.to_dict()
        d["pending"] = self.pending.to_dict() if self.pending else None
        d["version"] = 1
        return d


def thread_key(conversation_id: str, thread_id: str) -> str:
    return f"threads/{sha256_hex(conversation_id, thread_id)}.json"


def snapshot_from_dict(d: object, local_ace_id: str, code: str = "storage_failed") -> ThreadSnapshot:
    """Parse and replay-validate a snapshot (``ThreadStateMachine.from_state``)."""
    try:
        snap = ThreadSnapshot.from_dict(d)
        ThreadStateMachine.from_state([snap], local_ace_id)
    except ACEError as exc:
        raise ACEError(code, f"invalid thread snapshot: {exc.message}") from None  # type: ignore[arg-type]
    return snap


def rebuild_snapshot(base: ThreadSnapshot, history: list[ThreadHistoryEntry]) -> ThreadSnapshot | None:
    """Re-derive the state of ``history`` (no references: bodies are not stored).

    Returns ``None`` for an empty history; an invalid history is ``storage_failed``.
    """
    if not history:
        return None
    state = "idle"
    for h in history:
        rule = TRANSITIONS.get((state, h.type))
        if rule is None:
            raise ACEError("storage_failed", "thread history does not replay")
        state = rule[0]
    snap = ThreadSnapshot(base.conversation_id, base.thread_id, base.local_ace_id, base.peer_ace_id, state, tuple(history))
    return snapshot_from_dict(snap.to_dict(), base.local_ace_id)


class ThreadStore:
    """Persistent economic threads of ``local_ace_id``.

    Each record is re-validated on load by replaying its history
    (``ThreadStateMachine.from_state``); a record that fails is ``storage_failed`` and is
    never reset. Terminal threads without a pending send whose last entry is older than
    30 days are pruned on writes (at most once per hour of clock time per instance).
    """

    def __init__(self, store: ACEStore, local_ace_id: str, *, clock: Callable[[], int] | None = None) -> None:
        if not is_ace_id(local_ace_id):
            raise ACEError("invalid_argument", "local_ace_id must be an ACE ID")
        self._store = store
        self.local_ace_id = local_ace_id
        self._clock = clock
        self._last_prune: int | None = None

    # --- public ---

    def get(self, conversation_id: str, thread_id: str) -> ThreadSnapshot | None:
        rec = self.load(conversation_id, thread_id)
        return rec.snapshot if rec else None

    def list(self) -> list[ThreadSnapshot]:
        snaps = [self._load_key(k).snapshot for k in self._store.list("threads/")]
        return sorted(snaps, key=lambda s: (s.conversation_id, s.thread_id))

    def remove(self, conversation_id: str, thread_id: str) -> bool:
        with self.locked():
            key = thread_key(conversation_id, thread_id)
            existed = self._store.read(key) is not None
            self._store.delete(key)
            return existed

    def allowed_types(self, conversation_id: str, thread_id: str, sender_ace_id: str) -> list[str]:
        machine, _ = self.machine(conversation_id, thread_id)
        return machine.allowed_types(conversation_id, thread_id, sender_ace_id)

    # --- internal (Inbox / Outbox) ---

    def locked(self, timeout: float = 10.0):
        return self._store.lock("threads", timeout)

    def load(self, conversation_id: str, thread_id: str) -> ThreadRecord | None:
        key = thread_key(conversation_id, thread_id)
        if self._store.read(key) is None:
            return None
        rec = self._load_key(key)
        if (rec.snapshot.conversation_id, rec.snapshot.thread_id) != (conversation_id, thread_id):
            raise ACEError("storage_failed", f"{key} belongs to another thread")
        return rec

    def _load_key(self, key: str) -> ThreadRecord:
        d = load_record(self._store, key)
        if d is None:
            raise ACEError("storage_failed", f"{key} vanished")
        snap = snapshot_from_dict(d, self.local_ace_id)
        if key != thread_key(snap.conversation_id, snap.thread_id):
            raise ACEError("storage_failed", f"{key} does not match its thread")
        pending = None if d.get("pending") is None else PendingSend.from_dict(d["pending"])
        return ThreadRecord(snap, pending)

    def machine(self, conversation_id: str, thread_id: str) -> tuple[ThreadStateMachine, ThreadRecord | None]:
        rec = self.load(conversation_id, thread_id)
        snaps = [rec.snapshot] if rec else []
        try:
            return ThreadStateMachine.from_state(snaps, self.local_ace_id), rec
        except ACEError as exc:
            raise ACEError("storage_failed", exc.message) from None

    def save(self, record: ThreadRecord) -> None:
        snap = record.snapshot
        self._store.write(thread_key(snap.conversation_id, snap.thread_id), dump_record(record.to_dict()))
        self._maybe_prune()

    def delete(self, conversation_id: str, thread_id: str) -> None:
        self._store.delete(thread_key(conversation_id, thread_id))

    def records(self) -> list[ThreadRecord]:
        return [self._load_key(k) for k in self._store.list("threads/")]

    def _maybe_prune(self) -> None:
        now = _now(self._clock)
        if self._last_prune is not None and now - self._last_prune < _PRUNE_INTERVAL_SECONDS:
            return
        self._last_prune = now
        cutoff = now - THREAD_RETENTION_SECONDS
        for key in self._store.list("threads/"):
            try:
                rec = self._load_key(key)
            except ACEError:
                continue  # corrupt records are reported on access, never deleted
            snap = rec.snapshot
            if rec.pending is None and snap.state in TERMINAL_STATES and snap.history[-1].timestamp < cutoff:
                self._store.delete(key)
