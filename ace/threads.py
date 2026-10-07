"""Persistent thread records shared by Inbox and Outbox (lock ``threads``)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Literal

from ._encoding import is_ace_id, unix_now, wire_int
from .envelope import decode_envelope
from .errors import ACEError
from .limits import MAX_OPEN_THREADS_PER_PEER
from .state_machine import (
    TERMINAL_STATES,
    TRANSITIONS,
    ThreadHistoryEntry,
    ThreadSnapshot,
    ThreadStateMachine,
)
from .store import ACEStore, load_record, write_record
from .types import ACEMessage

THREAD_RETENTION_SECONDS = 30 * 86400
_PRUNE_INTERVAL_SECONDS = 3600


def sha256_hex(*parts: str) -> str:
    """Lowercase hex SHA-256 over the UTF-8 parts joined by one zero byte."""
    return hashlib.sha256(b"\x00".join(p.encode("utf-8") for p in parts)).hexdigest()


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
        if (
            not isinstance(rid, str)
            or not rid
            or status not in ("pending", "expired")
            or staged is None
        ):
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
        return d


def thread_key(conversation_id: str, thread_id: str) -> str:
    return f"threads/{sha256_hex(conversation_id, thread_id)}.json"


_INDEX_PREFIX = "threads/index/"


def thread_index_key(peer_ace_id: str) -> str:
    """The per-peer open-thread index: ``threads/index/<sha256(peerAceId)>.json``."""
    return f"{_INDEX_PREFIX}{sha256_hex(peer_ace_id)}.json"


def _is_record_key(key: str) -> bool:
    return not key.startswith(_INDEX_PREFIX)


def _index_entry(record_key: str) -> str:
    return record_key[: -len(".json")]


def snapshot_from_dict(
    d: object, local_ace_id: str, code: str = "storage_failed"
) -> ThreadSnapshot:
    """Parse and replay-validate a snapshot (``ThreadStateMachine.from_state``)."""
    try:
        snap = ThreadSnapshot.from_dict(d)
        ThreadStateMachine.from_state([snap], local_ace_id)
    except ACEError as exc:
        raise ACEError(code, f"invalid thread snapshot: {exc.message}") from None  # type: ignore[arg-type]
    return snap


def rebuild_snapshot(
    base: ThreadSnapshot, history: list[ThreadHistoryEntry]
) -> ThreadSnapshot | None:
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
    snap = ThreadSnapshot(
        base.conversation_id,
        base.thread_id,
        base.local_ace_id,
        base.peer_ace_id,
        state,
        tuple(history),
    )
    return snapshot_from_dict(snap.to_dict(), base.local_ace_id)


class ThreadStore:
    """Persistent economic threads of ``local_ace_id``.

    Each record is re-validated on load by replaying its history
    (``ThreadStateMachine.from_state``); a record that fails is ``storage_failed`` and is
    never reset. Threads without a pending send whose last entry is older than 30 days are
    pruned on writes (at most once per hour of clock time per instance) when they are
    terminal, or non-terminal without any local entry (04 § Retention).

    A per-peer index of non-terminal threads (``threads/index/``) bounds the open threads
    per peer at ``MAX_OPEN_THREADS_PER_PEER``. It is written so that a crash can only leave
    extra entries, which are reconciled when the bound is reached.
    """

    def __init__(
        self, store: ACEStore, local_ace_id: str, *, clock: Callable[[], int] | None = None
    ) -> None:
        if not is_ace_id(local_ace_id):
            raise ACEError("invalid_argument", "local_ace_id must be an ACE ID")
        self._store = store
        self.local_ace_id = local_ace_id
        self._clock = clock
        self._last_prune: int | None = None

    # --- public ---

    def get(self, conversation_id: str, thread_id: str) -> ThreadSnapshot | None:
        rec = self._load(conversation_id, thread_id)
        return rec.snapshot if rec else None

    def list(self) -> list[ThreadSnapshot]:
        snaps = [
            self._load_key(k).snapshot for k in self._store.list("threads/") if _is_record_key(k)
        ]
        return sorted(snaps, key=lambda s: (s.conversation_id, s.thread_id))

    def remove(self, conversation_id: str, thread_id: str) -> bool:
        with self._locked():
            key = thread_key(conversation_id, thread_id)
            if self._store.read(key) is None:
                return False
            try:
                peer: str | None = self._load_key(key).snapshot.peer_ace_id
            except ACEError:
                peer = None  # a corrupt record leaves at most an extra index entry
            self._store.delete(key)
            if peer is not None:
                self._set_open(peer, key, False)
            return True

    def allowed_types(self, conversation_id: str, thread_id: str, sender_ace_id: str) -> list[str]:
        machine, _ = self._machine(conversation_id, thread_id)
        return machine.allowed_types(conversation_id, thread_id, sender_ace_id)

    # --- internal (Inbox / Outbox; not part of the public API) ---

    def _locked(self, timeout: float = 10.0):
        return self._store.lock("threads", timeout)

    def _load(self, conversation_id: str, thread_id: str) -> ThreadRecord | None:
        key = thread_key(conversation_id, thread_id)
        d = load_record(self._store, key)
        if d is None:
            return None
        rec = self._record_from_dict(key, d)
        if (rec.snapshot.conversation_id, rec.snapshot.thread_id) != (conversation_id, thread_id):
            raise ACEError("storage_failed", f"{key} belongs to another thread")
        return rec

    def _load_key(self, key: str) -> ThreadRecord:
        d = load_record(self._store, key)
        if d is None:
            raise ACEError("storage_failed", f"{key} vanished")
        return self._record_from_dict(key, d)

    def _record_from_dict(self, key: str, d: dict) -> ThreadRecord:
        snap = snapshot_from_dict(d, self.local_ace_id)
        if key != thread_key(snap.conversation_id, snap.thread_id):
            raise ACEError("storage_failed", f"{key} does not match its thread")
        pending = None if d.get("pending") is None else PendingSend.from_dict(d["pending"])
        return ThreadRecord(snap, pending)

    def _machine(
        self, conversation_id: str, thread_id: str
    ) -> tuple[ThreadStateMachine, ThreadRecord | None]:
        rec = self._load(conversation_id, thread_id)
        snaps = [rec.snapshot] if rec else []
        try:
            return ThreadStateMachine.from_state(snaps, self.local_ace_id), rec
        except ACEError as exc:
            raise ACEError("storage_failed", exc.message) from None

    def _save(self, record: ThreadRecord) -> None:
        snap = record.snapshot
        key = thread_key(snap.conversation_id, snap.thread_id)
        is_open = snap.state not in TERMINAL_STATES
        if is_open:
            self._set_open(
                snap.peer_ace_id, key, True
            )  # index first: a crash leaves only an extra entry
        write_record(self._store, key, record.to_dict())
        if not is_open:
            self._set_open(snap.peer_ace_id, key, False)
        self._maybe_prune()

    def _delete(self, snapshot: ThreadSnapshot) -> None:
        key = thread_key(snapshot.conversation_id, snapshot.thread_id)
        self._store.delete(key)
        self._set_open(snapshot.peer_ace_id, key, False)

    def _records(self) -> list[ThreadRecord]:
        return [self._load_key(k) for k in self._store.list("threads/") if _is_record_key(k)]

    def _open_thread_count(self, peer_ace_id: str) -> int:
        """Non-terminal threads held with ``peer_ace_id`` (caller holds the lock). At the bound
        the index is reconciled against the records first, dropping stale entries."""
        entries = self._read_index(peer_ace_id)
        if len(entries) < MAX_OPEN_THREADS_PER_PEER:
            return len(entries)
        live = []
        for entry in entries:
            key = f"{entry}.json"
            if self._store.read(key) is None:
                continue
            try:
                snap = self._load_key(key).snapshot
                if snap.peer_ace_id != peer_ace_id or snap.state in TERMINAL_STATES:
                    continue
            except ACEError:
                pass  # a corrupt record still counts: it is never reset or discarded
            live.append(entry)
        if len(live) != len(entries):
            self._write_index(peer_ace_id, live)
        return len(live)

    def _check_can_open(self, peer_ace_id: str) -> None:
        """``limit_exceeded`` if a new thread with ``peer_ace_id`` would exceed
        ``MAX_OPEN_THREADS_PER_PEER`` (caller holds the lock)."""
        if self._open_thread_count(peer_ace_id) >= MAX_OPEN_THREADS_PER_PEER:
            raise ACEError(
                "limit_exceeded",
                f"open thread limit {MAX_OPEN_THREADS_PER_PEER} reached for this peer",
            )

    def _read_index(self, peer_ace_id: str) -> list[str]:
        key = thread_index_key(peer_ace_id)
        d = load_record(self._store, key)
        if d is None:
            return []
        entries = d.get("open")
        if not isinstance(entries, list) or not all(
            isinstance(e, str) and e.startswith("threads/") for e in entries
        ):
            raise ACEError("storage_failed", f"{key}: invalid open-thread index")
        return entries

    def _write_index(self, peer_ace_id: str, entries: list[str]) -> None:
        key = thread_index_key(peer_ace_id)
        if entries:
            write_record(self._store, key, {"open": sorted(entries)})
        else:
            self._store.delete(key)

    def _set_open(self, peer_ace_id: str, record_key: str, is_open: bool) -> None:
        entry = _index_entry(record_key)
        cur = self._read_index(peer_ace_id)
        if (entry in cur) == is_open:
            return
        self._write_index(peer_ace_id, [*cur, entry] if is_open else [e for e in cur if e != entry])

    def _maybe_prune(self) -> None:
        now = unix_now(self._clock)
        if self._last_prune is not None and now - self._last_prune < _PRUNE_INTERVAL_SECONDS:
            return
        self._last_prune = now
        cutoff = now - THREAD_RETENTION_SECONDS
        for key in self._store.list("threads/"):
            if not _is_record_key(key):
                continue
            try:
                rec = self._load_key(key)
            except ACEError:
                continue  # corrupt records are reported on access, never deleted
            snap = rec.snapshot
            if rec.pending is not None or snap.history[-1].timestamp >= cutoff:
                continue
            # terminal, or non-terminal with no local entry (no local obligation exists)
            if snap.state in TERMINAL_STATES or all(
                h.from_id != self.local_ace_id for h in snap.history
            ):
                self._delete(snap)
