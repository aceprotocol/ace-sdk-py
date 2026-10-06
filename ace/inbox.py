"""Receive engine (06-security "Durable Delivery", Receiver)."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Literal, NamedTuple

from ._encoding import is_ace_id, is_conversation_id, is_message_id, is_thread_id, wire_int
from .encryption import compute_conversation_id
from .envelope import decode_envelope, envelope_fingerprint
from .errors import ACEError
from .limits import (
    DEFAULT_REPLAY_CAPACITY,
    MAX_INBOX_PAGE,
    OFFLINE_WINDOW_SECONDS,
    TIMESTAMP_WINDOW_SECONDS,
)
from .messages import parse_message
from .peers import PeerStore
from .relay import STREAM_ID_RE, RelayClient, compare_stream_ids, normalize_relay_url
from .replay import ReplayDetector
from .state_machine import ThreadSnapshot, ThreadStateMachine
from .store import ACEStore, dump_record, load_record
from .threads import ThreadRecord, ThreadStore, sha256_hex, snapshot_from_dict
from .types import ACEIdentity, ACEMessage, ParsedMessage, is_economic_type, is_message_type

QUARANTINE_CAP = 1000
QUARANTINE_KEEP = 900
_SWEEP_EVERY = 1024
_REASON_MAX = 1000


@dataclass(frozen=True)
class ReceiveSource:
    """Where an envelope came from. Build with ``ReceiveSource.relay(url, stream_id)`` or
    ``ReceiveSource.direct()``. ``relay_url`` is normalized."""

    kind: Literal["relay", "direct"]
    relay_url: str | None = None
    stream_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind == "relay":
            object.__setattr__(self, "relay_url", normalize_relay_url(self.relay_url))
            if self.stream_id is not None and (
                not isinstance(self.stream_id, str) or STREAM_ID_RE.fullmatch(self.stream_id) is None
            ):
                raise ACEError("invalid_argument", "stream_id must be '<ms>-<seq>'")
        elif self.kind == "direct":
            if self.relay_url is not None or self.stream_id is not None:
                raise ACEError("invalid_argument", "a direct source has no relay_url / stream_id")
        else:
            raise ACEError("invalid_argument", "kind must be 'relay' or 'direct'")

    @classmethod
    def relay(cls, relay_url: str, stream_id: str | None = None) -> "ReceiveSource":
        return cls("relay", relay_url, stream_id)

    @classmethod
    def direct(cls) -> "ReceiveSource":
        return cls("direct")


@dataclass(frozen=True)
class ReceiveOutcome:
    """``kind``: ``delivered`` (``message``), ``duplicate`` (``from_id``, ``message_id``),
    ``quarantined`` (``error``, ``fingerprint`` or None) or ``retryable`` (``error``)."""

    kind: Literal["delivered", "duplicate", "quarantined", "retryable"]
    message: ParsedMessage | None = None
    error: ACEError | None = None
    fingerprint: str | None = None
    from_id: str | None = None
    message_id: str | None = None


class PullResult(NamedTuple):
    delivered: int
    duplicates: int
    quarantined: int
    blocked: ACEError | None


def delivery_key(from_id: str, message_id: str) -> str:
    return f"deliveries/{sha256_hex(from_id, message_id)}.json"


def _parsed_to_dict(m: ParsedMessage) -> dict[str, Any]:
    return {
        "body": m.body, "conversationId": m.conversation_id, "from": m.from_id, "messageId": m.message_id,
        "threadId": m.thread_id, "timestamp": m.timestamp, "to": m.to_id, "type": m.type,
    }


@dataclass
class _Delivery:
    key: str
    message: ParsedMessage
    fingerprint: str
    received_at: int
    source: str
    status: str
    thread: ThreadSnapshot | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint, "message": _parsed_to_dict(self.message),
            "receivedAt": self.received_at, "source": self.source, "status": self.status,
            "thread": self.thread.to_dict() if self.thread else None, "version": 1,
        }


def _delivery_from_dict(d: dict, key: str, local_ace_id: str) -> _Delivery:
    def bad(what: str) -> ACEError:
        return ACEError("storage_failed", f"{key}: invalid delivery record ({what})")

    m = d.get("message")
    if not isinstance(m, dict):
        raise bad("message")
    ts = wire_int(m.get("timestamp"))
    thread_id = m.get("threadId")
    if (
        not is_ace_id(m.get("from")) or not is_ace_id(m.get("to")) or not is_message_id(m.get("messageId"))
        or not is_conversation_id(m.get("conversationId")) or not is_message_type(m.get("type"))
        or ts is None or not isinstance(m.get("body"), dict)
        or (thread_id is not None and not is_thread_id(thread_id))
    ):
        raise bad("message fields")
    parsed = ParsedMessage(
        message_id=m["messageId"], from_id=m["from"], to_id=m["to"], conversation_id=m["conversationId"],
        type=m["type"], thread_id=thread_id, timestamp=ts, body=m["body"],
    )
    if key != delivery_key(parsed.from_id, parsed.message_id):
        raise bad("key")
    received_at = wire_int(d.get("receivedAt"))
    if (
        received_at is None or d.get("source") not in ("relay", "direct")
        or d.get("status") not in ("pending", "acked") or not isinstance(d.get("fingerprint"), str)
    ):
        raise bad("fields")
    thread = None if d.get("thread") is None else snapshot_from_dict(d["thread"], local_ace_id)
    return _Delivery(key, parsed, d["fingerprint"], received_at, d["source"], d["status"], thread)


def _history_dicts(snap: ThreadSnapshot | None) -> list[dict]:
    return [] if snap is None else [h.to_dict() for h in snap.history]


def _clear_proven_pending(rec: ThreadRecord | None, new_snap: ThreadSnapshot) -> Any:
    """The stored pending send, or None when ``new_snap`` proves its delivery (it is
    followed by an entry from the peer)."""
    if rec is None or rec.pending is None:
        return None if rec is None else rec.pending
    mid = rec.pending.message.message_id
    ids = [h.message_id for h in new_snap.history]
    if mid in ids and any(h.from_id != new_snap.local_ace_id for h in new_snap.history[ids.index(mid) + 1:]):
        return None
    return rec.pending


def load_deliveries(store: ACEStore, local_ace_id: str) -> list[_Delivery]:
    """All delivery records, ordered by (timestamp, key)."""
    out = []
    for key in store.list("deliveries/"):
        d = load_record(store, key)
        if d is not None:
            out.append(_delivery_from_dict(d, key, local_ace_id))
    return sorted(out, key=lambda r: (r.message.timestamp, r.key))


def repair_thread(threads: ThreadStore, rec: _Delivery) -> None:
    """Write ``rec.thread`` if it strictly extends the stored history; divergence is
    ``storage_failed``. Caller holds the ``threads`` lock."""
    if rec.thread is None:
        return
    stored = threads.load(rec.thread.conversation_id, rec.thread.thread_id)
    old = _history_dicts(stored.snapshot if stored else None)
    new = _history_dicts(rec.thread)
    if len(new) > len(old) and new[: len(old)] == old:
        threads.save(ThreadRecord(rec.thread, _clear_proven_pending(stored, rec.thread)))
    elif new != old[: len(new)]:
        raise ACEError("storage_failed", f"{rec.key}: thread history diverges from the delivery record")


class Inbox:
    """Durable, exactly-once-to-the-host receive engine.

    ``on_message(parsed)`` must persist the host effect durably and idempotently, keyed by
    ``(from_id, message_id)``, then return; raising means "retry later". Commit order per
    message: delivery record, thread state, replay state, ``on_message``, ack, cursor.
    Open with ``Inbox.open(...)``; the instance holds the store's ``receive`` lock until
    ``close()``.
    """

    def __init__(self, *_: object, **__: object) -> None:
        raise ACEError("invalid_argument", "use Inbox.open(...)")

    # --- open / recovery ---

    @classmethod
    def open(
        cls,
        identity: ACEIdentity,
        store: ACEStore,
        peers: PeerStore,
        on_message: Callable[[ParsedMessage], None],
        *,
        capacity: int = DEFAULT_REPLAY_CAPACITY,
        offline_window_seconds: int = OFFLINE_WINDOW_SECONDS,
        clock: Callable[[], int] | None = None,
    ) -> "Inbox":
        if not isinstance(peers, PeerStore):
            raise ACEError("invalid_argument", "peers must be a PeerStore")
        if not callable(on_message):
            raise ACEError("invalid_argument", "on_message must be callable")
        if type(offline_window_seconds) is not int or offline_window_seconds < TIMESTAMP_WINDOW_SECONDS:
            raise ACEError("invalid_argument", "offline_window_seconds must be an integer >= 300")
        if type(capacity) is not int or capacity < 1:
            raise ACEError("invalid_argument", "capacity must be an integer >= 1")
        self = object.__new__(cls)
        self._identity = identity
        self._local = identity.get_ace_id()
        self._store = store
        self._peers = peers
        self._on_message = on_message
        self._capacity = capacity
        self._offline = offline_window_seconds
        self._clock = clock
        self._threads = ThreadStore(store, self._local, clock=clock)
        self._mutex = threading.RLock()
        self._failed = False
        self._closed = False
        self._delivered_since_sweep = 0
        self._held_threads: Any = None
        lock = store.lock("receive", 0)
        lock.__enter__()
        self._lock = lock
        try:
            self._replay = self._load_replay()
            self._cursors = self._load_cursors()
            self._recover()
        except BaseException:
            self._closed = True
            lock.__exit__(None, None, None)
            raise
        return self

    def _now(self) -> int:
        return int(self._clock()) if self._clock is not None else int(time.time())

    def _floor(self) -> int:
        return max(0, self._now() - self._offline)

    def _load_replay(self) -> ReplayDetector:
        raw = self._store.read("replay.json")
        if raw is None:
            # Outbox-only threads (no inbound entry) may legitimately predate the first open.
            if self._store.list("deliveries/") or any(
                h.from_id != self._local for rec in self._threads.records() for h in rec.snapshot.history
            ):
                raise ACEError("storage_failed", "replay state missing beside history")
            replay = ReplayDetector(
                capacity=self._capacity, horizon=max(0, self._now() - self._offline - 1), clock=self._clock,
            )
            self._write_replay(replay)
            return replay
        try:
            state = json.loads(bytes(raw).decode("utf-8"))
            return ReplayDetector.from_state(state, capacity=self._capacity, clock=self._clock)
        except (UnicodeDecodeError, ValueError, RecursionError, ACEError) as exc:
            raise ACEError("storage_failed", f"replay.json is invalid: {exc}") from None

    def _write_replay(self, replay: ReplayDetector) -> None:
        self._store.write("replay.json", dump_record(replay.export_state()))

    def _load_cursors(self) -> dict[str, str]:
        d = load_record(self._store, "cursors.json")
        if d is None:
            return {}
        cursors = d.get("cursors")
        if not isinstance(cursors, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and STREAM_ID_RE.fullmatch(v) for k, v in cursors.items()
        ):
            raise ACEError("storage_failed", "cursors.json is invalid")
        return dict(cursors)

    def _covered(self, from_id: str, ts: int) -> bool:
        r = self._replay
        return ts <= max(r.horizon, r._sh.get(from_id, r.horizon))

    def _recover(self) -> None:
        """Repair threads and replay from every delivery record first (ordered by
        (timestamp, key)), then hand over the pending ones in the same order."""
        records = load_deliveries(self._store, self._local)
        changed = False
        with self._threads.locked():
            for rec in records:
                if rec.status == "acked" and self._covered(rec.message.from_id, rec.message.timestamp):
                    continue  # fully committed long ago; its thread may have been pruned
                repair_thread(self._threads, rec)
        for rec in records:
            m = rec.message
            if self._replay.accepts(m.message_id, m.from_id, m.timestamp):
                self._replay.commit(m.message_id, m.from_id, m.timestamp, self._floor())
                changed = True
        if changed:
            self._write_replay(self._replay)
        for rec in records:
            m = rec.message
            if rec.status == "pending":
                try:
                    self._on_message(m)
                except Exception as exc:
                    raise ACEError("handler_failed", f"on_message failed during recovery: {exc}") from exc
                rec.status = "acked"
                self._store.write(rec.key, dump_record(rec.to_dict()))
            if self._covered(m.from_id, m.timestamp):
                self._store.delete(rec.key)

    # --- public ---

    def cursor(self, relay_url: str) -> str | None:
        return self._cursors.get(normalize_relay_url(relay_url))

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            held, self._held_threads = self._held_threads, None
            try:
                if held is not None:
                    held.__exit__(None, None, None)
            finally:
                self._lock.__exit__(None, None, None)

    def __enter__(self) -> "Inbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def receive(self, envelope: dict | ACEMessage, source: ReceiveSource) -> ReceiveOutcome:
        if not isinstance(source, ReceiveSource):
            raise ACEError("invalid_argument", "source must be a ReceiveSource")
        with self._mutex:
            if self._closed:
                raise ACEError("invalid_argument", "the inbox is closed")
            if self._failed:
                return ReceiveOutcome("retryable", error=ACEError("storage_failed", "inbox is in a failed state; reopen it"))
            outcome = self._receive(envelope, source)
            if outcome.kind in ("delivered", "duplicate", "quarantined"):
                try:
                    self._advance_cursor(source)
                except ACEError as exc:
                    self._failed = True
                    return ReceiveOutcome("retryable", error=exc)
            return outcome

    def _advance_cursor(self, source: ReceiveSource) -> None:
        if source.kind != "relay" or source.stream_id is None:
            return
        url = source.relay_url
        current = self._cursors.get(url)  # type: ignore[arg-type]
        if current is not None and compare_stream_ids(source.stream_id, current) <= 0:
            return
        cursors = {**self._cursors, url: source.stream_id}
        self._store.write("cursors.json", dump_record({"cursors": cursors, "version": 1}))
        self._cursors = cursors  # type: ignore[assignment]

    def _quarantine(self, err: ACEError, env: ACEMessage | None, source: ReceiveSource) -> ReceiveOutcome:
        if env is None:
            return ReceiveOutcome("quarantined", error=err)
        fp = envelope_fingerprint(env)
        if source.kind == "relay":
            self._write_quarantine(err, env, fp)
        return ReceiveOutcome("quarantined", error=err, fingerprint=fp, from_id=env.from_id, message_id=env.message_id)

    def _write_quarantine(self, err: ACEError, env: ACEMessage, fp: str) -> None:
        key = f"quarantine/{fp}.json"
        existed = self._store.read(key) is not None
        self._store.write(key, dump_record({
            "code": err.code, "envelope": env.to_dict(), "fingerprint": fp, "quarantinedAt": self._now(),
            "reason": err.message[:_REASON_MAX], "source": "relay", "version": 1,
        }))
        if existed:
            return
        keys = self._store.list("quarantine/")
        if len(keys) <= QUARANTINE_CAP:
            return
        aged = []
        for k in keys:
            try:
                d = load_record(self._store, k)
                at = wire_int(d.get("quarantinedAt")) if d else None
            except ACEError:
                at = None
            aged.append((at if at is not None else -1, k[len("quarantine/"):-len(".json")], k))
        aged.sort()
        for _, _, k in aged[: len(aged) - QUARANTINE_KEEP]:
            self._store.delete(k)

    def _hand_over(self, rec: _Delivery) -> ReceiveOutcome:
        """Steps 4-5 for a stored pending delivery."""
        m = rec.message
        try:
            self._on_message(m)
        except Exception as exc:
            return ReceiveOutcome("retryable", error=ACEError("handler_failed", f"on_message failed: {exc}"),
                                  from_id=m.from_id, message_id=m.message_id)
        try:
            if self._covered(m.from_id, m.timestamp):
                self._store.delete(rec.key)
            else:
                rec.status = "acked"
                self._store.write(rec.key, dump_record(rec.to_dict()))
        except ACEError as exc:
            self._failed = True
            return ReceiveOutcome("retryable", error=exc, from_id=m.from_id, message_id=m.message_id)
        return ReceiveOutcome("delivered", message=m, from_id=m.from_id, message_id=m.message_id)

    def _receive(self, envelope: object, source: ReceiveSource) -> ReceiveOutcome:
        now = self._now()
        # 1. decode
        try:
            env = decode_envelope(envelope.to_dict() if isinstance(envelope, ACEMessage) else envelope)
        except ACEError as exc:
            return ReceiveOutcome("quarantined", error=exc)
        # 2. direct freshness
        if source.kind == "direct" and abs(now - env.timestamp) > TIMESTAMP_WINDOW_SECONDS:
            return ReceiveOutcome(
                "quarantined", error=ACEError("stale_timestamp", "direct delivery outside the timestamp window"),
                fingerprint=envelope_fingerprint(env), from_id=env.from_id, message_id=env.message_id,
            )
        # 3. peer
        try:
            peer = self._peers.resolve(env.from_id)
            my_enc = self._identity.get_encryption_public_key()
            if compute_conversation_id(peer.encryption_public_key, my_enc) != env.conversation_id:
                peer = self._peers.resolve(env.from_id, max_age_seconds=0)
        except ACEError as exc:
            if exc.is_transient:
                return ReceiveOutcome("retryable", error=exc, from_id=env.from_id, message_id=env.message_id)
            err = exc
            return self._safe(lambda: self._quarantine(err, env, source))
        # 4. stored delivery
        key = delivery_key(env.from_id, env.message_id)
        try:
            d = load_record(self._store, key)
            stored = None if d is None else _delivery_from_dict(d, key, self._local)
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc, from_id=env.from_id, message_id=env.message_id)
        if stored is not None:
            if stored.status == "pending":
                return self._hand_over(stored)
            return ReceiveOutcome("duplicate", from_id=env.from_id, message_id=env.message_id)
        # 5-7
        economic = is_economic_type(env.type)
        try:
            lock = self._threads.locked() if economic else None
            if lock is not None:
                lock.__enter__()
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc, from_id=env.from_id, message_id=env.message_id)
        try:
            result = self._parse_and_commit(env, peer, key, source, now, economic)
        except BaseException:
            if lock is not None:
                lock.__exit__(None, None, None)
            raise
        if lock is not None:
            if self._failed:
                self._held_threads = lock  # keep other writers out until close()/open() repairs
            else:
                lock.__exit__(None, None, None)
        if isinstance(result, ReceiveOutcome):
            return result
        outcome = self._hand_over(result)  # 7.4-7.5, without the threads lock
        if outcome.kind == "delivered":
            self._delivered_since_sweep += 1
            if self._delivered_since_sweep >= _SWEEP_EVERY:
                self._delivered_since_sweep = 0
                try:
                    self.sweep()
                except ACEError:
                    pass
        return outcome

    def _safe(self, fn: Callable[[], ReceiveOutcome]) -> ReceiveOutcome:
        try:
            return fn()
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc)

    def _parse_and_commit(
        self, env: ACEMessage, peer: Any, key: str, source: ReceiveSource, now: int, economic: bool,
    ) -> "ReceiveOutcome | _Delivery":
        """Steps 5-7.3 (caller holds ``threads`` for economic types). Returns an outcome,
        or the committed pending delivery to hand over."""
        ids = {"from_id": env.from_id, "message_id": env.message_id}
        try:
            if economic:
                machine, rec = self._threads.machine(env.conversation_id, env.thread_id)  # type: ignore[arg-type]
            else:
                machine, rec = ThreadStateMachine(self._local), None
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc, **ids)
        tr = self._replay.clone()
        floor = self._floor()
        # 6. parse
        try:
            parsed = parse_message(env, self._identity, peer, threads=machine, replay=tr, floor=floor, clock=self._clock)
        except ACEError as exc:
            if exc.code == "replay":
                return ReceiveOutcome("duplicate", **ids)
            if exc.category != "permanent":
                return ReceiveOutcome("retryable", error=exc, **ids)
            try:
                outcome = self._quarantine(exc, env, source)
                if not tr.accepts(env.message_id, env.from_id, env.timestamp):
                    self._write_replay(tr)  # a verified message stays one-shot
                    self._replay = tr
            except ACEError as store_exc:
                return ReceiveOutcome("retryable", error=store_exc, **ids)
            return outcome
        # 7. durable commit
        snap = machine.get_snapshot(env.conversation_id, env.thread_id) if economic else None  # type: ignore[arg-type]
        delivery = _Delivery(key, parsed, envelope_fingerprint(env), now, source.kind, "pending", snap)
        try:
            self._store.write(key, dump_record(delivery.to_dict()))  # 7.1 commit point
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc, **ids)
        try:
            if snap is not None:  # 7.2
                self._threads.save(ThreadRecord(snap, _clear_proven_pending(rec, snap)))
            self._write_replay(tr)  # 7.3
            self._replay = tr
        except ACEError as exc:
            self._failed = True
            return ReceiveOutcome("retryable", error=exc, **ids)
        return delivery

    def sweep(self) -> int:
        """Delete ``acked`` delivery records covered by a replay horizon; returns the count."""
        with self._mutex:
            removed = 0
            for key in self._store.list("deliveries/"):
                d = load_record(self._store, key)
                if d is None:
                    continue
                rec = _delivery_from_dict(d, key, self._local)
                if rec.status == "acked" and self._covered(rec.message.from_id, rec.message.timestamp):
                    self._store.delete(key)
                    removed += 1
            return removed

    # --- relay drivers ---

    def pull(self, relay: RelayClient, *, limit: int = MAX_INBOX_PAGE) -> PullResult:
        """Fetch and receive queued messages from the cursor; stops at the first retryable."""
        url = relay.base_url
        delivered = duplicates = quarantined = 0
        since = self.cursor(url) or "-"
        while True:
            try:
                page = relay.fetch_inbox(self._identity, since=since, limit=limit)
            except ACEError as exc:
                return PullResult(delivered, duplicates, quarantined, exc)
            for entry in page.entries:
                outcome = self.receive(entry.message, ReceiveSource.relay(url, entry.stream_id))
                if outcome.kind == "retryable":
                    return PullResult(delivered, duplicates, quarantined, outcome.error)
                delivered += outcome.kind == "delivered"
                duplicates += outcome.kind == "duplicate"
                quarantined += outcome.kind == "quarantined"
            if len(page.entries) < limit:
                return PullResult(delivered, duplicates, quarantined, None)
            since = page.entries[-1].stream_id

    def follow(self, relay: RelayClient, *, stop: threading.Event | None = None) -> Iterator[ReceiveOutcome]:
        """``pull``, then receive live SSE events and yield each outcome.

        Raises the blocking error of the initial pull, or of a ``retryable`` outcome right
        after yielding it. Set ``stop`` (or close the generator) to end.
        """
        result = self.pull(relay)
        if result.blocked is not None:
            raise result.blocked
        url = relay.base_url
        for entry in relay.listen(self._identity, since=self.cursor(url) or "-", stop=stop):
            outcome = self.receive(entry.message, ReceiveSource.relay(url, entry.stream_id))
            yield outcome
            if outcome.kind == "retryable":
                assert outcome.error is not None
                raise outcome.error
