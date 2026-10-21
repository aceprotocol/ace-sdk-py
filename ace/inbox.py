"""Receive pipeline (06 § Receive pipeline), transport-agnostic.

``Inbox.receive(raw)`` returns a ``ReceiveOutcome``: the caller sends ``outcome.receipt`` (if
any) first and acknowledges the relay entry only when ``outcome.ack`` is true. Order:

 1. packet shape (closed object, ``ace == "1"``, addressed to us)
 2. admission: blocked senders are dropped; strangers are dropped without any network query or
    pin write unless our card record is ``contact: open``, then they continue only as contact
    candidates
 3. sender KEL pin (refreshed at most once per sender per ``PIN_REFRESH_INTERVAL_SECONDS`` when
    the packet names a newer delegation; otherwise the packet continues as a contact candidate)
 4. operational signature (delegation ``seq``, signed while live, signer usable now)
 5. time window ``now - OFFLINE <= ts <= now + 300``
 6. prekey decryption (``rejected:unknown_prekey``)
 7. ``(type, schemaDigest)`` must be installed (``rejected:unsupported_schema``)
 8. body schema (``rejected:invalid_body``)
 9. dedupe by ``(from, messageId)``: a duplicate is receipted ``delivered``; a packet beyond the
    replay horizon is dropped (``replay_horizon``) and never receipted
10. busy thread, profile rules ``check``, then the delivery record, the rules' ``commit`` and the
    seen entry in one transaction
11. receipt, then relay ack

Capacity backpressure leaves the packet on the relay. Any other failure is retried; a packet
fetched ``MAX_FETCH_ATTEMPTS`` times without a final disposition is quarantined and acked.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Literal

from ._encoding import is_message_id, is_sha256_hex, loads_json, sha256_hex, unix_now, wire_int
from .card_record import Contact
from .descriptor import check_stranger_source, verify_published_agent
from .errors import ACEError, is_outcome_code
from .identity import ACEIdentity
from .kel import KelState
from .limits import (
    DEFAULT_REPLAY_CAPACITY,
    MAX_FETCH_ATTEMPTS,
    MAX_NOTE_BYTES,
    OFFLINE_WINDOW_SECONDS,
    PERMIT_RENEWAL_SECONDS,
    PIN_REFRESH_INTERVAL_SECONDS,
)
from .packet import (
    Packet,
    PrivateMessage,
    check_window,
    create_packet,
    decode_content,
    decrypt_packet,
    encode_content,
    parse_packet,
    verify_packet,
)
from .peers import PeerStore
from .permit import create_permit, verify_permit
from .prekeys import PrekeyVault
from .profiles import CONTACT_TYPE, CORE, RECEIPT_TYPE, Profiles
from .replay import ReplayDetector
from .rules import MessageEvent, ProfileRules, check_rules, governed, run_check, run_commit
from .store import ACEStore, load_record, write_record

QUARANTINE_CAP = 1000
QUARANTINE_KEEP = 900
_SNAPSHOT_EVERY = 256
_REPLAY_KEY = "inbox/replay.json"


def check_receipt_body(body: dict) -> None:
    """Core receipt rules beyond the schema (06 § Receipts), ``invalid_body``: ``messageId`` a
    UUIDv4; ``code`` exactly when rejected (outcome-code grammar); ``prekey`` (64 lowercase hex)
    exactly when ``code`` is ``unknown_prekey``; ``permit`` an object."""
    if not isinstance(body, dict) or not is_message_id(body.get("messageId")):
        raise ACEError("invalid_body", "receipt messageId must be a UUIDv4")
    if (body.get("outcome") == "rejected") != ("code" in body) or (
        "code" in body and not is_outcome_code(body["code"])
    ):
        raise ACEError("invalid_body", "receipt code must be present exactly when rejected")
    if (body.get("code") == "unknown_prekey") != ("prekey" in body) or (
        "prekey" in body and not is_sha256_hex(body["prekey"])
    ):
        raise ACEError("invalid_body", "receipt prekey must be present exactly with unknown_prekey")
    if "permit" in body and not isinstance(body["permit"], dict):
        raise ACEError("invalid_body", "receipt permit must be an object")


@dataclass(frozen=True)
class Reply:
    """A packet the caller must send to ``to`` (a receipt) before acknowledging the relay.
    ``permit`` is the renewal it carries: once the packet was sent, record it with
    ``PeerStore.note_issued(to, permit)``."""

    to: str
    packet: dict
    permit: dict | None = None


@dataclass(frozen=True)
class ReceiveOutcome:
    """``delivered`` / ``duplicate`` (message accepted; ``message`` set), ``rejected`` (a
    ``rejected:<code>`` receipt), ``dropped`` (silently discarded), ``retry`` (leave it on the
    relay) or ``quarantined`` (failed too often)."""

    kind: Literal["delivered", "duplicate", "rejected", "dropped", "retry", "quarantined"]
    ack: bool
    message: PrivateMessage | None = None
    receipt: Reply | None = None
    error: ACEError | None = None


def _delivery_key(from_id: str, message_id: str) -> str:
    return f"inbox/deliveries/{sha256_hex(from_id, message_id)}.json"


def _packet_header(packet: object) -> dict | None:
    """The scalar header fields of a (possibly malformed) packet, strings cut to 256 chars."""
    if not isinstance(packet, dict):
        return None
    enc = packet.get("encryption")
    fields = {**packet, "prekey": enc.get("prekey") if isinstance(enc, dict) else None}
    out: dict = {}
    for k in ("ace", "from", "to", "messageId", "timestamp", "prekey"):
        v = fields.get(k)
        if isinstance(v, str):
            out[k] = v[:256]
        elif wire_int(v) is not None:
            out[k] = v
    return out


def _attempts_key(fp: str) -> str:
    return f"inbox/attempts/{fp}.json"


class _Drop(Exception):
    """Internal: silently discard (and ack) the packet."""

    def __init__(self, error: ACEError) -> None:
        self.error = error


class _Retry(_Drop):
    """Internal: leave the packet on the relay; the fetch counts toward ``MAX_FETCH_ATTEMPTS``."""


class Inbox:
    """Durable receive engine, created with ``Inbox.open(...)``, which takes the store's
    ``receive`` lock (held until ``close()``) and loads the seen store. ``on_message(message)``
    must persist the host effect idempotently keyed by ``(from_id, message_id)``; raising means
    "retry later". Receipts are applied to ``outbox`` (``Outbox.settle``), a renewed permit inside
    one is kept in the PeerStore, and ``on_receipt(from_id, body, entry)`` is told (``entry``: the
    Outbox entry it settled, or None)."""

    @classmethod
    def open(
        cls,
        identity: ACEIdentity,
        store: ACEStore,
        vault: PrekeyVault,
        peers: PeerStore,
        profiles: Profiles,
        *,
        on_message: Callable[[PrivateMessage], None],
        on_receipt: Callable[[str, dict, Any], None] | None = None,
        rules: list[ProfileRules] | tuple[ProfileRules, ...] = (),
        outbox: Any = None,
        contact: Contact | Callable[[], Contact] = "closed",
        refresh: Callable[[str], Any] | None = None,
        resolve: Callable[[str], Any] | None = None,
        check_capacity: Callable[[PrivateMessage], None] | None = None,
        capacity: int = DEFAULT_REPLAY_CAPACITY,
        clock: Callable[[], int] | None = None,
    ) -> "Inbox":
        if not callable(on_message):
            raise ACEError("invalid_argument", "on_message must be callable")
        if not isinstance(peers, PeerStore) or not isinstance(profiles, Profiles):
            raise ACEError("invalid_argument", "peers must be a PeerStore and profiles a Profiles")
        self = object.__new__(cls)
        self._identity = identity
        self._me = identity.get_ace_id()
        self._store = store
        self._vault = vault
        self._peers = peers
        self._profiles = profiles
        self._on_message = on_message
        self._on_receipt = on_receipt
        self._rules = check_rules(list(rules))
        self._outbox = outbox
        # 05 § Receiver admission: strangers only while our card record is open (none is closed)
        self._contact = contact if callable(contact) else (lambda: contact)
        self._refresh = refresh
        self._resolve = resolve
        self._check_capacity = check_capacity
        self._capacity = capacity
        self._clock = clock
        self._mutex = threading.RLock()
        self._refreshed: dict[str, int] = {}
        self._since_snapshot: set[str] = set()
        self._dirty = 0
        self._closed = False
        lock = store.lock("receive", 0)
        lock.__enter__()
        self._lock = lock
        try:
            self._replay = self._load_replay()
            self._recover()
        except BaseException:
            self._closed = True
            lock.__exit__(None, None, None)
            raise
        return self

    def _now(self) -> int:
        return unix_now(self._clock)

    def _floor(self) -> int:
        """Seen-store retention floor ``now - 2 * OFFLINE_WINDOW_SECONDS`` (06 § Deduplication)."""
        return max(0, self._now() - 2 * OFFLINE_WINDOW_SECONDS)

    # --- persistence of the seen store --------------------------------------------

    def _load_replay(self) -> ReplayDetector:
        state = load_record(self._store, _REPLAY_KEY)
        if state is None:
            # 06 § Deduplication: missing state beside delivery history is a storage failure,
            # not a new store (a new one would deliver those messages again).
            if self._store.list("inbox/deliveries/"):
                raise ACEError(
                    "storage_failed", f"{_REPLAY_KEY} is missing beside delivery records"
                )
            replay = ReplayDetector(
                capacity=self._capacity, horizon=max(0, self._floor() - 1), clock=self._clock
            )
            write_record(self._store, _REPLAY_KEY, replay.export_state())
            return replay
        try:
            return ReplayDetector.from_state(state, capacity=self._capacity, clock=self._clock)  # type: ignore[arg-type]
        except ACEError as exc:
            raise ACEError("storage_failed", f"replay state is invalid: {exc.message}") from None

    def _snapshot(self) -> None:
        """Write the seen store, then drop the acknowledged delivery records it now covers and
        stale fetch-attempt counters."""
        write_record(self._store, _REPLAY_KEY, self._replay.export_state())
        self._dirty = 0
        for key in list(self._since_snapshot):  # only acked records are ever added
            self._store.delete(key)
            self._since_snapshot.discard(key)
        self._prune_attempts()

    def _prune_attempts(self) -> None:
        """Drop attempt counters first written ``OFFLINE_WINDOW_SECONDS`` or more ago: the relay
        no longer holds such a packet, so it will not be fetched again."""
        now = self._now()
        for key in self._store.list("inbox/attempts/"):
            rec = load_record(self._store, key)
            at = None if rec is None else wire_int(rec.get("at"))
            if at is None or now - at >= OFFLINE_WINDOW_SECONDS:
                self._store.delete(key)

    def _recover(self) -> None:
        changed = False
        for key in self._store.list("inbox/deliveries/"):
            d = load_record(self._store, key)
            if d is None:
                continue
            if d.get("status") == "pending":
                try:
                    m = PrivateMessage.from_dict(d["message"])
                except (KeyError, TypeError) as exc:
                    raise ACEError("storage_failed", f"{key}: invalid delivery record") from exc
                # seen only once step 10 completes; an aborted entry is gone and its re-sent
                # packet is processed anew
                try:
                    changed = self._hand_over(key, m) is None or changed
                except Exception:
                    continue  # stays pending: retried on the next open or re-sent packet
                continue
            from_id, message_id = d.get("from"), d.get("messageId")
            ts = wire_int(d.get("timestamp"))
            if (
                d.get("status") != "acked"
                or "message" in d
                or not isinstance(from_id, str)
                or not isinstance(message_id, str)
                or ts is None
                or _delivery_key(from_id, message_id) != key
            ):
                raise ACEError("storage_failed", f"{key}: invalid delivery record")
            changed = self._see(message_id, from_id, ts) or changed
            self._since_snapshot.add(key)
        if changed or self._since_snapshot:
            self._snapshot()
        else:
            self._prune_attempts()

    # --- public -------------------------------------------------------------------

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            if self._dirty:
                try:
                    self._snapshot()
                except ACEError:
                    pass
            self._closed = True
            self._lock.__exit__(None, None, None)

    def __enter__(self) -> "Inbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def receive(self, raw: bytes) -> ReceiveOutcome:
        """Process one packet given as its raw JSON bytes."""
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise ACEError("invalid_argument", "raw must be the packet bytes")
        raw = bytes(raw)
        with self._mutex:
            if self._closed:
                raise ACEError("invalid_argument", "the inbox is closed")
            fp = sha256_hex(raw)
            try:
                out = self._receive(raw)
            except _Retry as r:
                out = self._failed(fp, raw, r.error)
            except _Drop as d:
                out = ReceiveOutcome("dropped", True, error=d.error)
            except ACEError as exc:
                if exc.code == "receiver_capacity":
                    return ReceiveOutcome("retry", False, error=exc)
                out = self._failed(fp, raw, exc)
            except Exception as exc:  # a host hook or bug: never retry a poison packet forever
                out = self._failed(
                    fp, raw, ACEError("storage_failed", f"{type(exc).__name__}: {exc}")
                )
            if out.ack:
                self._store.delete(_attempts_key(fp))
            return out

    def quarantined(self) -> list[dict]:
        return [
            d for k in self._store.list("inbox/quarantine/") if (d := load_record(self._store, k))
        ]

    # --- failure accounting ---------------------------------------------------------

    def _failed(self, fp: str, raw: bytes, err: ACEError) -> ReceiveOutcome:
        """Count a fetch without a final disposition (persisted, so a restart does not reset
        it); the ``MAX_FETCH_ATTEMPTS``-th quarantines the packet and acks it."""
        try:
            rec = load_record(self._store, _attempts_key(fp))
            n = (wire_int(rec.get("attempts")) or 0 if rec else 0) + 1
            at = (wire_int(rec.get("at")) if rec else None) or self._now()
            if n < MAX_FETCH_ATTEMPTS:
                write_record(self._store, _attempts_key(fp), {"attempts": n, "at": at})
                return ReceiveOutcome("retry", False, error=err)
            self._quarantine(fp, raw, err)
            self._store.delete(_attempts_key(fp))
        except ACEError as store_exc:
            return ReceiveOutcome("retry", False, error=store_exc)
        return ReceiveOutcome("quarantined", True, error=err)

    def _quarantine(self, fp: str, raw: bytes, err: ACEError) -> None:
        """Record the packet's fingerprint, header and failure, never its ciphertext: a record is
        a few hundred bytes, so ``QUARANTINE_CAP`` records bound the quarantine's disk use."""
        try:
            packet = loads_json(raw)
        except ValueError:
            packet = None
        write_record(
            self._store,
            f"inbox/quarantine/{fp}.json",
            {
                "fingerprint": fp,
                "code": err.code,
                "reason": err.message[:1000],
                "quarantinedAt": self._now(),
                "packet": _packet_header(packet),
            },
        )
        keys = self._store.list("inbox/quarantine/")
        if len(keys) > QUARANTINE_CAP:
            aged = []
            for k in keys:
                d = load_record(self._store, k) or {}
                aged.append((wire_int(d.get("quarantinedAt")) or 0, k))
            for _, k in sorted(aged)[: len(keys) - QUARANTINE_KEEP]:
                self._store.delete(k)

    # --- pipeline -------------------------------------------------------------------

    def _event(self, m: PrivateMessage) -> MessageEvent:
        return MessageEvent(
            "receive", m.message_id, m.from_id, m.to_id, m.timestamp, m.type, m.thread_id
        )

    def _receive(self, raw: bytes) -> ReceiveOutcome:
        now = self._now()
        # 1. shape
        try:
            p = parse_packet(raw)
        except ACEError as exc:
            raise _Drop(exc) from None
        if p.to_id != self._me:
            raise _Drop(ACEError("wrong_recipient", "packet is not addressed to this identity"))
        # 2. admission (no network, no pin for strangers)
        if self._peers.is_blocked(p.from_id):
            raise _Drop(ACEError("not_permitted", "sender is blocked"))
        if not self._peers.is_admitted(p.from_id):
            return self._stranger(p, now)
        # 3. pin. A peer in the table without a pin is authenticated only by a contact's source.
        pinned = self._peers.state(p.from_id)
        if pinned is None:
            return self._candidate(p, now, stranger=False)
        state = self._sender_state(p, pinned, now)
        if state is None:
            return self._candidate(p, now, stranger=False)
        # 4. signature, 5. window
        try:
            verify_packet(p, state, now)
            check_window(p, now)
        except ACEError as exc:
            raise _Drop(exc) from None
        # 6. decrypt
        try:
            plaintext = decrypt_packet(p, self._vault, now)
        except ACEError as exc:
            if exc.code == "unknown_prekey":
                return self._reject(p, exc, now)
            raise _Drop(exc) from None
        # 7-8. content, installed schema, body
        c = None
        try:
            c = decode_content(plaintext)
            self._profiles.validate(c["type"], c["schemaDigest"], c["body"])
        except ACEError as exc:
            if exc.category != "permanent":
                raise
            if c is not None and c["type"] in (RECEIPT_TYPE, CONTACT_TYPE):
                raise _Drop(exc) from None  # receipts and contacts are never receipted
            return self._reject(p, exc, now)
        m = PrivateMessage.of(p, c)
        if m.type == RECEIPT_TYPE:
            return self._apply_receipt(m, state, now)
        if m.type == CONTACT_TYPE:
            try:
                self._check_contact(p, m, now)
            except ACEError as exc:
                raise _Drop(exc) from None
            return self._commit(m, now, receipt=False)
        return self._commit(m, now, receipt=True)

    def _sender_state(self, p: Packet, state: KelState, now: int) -> KelState | None:
        """Step 3: the pinned KEL; one refresh per sender per ``PIN_REFRESH_INTERVAL_SECONDS``
        when the packet names a newer delegation. Suppressed or transient refresh: retry. When
        no refresh is wired, the refresh fails permanently or it still does not reach the
        packet's delegation, ``None``: the packet continues only as a contact candidate
        authenticated by its ``source`` against the pin (e.g. a peer after a signing-key change
        that has not republished its descriptor yet)."""
        if state.signing is not None and p.signature["seq"] <= state.signing.seq:
            return state
        if self._refresh is None:
            return None
        for sender, at in list(self._refreshed.items()):
            if now - at >= PIN_REFRESH_INTERVAL_SECONDS:
                del self._refreshed[sender]
        if p.from_id in self._refreshed:
            raise _Retry(ACEError("relay_unavailable", "sender refresh suppressed; retry later"))
        self._refreshed[p.from_id] = now
        try:
            self._refresh(p.from_id)
        except ACEError as exc:
            if exc.is_transient:
                self._refreshed.pop(p.from_id, None)
                raise _Retry(exc) from None
            return None
        fresh = self._peers.state(p.from_id) or state
        if fresh.signing is None or p.signature["seq"] > fresh.signing.seq:
            return None
        return fresh

    def _stranger(self, p: Packet, now: int) -> ReceiveOutcome:
        """A sender outside the admission table: only a contact request, only while our card
        record is ``open``."""
        if self._contact() != "open":
            raise _Drop(ACEError("not_permitted", "sender is not admitted"))
        return self._candidate(p, now, stranger=True)

    def _candidate(self, p: Packet, now: int, *, stranger: bool) -> ReceiveOutcome:
        """The contact-candidate path (06): no pinned KEL, so only an ``ace:contact:1`` packet is
        processed, authenticated by its ``source``. A stranger may only send ``request``."""
        try:
            check_window(p, now)
            c = decode_content(decrypt_packet(p, self._vault, now))
            if c["type"] != CONTACT_TYPE:
                raise ACEError("not_permitted", "only contact requests are accepted from strangers")
            self._profiles.validate(c["type"], c["schemaDigest"], c["body"])
            m = PrivateMessage.of(p, c)
            if stranger and m.body["kind"] != "request":
                raise ACEError("not_permitted", "a stranger may only send a contact request")
            if stranger:
                check_stranger_source(m.body["source"])
            self._check_contact(p, m, now)
        except ACEError as exc:
            if exc.category != "permanent":
                raise
            raise _Drop(exc) from None
        return self._commit(m, now, receipt=False)

    def _check_contact(self, p: Packet, m: PrivateMessage, now: int) -> None:
        """Core contact rules: the note is bounded (checked first, it costs nothing); the source
        authenticates the packet; request/accepted carry a reply permit (rejected none); the
        profile is installed on both ends with one digest."""
        if len(m.body["note"].encode("utf-8")) > MAX_NOTE_BYTES:
            raise ACEError("invalid_body", "contact note exceeds 512 bytes")
        agent = verify_published_agent(
            m.body["source"],
            now=now,
            allow_loopback_relays=self._peers.allow_loopback_relays,
            pinned=self._peers.state(p.from_id),  # never trust an older log than the one pinned
            delegation_pins=self._peers.delegation_pins(m.body["source"]),
        )
        if agent.ace_id != p.from_id:
            raise ACEError("invalid_authorization", "contact source does not match the sender")
        verify_packet(p, agent.state, now)
        kind = m.body["kind"]
        if (kind == "rejected") == ("permit" in m.body):
            raise ACEError(
                "invalid_authorization", "request/accepted carry a reply permit, rejected none"
            )
        if "permit" in m.body:
            verify_permit(m.body["permit"], agent.state, self._me, now=now)
        if kind != "rejected" and not any(
            e["id"] == m.body["profile"] and self._profiles.supports(e) for e in agent.profiles
        ):
            raise ACEError(
                "unsupported_schema", "contact profile is not shared with an equal digest"
            )

    def _apply_receipt(self, m: PrivateMessage, state: KelState, now: int) -> ReceiveOutcome:
        """Core receipt rules: ``code`` exactly when rejected (outcome-code grammar); a renewal
        permit must be valid from the receipt's sender to us. Failures are dropped."""
        body = m.body
        try:
            check_receipt_body(body)
        except ACEError as exc:
            raise _Drop(exc) from None
        try:
            permit = (
                verify_permit(body["permit"], state, self._me, now=now)
                if "permit" in body
                else None
            )
        except ACEError as exc:
            raise _Drop(exc) from None
        if permit is not None:
            self._peers.save_permit(
                permit, state, self._me, now, when=lambda r: r is not None and r.status != "blocked"
            )
        entry = None
        if self._outbox is not None:
            entry = self._outbox.settle(
                body["messageId"],
                body["outcome"],
                body.get("code"),
                sender=m.from_id,
                prekey=body.get("prekey"),
            )
        if self._on_receipt is not None:
            self._on_receipt(m.from_id, body, entry)
        return ReceiveOutcome("delivered", True, message=m)

    def _commit(self, m: PrivateMessage, now: int, *, receipt: bool) -> ReceiveOutcome:
        key = _delivery_key(m.from_id, m.message_id)
        # 9. duplicate / horizon (before the rules: a re-sent message is still delivered)
        # A pending journal entry is completed by its re-sent copy; otherwise the seen store
        # alone decides (an acked record awaiting compaction is no seen entry once evicted).
        stored = load_record(self._store, key)
        if stored is not None and stored.get("status") == "pending":
            aborted = self._hand_over(key, PrivateMessage.from_dict(stored["message"]))
            if aborted is not None:
                return self._acked("rejected", m, now, receipt, aborted)
            return self._acked("duplicate", m, now, receipt)
        if self._replay.seen(m.message_id, m.from_id):
            return self._acked("duplicate", m, now, receipt)
        if self._replay.covered(m.from_id, m.timestamp):
            # never receipted: the sender's next retry carries a fresh timestamp
            raise _Drop(ACEError("replay_horizon", "message is beyond the replay horizon"))
        # 10. rules (a thread with our own rule-governed message in flight is busy)
        event = self._event(m)
        try:
            if (
                m.thread_id is not None
                and self._outbox is not None
                and governed(self._rules, m.type)
                and self._outbox.busy(m.from_id, m.thread_id) is not None
            ):
                raise ACEError("thread_busy", "a message of ours on this thread awaits its receipt")
            run_check(self._rules, event, m.body)
        except ACEError as exc:
            if exc.category != "permanent" and exc.code != "thread_busy":
                raise
            return self._acked("rejected", m, now, receipt, exc)
        if self._check_capacity is not None:
            self._check_capacity(m)
        # 10. persist: delivery record, then rules, seen store and hand-over (one transaction)
        write_record(
            self._store, key, {"status": "pending", "message": m.to_dict(), "receivedAt": now}
        )
        aborted = self._hand_over(key, m)
        if aborted is not None:
            return self._acked("rejected", m, now, receipt, aborted)
        self._dirty += 1
        if self._dirty >= _SNAPSHOT_EVERY:
            self._snapshot()
        return self._acked("delivered", m, now, receipt)

    def _acked(
        self,
        kind: Literal["delivered", "duplicate", "rejected"],
        m: PrivateMessage,
        now: int,
        receipt: bool,
        err: ACEError | None = None,
    ) -> ReceiveOutcome:
        """An acked outcome for ``m`` (``rejected`` with ``err``), receipted when ``receipt``."""
        code = None if err is None else err.code
        return ReceiveOutcome(
            kind,
            True,
            message=None if err is not None else m,
            error=err,
            receipt=self._receipt(m.from_id, m.message_id, now, code) if receipt else None,
        )

    def _hand_over(self, key: str, m: PrivateMessage) -> ACEError | None:
        """Complete step 10 from a journaled ``pending`` delivery (live, after a crash, or on a
        re-sent packet): commit the rules, add the seen entry, hand over, mark done. The seen
        entry, delivery record and rules commit are one transaction (06 step 10): a permanent
        commit failure aborts it (the record is deleted, nothing is seen or handed over) and is
        returned for a ``rejected:<code>`` answer; ``commit`` is idempotent, so one that already
        applied never fails on a re-run. Any other failure raises and leaves the record pending."""
        try:
            run_commit(self._rules, self._event(m), m.body)
        except ACEError as exc:
            if exc.category != "permanent":
                raise
            self._store.delete(key)
            return exc
        self._see(m.message_id, m.from_id, m.timestamp)
        self._on_message(m)
        self._finish(key, m)
        return None

    def _see(self, message_id: str, from_id: str, timestamp: int) -> bool:
        if not self._replay.accepts(message_id, from_id, timestamp):
            return False
        self._replay.commit(message_id, from_id, timestamp, self._floor())
        return True

    def _finish(self, key: str, m: PrivateMessage) -> None:
        """Mark the record acked: only its seen entry stays until the next snapshot, never the
        delivered plaintext (the pending record's message was the copy recovery needed)."""
        write_record(
            self._store,
            key,
            {
                "status": "acked",
                "from": m.from_id,
                "messageId": m.message_id,
                "timestamp": m.timestamp,
            },
        )
        self._since_snapshot.add(key)

    # --- receipts -------------------------------------------------------------------

    def _reject(self, p: Packet, err: ACEError, now: int) -> ReceiveOutcome:
        return ReceiveOutcome(
            "rejected",
            True,
            error=err,
            receipt=self._receipt(
                p.from_id,
                p.message_id,
                now,
                err.code,
                prekey=p.prekey_id if err.code == "unknown_prekey" else None,
            ),
        )

    def _receipt(
        self,
        to: str,
        message_id: str,
        now: int,
        code: str | None = None,
        *,
        prekey: str | None = None,
    ) -> Reply | None:
        """A receipt to ``to`` encrypted to its descriptor (``resolve``, default the pinned one),
        renewing our permit when the newest one sent has less than ``PERMIT_RENEWAL_SECONDS``
        left or was signed under a superseded delegation. None when no descriptor is known."""
        try:
            agent = self._resolve(to) if self._resolve is not None else self._peers.agent(to)
        except ACEError as exc:
            if exc.is_transient:
                raise
            agent = None
        if agent is None or agent.expires_at <= now:  # never encrypt to an expired descriptor
            return None
        body: dict = {
            "messageId": message_id,
            "outcome": "delivered" if code is None else "rejected",
        }
        if code is not None:
            body["code"] = code
        if prekey is not None:
            body["prekey"] = prekey
        issued = self._peers.issued(to)
        seq = self._identity.get_signing_seq()
        permit = None
        if self._peers.status(to) in ("pending", "admitted") and (
            issued is None
            or issued["expiresAt"] - now < PERMIT_RENEWAL_SECONDS
            or issued["seq"] != seq
        ):
            permit = body["permit"] = create_permit(self._identity, to, now=now)
        plaintext = encode_content(RECEIPT_TYPE, CORE.messages[RECEIPT_TYPE].digest, body)
        packet = create_packet(self._identity, to, agent.prekey, plaintext, timestamp=now)
        return Reply(to, packet, permit)
