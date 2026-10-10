"""Receive engine (06-security "Durable Delivery", Receiver)."""

from __future__ import annotations

import threading
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any, Callable, Literal

from ._encoding import (
    decode_b64,
    decode_signature,
    is_ace_id,
    is_conversation_id,
    is_message_id,
    is_sha256_hex,
    is_thread_id,
    loads_json,
    unix_now,
    wire_int,
)
from ._signing import is_valid_signing_public_key, verify_signature
from .encryption import compute_conversation_id
from .envelope import decode_envelope, envelope_fingerprint, message_sign_data
from .errors import ACEError
from .limits import (
    DEFAULT_REPLAY_CAPACITY,
    MAX_ENVELOPE_BYTES,
    OFFLINE_WINDOW_SECONDS,
    TIMESTAMP_WINDOW_SECONDS,
)
from .messages import (
    SchemaValidator,
    apply_receive_rules,
    check_schemas,
    parse_with_gate,
    run_schema_validator,
)
from .peers import PeerStore
from .principal import (
    PrincipalContext,
    fill_decision,
    is_caip10,
    open_request_to,
    sender_principal_usable,
    validate_principal_record,
)
from .replay import ReplayDetector
from .state_machine import ThreadSnapshot, ThreadStateMachine
from .store import ACEStore, load_record, write_record
from .threads import PendingSend, ThreadRecord, ThreadStore, sha256_hex, snapshot_from_dict
from .types import (
    SIGNING_SCHEMES,
    ACEIdentity,
    ACEMessage,
    ParsedMessage,
    PrincipalKey,
    PrincipalRecord,
    is_economic_type,
    is_message_type,
    is_principal_type,
)

QUARANTINE_CAP = 1000
QUARANTINE_KEEP = 900
_REPLAY_SNAPSHOT_EVERY = (
    1024  # commits between writes of replay.json (journaled by delivery records)
)
_REASON_MAX = 1000


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


def delivery_key(from_id: str, message_id: str) -> str:
    return f"deliveries/{sha256_hex(from_id, message_id)}.json"


def _parsed_to_dict(m: ParsedMessage) -> dict[str, Any]:
    return {
        "body": m.body,
        "conversationId": m.conversation_id,
        "from": m.from_id,
        "messageId": m.message_id,
        "threadId": m.thread_id,
        "timestamp": m.timestamp,
        "to": m.to_id,
        "type": m.type,
        "schemaDigest": m.schema_digest,
    }


@dataclass
class _Delivery:
    key: str
    message: ParsedMessage
    fingerprint: str
    received_at: int
    status: str
    thread: ThreadSnapshot | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "message": _parsed_to_dict(self.message),
            "receivedAt": self.received_at,
            "status": self.status,
            "thread": self.thread.to_dict() if self.thread else None,
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
        not is_ace_id(m.get("from"))
        or not is_ace_id(m.get("to"))
        or not is_message_id(m.get("messageId"))
        or not is_conversation_id(m.get("conversationId"))
        or not is_message_type(m.get("type"))
        or not is_sha256_hex(m.get("schemaDigest"))
        or ts is None
        or not isinstance(m.get("body"), dict)
        or (thread_id is not None and not is_thread_id(thread_id))
    ):
        raise bad("message fields")
    parsed = ParsedMessage(
        message_id=m["messageId"],
        from_id=m["from"],
        to_id=m["to"],
        conversation_id=m["conversationId"],
        type=m["type"],
        thread_id=thread_id,
        timestamp=ts,
        body=m["body"],
        schema_digest=m["schemaDigest"],
    )
    if key != delivery_key(parsed.from_id, parsed.message_id):
        raise bad("key")
    received_at = wire_int(d.get("receivedAt"))
    if (
        received_at is None
        or d.get("status") not in ("pending", "acked")
        or not isinstance(d.get("fingerprint"), str)
    ):
        raise bad("fields")
    thread = None if d.get("thread") is None else snapshot_from_dict(d["thread"], local_ace_id)
    return _Delivery(key, parsed, d["fingerprint"], received_at, d["status"], thread)


def _principal_key(value: object, what: str) -> PrincipalKey:
    if (
        not isinstance(value, dict)
        or set(value) != {"scheme", "publicKey"}
        or value["scheme"] not in SIGNING_SCHEMES
        or not isinstance(value["publicKey"], str)
        or not value["publicKey"]
    ):
        raise ACEError("invalid_argument", f"{what} must be {{'scheme', 'publicKey'}}")
    # Canonical Base64 (decode_b64) of a valid key for the scheme, as 09 rule 4 requires.
    raw = decode_b64(value["publicKey"], "invalid_argument", f"{what}.publicKey", max_bytes=64)
    if not is_valid_signing_public_key(value["scheme"], raw):
        raise ACEError("invalid_argument", f"{what}.publicKey is not a valid key for the scheme")
    return PrincipalKey(value["scheme"], value["publicKey"])


@dataclass(frozen=True)
class InboxPrincipal:
    """The receiver's principal for ``Inbox.open(principal=...)`` (09 § Same-Account Rules):
    its CAIP-10 ``account``, ``self_signer`` (the signer of the host's own principal record)
    and host-trusted ``trusted_signers`` (e.g. read from chain). With neither signer given
    only an ``eip155`` account whose address is the signer's passes step 4 (fail closed)."""

    account: str
    self_signer: PrincipalKey | None = None
    trusted_signers: tuple[PrincipalKey, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """The ``Inbox.open(principal=...)`` wire shape."""
        key = lambda k: {"scheme": k.scheme, "publicKey": k.public_key}  # noqa: E731
        return {
            "account": self.account,
            "selfSigner": None if self.self_signer is None else key(self.self_signer),
            "trustedSigners": [key(k) for k in self.trusted_signers],
        }


def inbox_principal_from_own_record(
    record: PrincipalRecord | dict | None,
    identity: ACEIdentity,
    *,
    now: int | None = None,
    trusted_signers: list[PrincipalKey] | tuple[PrincipalKey, ...] | None = None,
) -> tuple[InboxPrincipal | None, str | None]:
    """The ``principal`` option for a host's own saved principal record (09, R-B12a):
    ``(principal, warning)``. The record is P_self only while it validates for ``identity``'s
    signing key at ``now`` (default: the wall clock). A missing record is ``(None, None)``;
    an invalid or expired one never raises but is ``(None, '<code>: <detail>')`` so the host
    decides how to surface it; a valid one binds its ``account`` with the record's ``signer``
    as ``self_signer`` and ``trusted_signers`` (default none)."""
    if record is None:
        return None, None
    try:
        own = validate_principal_record(
            record, identity.get_signing_public_key(), unix_now(None) if now is None else now
        )
    except ACEError as exc:
        return None, str(exc)  # already ``<code>: <detail>``
    except Exception as exc:  # defensive: a malformed record never raises out of here
        return None, f"invalid_principal: {exc}"
    return InboxPrincipal(own.account, own.signer, tuple(trusted_signers or ())), None


def _principal_option(
    principal: object,
) -> tuple[str, PrincipalKey | None, frozenset[PrincipalKey]] | None:
    """Parse ``Inbox.open(principal=...)``: an ``InboxPrincipal`` or ``{"account": <CAIP-10>,
    "selfSigner"?: {"scheme","publicKey"} | None,
    "trustedSigners"?: [{"scheme","publicKey"}, ...]}``."""
    if principal is None:
        return None
    if isinstance(principal, InboxPrincipal):
        principal = principal.to_dict()
    if (
        not isinstance(principal, dict)
        or not set(principal) <= {"account", "selfSigner", "trustedSigners"}
        or not is_caip10(principal.get("account"))
    ):
        raise ACEError(
            "invalid_argument",
            "principal must be {'account': <CAIP-10>, 'selfSigner'?, 'trustedSigners'?}",
        )
    raw_self = principal.get("selfSigner")
    self_signer = None if raw_self is None else _principal_key(raw_self, "principal.selfSigner")
    raw_trusted = principal.get("trustedSigners")
    if raw_trusted is None:
        raw_trusted = []
    if not isinstance(raw_trusted, (list, tuple)):
        raise ACEError("invalid_argument", "principal.trustedSigners must be a list")
    trusted = frozenset(_principal_key(k, "principal.trustedSigners[]") for k in raw_trusted)
    return principal["account"], self_signer, trusted


def _authenticated_by(env: ACEMessage, peer: Any) -> bool:
    """The envelope signature verifies under ``peer``'s pinned key and scheme (as parse
    step 8, including the scheme check); malformed signatures are False."""
    if env.from_id != peer.ace_id or env.signature.scheme != peer.scheme:
        return False
    try:
        sig = decode_signature(env.signature.value, env.signature.scheme, "invalid_envelope")
    except ACEError:
        return False
    return verify_signature(message_sign_data(env), sig, peer.scheme, peer.signing_public_key)


def _history_dicts(snap: ThreadSnapshot | None) -> list[dict]:
    return [] if snap is None else [h.to_dict() for h in snap.history]


def _clear_proven_pending(rec: ThreadRecord | None, new_snap: ThreadSnapshot) -> PendingSend | None:
    """The stored pending send, or None when ``new_snap`` proves its delivery (it is
    followed by an entry from the peer)."""
    if rec is None or rec.pending is None:
        return None
    mid = rec.pending.message.message_id
    ids = [h.message_id for h in new_snap.history]
    if mid in ids and any(
        h.from_id != new_snap.local_ace_id for h in new_snap.history[ids.index(mid) + 1 :]
    ):
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


def stored_horizons(store: ACEStore) -> Callable[[str, int], bool]:
    """``covered(sender, timestamp)`` against the persisted replay horizons (read-only)."""
    state = load_record(store, "replay.json")
    if state is None:
        return lambda sender, ts: False
    h, sh = wire_int(state.get("horizon")), state.get("senderHorizons")
    if (
        h is None
        or not isinstance(sh, dict)
        or not all(wire_int(v) is not None for v in sh.values())
    ):
        raise ACEError("storage_failed", "replay.json is invalid")
    return lambda sender, ts: ts <= h or ts <= sh.get(sender, h)


def repair_thread(threads: ThreadStore, rec: _Delivery) -> None:
    """Write ``rec.thread`` if it strictly extends the stored history; divergence is
    ``storage_failed``. Caller holds the ``threads`` lock."""
    if rec.thread is None:
        return
    stored = threads._load(rec.thread.conversation_id, rec.thread.thread_id)
    old = _history_dicts(stored.snapshot if stored else None)
    new = _history_dicts(rec.thread)
    if len(new) > len(old) and new[: len(old)] == old:
        threads._save(ThreadRecord(rec.thread, _clear_proven_pending(stored, rec.thread)))
    elif new != old[: len(new)]:
        raise ACEError(
            "storage_failed", f"{rec.key}: thread history diverges from the delivery record"
        )


class Inbox:
    """Durable, exactly-once-to-the-host receive engine (the application codec).

    It knows nothing about the network: ``SecureMailbox`` (the only network receive
    boundary) feeds it authenticated MLS plaintext through ``receive``; in-process code and
    tests call ``receive`` directly. ``on_message(parsed)`` must persist the host effect
    durably and idempotently, keyed by ``(from_id, message_id)``, then return; raising means
    "retry later". Commit order per message: delivery record, ``requests/`` decision fill
    (``decision`` only), thread state, ``on_message``, ack. The delivery record journals the
    seen-store commit: ``replay.json`` is rewritten every 1024 commits and at ``close()``,
    ``open`` re-commits the records written since, and a record is deleted only once a
    written ``replay.json`` covers it. Open with ``Inbox.open(...)``; the instance holds the
    store's ``receive`` lock until ``close()``.

    ``principal`` (09) is the receiver's principal: ``{"account": <CAIP-10>, "selfSigner":
    {"scheme", "publicKey"} | None, "trustedSigners": [{"scheme", "publicKey"}, ...]}``
    (``selfSigner`` defaults to None and ``trustedSigners`` to empty: then only an ``eip155``
    account whose address is the signer's passes 09 step 4). Without it no account policy is
    installed: principal messages are delivered as plain data, unverified, and a ``decision``
    never fills ``requests/``.
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
        principal: InboxPrincipal | dict | None = None,
        commerce: bool = False,
        schemas: dict[str, SchemaValidator] | None = None,
    ) -> "Inbox":
        principal_option = _principal_option(principal)
        installed = check_schemas(schemas)
        if not isinstance(peers, PeerStore):
            raise ACEError("invalid_argument", "peers must be a PeerStore")
        if not callable(on_message):
            raise ACEError("invalid_argument", "on_message must be callable")
        if (
            type(offline_window_seconds) is not int
            or offline_window_seconds < TIMESTAMP_WINDOW_SECONDS
        ):
            raise ACEError(
                "invalid_argument",
                f"offline_window_seconds must be an integer >= {TIMESTAMP_WINDOW_SECONDS}",
            )
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
        self._principal = principal_option
        self._commerce = commerce
        self._schemas = installed
        self._threads = ThreadStore(store, self._local, clock=clock)
        self._mutex = threading.RLock()
        self._failed = False
        self._closed = False
        self._quarantine_count: int | None = None
        self._replay_dirty = 0  # commits since replay.json was last written
        self._acked: dict[str, tuple[str, int]] = {}  # acked records replay.json does not cover yet
        self._held_locks: Any = None  # ``threads`` or ``requests``, kept after a failure
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
        return max(0, self._now() - self._offline)

    def _principal_context(self) -> PrincipalContext | None:
        """Step-7 context. The Inbox refreshes the sender before parsing
        (``_refresh_principal_sender``), outside the ``requests`` lock."""
        if self._principal is None:
            return None
        account, self_signer, trusted = self._principal
        store = self._store

        def lookup(conversation_id: str, request_id: str, now: int) -> str | None:
            return open_request_to(store, conversation_id, request_id, now)

        return PrincipalContext(account, lookup, self_signer, trusted)

    def _refresh_principal_sender(self, env: ACEMessage, peer: Any, now: int) -> Any:
        """R-P20 (09 § Same-Account Rules): when the pinned sender principal fails steps 2-5,
        refresh the sender's binding from the relay once (rollback barrier) and return the
        binding the rules run on. Runs before any lock is taken, so relay I/O never holds
        ``requests``. A transient failure raises (the message is retryable, nothing committed);
        a non-ACE exception is ``relay_unavailable``; a permanent ``ACEError`` or no relay
        leaves the pinned binding to decide. Only an envelope authenticated by the pinned
        signing key triggers a refresh (R-P30); otherwise the pipeline rejects it later."""
        ctx = self._principal_context()
        if ctx is None or sender_principal_usable(
            peer.principal, peer.signing_public_key, ctx, now
        ):
            return peer
        # cheap pure-read pre-checks mirroring pipeline steps 1-3 (recipient, window, replay):
        # nothing is committed; a failing envelope is rejected by the pipeline as usual
        if (
            env.to_id != self._local
            or not self._floor() <= env.timestamp <= now + TIMESTAMP_WINDOW_SECONDS
            or not self._replay.accepts(env.message_id, env.from_id, env.timestamp)
        ):
            return peer
        if not _authenticated_by(env, peer):
            return peer
        try:
            fresh = self._peers._refresh(peer.ace_id)
        except ACEError as exc:
            if exc.is_transient:
                raise
            return peer
        except Exception as exc:
            raise ACEError(
                "relay_unavailable", f"peer refresh failed: {type(exc).__name__}: {exc}"
            ) from exc
        if (
            fresh is not None
            and fresh.ace_id == peer.ace_id
            and fresh.signing_public_key == peer.signing_public_key
        ):
            return fresh
        return peer

    def _load_replay(self) -> ReplayDetector:
        state = load_record(self._store, "replay.json")
        if state is None:
            # Outbox-only threads (no inbound entry) may legitimately predate the first open.
            if self._store.list("deliveries/") or any(
                h.from_id != self._local
                for rec in self._threads._records()
                for h in rec.snapshot.history
            ):
                raise ACEError("storage_failed", "replay state missing beside history")
            replay = ReplayDetector(
                capacity=self._capacity,
                horizon=max(0, self._now() - self._offline - 1),
                clock=self._clock,
            )
            self._write_replay(replay)
            return replay
        try:
            return ReplayDetector.from_state(state, capacity=self._capacity, clock=self._clock)
        except ACEError as exc:
            raise ACEError("storage_failed", f"replay.json is invalid: {exc}") from None

    def _write_replay(self, replay: ReplayDetector) -> None:
        write_record(self._store, "replay.json", replay.export_state())

    def _persist_replay(self) -> None:
        """Write the seen store, then delete the acked records it now covers."""
        self._write_replay(self._replay)
        self._replay_dirty = 0
        self._prune_acked()

    def _prune_acked(self) -> None:
        """Delete the acked records covered by the seen store; only while it equals replay.json."""
        for key, (from_id, ts) in list(self._acked.items()):
            if self._replay._covered(from_id, ts):
                self._store.delete(key)
                del self._acked[key]

    def _finish(self, rec: _Delivery) -> None:
        """After the hand-over: drop the record once the written replay state covers it, else
        mark it ``acked`` (pruned after a later write of replay.json)."""
        m = rec.message
        if self._replay_dirty == 0 and self._replay._covered(m.from_id, m.timestamp):
            self._store.delete(rec.key)
            return
        rec.status = "acked"
        write_record(self._store, rec.key, rec.to_dict())
        self._acked[rec.key] = (m.from_id, m.timestamp)

    def _recover(self) -> None:
        """Repair threads, ``requests/`` decision fills and replay from every delivery record
        first (ordered by (timestamp, key)), then hand over the pending ones in the same order.
        A decision's ``requests/`` fill is a replayed processing (09 step 7): the same-account
        rules run again on the pinned sender. A record that fails them with ``wrong_principal``
        or ``bad_reference`` was never accepted under this policy (e.g. it was delivered as
        data while no principal was installed, or the request is already decided) and changes
        nothing; any other error fails ``open()``."""
        records = load_deliveries(self._store, self._local)
        changed = False
        with self._threads._locked():
            for rec in records:
                if rec.status == "acked" and self._replay._covered(
                    rec.message.from_id, rec.message.timestamp
                ):
                    continue  # fully committed long ago; its thread may have been pruned
                repair_thread(self._threads, rec)
        ctx = self._principal_context()
        decisions = [rec.message for rec in records if rec.message.type == "decision"]
        if ctx is None:
            decisions = []
        if decisions:  # 1a: a decision's requests/ fill (no-op when already filled)
            with self._store.lock("requests"):
                for m in decisions:
                    sender = self._peers.get(m.from_id)
                    if sender is None:
                        continue
                    try:
                        apply_receive_rules(m, sender, threads=None, principal=ctx, now=self._now())
                    except ACEError as exc:
                        if exc.code in ("wrong_principal", "bad_reference"):
                            continue
                        raise
                    fill_decision(self._store, m)
        for rec in records:
            m = rec.message
            if self._replay.accepts(m.message_id, m.from_id, m.timestamp):
                self._replay.commit(m.message_id, m.from_id, m.timestamp, self._floor())
                changed = True
            if rec.status == "acked":
                self._acked[rec.key] = (m.from_id, m.timestamp)
        if changed:
            self._persist_replay()
        else:
            self._prune_acked()  # replay.json as loaded: its covered acked records go
        for rec in records:
            if rec.status != "pending":
                continue
            try:
                self._on_message(rec.message)
            except Exception as exc:
                raise ACEError(
                    "handler_failed", f"on_message failed during recovery: {exc}"
                ) from exc
            self._finish(rec)

    # --- public ---

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            if not self._failed and self._replay_dirty:
                try:  # best effort: the delivery records journal these commits
                    self._persist_replay()
                except ACEError:
                    pass
            self._closed = True
            held, self._held_locks = self._held_locks, None
            try:
                if held is not None:
                    held.__exit__(None, None, None)
            finally:
                self._lock.__exit__(None, None, None)

    def __enter__(self) -> "Inbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def receive(self, message: bytes) -> ReceiveOutcome:
        """Receive one envelope given as its raw JSON bytes (authenticated MLS plaintext from
        ``SecureMailbox``, or an in-process envelope).

        Bytes over ``MAX_ENVELOPE_BYTES``, or that are not UTF-8 JSON, are ``quarantined``
        (``invalid_envelope``, no fingerprint, nothing stored). A closed inbox or a non-bytes
        ``message`` raise ``invalid_argument``.
        """
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise ACEError("invalid_argument", "message must be the raw envelope bytes")
        with self._mutex:
            if self._closed:
                raise ACEError("invalid_argument", "the inbox is closed")
            if self._failed:
                return ReceiveOutcome(
                    "retryable",
                    error=ACEError("storage_failed", "inbox is in a failed state; reopen it"),
                )
            return self._receive(bytes(message))

    def _quarantine(self, err: ACEError, env: ACEMessage) -> ReceiveOutcome:
        fp = envelope_fingerprint(env)
        self._write_quarantine(err, env, fp)
        return ReceiveOutcome(
            "quarantined", error=err, fingerprint=fp, from_id=env.from_id, message_id=env.message_id
        )

    def _write_quarantine(self, err: ACEError, env: ACEMessage, fp: str) -> None:
        key = f"quarantine/{fp}.json"
        existed = self._store.read(key) is not None
        write_record(
            self._store,
            key,
            {
                "code": err.code,
                "envelope": env.to_dict(),
                "fingerprint": fp,
                "quarantinedAt": self._now(),
                "reason": err.message[:_REASON_MAX],
            },
        )
        if existed:
            return
        # O(1) per insert: listed once per Inbox (it holds ``receive``, so it is the only
        # writer); records are listed and read only when the cap is crossed (trim to 900).
        if self._quarantine_count is None:
            self._quarantine_count = len(self._store.list("quarantine/"))
        else:
            self._quarantine_count += 1
        if self._quarantine_count <= QUARANTINE_CAP:
            return
        keys = self._store.list("quarantine/")
        aged = []
        for k in keys:
            try:
                d = load_record(self._store, k)
                at = wire_int(d.get("quarantinedAt")) if d else None
            except ACEError:
                at = None
            aged.append((at if at is not None else -1, k[len("quarantine/") : -len(".json")], k))
        aged.sort()
        for _, _, k in aged[: len(aged) - QUARANTINE_KEEP]:
            self._store.delete(k)
        self._quarantine_count = min(len(keys), QUARANTINE_KEEP)

    def _hand_over(self, rec: _Delivery) -> ReceiveOutcome:
        """Steps 4-5 for a stored pending delivery."""
        m = rec.message
        try:
            self._on_message(m)
        except Exception as exc:
            return ReceiveOutcome(
                "retryable",
                error=ACEError("handler_failed", f"on_message failed: {exc}"),
                from_id=m.from_id,
                message_id=m.message_id,
            )
        try:
            self._finish(rec)
        except ACEError as exc:
            self._failed = True
            return ReceiveOutcome(
                "retryable", error=exc, from_id=m.from_id, message_id=m.message_id
            )
        return ReceiveOutcome("delivered", message=m, from_id=m.from_id, message_id=m.message_id)

    def _receive(self, data: bytes) -> ReceiveOutcome:
        now = self._now()
        # 1. decode
        if len(data) > MAX_ENVELOPE_BYTES:
            return ReceiveOutcome(
                "quarantined",
                error=ACEError("invalid_envelope", "envelope exceeds MAX_ENVELOPE_BYTES"),
            )
        try:
            env = decode_envelope(loads_json(data))
        except ValueError as exc:
            return ReceiveOutcome(
                "quarantined", error=ACEError("invalid_envelope", f"envelope is not JSON: {exc}")
            )
        except ACEError as exc:
            return ReceiveOutcome("quarantined", error=exc)
        # 2. peer (freshness is the MLS handshake's job; the replay floor stays in parse)
        try:
            peer = self._peers.resolve(env.from_id)
            my_enc = self._identity.get_encryption_public_key()
            if compute_conversation_id(peer.encryption_public_key, my_enc) != env.conversation_id:
                peer = self._peers.resolve(env.from_id, max_age_seconds=0)
        except ACEError as exc:
            if exc.is_transient:
                return ReceiveOutcome(
                    "retryable", error=exc, from_id=env.from_id, message_id=env.message_id
                )
            try:
                return self._quarantine(exc, env)
            except ACEError as store_exc:
                return ReceiveOutcome("retryable", error=store_exc)
        except Exception as exc:  # e.g. a custom relay client or transport bug: retry later
            err = ACEError(
                "relay_unavailable", f"peer resolution failed: {type(exc).__name__}: {exc}"
            )
            return ReceiveOutcome(
                "retryable", error=err, from_id=env.from_id, message_id=env.message_id
            )
        # 3. stored delivery
        key = delivery_key(env.from_id, env.message_id)
        try:
            d = load_record(self._store, key)
            stored = None if d is None else _delivery_from_dict(d, key, self._local)
        except ACEError as exc:
            return ReceiveOutcome(
                "retryable", error=exc, from_id=env.from_id, message_id=env.message_id
            )
        if stored is not None:
            if stored.status == "pending":
                return self._hand_over(stored)
            return ReceiveOutcome("duplicate", from_id=env.from_id, message_id=env.message_id)
        gate = _PeekReplay(self._replay)
        try:
            parsed = parse_with_gate(
                env,
                self._identity,
                peer,
                threads=None,
                replay=gate,
                floor=self._floor(),
                clock=self._clock,
                principal=None,
            )
            run_schema_validator(  # 06 step 6: installed deterministic validation
                self._schemas, parsed.type, parsed.schema_digest, parsed.thread_id, parsed.body
            )
            if self._principal is not None and is_principal_type(parsed.type):
                peer = self._refresh_principal_sender(env, peer, now)
        except ACEError as exc:
            return self._rejected(exc, env, gate.verified)
        economic = self._commerce and is_economic_type(parsed.type)
        if economic and parsed.thread_id is None:
            return self._rejected(
                ACEError("invalid_envelope", "commerce messages require a private threadId"),
                env,
                True,
            )
        decision = self._principal is not None and parsed.type == "decision"
        with ExitStack() as held:
            if economic or decision:
                try:
                    held.enter_context(
                        self._threads._locked() if economic else self._store.lock("requests")
                    )
                except ACEError as exc:
                    return ReceiveOutcome(
                        "retryable", error=exc, from_id=env.from_id, message_id=env.message_id
                    )
            result = self._parse_and_commit(env, peer, key, now, economic, decision, parsed)
            if self._failed and (economic or decision):
                self._held_locks = (
                    held.pop_all()
                )  # keep other writers out until close()/open() repairs
        if isinstance(result, ReceiveOutcome):
            return result
        return self._hand_over(result)  # 7.4-7.5, without the threads lock

    def _rejected(self, exc: ACEError, env: ACEMessage, verified: bool) -> ReceiveOutcome:
        """``verified``: the signature checked out (pipeline step 9 reached)."""
        ids = {"from_id": env.from_id, "message_id": env.message_id}
        if exc.code == "replay":
            return ReceiveOutcome("duplicate", **ids)
        if exc.is_transient:
            return ReceiveOutcome("retryable", error=exc, **ids)
        try:
            outcome = self._quarantine(exc, env)
            # An authenticated message stays one-shot. No delivery record journals it, so its
            # commit is written now, on a copy swapped in only once written.
            if verified:
                tr = self._replay.clone()
                if tr.commit(env.message_id, env.from_id, env.timestamp, self._floor()):
                    self._write_replay(tr)
                    self._replay = tr
                    self._replay_dirty = 0
                    try:
                        self._prune_acked()
                    except ACEError:
                        pass
            return outcome
        except ACEError as store_exc:
            return ReceiveOutcome("retryable", error=store_exc, **ids)

    def _parse_and_commit(
        self,
        env: ACEMessage,
        peer: Any,
        key: str,
        now: int,
        economic: bool,
        decision: bool,
        parsed: ParsedMessage,
    ) -> "ReceiveOutcome | _Delivery":
        ids = {"from_id": env.from_id, "message_id": env.message_id}
        try:
            if economic:
                machine, rec = self._threads._machine(env.conversation_id, parsed.thread_id)
            else:
                machine, rec = ThreadStateMachine(self._local), None
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc, **ids)
        try:
            apply_receive_rules(
                parsed,
                peer,
                threads=machine if economic else None,
                principal=self._principal_context(),
                now=now,
            )
            if economic and rec is None:
                self._threads._check_can_open(env.from_id)
        except ACEError as exc:
            return self._rejected(exc, env, True)
        # 7. durable commit
        snap = machine.get_snapshot(env.conversation_id, parsed.thread_id) if economic else None  # type: ignore[arg-type]
        delivery = _Delivery(key, parsed, envelope_fingerprint(env), now, "pending", snap)
        try:
            write_record(self._store, key, delivery.to_dict())  # 7.1 commit point
        except ACEError as exc:
            return ReceiveOutcome("retryable", error=exc, **ids)
        try:
            # 7.3 in memory; the record just written journals it until the next replay.json
            self._replay.commit(env.message_id, env.from_id, env.timestamp, self._floor())
            self._replay_dirty += 1
            if decision:  # 7.1a: mark the request decided
                fill_decision(self._store, parsed)
            if snap is not None:  # 7.2
                self._threads._save(ThreadRecord(snap, _clear_proven_pending(rec, snap)))
        except ACEError as exc:
            self._failed = True
            return ReceiveOutcome("retryable", error=exc, **ids)
        if self._replay_dirty >= _REPLAY_SNAPSHOT_EVERY:
            try:  # a failed snapshot only delays pruning: the records still journal every commit
                self._persist_replay()
            except ACEError:
                pass
        return delivery


class _PeekReplay:
    """Pipeline steps 7 and 9 against the live seen store without writing it: the Inbox
    commits only at its commit point. ``verified`` records that step 9 was reached."""

    def __init__(self, replay: ReplayDetector) -> None:
        self._replay = replay
        self.verified = False

    def accepts(self, message_id: str, from_id: str, timestamp: int) -> bool:
        return self._replay.accepts(message_id, from_id, timestamp)

    def commit(self, message_id: str, from_id: str, timestamp: int, floor: int) -> bool:
        self.verified = True
        return self._replay.accepts(message_id, from_id, timestamp)
