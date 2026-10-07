"""Sender durability (06-security "Durable Delivery", Sender)."""

from __future__ import annotations

import dataclasses
import uuid
from typing import Callable, TypeVar

from ._encoding import encode_signature, is_thread_id, unix_now
from .discovery import VerifiedPeer
from .encryption import compute_conversation_id
from .envelope import message_sign_data
from .errors import ACEError
from .messages import create_message
from .state_machine import ThreadHistoryEntry, ThreadStateMachine
from .store import ACEStore, load_record, write_record
from .threads import PendingSend, ThreadRecord, ThreadStore, rebuild_snapshot, sha256_hex
from .types import ACEIdentity, ACEMessage, MessageType, SignatureEnvelope, is_economic_type

T = TypeVar("T")


def _outbox_key(request_id: str) -> str:
    return f"outbox/{sha256_hex(request_id)}.json"


def _check_request_id(request_id: object) -> str:
    if not is_thread_id(request_id):  # same 1-256 / no-control-character rule
        raise ACEError(
            "invalid_argument", "request_id must be 1-256 characters without control characters"
        )
    return request_id


class Outbox:
    """Stage signed envelopes durably before sending them.

    - ``stage`` signs the message and persists it with its resulting thread state in one
      write (economic: in the thread record; otherwise ``outbox/<sha256(requestId)>.json``).
      Staging an existing ``request_id`` returns the pending send unchanged.
    - ``deliver(request_id, transport)`` calls ``transport(message)``; success clears the
      pending send, ``envelope_expired`` marks it ``expired``, other errors leave it as is.
      A pending send is never abandoned automatically.
    - ``resign`` re-signs an ``expired`` send with the same ``messageId`` and a fresh
      timestamp (the ciphertext is kept: the AEAD binds only the conversation ID).
    - ``abandon`` drops a pending send (economic: and its thread head entry).
    """

    def __init__(self, *_: object, **__: object) -> None:
        raise ACEError("invalid_argument", "use Outbox.open(...)")

    @classmethod
    def open(
        cls, identity: ACEIdentity, store: ACEStore, *, clock: Callable[[], int] | None = None
    ) -> "Outbox":
        """Create an outbox. Under lock ``threads``, repairs thread records from
        ``deliveries/`` whose snapshot strictly extends the stored history (an Inbox that
        crashed between its delivery and thread writes); divergence is ``storage_failed``.
        Records that are ``acked`` and covered by a replay horizon are skipped. Never hands
        messages over and never writes the replay state."""
        from .inbox import load_deliveries, repair_thread, stored_horizons

        self = object.__new__(cls)
        self._identity = identity
        self._store = store
        self._clock = clock
        self._threads = ThreadStore(store, identity.get_ace_id(), clock=clock)
        with self._threads._locked():
            covered = stored_horizons(store)
            for rec in load_deliveries(store, identity.get_ace_id()):
                if rec.status == "acked" and covered(rec.message.from_id, rec.message.timestamp):
                    continue  # fully committed long ago; its thread may have been pruned
                repair_thread(self._threads, rec)
        return self

    def _now(self) -> int:
        return unix_now(self._clock)

    # --- lookup ---

    def _find(self, request_id: str) -> tuple[PendingSend, ThreadRecord | None] | None:
        """Caller holds the ``threads`` lock."""
        d = load_record(self._store, _outbox_key(request_id))
        if d is not None:
            p = PendingSend.from_dict(d)
            if p.request_id != request_id:
                raise ACEError("storage_failed", "outbox record does not match its requestId")
            return p, None
        for rec in self._threads._records():
            if rec.pending is not None and rec.pending.request_id == request_id:
                return rec.pending, rec
        return None

    def _write_outbox(self, p: PendingSend) -> None:
        write_record(self._store, _outbox_key(p.request_id), p.to_dict())

    # --- API ---

    def stage(
        self,
        recipient: VerifiedPeer,
        type_: MessageType,
        body: dict,
        *,
        thread_id: str | None = None,
        request_id: str | None = None,
    ) -> PendingSend:
        rid = str(uuid.uuid4()) if request_id is None else _check_request_id(request_id)
        if not isinstance(recipient, VerifiedPeer):
            raise ACEError("invalid_argument", "recipient must be a VerifiedPeer")
        local = self._identity.get_ace_id()
        with self._threads._locked():
            # a fresh UUID cannot be staged yet: skip the scan over every thread record
            found = None if request_id is None else self._find(rid)
            if found is not None:
                return found[0]
            now = self._now()
            if is_economic_type(type_) and thread_id is not None:
                conversation_id = compute_conversation_id(
                    self._identity.get_encryption_public_key(),
                    recipient.encryption_public_key,
                )
                machine, rec = self._threads._machine(conversation_id, thread_id)
                if rec is not None and rec.pending is not None:
                    raise ACEError("pending_send_conflict", "the thread already has a pending send")
                # a message that opens a thread is bounded per peer (pre-checked before any crypto)
                if rec is None and type_ in machine.allowed_types(
                    conversation_id, thread_id, local
                ):
                    self._threads._check_can_open(recipient.ace_id)
                env = create_message(
                    self._identity,
                    recipient,
                    type_,
                    body,
                    machine,
                    thread_id=thread_id,
                    timestamp=now,
                )
                pending = PendingSend(rid, "pending", now, env)
                snap = machine.get_snapshot(conversation_id, thread_id)
                assert snap is not None
                self._threads._save(ThreadRecord(snap, pending))
                return pending
            env = create_message(
                self._identity,
                recipient,
                type_,
                body,
                ThreadStateMachine(local),
                thread_id=thread_id,
                timestamp=now,
            )
            pending = PendingSend(rid, "pending", now, env)
            self._write_outbox(pending)
            return pending

    def deliver(self, request_id: str, transport: Callable[[ACEMessage], T]) -> T:
        """Send the pending send through ``transport`` and return its result. An ``expired``
        one is refused with ``envelope_expired`` before any transport call (``resign`` it
        first)."""
        rid = _check_request_id(request_id)
        if not callable(transport):
            raise ACEError("invalid_argument", "transport must be callable")
        with self._threads._locked():
            found = self._find(rid)
        if found is None:
            raise ACEError("invalid_argument", "no pending send with this request_id")
        if found[0].status == "expired":
            raise ACEError("envelope_expired", "the pending send expired; resign it first")
        message = found[0].message
        try:
            result = transport(message)
        except ACEError as exc:
            if exc.code == "envelope_expired":
                self._set_pending(
                    rid, message.message_id, lambda p: dataclasses.replace(p, status="expired")
                )
            raise
        self._set_pending(rid, message.message_id, lambda p: None)
        return result

    def _set_pending(
        self,
        rid: str,
        message_id: str,
        change: Callable[[PendingSend], PendingSend | None],
    ) -> None:
        """Replace (or with None, clear) the pending send, if it still carries ``message_id``."""
        with self._threads._locked():
            found = self._find(rid)
            if found is None or found[0].message.message_id != message_id:
                return
            p, rec = found
            new = change(p)
            if rec is not None:
                self._threads._save(ThreadRecord(rec.snapshot, new))
            elif new is None:
                self._store.delete(_outbox_key(rid))
            else:
                self._write_outbox(new)

    def resign(self, request_id: str) -> PendingSend:
        rid = _check_request_id(request_id)
        with self._threads._locked():
            found = self._find(rid)
            if found is None:
                raise ACEError("invalid_argument", "no pending send with this request_id")
            p, rec = found
            if p.status != "expired":
                raise ACEError("invalid_argument", "only an expired pending send can be re-signed")
            now = self._now()
            old = p.message
            scheme = self._identity.get_signing_scheme()
            env = dataclasses.replace(
                old,
                timestamp=now,
                signature=SignatureEnvelope(scheme, ""),
                encryption=dataclasses.replace(old.encryption),
            )
            env.signature.value = encode_signature(
                self._identity.sign(message_sign_data(env)), scheme
            )
            new = PendingSend(rid, "pending", p.staged_at, env)
            if rec is None:
                self._write_outbox(new)
                return new
            history = list(rec.snapshot.history)
            if not history or history[-1].message_id != old.message_id:
                raise ACEError("storage_failed", "the pending send is not the thread head")
            history[-1] = ThreadHistoryEntry(
                history[-1].type, old.message_id, now, history[-1].from_id
            )
            snap = rebuild_snapshot(rec.snapshot, history)
            assert snap is not None
            self._threads._save(ThreadRecord(snap, new))
            return new

    def abandon(self, request_id: str) -> None:
        """Drop a pending send; a missing ``request_id`` is a no-op."""
        rid = _check_request_id(request_id)
        with self._threads._locked():
            found = self._find(rid)
            if found is None:
                return
            p, rec = found
            if rec is None:
                self._store.delete(_outbox_key(rid))
                return
            history = list(rec.snapshot.history)
            if history and history[-1].message_id == p.message.message_id:
                history.pop()
            snap = rebuild_snapshot(rec.snapshot, history)
            if snap is None:
                self._threads._delete(rec.snapshot)
            else:
                self._threads._save(ThreadRecord(snap, None))

    def pending(self) -> list[PendingSend]:
        out = [rec.pending for rec in self._threads._records() if rec.pending is not None]
        for key in self._store.list("outbox/"):
            d = load_record(self._store, key)
            if d is not None:
                out.append(PendingSend.from_dict(d))
        return sorted(out, key=lambda p: (p.staged_at, p.request_id))
