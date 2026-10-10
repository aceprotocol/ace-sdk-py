"""Secure network ingress and non-destructive reply reader. Keep the receiver online.

HTTP timeouts belong to RelayClient. Application callbacks durably persist or enqueue
work; they must not await a network response while holding the receive lock.
"""

from __future__ import annotations

import inspect
import os
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

from ._encoding import canonical_state_bytes, is_stream_id, loads_json
from .envelope import decode_envelope, envelope_fingerprint
from .errors import ACEError
from .inbox import Inbox, ReceiveOutcome
from .limits import (
    MAX_DIRECT_BODY_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_INBOX_PAGE,
    SECURE_DELIVERY_TTL_SECONDS,
)
from .relay import compare_stream_ids
from .secure_transport import SecureTransport
from .session import MLSError
from .store import load_record, write_record
from .threads import sha256_hex
from .types import ParsedMessage


@dataclass(frozen=True)
class PullResult:
    """The result of ``SecureMailbox.pull``: every outcome in relay order, the error that
    stopped the drain (a retryable error, a fetch error or an invalid argument) or None, and
    ``has_more`` when ``max_pages`` or ``stop`` ended it before the inbox was drained."""

    outcomes: list[ReceiveOutcome]
    blocked: ACEError | None
    has_more: bool = False

    @property
    def messages(self) -> list[ParsedMessage]:
        """The delivered messages, in order."""
        return [o.message for o in self.outcomes if o.kind == "delivered" and o.message is not None]

    @property
    def delivered(self) -> int:
        return sum(o.kind == "delivered" for o in self.outcomes)

    @property
    def duplicates(self) -> int:
        return sum(o.kind == "duplicate" for o in self.outcomes)

    @property
    def quarantined(self) -> int:
        return sum(o.kind == "quarantined" for o in self.outcomes)


@dataclass(frozen=True)
class DirectReply:
    """The HTTP reply for one direct-delivery request (08-relay § Direct Delivery, Receiver):
    ``status`` and the JSON ``body`` to send, and the receive ``outcome`` when the request
    reached the pipeline."""

    status: int
    body: dict[str, Any]
    outcome: ReceiveOutcome | None = None


def _error(exc):
    if isinstance(exc, ACEError):
        return exc
    if isinstance(exc, MLSError) and exc.is_permanent:
        return ACEError("invalid_body", exc.code)
    error = ACEError("storage_failed", "secure delivery failed")
    error.__cause__ = exc
    return error


def _decode(raw):
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ACEError("invalid_envelope", "envelope too large")
    try:
        return decode_envelope(loads_json(raw))
    except (ValueError, UnicodeError) as exc:
        raise ACEError("invalid_envelope", "invalid UTF-8 or JSON") from exc


def _cursor_key(relay) -> str:
    return f"secure/cursors/{sha256_hex(relay.base_url)}.json"


def _stored_cursor(store, relay, identity) -> str | None:
    """The receive cursor ``SecureMailbox`` persisted for ``relay`` (``storage_failed`` when
    the row is malformed or belongs to another identity)."""
    row = load_record(store, _cursor_key(relay))
    if row is None:
        return None
    if row.get("identity") != identity.get_ace_id() or not is_stream_id(row.get("cursor")):
        raise ACEError("storage_failed", "invalid secure cursor")
    return row["cursor"]


class SecureMailbox:
    def __init__(
        self, identity, store, peers, relay, secure, inbox, *, close_transport=True, dispose=None
    ):
        """``dispose`` runs once at ``close()`` after the transport and the Inbox are closed
        (``open_secure_mailbox`` passes the engine's ``close``)."""
        self.identity, self.store, self.peers, self.relay = identity, store, peers, relay
        self.secure, self.inbox, self.close_transport = secure, inbox, close_transport
        self.dispose = dispose
        self._closed, self._pid, self._lock = False, os.getpid(), threading.RLock()
        self._lease = store.lock("secure-mailbox", timeout=0)
        self._lease.__enter__()
        self._key = _cursor_key(relay)
        try:
            self._cursor = _stored_cursor(store, relay, identity)
        except Exception:
            self._lease.__exit__(None, None, None)
            raise

    def _check(self):
        if self._closed or self._pid != os.getpid():
            raise ACEError("storage_failed", "secure mailbox closed or inherited after fork")

    def cursor(self, relay):
        return self._cursor if relay.base_url == self.relay.base_url else None

    def _ingest(self, envelope):
        self._check()
        # admission first (13): an unadmitted sender never triggers a lookup or a pin
        if not self.secure.is_peer_allowed(self.secure.store, envelope.from_id):
            raise MLSError("delivery_peer_disabled")
        peer = self.peers.resolve(envelope.from_id)
        frame = self.secure._read(envelope, peer)  # authenticated once, then routed
        if frame["kind"] in ("offer", "ack"):
            return []
        outcomes = []

        def accept(data):
            outcome = self.inbox.receive(data)
            if outcome.kind == "retryable":
                raise outcome.error
            outcomes.append(outcome)  # a quarantined inner envelope travels in the receipt
            if outcome.kind == "quarantined":
                return f"rejected:{outcome.error.code}"
            return outcome.kind

        reply = self.secure._respond(frame, peer, accept)
        self.relay.send(reply)  # Never call a direct endpoint under the receive lock.
        return outcomes

    def _receive(self, raw, stream_id=None, envelope=None):
        """``(accepted, outcomes)``: ``accepted`` is False when the frame itself was refused
        (its single quarantined outcome then carries the frame-level error). ``envelope`` is
        ``raw`` already decoded."""
        self._check()  # Before entering a possibly inherited mutex.
        with self._lock:
            self._check()
            if stream_id and self._cursor and compare_stream_ids(stream_id, self._cursor) <= 0:
                return True, []
            accepted = True
            try:
                if envelope is None:
                    envelope = _decode(raw)
                outcomes = self._ingest(envelope)
            except Exception as exc:
                error = _error(exc)
                if error.category != "permanent":
                    raise error
                fingerprint = None if envelope is None else envelope_fingerprint(envelope)
                accepted = False
                outcomes = [ReceiveOutcome("quarantined", error=error, fingerprint=fingerprint)]
            if stream_id:
                write_record(
                    self.store,
                    self._key,
                    {"identity": self.identity.get_ace_id(), "cursor": stream_id},
                )
                self._cursor = stream_id
            return accepted, outcomes

    def pull(self, *, limit=MAX_INBOX_PAGE, max_pages=None, stop=None):
        outcomes = []
        try:
            self._check()
            if (
                type(limit) is not int
                or not 1 <= limit <= MAX_INBOX_PAGE
                or (max_pages is not None and (type(max_pages) is not int or max_pages < 1))
            ):
                raise ACEError("invalid_argument", "invalid page bounds")
            pages = 0
            while stop is None or not stop.is_set():
                if max_pages is not None and pages >= max_pages:
                    return PullResult(outcomes, None, True)
                page = self.relay.fetch_inbox(self.identity, since=self._cursor, limit=limit)
                pages += 1
                for entry in page.entries:
                    outcomes.extend(self._receive(entry.message, entry.stream_id)[1])
                if len(page.entries) < limit:
                    return PullResult(outcomes, None)
                if len(outcomes) >= 10_000:
                    return PullResult(outcomes, None, True)
            return PullResult(outcomes, None, True)
        except Exception as exc:
            return PullResult(outcomes, _error(exc))

    def follow(self, *, stop=None, on_live=None):
        backlog = self.pull(stop=stop)
        yield from backlog.outcomes
        if backlog.blocked:
            raise backlog.blocked
        for entry in self.relay.listen(
            self.identity, since=self._cursor, stop=stop, on_open=on_live
        ):
            yield from self._receive(entry.message, entry.stream_id)[1]

    def receive_direct(self, body):
        def fail(status, code, outcome=None):
            return DirectReply(status, {"ok": False, "error": code}, outcome)

        # Not accepting (08 § Receiver): not the request's fault, so the sender uses the relay.
        if self._closed:
            return fail(503, "internal_error")
        if len(body) > MAX_DIRECT_BODY_BYTES:
            return fail(413, "payload_too_large")
        try:
            wrapper = loads_json(body)
        except (ValueError, UnicodeError):
            return fail(400, "invalid_argument")
        if not isinstance(wrapper, dict) or "message" not in wrapper:
            return fail(400, "invalid_argument")
        try:
            raw = canonical_state_bytes(wrapper["message"])
            envelope = _decode(raw)
            accepted, outcomes = self._receive(raw, envelope=envelope)
            if not accepted:  # frame-level refusal; a rejected inner envelope is accepted (receipt)
                return fail(400, outcomes[0].error.code, outcomes[0])
            return DirectReply(
                200,
                {"ok": True, "messageId": envelope.message_id},
                outcomes[0] if outcomes else None,
            )
        except Exception as exc:
            if self._closed:
                return fail(503, "internal_error")  # closed meanwhile
            error = _error(exc)
            if error.category == "permanent":
                return fail(400, error.code)
            return fail(503, error.code, ReceiveOutcome("retryable", error=error))

    def close(self):
        if self._pid != os.getpid():
            raise ACEError("storage_failed", "inherited secure mailbox after fork")
        with self._lock:
            if self._closed:
                return
            self._closed = True
            with ExitStack() as stack:  # runs in reverse: transport, Inbox, dispose, lease
                stack.callback(self._lease.__exit__, None, None, None)
                if self.dispose is not None:
                    stack.callback(self.dispose)
                stack.callback(self.inbox.close)
                if self.close_transport:
                    stack.callback(self.secure.close)


class SecureRelayReplies:
    def __init__(self, identity, secure, relay, peer, send=None):
        """Replies are read after the receive cursor ``SecureMailbox`` persisted: every entry
        up to it already existed before this exchange sent anything, so none is its reply."""
        self.identity, self.secure, self.relay, self.peer = identity, secure, relay, peer
        self.send = send or relay.send
        try:
            self.cursor = _stored_cursor(secure.store, relay, identity)
        except ACEError:
            self.cursor = None  # an unreadable cursor only costs a full scan

    def exchange(self, packet, expected):
        remaining = expected["expiresAt"] - self.secure.clock()
        deadline = time.monotonic() + max(0, min(SECURE_DELIVERY_TTL_SECONDS, remaining))
        if time.monotonic() >= deadline:
            raise MLSError("delivery_expired")
        self.send(packet)
        while time.monotonic() < deadline:
            page = self.relay.fetch_inbox(self.identity, since=self.cursor)
            for entry in page.entries:
                self.cursor = entry.stream_id
                try:
                    candidate = _decode(entry.message)
                    if candidate.from_id != self.peer.ace_id:
                        continue
                    route = self.secure.route(candidate, self.peer)
                    if (
                        route["attempt"] == expected["attempt"]
                        and route["kind"] == expected["kind"]
                    ):
                        return candidate
                except (ACEError, MLSError):
                    continue
            if len(page.entries) < MAX_INBOX_PAGE:
                time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise MLSError("delivery_expired")


# --- integration glue: the composition every host needs once -----------------------------

_INBOX_KEYS = frozenset(inspect.signature(Inbox.open).parameters) - {
    "identity",
    "store",
    "peers",
}


def open_secure_mailbox(
    *, identity, store, peers, relay, engine, inbox: dict, clock=None
) -> SecureMailbox:
    """The recommended way to open the network receive boundary: ``Inbox.open`` with
    ``inbox`` (the remaining ``Inbox.open`` keyword arguments: ``on_message``, ``commerce``,
    ``principal``, ``schemas``, ``clock``, ...), ``SecureTransport(identity, engine, store,
    clock)``, then a ``SecureMailbox`` owning both (``close_transport=True``, ``dispose`` =
    the engine's ``close`` when it has one), so one ``close()`` releases the receive lock,
    the transport and the engine. A failure after the Inbox opened closes it (no leaked
    ``receive`` lock) before re-raising; the engine is then still the caller's to close."""
    if not isinstance(inbox, dict) or not set(inbox) <= _INBOX_KEYS or "on_message" not in inbox:
        raise ACEError(
            "invalid_argument",
            "inbox must be a dict of Inbox.open keyword arguments including on_message",
        )
    opened = Inbox.open(identity, store, peers, **inbox)
    try:
        secure = SecureTransport(identity, engine, store, clock)
        close = getattr(engine, "close", None)
        return SecureMailbox(
            identity, store, peers, relay, secure, opened,
            close_transport=True, dispose=close if callable(close) else None,
        )
    except BaseException:
        try:
            opened.close()
        except Exception:
            pass  # the open failure is the error to surface
        raise


def secure_transport_for(*, identity, secure, relay, peer, send=None):
    """The ``Outbox.deliver`` transport for ``peer``: every frame of the handshake goes out
    through ``send`` (default ``relay.send``; direct hosts pass
    ``deliver_direct_or_relay(relay, endpoint)``) and its signed reply is read back through
    the relay (``SecureRelayReplies``)."""
    replies = SecureRelayReplies(identity, secure, relay, peer, send)
    return lambda envelope: secure.deliver(envelope, peer, replies.exchange)


def deliver_secure(
    outbox, request_id: str, *, identity, secure, relay, peer, send=None
) -> None:
    """``outbox.deliver(request_id, secure_transport_for(...))``: returns once the peer's
    Inbox durably committed the envelope. On failure the operation stays pending under
    ``request_id``; retry that ID, never stage a new one."""
    outbox.deliver(
        request_id,
        secure_transport_for(identity=identity, secure=secure, relay=relay, peer=peer, send=send),
    )
