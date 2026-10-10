"""Authenticated one-use MLS delivery around the original Inbox/Outbox envelope.

No static-message fallback. Each peer must be enabled by a local administrator.
The exchange callback must enforce its own network timeout and return one ACE reply.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
import time
from typing import Callable

from ._encoding import (
    MAX_SAFE_INTEGER,
    canonical_state_bytes,
    decode_b64,
    is_ace_id,
    is_message_id,
    is_sha256_hex,
    loads_json,
    unix_now,
    wire_int,
)
from .discovery import VerifiedPeer
from .envelope import decode_envelope, envelope_fingerprint, revalidate, verify_envelope_signature
from .errors import ACEError
from .limits import (
    MLS_MAX_KEY_PACKAGE_CHARS,
    MLS_MAX_MESSAGE_CHARS,
    MLS_MAX_PLAINTEXT_BYTES,
    OFFLINE_WINDOW_SECONDS,
    SECURE_DELIVERY_TTL_SECONDS,
)
from .messages import create_message, parse_message
from .replay import ReplayDetector
from .session import MLSEngine, MLSError, PairwiseMLS
from .store import ACEStore, load_record, write_record
from .threads import sha256_hex
from .types import ACEIdentity, ACEMessage

SECURE_DELIVERY_TYPE = "urn:ace:secure-delivery:2"
SECURE_DELIVERY_SCHEMA = hashlib.sha256(
    b"ace.secure-delivery.v2:hello,offer,data,ack;fresh-pairwise-mls;exact-envelope;"
    b"outcome-receipt;120s"
).hexdigest()

#: What ``SecureTransport.respond``'s ``accept`` callback returns once the inner envelope went
#: through the Inbox: ``"delivered"``, ``"duplicate"`` or ``"rejected:<code>"`` (``<code>`` the
#: Inbox's permanent error code). The same string is the receiver's journal ``outcome`` and the
#: tail of the receipt the sender verifies. ``accept`` raises only for retryable/local failures.
DeliveryOutcome = str
_OUTCOME = re.compile(r"delivered|duplicate|rejected:([a-z0-9_]{1,64})")
_MAX_INBOUND_ROWS = 1024
_SWEEP_SECONDS = 30


def _peer_key(peer: str) -> str:
    return f"secure/peers/{sha256_hex(peer)}.json"


def _peer_lock(peer: str) -> str:
    return f"secure-peer-{sha256_hex(peer)[:48]}"


def _matches(a: dict, b: dict) -> bool:
    return all(a[k] == b[k] for k in ("attempt", "expiresAt", "messageId", "digest"))


def _proof(f: dict, outcome: str = "") -> bytes:
    """The receipt plaintext; without ``outcome``, its prefix up to and including the last colon."""
    return (
        f"ace.delivery.outcome.v1:{f['attempt']}:{f['nonce']}:{f['messageId']}:{f['digest']}:"
        f"{outcome}"
    ).encode()


def _is_policy_row(row: object, peer: str) -> bool:
    return (
        isinstance(row, dict)
        and set(row) == {"version", "peer", "allowed", "generation"}
        and wire_int(row.get("version")) == 1
        and row.get("peer") == peer
        and type(row.get("allowed")) is bool
    )


def _policy_generation(store: ACEStore, peer: str) -> int | None:
    """The admission generation when ``peer`` is enabled; None for a missing, malformed or
    disabled row (never raises for a row)."""
    try:
        row = load_record(store, _peer_key(peer)) if is_ace_id(peer) else None
    except ACEError:
        return None
    if not _is_policy_row(row, peer) or row["allowed"] is not True:
        return None
    generation = wire_int(row.get("generation"))
    if generation is None or generation < 1:
        return None
    return generation


def _plain(event: dict) -> bytes:
    if event.get("kind") != "application":
        raise MLSError("invalid_session_event")
    return decode_b64(
        event.get("plaintext"), "invalid_body", "MLS plaintext", max_bytes=MLS_MAX_PLAINTEXT_BYTES
    )


def _inner_envelope(raw: bytes) -> ACEMessage:
    try:
        return decode_envelope(loads_json(raw))
    except (ValueError, UnicodeError) as exc:
        raise ACEError("invalid_envelope", "invalid UTF-8 or JSON envelope") from exc


class SecureTransport:
    def __init__(
        self,
        identity: ACEIdentity,
        engine: MLSEngine,
        store: ACEStore,
        clock: Callable[[], int] | None = None,
    ):
        self.identity, self.engine, self.store = identity, engine, store
        self.clock = clock or (lambda: unix_now(None))
        self._sessions: dict[str, dict] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._pid = os.getpid()
        self._outgoing_lock = threading.Lock()
        self._outgoing = 0
        self._next_sweep = 0

    @staticmethod
    def set_peer_allowed(store: ACEStore, peer: str, allowed: bool) -> None:
        """Local administrative operation. Never invoke from discovery or a remote message."""
        if not is_ace_id(peer) or type(allowed) is not bool:
            raise MLSError("invalid_session_input")
        with store.lock(_peer_lock(peer)):
            old = load_record(store, _peer_key(peer))
            if old is not None and not _is_policy_row(old, peer):
                raise MLSError("invalid_delivery_policy")
            generation = 0 if old is None else wire_int(old.get("generation"))
            if (
                generation is None
                or (old is not None and generation < 1)
                or generation >= MAX_SAFE_INTEGER
            ):
                raise MLSError("session_limit")
            write_record(
                store,
                _peer_key(peer),
                {"peer": peer, "generation": generation + 1, "allowed": allowed},
            )

    @staticmethod
    def is_peer_allowed(store: ACEStore, peer: str) -> bool:
        """Whether local policy admits ``peer`` (13 § Local admission). A missing or malformed
        row is False; nothing is resolved or pinned. Read it before any peer resolution."""
        return _policy_generation(store, peer) is not None

    def _allowed(self, peer: str) -> int:
        if self._closed or self._pid != os.getpid():
            raise MLSError("session_closed")
        generation = _policy_generation(self.store, peer)
        if generation is None:
            raise MLSError("delivery_peer_disabled")
        return generation

    def _packet(self, peer: VerifiedPeer, frame: dict) -> ACEMessage:
        return create_message(
            self.identity,
            peer,
            SECURE_DELIVERY_TYPE,
            frame,
            timestamp=self.clock(),
            schema_digest=SECURE_DELIVERY_SCHEMA,
        )

    def _read(self, packet: ACEMessage, peer: VerifiedPeer) -> dict:
        self._allowed(peer.ace_id)
        parsed = parse_message(
            packet, self.identity, peer, replay=ReplayDetector(clock=self.clock), clock=self.clock
        )
        if (
            parsed.type != SECURE_DELIVERY_TYPE
            or parsed.schema_digest != SECURE_DELIVERY_SCHEMA
            or parsed.thread_id is not None
        ):
            raise MLSError("secure_delivery_required")
        f = parsed.body
        extra = {
            "hello": [],
            "offer": ["nonce", "keyPackage"],
            "data": ["nonce", "welcome", "ciphertext"],
            "ack": ["nonce", "ciphertext"],
        }
        if not isinstance(f.get("kind"), str) or f["kind"] not in extra:
            raise MLSError("invalid_delivery_frame")
        if (
            set(f) != {"kind", "attempt", "expiresAt", "messageId", "digest", *extra[f["kind"]]}
            or not is_sha256_hex(f.get("attempt"))
            or not is_sha256_hex(f.get("digest"))
            or not is_message_id(f.get("messageId"))
            or wire_int(f.get("expiresAt")) is None
        ):
            raise MLSError("invalid_delivery_frame")
        if f["kind"] != "hello" and not is_sha256_hex(f.get("nonce")):
            raise MLSError("invalid_delivery_frame")
        for field in ("keyPackage", "welcome", "ciphertext"):
            limit = MLS_MAX_KEY_PACKAGE_CHARS if field == "keyPackage" else MLS_MAX_MESSAGE_CHARS
            if field in f and (not isinstance(f[field], str) or len(f[field]) > limit):
                raise MLSError("invalid_delivery_frame")
        now = self.clock()
        if not now < f["expiresAt"] <= min(now, parsed.timestamp) + SECURE_DELIVERY_TTL_SECONDS:
            raise MLSError("delivery_expired")
        return f

    def pending_handshakes(self) -> bool:
        """Whether an offer this transport issued still awaits its data frame."""
        with self._lock:
            now = self.clock()
            return any(s["hello"]["expiresAt"] > now for s in self._sessions.values())

    def route(self, packet: ACEMessage, peer: VerifiedPeer) -> dict:
        """Return routing metadata only after ACE authentication and expiry checks."""
        frame = self._read(packet, peer)
        return {key: frame[key] for key in ("attempt", "kind", "expiresAt")}

    def deliver(self, envelope, peer, exchange) -> None:
        if self._pid != os.getpid() or self._closed:
            raise MLSError("session_closed")
        with self._outgoing_lock:
            if self._outgoing >= 32:
                raise MLSError("session_limit")
            self._outgoing += 1
        try:
            self._deliver(envelope, peer, exchange)
        finally:
            with self._outgoing_lock:
                self._outgoing -= 1

    def _deliver(
        self,
        envelope: ACEMessage,
        peer: VerifiedPeer,
        exchange: Callable[[ACEMessage, dict], ACEMessage],
    ) -> None:
        """Use as Outbox.deliver transport. Uncertain delivery throws, retaining the original ID."""
        inner = revalidate(envelope)
        if inner.from_id != self.identity.get_ace_id() or inner.to_id != peer.ace_id:
            raise MLSError("invalid_delivery_frame")
        verify_envelope_signature(
            inner,
            scheme=self.identity.get_signing_scheme(),
            signing_public_key=self.identity.get_signing_public_key(),
        )
        if inner.timestamp < self.clock() - OFFLINE_WINDOW_SECONDS:
            raise ACEError(
                "envelope_expired", "original application envelope exceeds offline retention"
            )
        raw = canonical_state_bytes(inner.to_dict())
        if len(raw) > MLS_MAX_PLAINTEXT_BYTES:
            raise MLSError("session_limit")

        def request(packet, route):
            try:
                return exchange(packet, route)
            except ACEError as exc:
                if exc.code == "envelope_expired":
                    raise MLSError("delivery_expired") from exc
                raise

        generation = self._allowed(peer.ace_id)
        deadline = time.monotonic() + SECURE_DELIVERY_TTL_SECONDS
        hello = {
            "kind": "hello",
            "attempt": secrets.token_hex(32),
            "expiresAt": self.clock() + SECURE_DELIVERY_TTL_SECONDS,
            "messageId": inner.message_id,
            "digest": envelope_fingerprint(inner),
        }
        offer = self._read(
            request(
                self._packet(peer, hello),
                {"attempt": hello["attempt"], "kind": "offer", "expiresAt": hello["expiresAt"]},
            ),
            peer,
        )
        if time.monotonic() >= deadline:
            raise MLSError("delivery_expired")
        if offer["kind"] != "offer" or not _matches(hello, offer):
            raise MLSError("invalid_delivery_frame")
        session = PairwiseMLS(self.engine, self.store, inner.from_id, inner.to_id)
        try:
            welcome = session.create(offer["keyPackage"])["message"]
            cipher = session.send(raw)["message"]
            data = {
                **hello,
                "kind": "data",
                "nonce": offer["nonce"],
                "welcome": welcome,
                "ciphertext": cipher,
            }
            packet = self._packet(peer, data)
            if self._allowed(peer.ace_id) != generation:
                raise MLSError("delivery_peer_disabled")
            if self.clock() >= hello["expiresAt"]:
                raise MLSError("delivery_expired")
            ack = self._read(
                request(
                    packet,
                    {"attempt": hello["attempt"], "kind": "ack", "expiresAt": hello["expiresAt"]},
                ),
                peer,
            )
            if ack["kind"] != "ack" or not _matches(hello, ack) or ack["nonce"] != offer["nonce"]:
                raise MLSError("invalid_delivery_frame")
            receipt, prefix = _plain(session.receive(ack["ciphertext"])), _proof(data)
            try:
                outcome = _OUTCOME.fullmatch(receipt[len(prefix) :].decode("utf-8"))
            except UnicodeDecodeError:
                outcome = None
            if not receipt.startswith(prefix) or outcome is None:
                raise MLSError("invalid_delivery_receipt")
            if self._allowed(peer.ace_id) != generation:
                raise MLSError("delivery_peer_disabled")
            if outcome.group(1) is not None:  # authenticated, permanent: the host decides
                raise ACEError(
                    "delivery_rejected",
                    f"the receiver's Inbox rejected the envelope: {outcome.group(1)}",
                    remote_code=outcome.group(1),
                )
        finally:
            session.close()
        if self.clock() >= hello["expiresAt"] or time.monotonic() >= deadline:
            raise MLSError("delivery_expired")

    def respond(
        self, packet: ACEMessage, peer: VerifiedPeer, accept: Callable[[bytes], DeliveryOutcome]
    ) -> ACEMessage:
        """``accept(envelope_bytes)`` must run the original Inbox and durably commit before
        returning its :data:`DeliveryOutcome`; the outcome is released in the receipt, which is
        encrypted while the attempt's MLS context is still alive. ``accept`` raises only for
        retryable/local failures: then no receipt is produced, the context is destroyed, the
        journal row keeps ``outcome`` null and any replay of that attempt is
        ``session_closed``; the sender's attempt expires and its fresh attempt is deduplicated
        by the Inbox. A completed attempt re-sends its receipt on replay."""
        if self._pid != os.getpid():
            raise MLSError("session_closed")
        return self._respond(self._read(packet, peer), peer, accept)

    def _respond(
        self, f: dict, peer: VerifiedPeer, accept: Callable[[bytes], DeliveryOutcome]
    ) -> ACEMessage:
        """``respond`` for a frame ``_read`` already authenticated from ``peer``."""
        if self._pid != os.getpid():
            raise MLSError("session_closed")
        with self._lock:
            if f["kind"] not in ("hello", "data"):
                raise MLSError("invalid_delivery_frame")
            with self.store.lock(_peer_lock(peer.ace_id)):
                generation = self._allowed(peer.ace_id)
                self._sweep_sessions()
                key = f"secure/in/{f['attempt']}.json"
                if f["kind"] == "hello":
                    active = self._sessions.get(f["attempt"])
                    if active:
                        if (
                            active["peer"] != peer.ace_id
                            or active["generation"] != generation
                            or not _matches(active["hello"], f)
                        ):
                            raise MLSError("invalid_delivery_frame")
                        return active["response"]
                    if self._live_journal_row(key) is not None:
                        raise MLSError("session_closed")
                    if len(self._sessions) >= 32 or self._journal_full():
                        raise MLSError("session_limit")
                    session = PairwiseMLS(
                        self.engine, self.store, self.identity.get_ace_id(), peer.ace_id
                    )
                    try:
                        offer = {
                            **f,
                            "kind": "offer",
                            "nonce": secrets.token_hex(32),
                            "keyPackage": session.state["keyPackage"],
                        }
                        response = self._packet(peer, offer)
                        write_record(
                            self.store,
                            key,
                            {
                                "peer": peer.ace_id,
                                "expiresAt": f["expiresAt"],
                                "generation": generation,
                                "response": response.to_dict(),
                            },
                        )
                        self._sessions[f["attempt"]] = {
                            "peer": peer.ace_id,
                            "hello": f,
                            "offer": offer,
                            "response": response,
                            "session": session,
                            "generation": generation,
                        }
                        return response
                    except BaseException:
                        session.close()
                        raise
                input_hash = hashlib.sha256(canonical_state_bytes(f)).hexdigest()
                received = self._live_journal_row(key)
                if received is None:
                    raise MLSError("session_closed")
                if "input" in received:
                    if (
                        received["peer"] != peer.ace_id
                        or received.get("generation") != generation
                        or received["input"] != input_hash
                    ):
                        raise MLSError("invalid_delivery_frame")
                    if "outcome" not in received or (
                        received["outcome"] is not None
                        and not (
                            isinstance(received["outcome"], str)
                            and _OUTCOME.fullmatch(received["outcome"])
                        )
                    ):
                        raise MLSError("invalid_delivery_journal")
                else:
                    active = self._sessions.get(f["attempt"])
                    if (
                        not active
                        or active["peer"] != peer.ace_id
                        or active["generation"] != generation
                        or not _matches(active["hello"], f)
                        or active["offer"]["nonce"] != f["nonce"]
                    ):
                        raise MLSError("session_closed")
                    session = active["session"]
                    try:
                        session.join(f["welcome"])
                        envelope = _inner_envelope(_plain(session.receive(f["ciphertext"])))
                        if (
                            envelope.from_id != peer.ace_id
                            or envelope.to_id != self.identity.get_ace_id()
                            or envelope.message_id != f["messageId"]
                            or envelope_fingerprint(envelope) != f["digest"]
                        ):
                            raise MLSError("invalid_delivery_frame")
                        received = {
                            "expiresAt": f["expiresAt"],
                            "generation": generation,
                            "peer": peer.ace_id,
                            "input": input_hash,
                            "envelope": envelope.to_dict(),
                            "response": None,
                            "outcome": None,
                        }
                        write_record(self.store, key, received)
                        # the handover runs while the context is alive: the receipt carries
                        # the Inbox outcome; a failure here destroys the context (no receipt)
                        outcome = accept(canonical_state_bytes(received["envelope"]))
                        if not isinstance(outcome, str) or not _OUTCOME.fullmatch(outcome):
                            raise MLSError("invalid_delivery_outcome")
                        cipher = session.send(_proof(f, outcome))["message"]
                        response = self._packet(
                            peer,
                            {
                                **{
                                    k: f[k]
                                    for k in (
                                        "attempt",
                                        "expiresAt",
                                        "messageId",
                                        "digest",
                                        "nonce",
                                    )
                                },
                                "kind": "ack",
                                "ciphertext": cipher,
                            },
                        )
                        received.update(outcome=outcome, envelope=None, response=response.to_dict())
                        write_record(self.store, key, received)
                    finally:
                        del self._sessions[f["attempt"]]
                        session.close()
                if received["outcome"] is None:  # decrypted, never receipted: a dead attempt
                    raise MLSError("session_closed")
                if self.clock() >= f["expiresAt"]:
                    raise MLSError("delivery_expired")
                self._allowed(peer.ace_id)
                return decode_envelope(received["response"])

    def _live_journal_row(self, key: str) -> dict | None:
        """The attempt's journal row, or None when missing or expired (an expired row is
        deleted here)."""
        row = load_record(self.store, key)
        if row is not None and row["expiresAt"] <= self.clock():
            self.store.delete(key)
            return None
        return row

    def _journal_full(self) -> bool:
        """Whether the receiver journal holds its bound of live rows. Expired rows are swept
        during receive activity: when the bound is reached, and at most every 30 seconds."""
        keys = self.store.list("secure/in/")
        now = self.clock()
        if len(keys) < _MAX_INBOUND_ROWS and now < self._next_sweep:
            return False
        self._next_sweep = now + _SWEEP_SECONDS
        live = sum(self._live_journal_row(key) is not None for key in keys)
        return live >= _MAX_INBOUND_ROWS

    def _sweep_sessions(self) -> None:
        for key, value in list(self._sessions.items()):
            if value["hello"]["expiresAt"] <= self.clock():
                del self._sessions[key]
                value["session"].close()

    def close(self) -> None:
        if self._pid != os.getpid():
            return
        self._closed = True
        with self._lock:
            errors = []
            for active in self._sessions.values():
                try:
                    active["session"].close()
                except Exception as error:
                    errors.append(error)
            self._sessions.clear()
            if errors:
                raise errors[0]
