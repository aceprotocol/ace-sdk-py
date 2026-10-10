"""The integration glue every host needs once: inbox_principal_from_own_record,
open_secure_mailbox, deliver_secure / secure_transport_for, and the public store validators."""

import hashlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from ace import (
    InboxPrincipal,
    PrincipalKey,
    PrincipalSigner,
    RelayClient,
    SecureTransport,
    SoftwareIdentity,
    check_key,
    check_lock_name,
    create_principal_record,
    deliver_secure,
    inbox_principal_from_own_record,
    open_secure_mailbox,
    secure_transport_for,
)
from ace.session import MLSError, NativeMLSEngine

from .fake_relay import FakeRelay
from .helpers import raises
from .pipeline import Agent, Clock

ACC = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
NOW = 1_800_000_000

native = pytest.mark.skipif(
    not os.getenv("ACE_MLS_LIBRARY"), reason="explicit native integration job"
)


class StubEngine:
    """An engine that is never reached by these tests (no handshake completes)."""

    def __init__(self):
        self.closed = 0

    def execute(self, command):
        raise AssertionError("engine must not run")

    def close(self):
        self.closed += 1


class StubRelay:
    """Records ``send`` / ``fetch_inbox`` calls; ``send`` raises ``send_error`` when given."""

    base_url = "https://relay.example"

    def __init__(self, send_error=None):
        self.sent, self.fetches, self.send_error = [], 0, send_error

    def send(self, packet):
        self.sent.append(packet)
        if self.send_error is not None:
            raise self.send_error

    def fetch_inbox(self, *a, **kw):
        self.fetches += 1
        raise AssertionError("fetch_inbox must not run")


def own_record(owner, me, *, roles, issued_at, expires_at):
    return create_principal_record(
        PrincipalSigner.from_identity(owner),
        subject_signing_public_key=me.get_signing_public_key(),
        account=ACC,
        roles=roles,
        issued_at=issued_at,
        expires_at=expires_at,
    )


# --- inbox_principal_from_own_record -----------------------------------------------------


def test_no_record_is_no_principal_without_a_warning():
    me = SoftwareIdentity.generate("ed25519")
    assert inbox_principal_from_own_record(None, me) == (None, None)


def test_valid_own_record_binds_account_with_record_signer_and_given_trusted_signers():
    owner, me = SoftwareIdentity.generate("secp256k1"), SoftwareIdentity.generate("ed25519")
    record = own_record(
        owner, me, roles=["controller", "delegate"], issued_at=NOW - 10, expires_at=NOW + 3600
    )
    other = PrincipalKey("ed25519", "x")
    assert inbox_principal_from_own_record(record, me, now=NOW) == (
        InboxPrincipal(ACC, record.signer, ()),
        None,
    )
    principal, warning = inbox_principal_from_own_record(
        record, me, now=NOW, trusted_signers=[other]
    )
    assert warning is None and principal.trusted_signers == (other,)
    # The wire shape Inbox.open(principal=...) reads; a dict record is accepted too.
    assert principal.to_dict() == {
        "account": ACC,
        "selfSigner": {"scheme": record.signer.scheme, "publicKey": record.signer.public_key},
        "trustedSigners": [{"scheme": "ed25519", "publicKey": "x"}],
    }
    assert inbox_principal_from_own_record(record.to_dict(), me, now=NOW)[0] == InboxPrincipal(
        ACC, record.signer
    )


def test_expired_or_foreign_record_is_no_principal_with_a_code_detail_warning_and_never_raises():
    owner, me = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    someone = SoftwareIdentity.generate("ed25519")
    expired = own_record(owner, me, roles=["delegate"], issued_at=NOW - 100, expires_at=NOW - 50)
    principal, warning = inbox_principal_from_own_record(expired, me, now=NOW)
    assert principal is None and re.match(r"^invalid_principal: .*expired", warning)
    principal, warning = inbox_principal_from_own_record(expired, someone, now=NOW - 75)
    assert principal is None and warning.startswith("invalid_principal: ")
    # The wall clock is the default: the expired record is expired now too.
    assert inbox_principal_from_own_record(expired, me)[1].startswith("invalid_principal: ")
    # A malformed record is a warning, not an exception.
    assert inbox_principal_from_own_record({"nope": 1}, me)[1].startswith("invalid_principal: ")


# --- open_secure_mailbox -------------------------------------------------------------------


def test_one_close_releases_the_receive_lock_and_disposes_the_engine():
    clock, a = Clock(NOW), Agent("a", "ed25519", Clock(NOW))
    relay, engine = StubRelay(), StubEngine()
    mailbox = open_secure_mailbox(
        identity=a.identity, store=a.store, peers=a.peers, relay=relay, engine=engine,
        clock=clock, inbox={"commerce": True, "on_message": a.host, "clock": clock},
    )
    assert mailbox.secure.engine is engine and mailbox.secure.clock is clock
    with raises("receiver_busy"), a.store.lock("receive", 0):
        pass
    with raises("lock_busy"), a.store.lock("secure-mailbox", 0):
        pass
    assert engine.closed == 0
    mailbox.close()
    assert engine.closed == 1
    mailbox.close()  # idempotent: the engine is not disposed twice
    assert engine.closed == 1
    with a.store.lock("receive", 0), a.store.lock("secure-mailbox", 0):
        pass
    with raises("invalid_argument"):  # the inbox options are validated before anything opens
        open_secure_mailbox(
            identity=a.identity, store=a.store, peers=a.peers, relay=relay, engine=engine,
            inbox={"commerce": True},
        )
    with a.store.lock("receive", 0):
        pass


def test_failure_after_inbox_opened_closes_it_and_leaves_the_engine_to_the_caller():
    a, relay, engine = Agent("a", "ed25519", Clock(NOW)), StubRelay(), StubEngine()
    # SecureMailbox refuses a corrupt persisted cursor: the failure comes after Inbox.open
    # took ``receive``.
    key = f"secure/cursors/{hashlib.sha256(relay.base_url.encode()).hexdigest()}.json"
    a.store.write(key, json.dumps({"version": 1, "identity": a.id, "cursor": "nope"}).encode())
    with raises("storage_failed"):
        open_secure_mailbox(
            identity=a.identity, store=a.store, peers=a.peers, relay=relay, engine=engine,
            inbox={"on_message": a.host},
        )
    assert engine.closed == 0
    with a.store.lock("receive", 0), a.store.lock("secure-mailbox", 0):
        pass


# --- deliver_secure / secure_transport_for ---------------------------------------------------


def staged():
    clock = Clock(NOW)
    a, b = Agent("a", "ed25519", clock), Agent("b", "secp256k1", clock)
    peer = a.pin(b)
    SecureTransport.set_peer_allowed(a.store, b.id, True)
    secure = SecureTransport(a.identity, StubEngine(), a.store, clock)
    pending = a.outbox.stage(peer, "text", {"message": "hi"})
    return a, b, peer, secure, pending


def test_sends_every_handshake_frame_through_the_given_send_not_the_relay():
    a, b, peer, secure, pending = staged()
    relay, sent = StubRelay(), []

    def send(packet):
        sent.append(packet)
        raise RuntimeError("frame transport stopped")

    with pytest.raises(RuntimeError, match="frame transport stopped"):
        deliver_secure(
            a.outbox, pending.request_id,
            identity=a.identity, secure=secure, relay=relay, peer=peer, send=send,
        )
    assert len(sent) == 1 and (sent[0].from_id, sent[0].to_id) == (a.id, b.id)
    assert sent[0].message_id != pending.message.message_id  # a frame, not the application envelope
    assert relay.sent == [] and relay.fetches == 0
    # The operation stays pending under its request_id.
    assert [p.request_id for p in a.outbox.pending()] == [pending.request_id]
    secure.close()


def test_defaults_to_relay_send_and_resolves_only_through_outbox_deliver():
    a, b, peer, secure, pending = staged()
    relay = StubRelay(send_error=RuntimeError("relay stopped"))
    transport = secure_transport_for(identity=a.identity, secure=secure, relay=relay, peer=peer)
    with pytest.raises(RuntimeError, match="relay stopped"):
        transport(pending.message)
    assert len(relay.sent) == 1 and (relay.sent[0].from_id, relay.sent[0].to_id) == (a.id, b.id)
    with raises("invalid_argument"):
        deliver_secure(a.outbox, "", identity=a.identity, secure=secure, relay=relay, peer=peer)
    assert len(relay.sent) == 1  # refused before any transport call
    secure.close()


# --- public store-key validators ------------------------------------------------------------


def test_check_key_and_check_lock_name_are_the_store_contract():
    assert check_key("secure/in/a.json") == "secure/in/a.json"
    assert check_lock_name("receive") == "receive"
    for bad in ("", "/x", "A", "a//b", "a/", "a" * 201, None):
        with raises("invalid_argument") as info:
            check_key(bad)
        assert "invalid store key" in info.value.message
    for bad in ("", "a/b", "A", "a" * 65, None):
        with raises("invalid_argument") as info:
            check_lock_name(bad)
        assert "invalid lock name" in info.value.message


# --- end to end over the native engine ------------------------------------------------------


@native
def test_helpers_end_to_end_over_a_relay():
    clock, stop = Clock(int(time.time())), threading.Event()
    server = FakeRelay(clock)
    engine = NativeMLSEngine(os.environ["ACE_MLS_LIBRARY"])
    try:
        ra, rb = RelayClient(server.url, clock=clock), RelayClient(server.url, clock=clock)
        a, b = Agent("a", "ed25519", clock, relay=ra), Agent("b", "secp256k1", clock, relay=rb)
        ra.register(a.identity)
        rb.register(b.identity)
        a.pin(b)
        b.pin(a)
        SecureTransport.set_peer_allowed(a.store, b.id, True)
        SecureTransport.set_peer_allowed(b.store, a.id, True)
        owner = SoftwareIdentity.generate("secp256k1")
        record = own_record(
            owner, b.identity, roles=["delegate"], issued_at=clock.t - 10, expires_at=clock.t + 3600
        )
        principal, warning = inbox_principal_from_own_record(record, b.identity, now=clock.t)
        assert warning is None
        mailbox = open_secure_mailbox(
            identity=b.identity, store=b.store, peers=b.peers, relay=rb, engine=engine, clock=clock,
            inbox={"on_message": b.host, "commerce": True, "principal": principal, "clock": clock},
        )
        sender = SecureTransport(a.identity, engine, a.store, clock)
        pending = a.outbox.stage(a.peers.get(b.id), "text", {"message": "hello"})

        def follow():
            for outcome in mailbox.follow(stop=stop):
                assert outcome.kind == "delivered", outcome

        with ThreadPoolExecutor(max_workers=1) as pool:
            listener = pool.submit(follow)
            try:
                deliver_secure(
                    a.outbox, pending.request_id,
                    identity=a.identity, secure=sender, relay=ra, peer=a.peers.get(b.id),
                )
            finally:
                stop.set()
                listener.result(timeout=5)
        assert len(b.host.calls) == 1 and not a.outbox.pending()
        # One engine shared by a sender and the mailbox: close the sender first; the mailbox
        # then closes the engine.
        sender.close()
        mailbox.close()
        with pytest.raises(MLSError) as info:
            engine.execute(b"{}")
        assert info.value.code == "engine_closed"
    finally:
        engine.close()
        server.close()
