"""Outbox: stage / deliver / resign / abandon / pending."""

from __future__ import annotations

import json

import pytest

from ace import ACEError, Outbox, PendingSend, ThreadStore
from ace.outbox import _outbox_key
from ace.threads import thread_key

from .helpers import raises, wire
from .pipeline import Agent, Clock


@pytest.fixture
def pair():
    clock = Clock()
    alice, bob = Agent("alice", "ed25519", clock), Agent("bob", "secp256k1", clock)
    alice.pin(bob)
    bob.pin(alice)
    return clock, alice, bob


def test_stage_economic_persists_thread_and_pending(pair):
    clock, alice, bob = pair
    p = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="req-1"
    )
    assert isinstance(p, PendingSend) and p.status == "pending" and p.staged_at == clock.t
    rec = json.loads(alice.store.read(thread_key(p.message.conversation_id, "d")))
    assert rec["state"] == "rfq" and rec["pending"] == {
        "message": p.message.to_dict(),
        "requestId": "req-1",
        "stagedAt": clock.t,
        "status": "pending",
        "intentDigest": p.intent_digest,
        "type": p.type,
        "schemaDigest": p.schema_digest,
        "threadId": p.thread_id,
    }
    # same requestId: unchanged, no new message
    with raises("pending_send_conflict"):
        alice.outbox.stage(
            alice.peers.get(bob.id), "rfq", {"need": "other"}, thread_id="zzz", request_id="req-1"
        )
    again = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="req-1"
    )
    assert again == p
    alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "x"}, request_id="req-2")
    with raises("pending_send_conflict"):
        alice.outbox.stage(
            alice.peers.get(bob.id), "rfq", {"need": "y"}, thread_id="d", request_id="req-3"
        )
    assert [x.request_id for x in alice.outbox.pending()] == ["req-1", "req-2"]


def test_stage_validation(pair):
    clock, alice, bob = pair
    peer = alice.peers.get(bob.id)
    for rid in ("", "x" * 257, "a\nb", 5):
        with raises("invalid_argument"):
            alice.outbox.stage(peer, "text", {"message": "x"}, request_id=rid)
    with raises("invalid_argument"):
        alice.outbox.stage(peer, "rfq", {"need": "x"})  # economic without thread
    with raises("transition_not_allowed"):
        alice.outbox.stage(peer, "offer", {"price": "1", "currency": "USDC"}, thread_id="d")
    with raises("invalid_body"):
        alice.outbox.stage(peer, "rfq", {"need": 5}, thread_id="d")
    assert alice.outbox.pending() == [] and alice.store.list("") == [
        k for k in alice.store.list("peers/")
    ]


def test_stage_non_economic_file(pair):
    clock, alice, bob = pair
    p = alice.outbox.stage(alice.peers.get(bob.id), "info", {"message": "hello"}, request_id="i1")
    d = json.loads(alice.store.read(_outbox_key("i1")))
    assert d == {**p.to_dict(), "version": 1}
    assert alice.store.list("threads/") == []


def test_deliver_ack_and_failures(pair):
    clock, alice, bob = pair
    p = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="r"
    )
    n = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "hi"}, request_id="t")
    sent = []

    def flaky(env):
        raise ACEError("relay_unavailable", "down")

    for rid in ("r", "t"):
        with raises("relay_unavailable"):
            alice.outbox.deliver(rid, flaky)
    assert {x.request_id for x in alice.outbox.pending()} == {"r", "t"}

    def boom(env):
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        alice.outbox.deliver("r", boom)
    alice.outbox.deliver("r", sent.append)
    alice.outbox.deliver("t", sent.append)
    assert [e.message_id for e in sent] == [p.message.message_id, n.message.message_id]
    assert alice.outbox.pending() == [] and alice.store.list("outbox/") == []
    snap = ThreadStore(alice.store, alice.id).get(p.message.conversation_id, "d")
    assert snap.state == "rfq" and len(snap.history) == 1  # retry never advances twice
    with raises("invalid_argument"):
        alice.outbox.deliver("r", sent.append)


def test_expiry_resign_deliver(pair):
    clock, alice, bob = pair
    t0 = clock.t
    p = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="r"
    )
    with raises("invalid_argument"):
        alice.outbox.resign("r")  # only expired

    def expired(env):
        raise ACEError("envelope_expired", "stale", status=400, relay_code="envelope_expired")

    clock.t += 1000
    with raises("envelope_expired"):
        alice.outbox.deliver("r", expired)
    (pending,) = alice.outbox.pending()
    assert pending.status == "expired" and pending.message == p.message
    calls = []
    with raises("envelope_expired"):  # an expired send is refused before any transport call
        alice.outbox.deliver("r", calls.append)
    assert calls == []
    with raises("invalid_argument"):
        alice.outbox.deliver("r", None)  # type: ignore[arg-type]
    r = alice.outbox.resign("r")
    assert r.status == "pending" and r.message.message_id == p.message.message_id
    assert (
        r.message.timestamp == t0 + 1000 and r.message.signature.value != p.message.signature.value
    )
    assert r.staged_at == t0
    snap = ThreadStore(alice.store, alice.id).get(p.message.conversation_id, "d")
    assert snap.history[0].timestamp == t0 + 1000 and snap.state == "rfq"
    got = []
    alice.outbox.deliver("r", got.append)
    inbox = bob.open()
    out = inbox.receive(wire(got[0]))
    assert out.kind == "delivered" and out.message.timestamp == t0 + 1000


def test_resign_non_economic(pair):
    clock, alice, bob = pair
    alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "hi"}, request_id="t")
    with raises("envelope_expired"):
        alice.outbox.deliver("t", _raise_expired)
    clock.t += 50
    r = alice.outbox.resign("t")
    assert r.message.timestamp == clock.t
    assert json.loads(alice.store.read(_outbox_key("t")))["status"] == "pending"


def test_abandon(pair):
    clock, alice, bob = pair
    p = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="r"
    )
    alice.outbox.abandon("r")
    assert (
        alice.store.read(thread_key(p.message.conversation_id, "d")) is None
    )  # empty history: removed
    alice.outbox.abandon("r")  # no-op
    # a later head is dropped, earlier history kept
    first = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="r1"
    )
    alice.outbox.deliver("r1", lambda e: None)
    inbox = bob.open()
    inbox.receive(wire(first.message))
    offer = bob.outbox.stage(
        bob.peers.get(alice.id),
        "offer",
        {"price": "3", "currency": "USDC"},
        thread_id="d",
        request_id="o1",
    )
    bob.outbox.abandon("o1")
    snap = ThreadStore(bob.store, bob.id).get(offer.message.conversation_id, "d")
    assert snap.state == "rfq" and [h.type for h in snap.history] == ["rfq"]
    again = bob.outbox.stage(
        bob.peers.get(alice.id),
        "offer",
        {"price": "4", "currency": "USDC"},
        thread_id="d",
        request_id="o2",
    )
    assert again.message.message_id != offer.message.message_id
    n = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "x"}, request_id="t")
    alice.outbox.abandon("t")
    assert alice.store.read(_outbox_key("t")) is None and n is not None


def _raise_expired(env):
    raise ACEError("envelope_expired", "stale")


def test_thread_store_prunes_old_terminal_threads(pair):
    clock, alice, bob = pair
    peer = alice.peers.get(bob.id)
    p = alice.outbox.stage(peer, "rfq", {"need": "x"}, thread_id="old", request_id="a")
    alice.outbox.deliver("a", lambda e: None)
    inbox = bob.open()
    inbox.receive(wire(p.message))
    rej = bob.outbox.stage(
        bob.peers.get(alice.id), "reject", {"reason": "busy"}, thread_id="old", request_id="r"
    )
    bob.outbox.deliver("r", lambda e: None)
    store = ThreadStore(bob.store, bob.id, clock=clock)
    assert store.get(rej.message.conversation_id, "old").state == "rejected"
    clock.t += 30 * 86400 + 10
    keep = bob.outbox.stage(
        bob.peers.get(alice.id), "rfq", {"need": "new"}, thread_id="new", request_id="n"
    )
    assert [s.thread_id for s in store.list()] == ["new"]
    assert store.remove(keep.message.conversation_id, "new") and store.list() == []


def test_completed_operation_survives_restart(pair):
    clock, alice, bob = pair
    peer = alice.peers.get(bob.id)
    p = alice.outbox.stage(peer, "text", {"message": "same operation"}, request_id="stable")
    rx = bob.open()
    assert (
        alice.outbox.deliver(
            "stable", lambda env: rx.receive(wire(env))
        ).kind
        == "delivered"
    )
    restarted = Outbox.open(alice.identity, alice.store, clock=clock)
    assert (
        restarted.stage(peer, "text", {"message": "same operation"}, request_id="stable").message
        == p.message
    )
    assert (
        restarted.deliver("stable", lambda env: rx.receive(wire(env))).kind
        == "duplicate"
    )
    with raises("pending_send_conflict"):
        restarted.stage(peer, "text", {"message": "different"}, request_id="stable")
    rx.close()
