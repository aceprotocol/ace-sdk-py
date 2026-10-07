"""Inbox: commit order, recovery, crash injection, quarantine, cursor rules."""

from __future__ import annotations

import json
import uuid

import pytest

import ace.inbox as inbox_mod
from ace import (
    ACEError,
    FileStore,
    Inbox,
    MemoryStore,
    PeerStore,
    ReceiveSource,
    RelayClient,
    ReplayDetector,
    ThreadStateMachine,
    ThreadStore,
    create_message,
    envelope_fingerprint,
)
from ace.inbox import delivery_key
from ace.threads import thread_index_key, thread_key

from .helpers import raises, wire
from .pipeline import Agent, Clock, CountingStore, clone_memory

RELAY = "https://Relay.Example/"
SRC = "https://relay.example"
SRC_RELAY = RelayClient(RELAY)  # base_url == SRC


def relay_src(n: int) -> ReceiveSource:
    return ReceiveSource.relay(RELAY, f"{n}-0")


@pytest.fixture
def pair():
    clock = Clock()
    alice, bob = Agent("alice", "ed25519", clock), Agent("bob", "secp256k1", clock)
    alice.pin(bob)
    bob.pin(alice)
    return clock, alice, bob


def rfq(alice, bob, thread_id="deal-1", ts=None):
    return alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "translate"}, thread_id=thread_id
    ).message


def test_receive_source():
    s = ReceiveSource.relay("HTTPS://Relay.Example/", "1-2")
    assert s.relay_url == SRC and s.stream_id == "1-2" and s.kind == "relay"
    with raises("invalid_argument"):
        ReceiveSource.relay(SRC, "abc")
    with raises("invalid_argument"):
        ReceiveSource("direct", SRC)
    with raises("invalid_argument"):
        Inbox()


def test_open_creates_replay_and_lock(pair):
    clock, alice, bob = pair
    inbox = bob.open(offline_window_seconds=1000)
    state = json.loads(bob.store.read("replay.json"))
    assert state == {"entries": [], "horizon": clock.t - 1001, "senderHorizons": {}, "version": 1}
    with raises("receiver_busy"):
        bob.open()
    inbox.close()
    inbox.close()
    bob.open().close()


def test_replay_missing_beside_history(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    inbox.receive(wire(rfq(alice, bob)), relay_src(1))
    inbox.close()
    bob.store.delete("replay.json")
    with raises("storage_failed"):
        bob.open()
    bob.store.write("replay.json", b'{"version":2}')
    with raises("storage_failed"):
        bob.open()


def test_delivered_commit_order_and_formats(pair):
    clock, alice, bob = pair
    env = rfq(alice, bob)
    counting = CountingStore(bob.store)
    inbox = bob.open(store=counting)
    assert counting.writes == ["replay.json"]
    counting.writes.clear()
    out = inbox.receive(wire(env), relay_src(7))
    assert out.kind == "delivered" and out.message.body == {"need": "translate"}
    dkey = delivery_key(alice.id, env.message_id)
    tkey = thread_key(env.conversation_id, "deal-1")
    # a new open thread is indexed before its record is written
    assert counting.writes == [
        dkey,
        thread_index_key(alice.id),
        tkey,
        "replay.json",
        dkey,
        "cursors.json",
    ]
    assert bob.host.calls == [(alice.id, env.message_id)]
    assert inbox.cursor(SRC_RELAY) == "7-0"
    rec = json.loads(bob.store.read(dkey))
    assert set(rec) == {
        "fingerprint",
        "message",
        "receivedAt",
        "source",
        "status",
        "thread",
        "version",
    }
    assert (
        rec["status"] == "acked"
        and rec["source"] == "relay"
        and rec["fingerprint"] == envelope_fingerprint(env)
    )
    assert set(rec["message"]) == {
        "body",
        "conversationId",
        "from",
        "messageId",
        "threadId",
        "timestamp",
        "to",
        "type",
    }
    assert rec["thread"]["state"] == "rfq"
    assert json.loads(bob.store.read("cursors.json")) == {"cursors": {SRC: "7-0"}, "version": 1}
    thread = json.loads(bob.store.read(tkey))
    assert thread["pending"] is None and thread["version"] == 1 and thread["peerAceId"] == alice.id
    raw = bob.store.read(tkey)
    assert (
        raw
        == json.dumps(thread, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )
    # duplicate: nothing written, cursor still advances (monotonic)
    counting.writes.clear()
    assert inbox.receive(wire(env), relay_src(9)).kind == "duplicate"
    assert counting.writes == ["cursors.json"] and inbox.cursor(SRC_RELAY) == "9-0"
    assert inbox.receive(wire(env), relay_src(8)).kind == "duplicate"
    assert inbox.cursor(SRC_RELAY) == "9-0"
    assert ThreadStore(bob.store, bob.id).get(env.conversation_id, "deal-1").state == "rfq"
    assert bob.host.calls == [(alice.id, env.message_id)]


def test_non_economic_and_direct(pair):
    clock, alice, bob = pair
    p = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "hi"})
    inbox = bob.open()
    out = inbox.receive(wire(p.message), ReceiveSource.direct())
    assert out.kind == "delivered" and out.message.thread_id is None
    rec = json.loads(bob.store.read(delivery_key(alice.id, p.message.message_id)))
    assert rec["thread"] is None and rec["source"] == "direct"
    assert bob.store.list("cursors.json") == []
    # direct freshness window
    clock.t += 301
    p2 = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "late"})
    clock.t += 301
    out = inbox.receive(wire(p2.message), ReceiveSource.direct())
    assert out.kind == "quarantined" and out.error.code == "stale_timestamp" and out.fingerprint
    assert bob.store.list("quarantine/") == []
    # the same message via the relay is still fine (offline window)
    assert inbox.receive(wire(p2.message), relay_src(1)).kind == "delivered"


def test_decode_failure_and_unknown_peer_quarantine(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    out = inbox.receive(wire({"ace": "1.0"}), relay_src(1))
    assert (
        out.kind == "quarantined"
        and out.fingerprint is None
        and out.error.code == "invalid_envelope"
    )
    assert inbox.cursor(SRC_RELAY) == "1-0" and bob.store.list("quarantine/") == []
    stranger = Agent("eve", "ed25519", clock)
    stranger.pin(bob)
    env = stranger.outbox.stage(stranger.peers.get(bob.id), "text", {"message": "x"}).message
    out = inbox.receive(wire(env), relay_src(2))
    assert out.kind == "quarantined" and out.error.code == "unknown_peer"
    q = json.loads(bob.store.read(f"quarantine/{out.fingerprint}.json"))
    assert q["code"] == "unknown_peer" and q["source"] == "relay" and q["envelope"] == env.to_dict()
    assert set(q) == {
        "code",
        "envelope",
        "fingerprint",
        "quarantinedAt",
        "reason",
        "source",
        "version",
    }
    assert inbox.receive(wire(env), ReceiveSource.direct()).kind == "quarantined"
    assert len(bob.store.list("quarantine/")) == 1


def test_wrong_role_quarantined_and_one_shot(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    env = rfq(alice, bob)
    assert inbox.receive(wire(env), relay_src(1)).kind == "delivered"
    # alice (the buyer) forges a seller move with a machine where bob is the buyer
    snap = ThreadStore(bob.store, bob.id).get(env.conversation_id, "deal-1")
    from ace import ThreadHistoryEntry, ThreadSnapshot

    fake = ThreadSnapshot(
        env.conversation_id,
        "deal-1",
        alice.id,
        bob.id,
        "rfq",
        (ThreadHistoryEntry("rfq", snap.history[0].message_id, snap.history[0].timestamp, bob.id),),
    )
    machine = ThreadStateMachine.from_state([fake], alice.id)
    offer = create_message(
        alice.identity,
        alice.peers.get(bob.id),
        "offer",
        {"price": "1", "currency": "USDC"},
        machine,
        thread_id="deal-1",
        timestamp=clock.t,
    )
    out = inbox.receive(wire(offer), relay_src(2))
    assert out.kind == "quarantined" and out.error.code == "wrong_role"
    assert bob.store.read(f"quarantine/{out.fingerprint}.json") is not None
    assert inbox.cursor(SRC_RELAY) == "2-0"
    assert inbox.receive(wire(offer), relay_src(3)).kind == "duplicate"  # replay persisted
    inbox.close()
    inbox = bob.open()
    assert inbox.receive(wire(offer), relay_src(4)).kind == "duplicate"
    assert ThreadStore(bob.store, bob.id).get(env.conversation_id, "deal-1").state == "rfq"
    assert bob.host.calls == [(alice.id, env.message_id)]


def test_quarantine_cap(pair, monkeypatch):
    clock, alice, bob = pair
    monkeypatch.setattr(inbox_mod, "QUARANTINE_CAP", 5)
    monkeypatch.setattr(inbox_mod, "QUARANTINE_KEEP", 3)
    inbox = bob.open()
    fps = []
    for i in range(6):
        clock.t += 1
        eve = Agent(f"eve{i}", "ed25519", clock)
        eve.pin(bob)
        out = inbox.receive(
            wire(eve.outbox.stage(eve.peers.get(bob.id), "text", {"message": "x"}).message),
            relay_src(i + 1),
        )
        fps.append(out.fingerprint)
    assert sorted(bob.store.list("quarantine/")) == sorted(
        f"quarantine/{fp}.json" for fp in fps[3:]
    )


def test_quarantine_count_is_listed_once(pair):
    clock, alice, bob = pair
    inner = MemoryStore()
    lists = [0]

    class Counting(CountingStore):
        def list(self, prefix):
            if prefix == "quarantine/":
                lists[0] += 1
            return self.inner.list(prefix)

    store = Counting(inner)
    inbox = Inbox.open(bob.identity, store, PeerStore(store, clock=clock), bob.host, clock=clock)
    PeerStore(store, clock=clock).pin_registration_file(alice.registration(), pinned_at=0)
    env = rfq(alice, bob).to_dict()
    for n in range(inbox_mod.QUARANTINE_CAP + 1):
        # a fresh messageId under the old signature: invalid_signature, a new fingerprint
        forged = {**env, "messageId": f"00000000-0000-4000-8000-{n:012d}"}
        out = inbox.receive(wire(forged), relay_src(n + 1))
        assert out.kind == "quarantined" and out.error.code == "invalid_signature"
    assert len(inner.list("quarantine/")) == inbox_mod.QUARANTINE_KEEP
    assert lists[0] <= 2  # the first insert and the trim
    inbox.close()


def test_retryable_peer_error_does_not_advance_cursor(pair):
    clock, alice, bob = pair

    class Down:
        def lookup_peer(self, ace_id):
            raise ACEError("relay_unavailable", "down")

    store = MemoryStore()
    inbox = Inbox.open(
        bob.identity, store, PeerStore(store, relay=Down(), clock=clock), bob.host, clock=clock
    )
    out = inbox.receive(wire(rfq(alice, bob)), relay_src(5))
    assert out.kind == "retryable" and out.error.code == "relay_unavailable"
    assert inbox.cursor(SRC_RELAY) is None and store.list("deliveries/") == []


def test_handler_failure_then_redelivery(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    env = rfq(alice, bob)
    bob.host.fail = True
    out = inbox.receive(wire(env), relay_src(1))
    assert (
        out.kind == "retryable"
        and out.error.code == "handler_failed"
        and inbox.cursor(SRC_RELAY) is None
    )
    bob.host.fail = False
    out = inbox.receive(wire(env), relay_src(1))
    assert out.kind == "delivered" and inbox.cursor(SRC_RELAY) == "1-0"
    assert bob.host.calls == [(alice.id, env.message_id)]


def test_recovery_hands_over_pending(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    env = rfq(alice, bob)
    bob.host.fail = True
    inbox.receive(wire(env), relay_src(1))
    inbox.close()
    with raises("handler_failed"):
        bob.open()  # still failing: open reports it, the record stays pending
    bob.host.fail = False
    inbox = bob.open()
    assert bob.host.calls == [(alice.id, env.message_id)]
    rec = json.loads(bob.store.read(delivery_key(alice.id, env.message_id)))
    assert rec["status"] == "acked"
    assert inbox.receive(wire(env), relay_src(1)).kind == "duplicate"


def test_recovery_divergent_thread(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    env = rfq(alice, bob)
    inbox.receive(wire(env), relay_src(1))
    inbox.close()
    # replace bob's thread with a different history
    tkey = thread_key(env.conversation_id, "deal-1")
    rec = json.loads(bob.store.read(tkey))
    rec["history"][0]["messageId"] = str(uuid.uuid4())
    bob.store.write(tkey, json.dumps(rec).encode())
    with raises("storage_failed"):
        bob.open()


def test_sweep_removes_covered_acked(pair, monkeypatch):
    import ace.inbox as inbox_mod

    monkeypatch.setattr(inbox_mod, "_SWEEP_EVERY", 4)  # sweep automatically on the 4th delivery
    clock, alice, bob = pair
    inbox = bob.open(offline_window_seconds=1000)
    envs = [rfq(alice, bob, thread_id=f"t{i}") for i in range(3)]
    for i, e in enumerate(envs):
        assert inbox.receive(wire(e), relay_src(i + 1)).kind == "delivered"
    assert len(bob.store.list("deliveries/")) == 3
    clock.t += 2000
    late = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "later"}).message
    assert (
        inbox.receive(wire(late), relay_src(10)).kind == "delivered"
    )  # floor raises H, then sweeps
    assert bob.store.list("deliveries/") == [delivery_key(alice.id, late.message_id)]
    for e in envs:  # still rejected: now below the acceptance floor
        out = inbox.receive(wire(e), relay_src(11))
        assert out.kind == "quarantined" and out.error.code == "stale_timestamp"
    assert bob.host.calls == [(alice.id, e.message_id) for e in envs] + [
        (alice.id, late.message_id)
    ]


def test_inbound_clears_proven_pending(pair):
    clock, alice, bob = pair
    a_inbox = alice.open()
    b_inbox = bob.open()
    sent = alice.outbox.stage(
        alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="d", request_id="r1"
    )
    assert b_inbox.receive(wire(sent.message), relay_src(1)).kind == "delivered"
    # alice never saw an ack (uncertain network); bob's offer proves delivery
    offer = bob.outbox.stage(
        bob.peers.get(alice.id), "offer", {"price": "5", "currency": "USDC"}, thread_id="d"
    )
    assert [p.request_id for p in alice.outbox.pending()] == ["r1"]
    assert a_inbox.receive(wire(offer.message), relay_src(1)).kind == "delivered"
    assert alice.outbox.pending() == []
    assert (
        ThreadStore(alice.store, alice.id).get(sent.message.conversation_id, "d").state == "offered"
    )


# --- crash injection ------------------------------------------------------------------------------


def _scenario(clock):
    """bob (buyer) has a pending rfq; alice's offer arrives.

    Returns (bob, offer_env, base_store).
    """
    alice, bob = Agent("alice", "ed25519", clock), Agent("bob", "secp256k1", clock)
    alice.pin(bob)
    bob.pin(alice)
    a_inbox = alice.open()
    sent = bob.outbox.stage(
        bob.peers.get(alice.id), "rfq", {"need": "x"}, thread_id="d", request_id="r1"
    )
    a_inbox.receive(wire(sent.message), relay_src(1))
    offer = alice.outbox.stage(
        alice.peers.get(bob.id), "offer", {"price": "5", "currency": "USDC"}, thread_id="d"
    ).message
    bob.open().close()  # creates replay.json
    return bob, offer


COMMIT_STEPS = 5  # delivery, thread, replay, ack, cursor


@pytest.mark.parametrize("fail_at", range(1, COMMIT_STEPS + 1))
@pytest.mark.parametrize("backend", ["memory", "file"])
def test_crash_injection(fail_at, backend, tmp_path):
    clock = Clock()
    bob, offer = _scenario(clock)
    if backend == "file":
        fs = FileStore(tmp_path / "bob")
        for k in bob.store.list(""):
            fs.write(k, bob.store.read(k))
        base = fs
    else:
        base = clone_memory(bob.store)
    conv = offer.conversation_id
    failing = CountingStore(base, fail_at=fail_at)
    inbox = bob.open(store=failing)
    out = inbox.receive(wire(offer), relay_src(3))
    assert out.kind == "retryable" and out.error.code == "storage_failed"
    if fail_at > 1:  # after the commit point the instance refuses further work until reopened
        later = inbox.receive(wire(offer), relay_src(3))
        assert later.kind == "retryable" and "failed state" in later.error.message
    inbox.close()  # the process "dies"; nothing else is written

    threads = ThreadStore(base, bob.id)
    if fail_at > 2:  # thread written: never rolled back afterwards
        assert threads.get(conv, "d").state == "offered"

    inbox = bob.open(store=base)  # recovery
    snap = threads.get(conv, "d")
    if fail_at > 1:
        assert snap.state == "offered" and [h.type for h in snap.history] == ["rfq", "offer"]
        assert threads._load(conv, "d").pending is None  # delivery proven by the offer
    out = inbox.receive(wire(offer), relay_src(3))  # the relay redelivers (cursor not advanced)
    assert out.kind == ("delivered" if fail_at == 1 else "duplicate")
    assert inbox.cursor(SRC_RELAY) == "3-0"
    assert threads.get(conv, "d").state == "offered"
    assert list(bob.host.effects) == [
        (offer.from_id, offer.message_id)
    ]  # nothing lost, no duplicate effect
    # on_message itself runs twice only if the crash hit the ack write after the handover
    assert len(bob.host.calls) == (2 if fail_at == 4 else 1)
    replay = ReplayDetector.from_state(json.loads(base.read("replay.json")), capacity=100000)
    assert not replay.accepts(offer.message_id, offer.from_id, offer.timestamp)
    inbox.close()
    inbox = bob.open(store=base)
    assert inbox.receive(wire(offer), relay_src(4)).kind == "duplicate"
    assert len(bob.host.calls) == (2 if fail_at == 4 else 1)


def test_crash_during_quarantine_write(pair):
    clock, alice, bob = pair
    eve = Agent("eve", "ed25519", clock)
    eve.pin(bob)
    env = eve.outbox.stage(eve.peers.get(bob.id), "text", {"message": "x"}).message
    bob.open().close()
    inbox = bob.open(store=CountingStore(bob.store, fail_at=1))
    out = inbox.receive(wire(env), relay_src(1))
    assert out.kind == "retryable" and out.error.code == "storage_failed"
    assert inbox.cursor(SRC_RELAY) is None and bob.store.list("quarantine/") == []


# --- lead amendments ------------------------------------------------------------------------------


def test_handler_can_stage_reply_on_same_thread(pair):
    clock, alice, bob = pair
    replies = []

    def on_message(m):
        if m.type == "rfq":  # the threads lock is released before the handover
            replies.append(
                bob.outbox.stage(
                    bob.peers.get(alice.id),
                    "offer",
                    {"price": "2", "currency": "USDC"},
                    thread_id=m.thread_id,
                    request_id=f"offer:{m.message_id}",
                )
            )

    bob.host = on_message
    inbox = bob.open()
    env = rfq(alice, bob)
    assert inbox.receive(wire(env), relay_src(1)).kind == "delivered"
    assert len(replies) == 1
    assert ThreadStore(bob.store, bob.id).get(env.conversation_id, "deal-1").state == "offered"


def test_failed_state_keeps_threads_lock_until_close(pair):
    clock, alice, bob = pair
    bob.open().close()
    inbox = bob.open(store=CountingStore(bob.store, fail_at=3))  # replay write fails
    assert inbox.receive(wire(rfq(alice, bob)), relay_src(1)).kind == "retryable"
    with raises("lock_busy"):
        bob.store.lock("threads", timeout=0)
    with raises("lock_busy"):
        bob.outbox.stage(
            bob.peers.get(alice.id), "text", {"message": "x"}
        )  # stage takes `threads` too
    inbox.close()
    with bob.store.lock("threads", timeout=0):
        pass


def test_outbox_open_repairs_thread_after_crash(pair):
    clock, alice, bob = pair
    from ace import Outbox

    sent = bob.outbox.stage(
        bob.peers.get(alice.id), "rfq", {"need": "x"}, thread_id="d", request_id="r1"
    )
    alice.open().receive(wire(sent.message), relay_src(1))
    offer = alice.outbox.stage(
        alice.peers.get(bob.id), "offer", {"price": "5", "currency": "USDC"}, thread_id="d"
    ).message
    bob.open().close()
    inbox = bob.open(
        store=CountingStore(bob.store, fail_at=2)
    )  # delivery written, thread write fails
    assert inbox.receive(wire(offer), relay_src(2)).kind == "retryable"
    inbox.close()
    outbox = Outbox.open(
        bob.identity, bob.store, clock=clock
    )  # repairs the thread from deliveries/
    snap = ThreadStore(bob.store, bob.id).get(offer.conversation_id, "d")
    assert snap.state == "offered" and outbox.pending() == []  # delivery proven: pending cleared
    outbox.stage(
        bob.peers.get(alice.id),
        "accept",
        {"offerId": offer.message_id},
        thread_id="d",
        request_id="a1",
    )
    inbox = bob.open()  # no divergence: the delivery snapshot is a prefix of the stored history
    assert bob.host.calls == [(alice.id, offer.message_id)]
    assert ThreadStore(bob.store, bob.id).get(offer.conversation_id, "d").state == "accepted"
    assert inbox.receive(wire(offer), relay_src(2)).kind == "duplicate"
    with raises("invalid_argument"):
        Outbox(bob.identity, bob.store)


def test_recovery_order_repairs_first_then_hands_over(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    first = rfq(alice, bob, thread_id="a")
    clock.t += 1
    second = rfq(alice, bob, thread_id="b")
    bob.host.fail = True
    for i, e in enumerate((second, first)):
        assert inbox.receive(wire(e), relay_src(i + 1)).kind == "retryable"
    inbox.close()
    seen = []

    def flaky(m):
        replay = json.loads(bob.store.read("replay.json"))
        seen.append((m.message_id, len(replay["entries"])))
        if m.message_id == second.message_id:
            raise RuntimeError("still down")

    bob.host = flaky
    with raises("handler_failed"):
        bob.open()
    assert seen == [(first.message_id, 2), (second.message_id, 2)]  # (timestamp, key) order
    assert json.loads(bob.store.read(delivery_key(alice.id, first.message_id)))["status"] == "acked"
    assert (
        json.loads(bob.store.read(delivery_key(alice.id, second.message_id)))["status"] == "pending"
    )


# --- raw bytes, direct replies, peer resolution failures ------------------------------------------


def test_receive_takes_raw_bytes(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    for raw in (
        b"{bad",
        b"\xff",
        b"NaN",
        b'{"x": NaN}',
        b"[" * 5000,
        b" " * (inbox_mod.MAX_ENVELOPE_BYTES + 1),
    ):
        out = inbox.receive(raw, relay_src(1))
        assert (
            out.kind == "quarantined"
            and out.error.code == "invalid_envelope"
            and out.fingerprint is None
        )
    assert bob.store.list("quarantine/") == []  # nothing to store without an envelope
    assert inbox.cursor(SRC_RELAY) == "1-0"  # a poison frame still advances the cursor
    env = rfq(alice, bob)
    assert inbox.receive(bytearray(wire(env)), relay_src(2)).kind == "delivered"
    for bad_message in (env, env.to_dict(), "text"):
        with raises("invalid_argument"):
            inbox.receive(bad_message, relay_src(3))  # type: ignore[arg-type]
    with raises("invalid_argument"):
        inbox.receive(wire(env), "direct")  # type: ignore[arg-type]
    inbox.close()
    with raises("invalid_argument"):
        inbox.receive(wire(env), relay_src(3))


def _direct_body(env) -> bytes:
    return json.dumps({"message": env.to_dict(), "extra": 1}).encode()


def test_receive_direct_replies(pair):
    clock, alice, bob = pair
    inbox = bob.open()
    env = rfq(alice, bob)
    reply = inbox.receive_direct(_direct_body(env))
    assert (reply.status, reply.body) == (200, {"ok": True, "messageId": env.message_id})
    assert reply.outcome.kind == "delivered"
    reply = inbox.receive_direct(_direct_body(env))
    assert (reply.status, reply.body, reply.outcome.kind) == (
        200,
        {"ok": True, "messageId": env.message_id},
        "duplicate",
    )
    old = rfq(alice, bob, thread_id="late")
    clock.t += 1000  # direct deliveries must be fresh
    late = inbox.receive_direct(_direct_body(old))
    clock.t -= 1000
    assert (late.status, late.body) == (400, {"ok": False, "error": "stale_timestamp"})
    assert late.outcome.kind == "quarantined" and bob.store.list("quarantine/") == []
    bob.host.fail = True
    busy = inbox.receive_direct(_direct_body(rfq(alice, bob, thread_id="busy")))
    assert (busy.status, busy.body) == (503, {"ok": False, "error": "handler_failed"})
    assert busy.outcome.kind == "retryable"
    with raises("invalid_argument"):
        inbox.receive_direct("{}")  # type: ignore[arg-type]
    inbox.close()
    closed = inbox.receive_direct(_direct_body(env))
    assert (closed.status, closed.body, closed.outcome) == (  # not accepting: use the relay
        503,
        {"ok": False, "error": "internal_error"},
        None,
    )
    assert inbox.receive_direct(b"x" * (inbox_mod.MAX_DIRECT_BODY_BYTES + 1)).status == 503


def test_receive_direct_unexpected_failure(pair, monkeypatch):
    clock, alice, bob = pair
    inbox = bob.open()

    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(inbox, "_receive", boom)
    reply = inbox.receive_direct(_direct_body(rfq(alice, bob)))
    assert (reply.status, reply.body) == (503, {"ok": False, "error": "internal_error"})


def test_peer_resolution_non_ace_error_is_retryable(pair, monkeypatch):
    clock, alice, bob = pair
    inbox = bob.open()

    def broken(*a, **k):
        raise KeyError("custom relay bug")

    monkeypatch.setattr(inbox._peers, "resolve", broken)
    out = inbox.receive(wire(rfq(alice, bob)), relay_src(1))
    assert out.kind == "retryable" and out.error.code == "relay_unavailable"
    assert inbox.cursor(SRC_RELAY) is None


def test_outbox_open_skips_acked_covered_deliveries(pair):
    clock, alice, bob = pair
    from ace import Outbox

    inbox = bob.open(offline_window_seconds=1000)
    env = rfq(alice, bob)
    assert inbox.receive(wire(env), relay_src(1)).kind == "delivered"
    key = delivery_key(alice.id, env.message_id)
    inbox.close()
    # a thread pruned after its delivery record was acked and covered: never resurrected
    ThreadStore(bob.store, bob.id).remove(env.conversation_id, "deal-1")
    record = json.loads(bob.store.read(key))
    record.update(status="acked")
    bob.store.write(key, json.dumps(record).encode())
    state = json.loads(bob.store.read("replay.json"))
    state.update(entries=[], horizon=env.timestamp)
    bob.store.write("replay.json", json.dumps(state).encode())
    Outbox.open(bob.identity, bob.store, clock=clock)
    assert ThreadStore(bob.store, bob.id).get(env.conversation_id, "deal-1") is None
    # not covered: repaired
    state.update(horizon=env.timestamp - 1)
    bob.store.write("replay.json", json.dumps(state).encode())
    Outbox.open(bob.identity, bob.store, clock=clock)
    assert ThreadStore(bob.store, bob.id).get(env.conversation_id, "deal-1") is not None


def test_follow_quarantines_poison_frames(relay):
    clock = Clock()
    clock.t = int(__import__("time").time())
    bob = Agent("bob", "ed25519", clock)
    client = RelayClient(relay.url)
    client.register(bob.identity)
    relay.raw_responses["/v1/listen"] = (
        200,
        b"id: 5-0\nevent: message\ndata: not json\n\n",
        "text/event-stream",
    )
    inbox = bob.open()
    gen = inbox.follow(client)
    out = next(gen)
    gen.close()
    assert out.kind == "quarantined" and out.error.code == "invalid_envelope"
    assert inbox.cursor(client) == "5-0"
