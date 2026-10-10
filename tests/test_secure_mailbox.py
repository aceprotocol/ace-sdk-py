"""SecureMailbox: the only network receive boundary (pull, follow, receive_direct, cursor)."""

import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from ace import (
    ACEError,
    FileStore,
    RelayClient,
    SecureMailbox,
    SecureRelayReplies,
    SecureTransport,
    create_message,
)
from ace._encoding import canonical_state_bytes
from ace.limits import MAX_DIRECT_BODY_BYTES
from ace.session import NativeMLSEngine

from .fake_relay import FakeRelay
from .helpers import raises
from .pipeline import Agent, Clock

native = pytest.mark.skipif(
    not os.getenv("ACE_MLS_LIBRARY"), reason="explicit native integration job"
)


def cursor_key(client: RelayClient) -> str:
    return f"secure/cursors/{hashlib.sha256(client.base_url.encode()).hexdigest()}.json"


@pytest.fixture
def world(tmp_path):
    """alice posts static (pre-MLS) packets; bob's mailbox refuses them without an engine."""
    clock = Clock(1_800_000_000)
    relay = FakeRelay(clock=clock)
    client = RelayClient(relay.url, clock=clock)
    alice = Agent("alice", "ed25519", clock, relay=client)
    bob = Agent("bob", "secp256k1", clock, store=FileStore(tmp_path / "bob"), relay=client)
    assert client.register(alice.identity) == "registered"
    assert client.register(bob.identity) == "registered"
    SecureTransport.set_peer_allowed(bob.store, alice.id, True)
    mailbox = SecureMailbox(
        bob.identity,
        bob.store,
        bob.peers,
        client,
        SecureTransport(bob.identity, None, bob.store, clock),
        bob.open(),
    )
    yield clock, relay, client, alice, bob, mailbox
    mailbox.close()
    relay.close()


def post_static(alice: Agent, client: RelayClient, bob: Agent, text: str):
    p = alice.outbox.stage(alice.peers.resolve(bob.id), "text", {"message": text})
    client.send(p.message)
    return p.message


def test_pull_refuses_static_packets_and_bounds_pages(world):
    clock, relay, client, alice, bob, mailbox = world
    for i in range(6):
        post_static(alice, client, bob, f"m{i}")
    for bad in ({"max_pages": 0}, {"max_pages": True}, {"limit": 0}, {"limit": 101}):
        r = mailbox.pull(**bad)
        assert (r.blocked.code, r.outcomes, r.has_more) == ("invalid_argument", [], False)
    first = mailbox.pull(limit=3, max_pages=1)
    assert (first.quarantined, first.blocked, first.has_more) == (3, None, True)
    assert {o.error.code for o in first.outcomes} == {"invalid_body"}  # no downgrade fallback
    assert {o.error.message for o in first.outcomes} == {"secure_delivery_required"}
    assert all(o.fingerprint for o in first.outcomes) and first.messages == []
    stop = threading.Event()
    stop.set()
    stopped = mailbox.pull(stop=stop)
    assert (stopped.outcomes, stopped.blocked, stopped.has_more) == ([], None, True)
    rest = mailbox.pull(limit=3)
    assert (rest.quarantined, rest.delivered, rest.blocked, rest.has_more) == (3, 0, None, False)
    assert mailbox.pull().outcomes == []
    assert bob.host.calls == [] and bob.store.list("quarantine/") == []
    last = relay.streams[bob.id][-1][0]
    assert mailbox.cursor(client) == last
    assert mailbox.cursor(RelayClient("https://other.example")) is None  # keyed by relay
    assert json.loads(bob.store.read(cursor_key(client))) == {
        "cursor": last,
        "identity": bob.id,
        "version": 1,
    }
    assert bob.store.list("cursors.json") == []


def test_follow_yields_initial_pull_then_live_with_on_live(world):
    clock, relay, client, alice, bob, mailbox = world
    for m in ("q0", "q1"):
        post_static(alice, client, bob, m)
    stop = threading.Event()
    events: list[str] = []
    errors: list[BaseException] = []

    def on_live():
        events.append("live")
        if events.count("live") == 1:
            post_static(alice, client, bob, "live")

    def run():
        try:
            for o in mailbox.follow(stop=stop, on_live=on_live):
                events.append(o.kind)
                seen = events.count("quarantined")
                if seen == 3:
                    relay.drain_after = 0  # the next event drains the stream: a reconnect
                    post_static(alice, client, bob, "after")
                if seen == 4:
                    stop.set()
        except BaseException as exc:  # surfaced below
            errors.append(exc)

    th = threading.Thread(target=run)
    th.start()
    th.join(10)
    stop.set()
    assert not th.is_alive() and errors == []
    assert events == ["quarantined"] * 2 + ["live", "quarantined", "live", "quarantined"]
    assert mailbox.cursor(client) == relay.streams[bob.id][-1][0]


def test_follow_raises_failed_initial_pull_without_on_live(world):
    clock, relay, client, alice, bob, mailbox = world
    relay.inject.append(("/v1/inbox", 503, "down", {}))
    live = []
    with raises("relay_unavailable"):
        for _ in mailbox.follow(on_live=lambda: live.append(1)):
            pass
    assert live == []


def test_pull_refuses_unadmitted_sender_before_resolution(world):
    clock, relay, client, alice, bob, mailbox = world
    SecureTransport.set_peer_allowed(bob.store, alice.id, False)
    post_static(alice, client, bob, "stranger")
    relay.inject.append(("/v1/peer", 503, "down", {}))  # would block the drain if resolved
    result = mailbox.pull()
    assert (result.quarantined, result.blocked) == (1, None)
    assert result.outcomes[0].error.message == "delivery_peer_disabled"
    assert relay.inject and bob.store.list("peers/") == []  # never resolved, never pinned
    assert mailbox.cursor(client) is not None


def test_transient_failure_blocks_pull_without_advancing_cursor(world):
    clock, relay, client, alice, bob, mailbox = world
    post_static(alice, client, bob, "1")
    relay.inject.append(("/v1/peer", 503, "down", {}))  # alice is not pinned: resolution fails
    result = mailbox.pull()
    assert result.blocked.code == "relay_unavailable" and result.outcomes == []
    assert mailbox.cursor(client) is None and bob.store.read(cursor_key(client)) is None
    assert mailbox.pull().quarantined == 1 and mailbox.cursor(client) is not None
    relay.inject.append(("/v1/inbox", 503, "down", {}))
    assert mailbox.pull().blocked.code == "relay_unavailable"


def test_follow_quarantines_poison_frames(relay):
    clock = Clock(int(time.time()))
    bob = Agent("bob", "ed25519", clock)
    client = RelayClient(relay.url)
    client.register(bob.identity)
    relay.raw_responses["/v1/listen"] = (
        200,
        b"id: 5-0\nevent: message\ndata: not json\n\n",
        "text/event-stream",
    )
    mailbox = SecureMailbox(
        bob.identity,
        bob.store,
        bob.peers,
        client,
        SecureTransport(bob.identity, None, bob.store, clock),
        bob.open(),
    )
    try:
        gen = mailbox.follow()
        out = next(gen)
        gen.close()
        assert out.kind == "quarantined" and out.error.code == "invalid_envelope"
        assert out.fingerprint is None and mailbox.cursor(client) == "5-0"
    finally:
        mailbox.close()


def test_receive_direct_contract(world):
    clock, relay, client, alice, bob, mailbox = world

    def body(env) -> bytes:
        return json.dumps({"message": env.to_dict(), "extra": 1}).encode()

    assert mailbox.receive_direct(b"x" * (MAX_DIRECT_BODY_BYTES + 1)).status == 413
    assert mailbox.receive_direct(b"\xff").body == {"ok": False, "error": "invalid_argument"}
    assert mailbox.receive_direct(b'{"msg":{}}').status == 400
    static = alice.outbox.stage(alice.peers.resolve(bob.id), "text", {"message": "x"}).message
    reply = mailbox.receive_direct(body(static))  # a static packet is refused, never delivered
    assert (reply.status, reply.body) == (400, {"ok": False, "error": "invalid_body"})
    assert reply.outcome.kind == "quarantined" and reply.outcome.fingerprint
    eve = Agent("eve", "ed25519", clock)
    eve.pin(bob)
    assert client.register(eve.identity) == "registered"  # resolvable, but not admitted
    stranger = eve.outbox.stage(eve.peers.get(bob.id), "text", {"message": "x"}).message
    resolves = []
    original = bob.peers.resolve
    mailbox.peers.resolve = lambda *a, **k: (resolves.append(a), original(*a, **k))[1]
    lookups, pins = relay.requests.count(("GET", "/v1/peer")), bob.store.list("peers/")
    refused = mailbox.receive_direct(body(stranger))
    assert refused.body == {"ok": False, "error": "invalid_body"}
    assert refused.outcome.error.message == "delivery_peer_disabled" and refused.outcome.fingerprint
    # admission is checked before any peer resolution: no lookup, no pin of the stranger
    assert resolves == [] and relay.requests.count(("GET", "/v1/peer")) == lookups
    assert bob.peers.get(eve.id) is None and bob.store.list("peers/") == pins
    assert bob.host.calls == [] and mailbox.cursor(client) is None
    mailbox.close()
    closed = mailbox.receive_direct(body(static))  # not accepting: the sender uses the relay
    assert closed.status == 503 and closed.outcome is None
    assert closed.body["error"] == "internal_error"
    # 08 § Receiver: "not accepting" is the first row, before the size check
    assert mailbox.receive_direct(b"x" * (MAX_DIRECT_BODY_BYTES + 1)).status == 503


@native
def test_bidirectional_secure_relay_and_static_downgrade():
    clock = Clock(int(time.time()))
    server = FakeRelay(clock)
    stop = threading.Event()
    with NativeMLSEngine(os.environ["ACE_MLS_LIBRARY"]) as engine:
        ra, rb = RelayClient(server.url, clock=clock), RelayClient(server.url, clock=clock)
        a = Agent("a", "ed25519", clock, relay=ra)
        b = Agent("b", "secp256k1", clock, relay=rb)
        ra.register(a.identity)
        rb.register(b.identity)
        a.pin(b)
        b.pin(a)
        ta = SecureTransport(a.identity, engine, a.store, clock)
        tb = SecureTransport(b.identity, engine, b.store, clock)
        SecureTransport.set_peer_allowed(a.store, b.id, True)
        SecureTransport.set_peer_allowed(b.store, a.id, True)
        ma = SecureMailbox(a.identity, a.store, a.peers, ra, ta, a.open())
        mb = SecureMailbox(b.identity, b.store, b.peers, rb, tb, b.open())
        pa, pb = b.peers.get(a.id), a.peers.get(b.id)
        one = a.outbox.stage(pb, "text", {"message": "A"})
        two = b.outbox.stage(pa, "text", {"message": "B"})
        da, db = (
            SecureRelayReplies(a.identity, ta, ra, pb),
            SecureRelayReplies(b.identity, tb, rb, pa),
        )

        def follow(mailbox):
            for outcome in mailbox.follow(stop=stop):
                assert outcome.kind in ("delivered", "duplicate")

        try:
            assert mb.receive_direct(b"\xff").status == 400
            assert mb.receive_direct(b"{bad").status == 400
            reply = mb.receive_direct(canonical_state_bytes({"message": one.message.to_dict()}))
            assert reply.status == 400
            assert not b.host.calls
            with ThreadPoolExecutor(max_workers=4) as pool:
                listeners = [pool.submit(follow, mailbox) for mailbox in (ma, mb)]
                sends = [
                    pool.submit(
                        a.outbox.deliver, one.request_id, lambda p: ta.deliver(p, pb, da.exchange)
                    ),
                    pool.submit(
                        b.outbox.deliver, two.request_id, lambda p: tb.deliver(p, pa, db.exchange)
                    ),
                ]
                try:
                    for send in sends:
                        send.result(timeout=10)
                finally:
                    stop.set()
                    for listener in listeners:
                        listener.result(timeout=5)
            assert len(a.host.calls) == len(b.host.calls) == 1
            assert not a.outbox.pending() and not b.outbox.pending()
            assert len(server.stored) == 8
            # direct path: frames POSTed to b's endpoint, replies read back through the relay
            three = a.outbox.stage(pb, "text", {"message": "C"})
            replies = []

            def send_direct(packet):
                reply = mb.receive_direct(canonical_state_bytes({"message": packet.to_dict()}))
                replies.append(reply)
                if reply.status != 200:
                    raise ACEError("direct_unavailable", f"HTTP {reply.status} {reply.body}")
                assert reply.body == {"ok": True, "messageId": packet.message_id}

            dc = SecureRelayReplies(a.identity, ta, ra, pb, send=send_direct)
            b.host.fail = True  # the host is down: 503, the operation stays pending
            with raises("direct_unavailable"):
                a.outbox.deliver(three.request_id, lambda p: ta.deliver(p, pb, dc.exchange))
            assert (replies[-1].status, replies[-1].body["error"]) == (503, "handler_failed")
            assert replies[-1].outcome.kind == "retryable" and a.outbox.pending()
            b.host.fail = False
            a.outbox.deliver(three.request_id, lambda p: ta.deliver(p, pb, dc.exchange))
            assert [r.outcome.kind if r.outcome else None for r in replies[-2:]] == [
                None,
                "delivered",
            ]
            assert len(b.host.calls) == 2 and not a.outbox.pending()
            # a rejected inner envelope is an accepted frame: 200, outcome in the receipt
            bad = create_message(a.identity, pb, "rfq", {"need": "x"}, timestamp=clock.t)
            with raises("delivery_rejected") as info:
                ta.deliver(bad, pb, dc.exchange)
            assert info.value.remote_code == "invalid_envelope"  # commerce needs a threadId
            assert (replies[-1].status, replies[-1].body["ok"]) == (200, True)
            assert replies[-1].outcome.kind == "quarantined"
            assert replies[-1].outcome.error.code == "invalid_envelope"
            assert b.store.read(f"quarantine/{replies[-1].outcome.fingerprint}.json")
            assert len(b.host.calls) == 2
            cursor = mb.cursor(rb)
            assert cursor is not None
            mb.close()
            restored = SecureMailbox(
                b.identity,
                b.store,
                b.peers,
                rb,
                SecureTransport(b.identity, engine, b.store, clock),
                b.open(),
            )
            try:
                assert restored.cursor(rb) == cursor
                assert not restored.pull().outcomes
            finally:
                restored.close()
        finally:
            stop.set()
            ma.close()
            mb.close()
            server.close()
