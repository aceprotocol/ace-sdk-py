"""Two agents complete a deal through the fake relay with the full pipeline."""

from __future__ import annotations

import threading

import pytest

from ace import (
    FileStore,
    MemoryStore,
    RelayClient,
    ThreadHistoryEntry,
    ThreadSnapshot,
    ThreadStateMachine,
    ThreadStore,
    create_message,
)

from .fake_relay import FakeRelay
from .helpers import raises
from .pipeline import Agent, Clock


@pytest.fixture
def world(tmp_path):
    clock = Clock(1_800_000_000)
    relay = FakeRelay(clock=clock)
    client = RelayClient(relay.url, clock=clock)
    alice = Agent("alice", "ed25519", clock, store=FileStore(tmp_path / "alice"), relay=client)
    bob = Agent("bob", "secp256k1", clock, store=MemoryStore(), relay=client)
    assert client.register(alice.identity) == "registered"
    assert client.register(bob.identity) == "registered"
    alice.open()
    bob.open()
    yield clock, relay, client, alice, bob
    alice.inbox.close()
    bob.inbox.close()
    relay.close()


def send(agent: Agent, client: RelayClient, to: Agent, type_: str, body: dict, thread_id: str):
    peer = agent.peers.resolve(to.id)
    p = agent.outbox.stage(peer, type_, body, thread_id=thread_id)
    agent.outbox.deliver(p.request_id, client.send)
    return p.message


def receive_one(agent: Agent, client: RelayClient):
    before = len(agent.host.calls)
    result = agent.inbox.pull(client)
    assert result.blocked is None and result.delivered == 1, result
    assert len(agent.host.calls) == before + 1
    return agent.host.effects[agent.host.calls[-1]]


def test_full_deal_rfq_to_confirm(world):
    clock, relay, client, alice, bob = world
    t = "deal-42"
    rfq = send(alice, client, bob, "rfq", {"need": "Translate 500 words EN→FR", "maxPrice": "10", "currency": "USDC"}, t)
    m = receive_one(bob, client)
    assert m.type == "rfq" and m.body["need"].endswith("EN→FR") and m.message_id == rfq.message_id
    offer = send(bob, client, alice, "offer", {"price": "8", "currency": "USDC"}, t)
    assert receive_one(alice, client).type == "offer"
    send(alice, client, bob, "accept", {"offerId": offer.message_id}, t)
    assert receive_one(bob, client).type == "accept"
    invoice = send(bob, client, alice, "invoice", {"offerId": offer.message_id, "amount": "8", "currency": "USDC",
                                                   "settlementMethod": "solana-spl"}, t)
    assert receive_one(alice, client).type == "invoice"
    send(alice, client, bob, "receipt", {"referenceId": invoice.message_id, "amount": "8", "currency": "USDC",
                                         "settlementMethod": "solana-spl", "proof": {"tx": "abc"}}, t)
    assert receive_one(bob, client).type == "receipt"
    deliver = send(bob, client, alice, "deliver", {"type": "inline", "content": "Bonjour"}, t)
    assert receive_one(alice, client).body["content"] == "Bonjour"
    send(alice, client, bob, "confirm", {"deliverId": deliver.message_id}, t)
    assert receive_one(bob, client).type == "confirm"

    for agent in (alice, bob):
        snap = ThreadStore(agent.store, agent.id).get(rfq.conversation_id, t)
        assert snap.state == "confirmed" and len(snap.history) == 7
        assert agent.outbox.pending() == []
        empty = agent.inbox.pull(client)
        assert empty.outcomes == [] and empty.blocked is None
    assert ThreadStore(bob.store, bob.id).allowed_types(rfq.conversation_id, t, alice.id) == []
    assert bob.inbox.cursor(client) is not None


def test_pull_returns_outcomes_in_order(world):
    clock, relay, client, alice, bob = world
    sent = [send(alice, client, bob, "text", {"message": f"m{i}"}, None) for i in range(3)]
    result = bob.inbox.pull(client, limit=2)
    assert result.blocked is None
    assert [o.kind for o in result.outcomes] == ["delivered"] * 3
    assert [m.message_id for m in result.messages] == [e.message_id for e in sent]
    assert (result.delivered, result.duplicates, result.quarantined) == (3, 0, 0)


def test_follow_yields_initial_pull_then_live_with_on_live(world):
    clock, relay, client, alice, bob = world
    for m in ("q0", "q1"):
        send(alice, client, bob, "text", {"message": m}, None)
    stop = threading.Event()
    events: list[str] = []
    errors: list[BaseException] = []

    def on_live():
        events.append("live")
        if events.count("live") == 1:
            send(alice, client, bob, "rfq", {"need": "live"}, "live-1")

    def run():
        try:
            for o in bob.inbox.follow(client, stop=stop, on_live=on_live):
                m = o.message
                events.append(f"{m.type}:{m.body.get('message', m.body.get('need'))}" if o.kind == "delivered" else o.kind)
                if o.kind == "delivered" and m.type == "rfq":
                    relay.drain_after = 0  # the next event drains the stream: a reconnect
                    send(alice, client, bob, "text", {"message": "after"}, None)
                if o.kind == "delivered" and m.body.get("message") == "after":
                    stop.set()
        except BaseException as exc:  # surfaced below
            errors.append(exc)

    th = threading.Thread(target=run)
    th.start()
    th.join(10)
    stop.set()
    assert not th.is_alive() and errors == []
    assert events == ["text:q0", "text:q1", "live", "rfq:live", "live", "text:after"]
    assert bob.inbox.cursor(client) == relay.streams[bob.id][-1][0]


def test_follow_raises_failed_initial_pull_without_on_live(world):
    clock, relay, client, alice, bob = world
    relay.inject.append(("/v1/inbox", 503, "down", {}))
    live = []
    with raises("relay_unavailable"):
        for _ in bob.inbox.follow(client, on_live=lambda: live.append(1)):
            pass
    assert live == []


def test_role_violation_is_quarantined(world):
    clock, relay, client, alice, bob = world
    rfq = send(alice, client, bob, "rfq", {"need": "x"}, "d")
    receive_one(bob, client)
    # alice forges a seller move (offer) on a thread where she is the buyer
    fake = ThreadSnapshot(rfq.conversation_id, "d", alice.id, bob.id, "rfq",
                          (ThreadHistoryEntry("rfq", rfq.message_id, rfq.timestamp, bob.id),))
    env = create_message(alice.identity, alice.peers.get(bob.id), "offer", {"price": "1", "currency": "USDC"},
                         ThreadStateMachine.from_state([fake], alice.id), thread_id="d", timestamp=clock.t)
    client.send(env)
    result = bob.inbox.pull(client)
    assert [o.kind for o in result.outcomes] == ["quarantined"] and result.blocked is None
    assert (result.delivered, result.duplicates, result.quarantined) == (0, 0, 1)
    assert result.outcomes[0].error.code == "wrong_role"
    (qkey,) = bob.store.list("quarantine/")
    assert bob.store.read(qkey) is not None
    assert ThreadStore(bob.store, bob.id).get(rfq.conversation_id, "d").state == "rfq"
    assert bob.inbox.cursor(client) == relay.streams[bob.id][-1][0]
    assert len(bob.host.calls) == 1


def test_expired_send_resign_through_relay(world):
    clock, relay, client, alice, bob = world
    peer = alice.peers.resolve(bob.id)
    p = alice.outbox.stage(peer, "rfq", {"need": "x"}, thread_id="d", request_id="r")
    clock.t += 1000  # the sender was offline: the relay now rejects the stale envelope
    with raises("envelope_expired"):
        alice.outbox.deliver("r", client.send)
    assert alice.outbox.pending()[0].status == "expired"
    r = alice.outbox.resign("r")
    alice.outbox.deliver("r", client.send)
    m = receive_one(bob, client)
    assert m.message_id == p.message.message_id and m.timestamp == r.message.timestamp == clock.t


def test_retryable_blocks_pull_and_cursor(world):
    clock, relay, client, alice, bob = world
    send(alice, client, bob, "text", {"message": "1"}, None)
    bob.host.fail = True
    result = bob.inbox.pull(client)
    assert result.blocked is not None and result.blocked.code == "handler_failed"
    assert bob.inbox.cursor(client) is None
    seen = []
    with raises("handler_failed"):
        for o in bob.inbox.follow(client):
            seen.append(o.kind)
    assert seen == ["retryable"]  # yielded, then raised
    bob.host.fail = False
    assert bob.inbox.pull(client).delivered == 1
    relay.inject.append(("/v1/inbox", 503, "down", {}))
    assert bob.inbox.pull(client).blocked.code == "relay_unavailable"
