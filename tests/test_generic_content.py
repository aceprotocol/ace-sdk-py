import pytest

from ace import (
    Inbox,
    MemoryStore,
    Outbox,
    PeerStore,
    ReplayDetector,
    create_message,
    decode_envelope,
    parse_message,
)
from ace.messages import known_schema_digest
from tests.helpers import agent, peer_of, raises, wire

TYPE = "https://example.org/schemas/task/1"
DIGEST = "ab" * 32


def test_private_extensible_round_trip():
    alice, bob = agent("alice"), agent("bob")
    env = create_message(
        alice,
        peer_of(bob),
        TYPE,
        {"text": "你好", "task": {"amount": "10"}},
        thread_id="secret workflow",
        schema_digest=DIGEST,
    )
    assert set(env.to_dict()) == {
        "ace",
        "messageId",
        "from",
        "to",
        "conversationId",
        "timestamp",
        "encryption",
        "signature",
    }
    m = parse_message(env, bob, peer_of(alice), replay=ReplayDetector())
    assert (m.type, m.schema_digest, m.thread_id, m.body["text"]) == (
        TYPE,
        DIGEST,
        "secret workflow",
        "你好",
    )
    assert (
        known_schema_digest("text")
        == "c82da8dde17338c28c42d2a6fad644961c3e7a8d1d008f9d2b18e8d624cf4a52"
    )


@pytest.mark.parametrize("field", ["type", "threadId", "schemaDigest", "body"])
def test_reject_public_application_fields(field):
    env = create_message(agent("alice"), peer_of(agent("bob")), "text", {"message": "hello"})
    with raises("invalid_envelope"):
        decode_envelope({**env.to_dict(), field: "leak"})


def test_schema_pin_and_durable_custom_content():
    alice, bob = agent("alice"), agent("bob")
    with raises("invalid_body"):
        create_message(alice, peer_of(bob), TYPE, {})
    with raises("invalid_body"):
        create_message(alice, peer_of(bob), "text", {"message": "hello"}, schema_digest=DIGEST)
    store, rx_store = MemoryStore(), MemoryStore()
    outbox = Outbox.open(alice, store)

    def stage(out, digest=DIGEST):
        return out.stage(
            peer_of(bob),
            TYPE,
            {"data": 1},
            schema_digest=digest,
            thread_id="private",
            request_id="operation",
        )

    p = stage(outbox)
    restarted = Outbox.open(alice, store)
    assert stage(restarted) == p
    with raises("pending_send_conflict"):
        stage(restarted, "cd" * 32)
    peers = PeerStore(rx_store)
    peers.adopt(peer_of(alice))
    received = []
    inbox = Inbox.open(bob, rx_store, peers, received.append)
    assert inbox.receive(wire(p.message)).kind == "delivered"
    inbox.close()
    inbox = Inbox.open(bob, rx_store, peers, received.append)
    assert inbox.receive(wire(p.message)).kind == "duplicate"
    assert len(received) == 1 and received[0].schema_digest == DIGEST
    assert store.list("threads/") == []
    inbox.close()


def test_missing_commerce_thread_is_permanent_and_one_shot():
    alice, bob = agent("alice"), agent("bob")
    store = MemoryStore()
    peers = PeerStore(store)
    peers.adopt(peer_of(alice))
    inbox = Inbox.open(bob, store, peers, lambda m: None, commerce=True)
    env = create_message(alice, peer_of(bob), "rfq", {"need": "data"})
    r = inbox.receive(wire(env))
    assert r.kind == "quarantined" and r.error.code == "invalid_envelope"
    assert inbox.receive(wire(env)).kind == "duplicate"
    inbox.close()


@pytest.mark.parametrize("suffix", ["\n", "\r", "\u2028", "\u2029"])
def test_strict_identifier_and_digest(suffix):
    from ace import is_message_type

    assert not is_message_type(TYPE + suffix)
    with raises("invalid_body"):
        create_message(
            agent("alice"), peer_of(agent("bob")), TYPE, {}, schema_digest=DIGEST + suffix
        )


def test_installed_schema_validators():
    from ace import ACEError, SchemaValidator

    alice, bob = agent("alice"), agent("bob")
    seen: list[dict] = []

    def task(m: dict) -> None:  # a SchemaValidator
        seen.append(m)
        if m["body"].get("amount") == "nan":
            raise ACEError("limit_exceeded", "amount is not a number")
        if "amount" not in m["body"]:
            raise KeyError("amount")  # any other exception: invalid_body

    validators: dict[str, SchemaValidator] = {DIGEST: task}
    for bad in ({"xyz": task}, {DIGEST: "not callable"}, {DIGEST.upper(): task}, [task]):
        with raises("invalid_argument"):
            Inbox.open(bob, MemoryStore(), PeerStore(MemoryStore()), lambda m: None, schemas=bad)
        with raises("invalid_argument"):
            Outbox.open(alice, MemoryStore(), schemas=bad)
    store, rx_store = MemoryStore(), MemoryStore()
    outbox = Outbox.open(alice, store, schemas=validators)
    # Outbox.stage runs the validator before persisting anything
    with raises("limit_exceeded"):
        outbox.stage(peer_of(bob), TYPE, {"amount": "nan"}, schema_digest=DIGEST, request_id="x")
    with raises("invalid_body"):
        outbox.stage(peer_of(bob), TYPE, {}, schema_digest=DIGEST, request_id="x")
    assert outbox.pending() == [] and store.list("") == []
    good = outbox.stage(peer_of(bob), TYPE, {"amount": "1"}, schema_digest=DIGEST, request_id="x")
    assert seen[-1] == {
        "type": TYPE,
        "schemaDigest": DIGEST,
        "threadId": None,
        "body": {"amount": "1"},
    }
    # an unvalidated outbox can still produce bodies the receiver's validator rejects
    plain = Outbox.open(alice, MemoryStore())
    nan = plain.stage(peer_of(bob), TYPE, {"amount": "nan"}, schema_digest=DIGEST)
    missing = plain.stage(peer_of(bob), TYPE, {"x": 1}, schema_digest=DIGEST, thread_id="t")
    peers = PeerStore(rx_store)
    peers.adopt(peer_of(alice))
    received = []
    inbox = Inbox.open(bob, rx_store, peers, received.append, schemas=validators)
    out = inbox.receive(wire(nan.message))
    assert out.kind == "quarantined" and out.error.code == "limit_exceeded"
    assert rx_store.read(f"quarantine/{out.fingerprint}.json") is not None
    out = inbox.receive(wire(missing.message))
    assert out.kind == "quarantined" and out.error.code == "invalid_body"
    assert "KeyError" in out.error.message and seen[-1]["threadId"] == "t"
    assert inbox.receive(wire(nan.message)).kind == "duplicate"  # one-shot, replay committed
    assert inbox.receive(wire(good.message)).kind == "delivered"
    assert [m.body for m in received] == [{"amount": "1"}]
    # a validator installed for a bundled digest runs in addition to the built-in check
    text_digest = known_schema_digest("text")
    strict = Inbox.open(
        bob, MemoryStore(), peers, received.append, schemas={text_digest: lambda m: 1 / 0}
    )
    hello = plain.stage(peer_of(bob), "text", {"message": "hi"})
    out = strict.receive(wire(hello.message))
    assert out.kind == "quarantined" and out.error.code == "invalid_body"
    assert len(received) == 1
    strict.close()
    inbox.close()
