"""Open-thread bound per peer (04 § Open-thread bound) and idle-thread retention."""

from __future__ import annotations

import json
import uuid

from ace import (
    MAX_OPEN_THREADS_PER_PEER,
    MemoryStore,
    ReceiveSource,
    ThreadHistoryEntry,
    ThreadSnapshot,
    ThreadStore,
    compute_conversation_id,
)
from ace.threads import (
    THREAD_RETENTION_SECONDS,
    ThreadRecord,
    sha256_hex,
    thread_index_key,
    thread_key,
)

from .helpers import raises
from .pipeline import Agent, Clock


def rfq_snapshot(local: str, peer: str, conv: str, thread_id: str, ts: int, from_id: str | None = None) -> ThreadSnapshot:
    entry = ThreadHistoryEntry("rfq", str(uuid.uuid4()), ts, from_id or peer)
    return ThreadSnapshot(conv, thread_id, local, peer, "rfq", (entry,))


def fill(store, local: str, peer: str, conv: str, n: int, ts: int) -> ThreadStore:
    threads = ThreadStore(store, local, clock=lambda: ts)
    for i in range(n):
        threads.save(ThreadRecord(rfq_snapshot(local, peer, conv, f"fill-{i}", ts), None))
    return threads


def make_pair():
    clock = Clock()
    alice, bob = Agent("alice", "ed25519", clock), Agent("bob", "secp256k1", clock)
    alice.pin(bob)
    bob.pin(alice)
    conv = compute_conversation_id(alice.identity.get_encryption_public_key(), bob.identity.get_encryption_public_key())
    return clock, alice, bob, conv


def read_index(store, peer: str) -> bytes | None:
    raw = store.read(thread_index_key(peer))
    return None if raw is None else bytes(raw)


def test_index_format_and_maintenance():
    store = MemoryStore()
    _, alice, bob, conv = make_pair()
    threads = fill(store, bob.id, alice.id, conv, 2, 1000)
    assert thread_index_key(alice.id) == f"threads/index/{sha256_hex(alice.id)}.json"
    entries = sorted(thread_key(conv, t)[: -len(".json")] for t in ("fill-0", "fill-1"))
    assert read_index(store, alice.id) == json.dumps({"open": entries, "version": 1}, separators=(",", ":")).encode()
    assert len(threads.records()) == 2 and len(threads.list()) == 2  # the index is not a thread record
    assert threads.open_thread_count(alice.id) == 2
    done = threads.get(conv, "fill-0")
    reject = ThreadHistoryEntry("reject", str(uuid.uuid4()), 1001, bob.id)
    threads.save(ThreadRecord(ThreadSnapshot(conv, "fill-0", bob.id, alice.id, "rejected", (*done.history, reject)), None))
    assert threads.open_thread_count(alice.id) == 1
    assert threads.remove(conv, "fill-1") is True
    assert read_index(store, alice.id) is None


def test_bound_on_receive_and_stage():
    clock, alice, bob, conv = make_pair()
    inbox = bob.open()  # replay state first: the filled threads model earlier receipts
    threads = fill(bob.store, bob.id, alice.id, conv, MAX_OPEN_THREADS_PER_PEER, clock.t)
    env = alice.outbox.stage(alice.peers.get(bob.id), "rfq", {"need": "x"}, thread_id="one-more").message
    out = inbox.receive(env.to_dict(), ReceiveSource.relay("https://relay.example", "1-0"))
    assert out.kind == "quarantined" and out.error.code == "limit_exceeded"
    assert bob.host.calls == [] and threads.get(conv, "one-more") is None
    # sender side: pre-checked before any crypto
    with raises("limit_exceeded"):
        bob.outbox.stage(bob.peers.get(alice.id), "rfq", {"need": "y"}, thread_id="mine")
    # an existing thread still advances
    offer = bob.outbox.stage(bob.peers.get(alice.id), "offer", {"price": "1", "currency": "USDC"}, thread_id="fill-7")
    assert offer.message.type == "offer"
    threads.remove(conv, "fill-0")
    bob.outbox.stage(bob.peers.get(alice.id), "rfq", {"need": "y"}, thread_id="mine")
    assert threads.open_thread_count(alice.id) == MAX_OPEN_THREADS_PER_PEER
    inbox.close()


def test_stale_index_entries_are_reconciled_at_the_bound():
    store = MemoryStore()
    _, alice, bob, conv = make_pair()
    threads = fill(store, bob.id, alice.id, conv, 3, 1000)
    real = json.loads(read_index(store, alice.id))["open"]
    ghosts = [f"threads/{sha256_hex(f'ghost-{i}')}" for i in range(MAX_OPEN_THREADS_PER_PEER)]
    store.write(thread_index_key(alice.id), json.dumps({"open": sorted(real + ghosts), "version": 1}).encode())
    assert threads.open_thread_count(alice.id) == 3
    assert json.loads(read_index(store, alice.id))["open"] == real
    store.write(thread_index_key(alice.id), b'{"open":[1],"version":1}')
    with raises("storage_failed"):
        threads.open_thread_count(alice.id)


def test_prunes_idle_threads_without_local_entry():
    store = MemoryStore()
    _, alice, bob, conv = make_pair()
    old = 10_000
    now = old + THREAD_RETENTION_SECONDS + 1
    seed = ThreadStore(store, bob.id, clock=lambda: old)
    seed.save(ThreadRecord(rfq_snapshot(bob.id, alice.id, conv, "idle", old), None))
    seed.save(ThreadRecord(rfq_snapshot(bob.id, alice.id, conv, "mine", old, bob.id), None))
    seed.save(ThreadRecord(rfq_snapshot(bob.id, alice.id, conv, "recent", now - 10), None))
    later = ThreadStore(store, bob.id, clock=lambda: now)
    later.save(ThreadRecord(rfq_snapshot(bob.id, alice.id, conv, "trigger", now), None))
    assert sorted(s.thread_id for s in later.list()) == ["mine", "recent", "trigger"]
    assert later.open_thread_count(alice.id) == 3
