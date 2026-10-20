"""Receive pipeline (06 § Receive pipeline)."""

import json

from ace import (
    CORE,
    TEXT,
    Inbox,
    Outbox,
    ProfileManifest,
    Profiles,
    create_packet,
    create_permit,
    decode_content,
    decode_packet,
    decrypt_packet,
    encode_content,
)
from ace.limits import MAX_PERMIT_LIFETIME, OFFLINE_WINDOW_SECONDS
from tests.helpers import Clock, Party, raises, wire

TEXT_DIGEST = TEXT.messages["ace:text:1"].digest
CONTACT_DIGEST = CORE.messages["ace:contact:1"].digest


class World:
    def __init__(
        self, *, contact="closed", admitted=True, refresh=None, on_message=None, capacity=None
    ):
        self.clock = Clock()
        self.a, self.b = Party(self.clock), Party(self.clock)
        self.got = []
        self.refreshes = []
        if admitted:
            self.b.peers.adopt(self.a.source())
            self.b.peers.set_status(self.a.id, "admitted")
            self.a.peers.adopt(self.b.source())
            self.a.peers.set_status(self.b.id, "admitted")
        self.outbox = Outbox(self.a.identity, self.a.store, Profiles(), clock=self.clock)
        self.inbox = Inbox.open(
            self.b.identity,
            self.b.store,
            self.b.vault,
            self.b.peers,
            Profiles(),
            on_message=on_message or self.got.append,
            contact=contact,
            refresh=refresh or (lambda ace_id: self.refreshes.append(ace_id)),
            check_capacity=capacity,
            clock=self.clock,
        )
        self.a_inbox = Inbox.open(
            self.a.identity,
            self.a.store,
            self.a.vault,
            self.a.peers,
            Profiles(),
            on_message=lambda m: None,
            outbox=self.outbox,
            clock=self.clock,
        )

    def packet(
        self,
        type_="ace:text:1",
        body=None,
        digest=None,
        ts=None,
        sender=None,
        mid=None,
        prekey=None,
    ):
        sender = sender or self.a
        plain = encode_content(
            type_, digest or TEXT_DIGEST, body if body is not None else {"message": "hi"}
        )
        return create_packet(
            sender.identity,
            self.b.id,
            prekey or self.b.vault.current(),
            plain,
            timestamp=self.clock.now if ts is None else ts,
            message_id=mid,
        )

    def receipt_body(self, out):
        p = decode_packet(out.receipt.packet)
        return decode_content(decrypt_packet(p, self.a.vault))["body"]


def test_delivered_then_duplicate_with_receipts():
    w = World()
    p = w.packet()
    out = w.inbox.receive(wire(p))
    assert out.kind == "delivered" and out.ack and w.got[0].body == {"message": "hi"}
    body = w.receipt_body(out)
    assert body["messageId"] == p["messageId"] and body["outcome"] == "delivered"
    assert "permit" in body  # first receipt carries a permit for the admitted peer
    assert out.receipt.permit == body["permit"]
    w.b.peers.note_issued(w.a.id, out.receipt.permit)  # the caller sent the receipt
    again = w.inbox.receive(wire(p))
    assert again.kind == "duplicate" and len(w.got) == 1
    body2 = w.receipt_body(again)
    assert body2["outcome"] == "delivered" and "permit" not in body2  # still fresh


def test_unsupported_schema_and_invalid_body_are_rejected():
    w = World()
    custom = ProfileManifest(
        {
            "id": "urn:x:1",
            "messages": [
                {
                    "type": "urn:x:m:1",
                    "schema": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                        "additionalProperties": True,
                    },
                }
            ],
        }
    )
    out = w.inbox.receive(wire(w.packet("urn:x:m:1", {}, custom.messages["urn:x:m:1"].digest)))
    assert out.kind == "rejected" and out.error.code == "unsupported_schema"
    body = w.receipt_body(out)
    assert (body["outcome"], body["code"]) == ("rejected", "unsupported_schema")
    out = w.inbox.receive(wire(w.packet(body={"message": 5})))
    assert out.kind == "rejected" and w.receipt_body(out)["code"] == "invalid_body"
    assert w.got == []


def test_beyond_the_replay_horizon_is_dropped_never_delivered():
    w = World()
    w.inbox._replay._horizon = w.clock.now - 10  # as if capacity eviction raised it
    out = w.inbox.receive(wire(w.packet(ts=w.clock.now - 20)))
    assert out.kind == "dropped" and out.error.code == "replay_horizon"
    assert out.receipt is None and w.got == []


def test_admission_before_any_lookup():
    w = World(admitted=False)
    stranger_text = w.packet()
    out = w.inbox.receive(wire(stranger_text))
    assert out.kind == "dropped" and out.ack and out.receipt is None
    assert w.refreshes == [] and w.b.peers.get(w.a.id) is None  # no lookup, no pin
    # blocked senders are dropped too
    w.b.peers.set_status(w.a.id, "blocked")
    assert w.inbox.receive(wire(w.packet())).kind == "dropped"


def contact(w, kind="request", profile=TEXT, permit=True, ts=None):
    body = {
        "kind": kind,
        "profile": profile.id,
        "note": "hello",
        "source": w.a.source(profiles=[profile.descriptor()]),
    }
    if permit:
        body["permit"] = create_permit(w.a.identity, w.b.id, now=w.clock.now)
    return w.packet("ace:contact:1", body, CONTACT_DIGEST, ts=ts)


def test_stranger_contacts_only_while_open_and_never_admit():
    private = World(admitted=False)
    assert private.inbox.receive(wire(contact(private))).kind == "dropped"
    w = World(admitted=False, contact="open")
    out = w.inbox.receive(wire(contact(w)))
    assert out.kind == "delivered" and out.receipt is None  # contacts are never receipted
    assert w.got[0].type == "ace:contact:1"
    assert w.b.peers.get(w.a.id) is None  # nothing pinned or admitted by remote content
    for bad in (
        contact(w, kind="accepted"),
        contact(w, permit=False),
        contact(w, ts=w.clock.now - OFFLINE_WINDOW_SECONDS - 1),
    ):
        assert w.inbox.receive(wire(bad)).kind == "dropped"
    # a non-contact from a stranger is dropped even while open
    assert w.inbox.receive(wire(w.packet())).kind == "dropped"


def test_unknown_prekey_signature_and_window():
    w = World()
    old = w.b.vault.current()
    w.b.vault.rotate(w.clock.now)
    w.b.vault.prune(w.clock.now + 10**7)
    out = w.inbox.receive(wire(w.packet(prekey=old)))
    assert out.kind == "rejected" and w.receipt_body(out)["code"] == "unknown_prekey"
    p = w.packet()
    p["signature"]["value"] = w.packet()["signature"]["value"]
    assert w.inbox.receive(wire(p)).kind == "dropped"
    assert w.inbox.receive(wire(w.packet(ts=w.clock.now + 301))).kind == "dropped"
    assert w.inbox.receive(b"{not json").kind == "dropped"


def test_newer_delegation_refreshes_once_then_retries():
    w = World()
    w.a.identity.delegate(now=w.clock.now)
    out = w.inbox.receive(wire(w.packet()))
    assert w.refreshes == [w.a.id]
    assert out.kind == "dropped"  # refresh brought nothing newer: stale_peer_binding
    raw = wire(w.packet())
    out = w.inbox.receive(raw)
    assert out.kind == "retry" and not out.ack  # suppressed refresh within 30 s
    # a suppressed refresh counts toward MAX_FETCH_ATTEMPTS: no head-of-line block
    assert [w.inbox.receive(raw).kind for _ in range(2)] == ["retry", "quarantined"]
    assert len(w.inbox.quarantined()) == 1
    w.clock.now += 31
    w.b.peers.pin(w.a.identity.get_kel())
    assert w.inbox.receive(wire(w.packet())).kind == "delivered"


def test_poison_packet_is_quarantined_after_three_attempts():
    def boom(m):
        raise RuntimeError("host bug")

    w = World(on_message=boom)
    raw = wire(w.packet())
    kinds = [w.inbox.receive(raw).kind for _ in range(3)]
    assert kinds == ["retry", "retry", "quarantined"]
    assert len(w.inbox.quarantined()) == 1


def test_capacity_holds_without_counting():
    from ace import ACEError

    def full(m):
        raise ACEError("receiver_capacity", "full")

    w = World(capacity=full)
    raw = wire(w.packet())
    assert [w.inbox.receive(raw).kind for _ in range(4)] == ["retry"] * 4


def test_receipts_settle_the_outbox_and_renew_permits():
    w = World()
    mid = w.outbox.enqueue(w.b.id, "ace:text:1", {"message": "hi"})
    sent = []
    w.outbox.deliver(
        mid,
        lambda packet, agent: sent.append(packet),
        lambda ace_id, refresh=False: w.a.peers.agent(ace_id),
    )
    out = w.inbox.receive(wire(sent[0]))
    assert out.kind == "delivered"
    back = w.a_inbox.receive(wire(out.receipt.packet))
    assert back.kind == "delivered" and w.outbox.get(mid).status == "delivered"
    held = w.a.peers.permit_from(w.b.id)
    assert held["issuer"] == w.b.id and held["subject"] == w.a.id
    # a receipt never produces a receipt
    assert back.receipt is None
    # renewal: once less than 15 days remain, the next receipt carries a fresh permit
    w.clock.now += MAX_PERMIT_LIFETIME - 15 * 86400 + 1
    w.b.peers.adopt(w.a.source())
    out = w.inbox.receive(wire(w.packet()))
    assert "permit" in w.receipt_body(out)


def test_restart_recovers_seen_store():
    w = World()
    p = w.packet()
    assert w.inbox.receive(wire(p)).kind == "delivered"
    w.inbox.close()
    again = Inbox.open(
        w.b.identity,
        w.b.store,
        w.b.vault,
        w.b.peers,
        Profiles(),
        on_message=w.got.append,
        clock=w.clock,
    )
    assert again.receive(wire(p)).kind == "duplicate" and len(w.got) == 1
    with raises("lock_busy"):
        Inbox.open(
            w.b.identity,
            w.b.store,
            w.b.vault,
            w.b.peers,
            Profiles(),
            on_message=w.got.append,
            clock=w.clock,
        )


def test_missing_seen_store_beside_delivery_history_is_storage_failed():
    w = World()
    p = w.packet()
    assert w.inbox.receive(wire(p)).kind == "delivered"
    w.inbox._lock.release()  # crash: the journaled delivery record was never compacted
    assert w.b.store.list("inbox/deliveries/")
    w.b.store.delete("inbox/replay.json")
    with raises("storage_failed"):
        Inbox.open(
            w.b.identity,
            w.b.store,
            w.b.vault,
            w.b.peers,
            Profiles(),
            on_message=w.got.append,
            clock=w.clock,
        )
    assert len(w.got) == 1 and w.b.store.read("inbox/replay.json") is None


def test_quarantine_keeps_only_a_bounded_header():
    def boom(m):
        raise RuntimeError("host bug")

    w = World(on_message=boom)
    p = w.packet(body={"message": "x" * 60000})
    raw = wire(p)
    for _ in range(3):
        w.inbox.receive(raw)
    (rec,) = w.inbox.quarantined()
    header = {k: p[k] for k in ("ace", "from", "to", "messageId", "timestamp")}
    assert rec["packet"] == {**header, "prekey": p["encryption"]["prekey"]}
    assert len(json.dumps(rec)) < 4096


MARKER = b"plaintext-marker-7f3a9c"


def _leaked(store):
    return [k for k in store.list("") if MARKER in store.read(k)]


def _reopen(w, on_message=None):
    return Inbox.open(
        w.b.identity,
        w.b.store,
        w.b.vault,
        w.b.peers,
        Profiles(),
        on_message=on_message or w.got.append,
        clock=w.clock,
    )


def test_acked_delivery_records_hold_no_plaintext_and_dedup_survives_a_crash():
    w = World()
    packets = [w.packet(body={"message": f"{MARKER.decode()} {i}"}) for i in range(5)]
    for p in packets:
        assert w.inbox.receive(wire(p)).kind == "delivered"
    assert len(w.b.store.list("inbox/deliveries/")) == 5
    assert _leaked(w.b.store) == []
    # crash before the next snapshot: only the records carry these seen entries
    w.inbox._lock.release()
    again = _reopen(w)
    assert [again.receive(wire(p)).kind for p in packets] == ["duplicate"] * 5
    assert len(w.got) == 5


def test_interrupted_hand_over_is_redelivered_after_restart_then_its_body_is_gone():
    def crash(m):
        raise RuntimeError("process died")

    w = World(on_message=crash)
    assert w.inbox.receive(wire(w.packet(body={"message": MARKER.decode()}))).kind == "retry"
    assert len(_leaked(w.b.store)) == 1  # the pending record: the only copy recovery can hand over
    w.inbox._lock.release()
    _reopen(w)
    assert [m.body["message"] for m in w.got] == [MARKER.decode()]
    assert _leaked(w.b.store) == []
