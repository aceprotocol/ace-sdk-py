"""Peer prekeys end to end (04 § Peer prekeys, 06 § Outbox, § Receipts, § Receive pipeline)."""

import json
import os
import time

from ace import (
    TEXT,
    ACEError,
    MemoryStore,
    NetworkClient,
    PrekeyVault,
    RelayClient,
    SoftwareIdentity,
    _xwing,
    create_packet,
    decode_content,
    decode_packet,
    decrypt_packet,
    encode_content,
)
from ace.prekeys import Prekey, prekey_id, prekey_public_key
from tests.helpers import wire
from tests.test_inbox import TEXT_DIGEST

RECEIPT = "ace:receipt:1"


def _client(relay, now, identity=None, vault=None, **kw):
    received = []
    nc = NetworkClient.open(
        identity or SoftwareIdentity.generate(),
        MemoryStore(),
        RelayClient(relay.url, allow_loopback=True),
        vault or PrekeyVault(clock=lambda: now[0]),
        on_message=received.append,
        clock=lambda: now[0],
        **kw,
    )
    nc.publish()
    nc.received = received
    return nc


def _pair(relay, *, b_vault=None):
    """A connects, B (open, listed) accepts: both admitted, nothing held yet."""
    now = [int(time.time())]
    alice = _client(relay, now)
    bob = _client(relay, now, vault=b_vault, contact="open", listed=True)
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.connect(b, profile=TEXT.id)
    bob.pull()
    bob.accept(a)
    alice.pull()
    assert alice.peers.status(b) == "admitted" and bob.peers.status(a) == "admitted"
    return now, alice, bob, a, b


def _id(c):
    return c.identity.get_ace_id()


def _pin(holder, peer):
    return holder.peers.state(peer).last_hash


def _since(relay, n, frm, to):
    """Packets accepted by the relay since index ``n``, from ``frm`` to ``to``."""
    return [
        decode_packet(s["packet"])
        for s in relay.sent[n:]
        if s["packet"]["from"] == _id(frm) and s["packet"]["to"] == _id(to)
    ]


def _content(p, recipient, now):
    return decode_content(decrypt_packet(p, recipient.vault, now))


def _offered(p, recipient, now):
    """The peer prekey ID a packet carries (decrypted by its recipient)."""
    return prekey_id(_content(p, recipient, now)["prekey"])


def _ratchet(relay, now, alice, bob, a, b):
    """m1 A→B, receipt, m2 A→B (to B's offered key), receipt. Returns the relay index at start
    and the ID B offered A in its first receipt."""
    start = len(relay.sent)
    m1 = alice.send(b, "ace:text:1", {"message": "m1"})
    (p1,) = _since(relay, start, alice, bob)
    assert p1.prekey_id == bob.vault.current().id  # A holds nothing yet: B's published prekey
    n = len(relay.sent)
    bob.pull()
    (r1,) = _since(relay, n, bob, alice)
    assert _content(r1, alice, now[0])["type"] == RECEIPT
    assert r1.prekey_id == alice.vault.current().id
    offered = _offered(r1, alice, now[0])
    alice.pull()
    assert alice.outbox.get(m1).status == "delivered"
    n = len(relay.sent)
    m2 = alice.send(b, "ace:text:1", {"message": "m2"})
    (p2,) = _since(relay, n, alice, bob)
    assert p2.prekey_id == offered != bob.vault.current().id
    bob.pull()
    alice.pull()
    assert alice.outbox.get(m2).status == "delivered"
    assert [m.body["message"] for m in bob.received if m.type == "ace:text:1"] == ["m1", "m2"]
    return start, offered


def test_ratchet_ping_pong(relay):
    now, alice, bob, a, b = _pair(relay)
    _, offered = _ratchet(relay, now, alice, bob, a, b)
    # B's vault: the offered key is now in use (opens for A only) and a new one is offered
    assert bob.vault.open(offered, now[0], sender=a) is not None
    assert bob.vault.offer(a, now[0]).id != offered
    alice.close()
    bob.close()


def test_receipt_uses_published_prekey(relay):
    now, alice, bob, a, b = _pair(relay)
    start, _ = _ratchet(relay, now, alice, bob, a, b)
    reply = bob.send(a, "ace:text:1", {"message": "back"})  # B holds A's offered key now
    alice.pull()
    bob.pull()
    assert bob.outbox.get(reply).status == "delivered"
    receipts = 0
    for sender, recipient in ((alice, bob), (bob, alice)):
        for p in _since(relay, start, sender, recipient):
            if _content(p, recipient, now[0])["type"] == RECEIPT:
                receipts += 1
                assert p.prekey_id == recipient.vault.current().id
    assert receipts == 3
    alice.close()
    bob.close()


def test_retry_uses_published_prekey(relay):
    now, alice, bob, a, b = _pair(relay)
    _, offered = _ratchet(relay, now, alice, bob, a, b)
    n = len(relay.sent)
    mid = alice.send(b, "ace:text:1", {"message": "m3"})  # B offline: nothing pulled
    now[0] += 61
    alice.attempt(mid)
    first, second = _since(relay, n, alice, bob)
    assert first.prekey_id != bob.vault.current().id  # the held key (B's newest offer)
    assert "admission" not in _content(first, bob, now[0])
    assert second.prekey_id == bob.vault.current().id
    assert "admission" in _content(second, bob, now[0])
    alice.close()
    bob.close()


def test_reinstall_recovers_on_second_attempt(relay):
    now, alice, bob, a, b = _pair(relay)
    _ratchet(relay, now, alice, bob, a, b)
    bob.close()
    now[0] += 5
    bob = _client(relay, now, identity=bob.identity, contact="open", listed=True)
    assert bob.peers.get(a) is None
    mid = alice.send(b, "ace:text:1", {"message": "m3"})
    n = len(relay.sent)
    (out,) = bob.pull()
    assert out.kind == "dropped" and _since(relay, n, bob, alice) == []  # no receipt
    now[0] += 61
    (attempt,) = alice.flush()
    assert attempt.result == "sent"
    (out,) = bob.pull()
    assert out.kind == "delivered" and bob.peers.status(a) == "admitted"
    assert bob.vault.held(a, _pin(bob, a), now[0]) is not None  # recorded by the recovery path
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"
    alice.close()
    bob.close()


def test_reorder_keeps_newer_held_key(relay):
    now, alice, bob, a, b = _pair(relay)
    t = now[0]
    keys = [prekey_public_key(bytes([i]) * 32) for i in (1, 2)]
    for ts, key in ((t + 10, keys[0]), (t + 5, keys[1])):
        plain = encode_content("ace:text:1", TEXT_DIGEST, {"message": "x"}, prekey=key)
        p = create_packet(alice.identity, b, bob.vault.current(), plain, timestamp=ts)
        assert bob.inbox.receive(wire(p)).kind == "delivered"
    assert bob.vault.held(a, _pin(bob, a), t).id == prekey_id(keys[0])
    alice.close()
    bob.close()


def test_unknown_prekey_on_held_key_drops_it(relay, tmp_path):
    path = tmp_path / "bob-prekeys.json"
    now, alice, bob, a, b = _pair(relay, b_vault=PrekeyVault(path))
    _ratchet(relay, now, alice, bob, a, b)
    held = alice.vault.held(b, _pin(alice, b), now[0])
    assert held is not None
    doc = json.loads(path.read_bytes())  # B loses its peer state
    doc["peers"] = {}
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    now[0] += 1
    n = len(relay.sent)
    mid = alice.send(b, "ace:text:1", {"message": "m3"})
    (first,) = _since(relay, n, alice, bob)
    assert first.prekey_id == held.id
    (out,) = bob.pull()
    assert out.kind == "rejected" and out.error.code == "unknown_prekey"
    alice.pull()
    assert alice.outbox.get(mid).refresh
    # the rejection carried B's new offer, which replaced the rejected key
    assert alice.vault.held(b, _pin(alice, b), now[0]).id != held.id
    n = len(relay.sent)
    (attempt,) = alice.flush()
    assert attempt.result == "sent"
    (retry,) = _since(relay, n, alice, bob)
    assert retry.prekey_id == bob.vault.current().id
    bob.pull()
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"

    # a rejection naming the key still held drops it before the retry chooses
    n = len(relay.sent)
    mid = alice.send(b, "ace:text:1", {"message": "m4"})
    (first,) = _since(relay, n, alice, bob)
    held = alice.vault.held(b, _pin(alice, b), now[0])
    assert first.prekey_id == held.id
    alice.outbox.settle(mid, "rejected", "unknown_prekey", sender=b, prekey=held.id)
    n = len(relay.sent)
    alice.flush()
    (retry,) = _since(relay, n, alice, bob)
    assert retry.prekey_id == bob.vault.current().id
    assert alice.vault.held(b, _pin(alice, b), now[0]) is None
    alice.close()
    bob.close()


def test_held_key_with_all_zero_x25519_half(relay):
    """A held key whose ML-KEM half is valid and whose X25519 half is all zeros is an X-Wing
    public key (03 § X-Wing: no added X25519 checks). pyca's ``exchange`` raises ``ValueError``
    for the all-zero shared secret; ``_xwing`` takes it as 32 zero bytes, as the draft does, so
    encapsulation to the held key never fails here and needs no fallback: the first attempt goes
    to it, B (which has no such key) answers ``unknown_prekey`` naming it, and the retry drops it
    and goes to the published prekey."""
    now, alice, bob, a, b = _pair(relay)
    _ratchet(relay, now, alice, bob, a, b)
    pin = _pin(alice, b)
    real = alice.vault.held(b, pin, now[0]).public_key
    low_order = real[:-32] + bytes(32)
    alice.vault.drop_held(b)
    alice.vault.hold(b, Prekey(prekey_id(low_order), low_order), now[0], pin)
    n = len(relay.sent)
    mid = alice.send(b, "ace:text:1", {"message": "m3"})
    (first,) = _since(relay, n, alice, bob)
    assert first.prekey_id == prekey_id(low_order)
    (out,) = bob.pull()
    assert out.kind == "rejected" and out.error.code == "unknown_prekey"
    alice.pull()
    assert alice.outbox.get(mid).refresh
    n = len(relay.sent)
    (attempt,) = alice.flush()
    assert attempt.result == "sent"
    (retry,) = _since(relay, n, alice, bob)
    assert retry.prekey_id == bob.vault.current().id
    assert alice.vault.held(b, pin, now[0]) is None
    bob.pull()
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"
    alice.close()
    bob.close()


def test_held_key_failing_the_mlkem_modulus_check_falls_back_to_published(relay):
    """A held key whose ML-KEM half fails pyca's modulus check cannot be encapsulated to
    (``invalid_argument``, never an outage): it is dropped and the same first attempt goes to
    the published prekey."""
    now, alice, bob, a, b = _pair(relay)
    _ratchet(relay, now, alice, bob, a, b)
    pin = _pin(alice, b)
    real = alice.vault.held(b, pin, now[0]).public_key
    bad = b"\xff\xff" + real[2:]  # the first 12-bit coefficient is 0xfff >= q
    try:
        _xwing.encapsulate(bad)
    except ACEError as exc:
        assert exc.code == "invalid_argument"
    else:
        raise AssertionError("encapsulated to a key failing the modulus check")
    alice.vault.drop_held(b)
    alice.vault.hold(b, Prekey(prekey_id(bad), bad), now[0], pin)
    n = len(relay.sent)
    mid = alice.send(b, "ace:text:1", {"message": "m3"})
    (first,) = _since(relay, n, alice, bob)
    assert first.prekey_id == bob.vault.current().id
    assert alice.vault.held(b, pin, now[0]) is None
    assert alice.outbox.get(mid).attempts == 1
    (out,) = bob.pull()
    assert out.kind == "delivered"
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"
    alice.close()
    bob.close()


def test_block_drops_held_key(relay):
    now, alice, bob, a, b = _pair(relay)
    _ratchet(relay, now, alice, bob, a, b)
    pin = _pin(alice, b)
    assert alice.vault.held(b, pin, now[0]) is not None
    alice.block(b)
    assert alice.vault.held(b, pin, now[0]) is None
    alice.close()
    bob.close()


def test_contact_packets_record_no_held_key(relay):
    now, alice, bob, a, b = _pair(relay)
    assert alice.vault.held(b, _pin(alice, b), now[0]) is None
    assert bob.vault.held(a, _pin(bob, a), now[0]) is None
    assert isinstance(bob.vault.offer(a, now[0]), Prekey)
    alice.close()
    bob.close()
