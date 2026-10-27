"""Admission recovery (05 § Admission recovery, 06 § Recovery candidates, 03 § Private content)."""

import json
import time

import pytest

from ace import (
    CORE,
    TEXT,
    ACEError,
    MemoryStore,
    NetworkClient,
    Outbox,
    PrekeyVault,
    Profiles,
    RelayClient,
    create_packet,
    create_permit,
    decode_content,
    decode_packet,
    decrypt_packet,
    encode_content,
)
from ace._encoding import canonical_state_bytes, to_base64
from ace.limits import MAX_PLAINTEXT_BYTES
from ace.outbox import Admission, _key
from ace.store import load_record, write_record
from tests.helpers import PEER_PREKEY, Clock, Party, raises, wire
from tests.test_inbox import TEXT_DIGEST, World

RECEIPT_DIGEST = CORE.messages["ace:receipt:1"].digest


# --- private content shape (03 § Private content) ---------------------------------------------


def _adm():
    return {"proof": {"issuer": "x"}, "permit": {"issuer": "y"}, "source": {"kel": []}}


def test_admission_is_encoded_when_present_and_decoded_as_the_closed_triple():
    raw = encode_content(
        "ace:text:1", TEXT_DIGEST, {"message": "hi"}, admission=_adm(), prekey=PEER_PREKEY
    )
    assert json.loads(raw)["admission"] == _adm()
    assert decode_content(raw)["admission"] == _adm()
    assert "admission" not in json.loads(
        encode_content("ace:text:1", TEXT_DIGEST, {}, prekey=PEER_PREKEY)
    )


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {"proof": {}},
        {"proof": {}, "permit": {}},
        {"proof": {}, "permit": {}, "source": {}, "extra": {}},
        {"proof": "permit", "permit": {}, "source": {}},
        {"proof": {}, "permit": None, "source": {}},
        {"proof": {}, "permit": {}, "source": []},
    ],
)
def test_any_other_admission_shape_is_invalid_body(bad):
    content = {"type": "ace:text:1", "schemaDigest": TEXT_DIGEST, "body": {}, "admission": bad}
    with raises("invalid_body"):
        decode_content(json.dumps(content).encode())
    if bad is not None:
        with raises("invalid_argument"):
            encode_content("ace:text:1", TEXT_DIGEST, {}, admission=bad, prekey=PEER_PREKEY)


def test_admission_on_a_receipt_or_contact_is_invalid():
    for type_ in ("ace:receipt:1", "ace:contact:1"):
        content = {"type": type_, "schemaDigest": TEXT_DIGEST, "body": {}, "admission": _adm()}
        with raises("invalid_body"):
            decode_content(json.dumps(content).encode())
        with raises("invalid_argument"):
            encode_content(type_, TEXT_DIGEST, {}, admission=_adm(), prekey=PEER_PREKEY)


# --- Outbox sender (05 § Admission recovery 1, 06 § Outbox) -----------------------------------


def _outbox(fresh=True):
    clock = Clock()
    a, b = Party(clock), Party(clock)
    a.peers.adopt(b.source())
    hooked = []

    def admission(to, now):
        assert to == b.id
        hooked.append(now)
        return Admission(_adm(), fresh)

    ob = Outbox(a.identity, a.store, Profiles(), admission=admission, clock=clock)
    return clock, a, b, ob, hooked


def _content(packet, b):
    return json.loads(decrypt_packet(decode_packet(packet), b.vault))


def test_retries_refresh_the_descriptor_and_carry_admission_never_stored():
    clock, a, b, ob, hooked = _outbox()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    sent, refreshes = [], []

    def resolve(ace_id, refresh=False):
        refreshes.append(refresh)
        return a.peers.agent(ace_id)

    def transport(packet, agent, admission=None):
        sent.append((packet, admission))

    ob.deliver(mid, transport, resolve)
    clock.now += 60
    ob.deliver(mid, transport, resolve)
    assert refreshes == [False, True]  # every attempt after the first refreshes
    (first, none), (second, adm) = sent
    assert none is None and "admission" not in _content(first, b)
    assert adm.content == _content(second, b)["admission"] == _adm() and adm.fresh
    assert hooked == [clock.now]  # asked on the retry only
    assert "admission" not in ob.get(mid).content


def test_admission_is_left_out_when_the_content_would_exceed_the_limit():
    clock, a, b, ob, _ = _outbox()
    base = len(encode_content("ace:text:1", TEXT_DIGEST, {"message": ""}, prekey=PEER_PREKEY))
    mid = ob.enqueue(b.id, "ace:text:1", {"message": ""})
    big = {"message": "x" * (MAX_PLAINTEXT_BYTES - base - 10)}  # beyond the text schema: white-box
    e = ob.get(mid)
    write_record(a.store, _key(mid), e.replace(content={**e.content, "body": big}).to_dict())
    sent = []
    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731

    def transport(packet, agent, admission=None):
        sent.append((packet, admission))

    ob.deliver(mid, transport, resolve)
    clock.now += 60
    assert ob.deliver(mid, transport, resolve).result == "sent"
    packet, adm = sent[1]
    assert adm is None and "admission" not in _content(packet, b)


# --- receiver: recovery candidates (05 § Admission recovery 2-3) ------------------------------


def _recovering(**kw):
    """B lost its table: A is a stranger to it. Recovery never looks anything up."""

    def refresh(ace_id):
        raise AssertionError("recovery performs no lookup")

    return World(admitted=False, refresh=refresh, **kw)


def _packet(w, admission, *, type_="ace:text:1", digest=TEXT_DIGEST, body=None, sender=None):
    sender = sender or w.a
    content = {
        "type": type_,
        "schemaDigest": digest,
        "body": {"message": "hi"} if body is None else body,
        "prekey": to_base64(PEER_PREKEY),
    }
    plain = canonical_state_bytes({**content, "admission": admission})  # also where encode refuses
    return create_packet(sender.identity, w.b.id, w.b.vault.current(), plain, timestamp=w.clock.now)


def _adm_of(w, *, proof_issuer=None, proof_subject=None, permit_issuer=None, source=None):
    now = w.clock.now
    issuer = proof_issuer or w.b
    proof = create_permit(issuer.identity, (proof_subject or w.a).id, now=now)
    permit = create_permit((permit_issuer or w.a).identity, w.b.id, now=now)
    return {"proof": proof, "permit": permit, "source": source or w.a.source()}


def _untouched(w):
    """Nothing pinned, recorded or handed over."""
    return w.b.peers.get(w.a.id) is None and w.got == []


def test_a_valid_proof_restores_the_sender_from_its_source_without_any_lookup():
    w = _recovering()
    adm = _adm_of(w)
    out = w.inbox.receive(wire(_packet(w, adm)))
    assert out.kind == "delivered"
    rec = w.b.peers.get(w.a.id)
    assert rec.status == "admitted" and rec.profile is None
    assert w.b.peers.state(w.a.id).ace_id == w.a.id and w.b.peers.current(w.a.id) is not None
    assert w.b.peers.permit_from(w.a.id) == adm["permit"]
    assert w.got[0].body == {"message": "hi"} and not hasattr(w.got[0], "admission")
    for key in w.b.store.list("inbox/"):  # never journaled
        assert b"admission" not in w.b.store.read(key)
    assert w.b.peers.issued(w.a.id) == adm["proof"]  # the proof is the newest issued
    body = w.receipt_body(out)
    assert body["outcome"] == "delivered" and "permit" not in body  # no needless renewal


def test_an_older_proof_never_replaces_a_newer_issued_permit():
    w = _recovering()
    newer = create_permit(w.b.identity, w.a.id, now=w.clock.now + 5)
    w.b.peers.note_issued(w.a.id, newer)
    assert w.inbox.receive(wire(_packet(w, _adm_of(w)))).kind == "delivered"
    assert w.b.peers.issued(w.a.id) == newer


def test_an_uninstalled_type_is_dropped_before_recording():
    w = _recovering()
    out = w.inbox.receive(wire(_packet(w, _adm_of(w), digest="0" * 64)))
    assert out.kind == "dropped" and out.error.code == "unsupported_schema"
    assert _untouched(w)


@pytest.mark.parametrize("contact", ["closed", "open"])
def test_a_forged_or_invalid_proof_is_dropped_and_nothing_is_admitted(contact):
    w = _recovering(contact=contact)
    c = Party(w.clock)
    forged = _adm_of(w)
    forged["proof"] = {**forged["proof"], "expiresAt": forged["proof"]["expiresAt"] + 1}
    cases = [
        forged,  # signature no longer covers the claims
        _adm_of(w, proof_issuer=c),  # not issued by us
        _adm_of(w, proof_subject=c),  # issued to someone else
        {"proof": {}, "permit": {}, "source": {}},
    ]
    for adm in cases:
        out = w.inbox.receive(wire(_packet(w, adm)))
        assert out.kind == "dropped" and out.error.code == "not_permitted"
    expired = _adm_of(w)
    expired["proof"] = create_permit(w.b.identity, w.a.id, now=w.clock.now, lifetime=60)
    w.clock.now += 60
    out = w.inbox.receive(wire(_packet(w, expired)))
    assert out.kind == "dropped"
    assert _untouched(w)


def test_an_invalid_reply_permit_is_dropped_invalid_authorization_and_pins_nothing():
    w = _recovering()
    out = w.inbox.receive(wire(_packet(w, _adm_of(w, permit_issuer=Party(w.clock)))))
    assert out.kind == "dropped" and out.error.code == "invalid_authorization"
    assert _untouched(w)


def test_a_forged_packet_is_dropped_and_pins_nothing():
    w = _recovering()
    adm = _adm_of(w)
    p = _packet(w, adm)
    other = _packet(w, adm, sender=Party(w.clock))  # a valid signature, by someone else
    p["signature"] = other["signature"]
    out = w.inbox.receive(wire(p))
    assert out.kind == "dropped" and out.error.code == "invalid_signature"
    assert _untouched(w)


def test_a_source_naming_another_identity_is_dropped():
    w = _recovering()
    c = Party(w.clock)
    out = w.inbox.receive(wire(_packet(w, _adm_of(w, source=c.source()))))
    assert out.kind == "dropped" and out.error.code == "invalid_authorization"
    assert _untouched(w) and w.b.peers.get(c.id) is None


def test_a_source_older_than_the_pin_is_refused():
    w = _recovering()
    old = w.a.source()
    w.clock.now += 1
    w.a.identity.delegate(now=w.clock.now)
    w.b.peers.pin(w.a.identity.get_kel(), w.clock.now)  # a pinned stranger, newer than `old`
    pinned = w.b.peers.state(w.a.id).last_hash
    out = w.inbox.receive(wire(_packet(w, _adm_of(w, source=old))))
    assert out.kind == "dropped"
    rec = w.b.peers.get(w.a.id)
    assert rec.status is None and rec.agent is None and w.got == []
    assert w.b.peers.state(w.a.id).last_hash == pinned
    # its current source restores it under the pin
    assert w.inbox.receive(wire(_packet(w, _adm_of(w)))).kind == "delivered"
    assert w.b.peers.status(w.a.id) == "admitted"


def test_a_blocked_row_is_dropped_proof_or_not():
    w = _recovering()
    w.b.peers.set_status(w.a.id, "blocked")
    out = w.inbox.receive(wire(_packet(w, _adm_of(w))))
    assert out.kind == "dropped" and out.error.code == "not_permitted"
    assert w.b.peers.is_blocked(w.a.id) and w.b.peers.permit_from(w.a.id) is None
    assert w.b.peers.state(w.a.id) is None and w.got == []


def test_a_block_during_recovery_wins_and_changes_no_pin():
    w = _recovering()
    real = w.b.peers.restore

    def restore(*a, **kw):  # a local block lands after the checks, before the sender is recorded
        w.b.peers.set_status(w.a.id, "blocked")
        return real(*a, **kw)

    w.b.peers.restore = restore
    out = w.inbox.receive(wire(_packet(w, _adm_of(w))))
    assert out.kind == "dropped" and out.error.code == "not_permitted"
    assert w.b.peers.is_blocked(w.a.id) and w.b.peers.permit_from(w.a.id) is None
    assert w.b.peers.state(w.a.id) is None


def test_a_pending_row_without_a_pin_is_recovered_and_keeps_its_profile():
    w = _recovering()
    w.b.peers.set_status(w.a.id, "pending", TEXT.id)
    out = w.inbox.receive(wire(_packet(w, _adm_of(w))))
    assert out.kind == "delivered"
    rec = w.b.peers.get(w.a.id)
    assert rec.status == "admitted" and rec.profile == TEXT.id


def test_an_invalid_body_is_rejected_once_the_sender_is_recorded():
    w = _recovering()
    out = w.inbox.receive(wire(_packet(w, _adm_of(w), body={"message": 1})))
    assert out.kind == "rejected" and out.error.code == "invalid_body"
    assert w.b.peers.status(w.a.id) == "admitted" and out.receipt is not None


def test_receipts_and_contacts_carrying_admission_are_dropped():
    w = _recovering()
    receipt = {"messageId": "6f9619ff-8b86-4011-b42d-00c04fc964ff", "outcome": "delivered"}
    out = w.inbox.receive(
        wire(_packet(w, _adm_of(w), type_="ace:receipt:1", digest=RECEIPT_DIGEST, body=receipt))
    )
    assert out.kind == "dropped" and out.error.code == "invalid_body"
    assert _untouched(w)
    pinned = World()  # an authenticated sender's receipt carrying it is dropped too
    p = _packet(pinned, _adm_of(pinned), type_="ace:receipt:1", digest=RECEIPT_DIGEST, body=receipt)
    out = pinned.inbox.receive(wire(p))
    assert out.kind == "dropped" and out.error.code == "invalid_body"


# --- receiver: authenticated sender (05 § Admission recovery 4) -------------------------------


def test_a_pinned_sender_s_proof_is_ignored_and_a_valid_permit_held():
    w = World()
    adm = _adm_of(w, proof_issuer=Party(w.clock))  # an invalid proof is ignored
    out = w.inbox.receive(wire(_packet(w, adm)))
    assert out.kind == "delivered" and w.b.peers.permit_from(w.a.id) == adm["permit"]
    w.clock.now += 1
    bad = _adm_of(w, permit_issuer=Party(w.clock))
    out = w.inbox.receive(wire(_packet(w, bad)))
    assert out.kind == "delivered" and w.b.peers.permit_from(w.a.id) == adm["permit"]
    assert w.refreshes == []


# --- end to end: a reinstall (05 § Admission recovery) ----------------------------------------


def _client(relay, now, identity=None, **kw):
    from ace import SoftwareIdentity

    received = []
    nc = NetworkClient.open(
        identity or SoftwareIdentity.generate(),
        MemoryStore(),
        RelayClient(relay.url, allow_loopback=True),
        PrekeyVault(clock=lambda: now[0]),
        on_message=received.append,
        clock=lambda: now[0],
        **kw,
    )
    nc.publish()
    nc.received = received
    return nc


def test_a_reinstalled_peer_recovers_its_admitted_peer_from_the_next_retry(relay):
    now = [int(time.time())]
    alice = _client(relay, now, contact="open", listed=True)
    bob = _client(relay, now)  # closed
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    alice.accept(b)
    bob.pull()
    first = alice.send(b, "ace:text:1", {"message": "before"})
    bob.pull()
    alice.pull()
    assert alice.outbox.get(first).status == "delivered"

    # Bob loses its store; the identity survives, a new prekey and descriptor are published.
    bob.close()
    now[0] += 5
    bob = _client(relay, now, identity=bob.identity)
    assert bob.peers.get(a) is None

    mid = alice.send(b, "ace:text:1", {"message": "after the reinstall"})
    (out,) = bob.pull()
    assert out.kind == "dropped"  # attempt 1: the old prekey, a stranger without proof
    assert bob.peers.get(a) is None and alice.outbox.get(mid).status == "pending"

    now[0] += 61
    (attempt,) = alice.flush()  # attempt 2: refreshed descriptor, carries admission
    assert attempt.result == "sent"
    (out,) = bob.pull()
    assert out.kind == "delivered"
    assert bob.peers.status(a) == "admitted" and bob.peers.permit_from(a) is not None
    assert [m.body["message"] for m in bob.received] == ["after the reinstall"]
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"

    reply = bob.send(a, "ace:text:1", {"message": "back"})
    alice.pull()
    bob.pull()
    assert bob.outbox.get(reply).status == "delivered"
    assert [m.body["message"] for m in alice.received if m.type == "ace:text:1"] == ["back"]
    alice.close()
    bob.close()


def test_recovery_across_relays_needs_no_lookup(relay):
    """Relays do not federate: Bob (homed on another relay) recovers Alice from her source."""
    from .fake_relay import FakeRelay

    other = FakeRelay()
    now = [int(time.time())]
    alice = _client(relay, now, contact="open", listed=True)
    bob = _client(other, now)
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(alice.publish(), profile=TEXT.id)
    alice.pull()
    alice.accept(b)
    bob.pull()
    assert bob.peers.status(a) == "admitted"
    bob.close()
    now[0] += 5
    bob = _client(other, now, identity=bob.identity)
    with raises("unknown_peer"):  # Bob's home relay cannot resolve Alice
        bob.agent(a)
    mid = alice.send(b, "ace:text:1", {"message": "across"})
    assert bob.pull()[0].kind == "dropped"
    now[0] += 61
    alice.flush()
    (out,) = bob.pull()
    assert out.kind == "delivered" and bob.peers.status(a) == "admitted"
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"
    reply = bob.send(a, "ace:text:1", {"message": "back across"})
    alice.pull()
    bob.pull()
    assert bob.outbox.get(reply).status == "delivered"
    alice.close()
    bob.close()
    other.close()


def test_a_failing_publish_never_fails_a_retry(relay):
    """The source is the stored PublishedAgent (no publish) while unexpired, else left out."""
    from ace.network import _SELF_KEY

    now = [int(time.time())]
    alice = _client(relay, now, contact="open", listed=True)
    bob = _client(relay, now)
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    alice.accept(b)
    bob.pull()
    published = alice.publish()

    def down(**kw):
        raise ACEError("relay_unavailable", "home relay down")

    alice.publish = down
    assert alice._admission(b, now[0]).content["source"] == published
    alice.store.delete(_SELF_KEY)
    assert alice._admission(b, now[0]) is None
    relay.inject.append(("/v1/send", 503, "internal_error", {}))
    mid = alice.send(b, "ace:text:1", {"message": "hi"})
    now[0] += 61
    (attempt,) = alice.flush()
    assert attempt.result == "sent"
    bob.pull()
    assert [m.body for m in bob.received if m.type == "ace:text:1"] == [{"message": "hi"}]
    assert alice.outbox.get(mid).status == "pending"
    alice.close()
    bob.close()


# --- blocks (05 § Blocks) ---------------------------------------------------------------------


def test_block_revisions_follow_the_clock_and_outrank_lost_records(relay):
    now = [int(time.time())]
    alice = _client(relay, now)
    bob = _client(relay, now)
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.block(b)
    assert relay.blocks[(a, b)] == (True, now[0])
    alice.unblock(b)  # within the same second: previous + 1
    assert relay.blocks[(a, b)] == (False, now[0] + 1)
    # A reinstall lost the block records: a decision in that second is stale at the relay,
    # which holds a later one, and counts as synced; a later decision outranks it.
    alice.close()
    now[0] += 1  # republishing needs a newer issuedAt
    again = _client(relay, now, identity=alice.identity)
    again.block(b)
    assert relay.blocks[(a, b)] == (False, now[0])
    (key,) = again.store.list("network/blocks/")
    assert load_record(again.store, key)["unsynced"] is None
    now[0] += 10
    again.unblock(b)
    again.block(b)
    assert relay.blocks[(a, b)] == (True, now[0] + 1)
    again.close()
    bob.close()
