"""Regression tests for the 2026-10-13 security review fixes."""

import json
import threading

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
    SoftwareIdentity,
    create_packet,
    create_permit,
    encode_content,
    sha256_hex,
)
from tests.helpers import PEER_PREKEY, Clock, raises, wire
from tests.test_inbox import World
from tests.test_network import client

CONTACT_DIGEST = CORE.messages["ace:contact:1"].digest


def _pause_decision_lock(monkeypatch, store):
    """Stop just before the receiving thread takes the shared admission-decision lock."""
    ready, resume = threading.Event(), threading.Event()
    real = store.lock

    def lock(name, timeout=10.0):
        if name == "network-blocks" and threading.current_thread().name == "contact-race":
            ready.set()
            assert resume.wait(10)
        return real(name, timeout)

    monkeypatch.setattr(store, "lock", lock)
    return ready, resume


@pytest.fixture
def pair(relay):
    alice, bob = client(relay, contact="open", listed=True, handle="alice"), client(relay)
    yield alice, bob
    alice.close()
    bob.close()


@pytest.mark.parametrize("kind", ["accepted", "rejected", "request"])
def test_contact_cannot_undo_a_block_completed_by_another_client(relay, pair, monkeypatch, kind):
    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    source = alice.publish()
    bob.import_agent(source)
    bob.peers.set_status(a, "pending", TEXT.id)
    body = {"kind": kind, "profile": TEXT.id, "note": "", "source": source}
    if kind != "rejected":
        body["permit"] = create_permit(alice.identity, b)
    packet = create_packet(
        alice.identity,
        b,
        bob.vault.current(),
        encode_content("ace:contact:1", CONTACT_DIGEST, body, prekey=PEER_PREKEY),
        timestamp=bob._now(),
    )
    actor = NetworkClient.open(bob.identity, bob.store, bob.relay, bob.vault, receive=False)
    ready, resume = _pause_decision_lock(monkeypatch, bob.store)
    outcomes, errors = [], []

    def receive():
        try:
            outcomes.append(bob.inbox.receive(wire(packet)))
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=receive, name="contact-race")
    worker.start()
    try:
        assert ready.wait(10)
        actor.block(a)
        assert bob.peers.is_blocked(a)
    finally:
        resume.set()
        worker.join(10)
        actor.close()
    assert not worker.is_alive() and not errors
    assert outcomes[0].ack
    assert bob.peers.is_blocked(a)
    assert bob.requests() == [] and bob.peers.permit_from(a) is None


def test_connect_rechecks_a_block_after_resolving_the_contact(relay, pair, monkeypatch):
    alice, bob = pair
    a = alice.identity.get_ace_id()
    actor = NetworkClient.open(bob.identity, bob.store, bob.relay, bob.vault, receive=False)
    ready, resume = _pause_decision_lock(monkeypatch, bob.store)
    errors = []

    def connect():
        try:
            bob.connect(a, profile=TEXT.id)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=connect, name="contact-race")
    worker.start()
    try:
        assert ready.wait(10)
        actor.block(a)
    finally:
        resume.set()
        worker.join(10)
        actor.close()
    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], ACEError)
    assert errors[0].code == "not_permitted" and bob.peers.is_blocked(a)


def test_receipt_failures_share_persistent_fetch_budget_and_release_the_queue(relay, pair):
    alice, bob = pair
    a = alice.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    first = bob.send(a, "ace:text:1", {"message": "first"})
    second = bob.send(a, "ace:text:1", {"message": "second"})
    attempts = []

    def reply(out):
        attempts.append(out)
        if len(attempts) <= 3:
            raise ACEError("relay_unavailable", "sender relay unreachable")

    alice._reply = reply
    assert [o.kind for o in alice.pull()] == ["retry"]
    assert len(alice.store.list("inbox/attempts/")) == 1
    received = alice.received
    alice.close()
    restarted = NetworkClient.open(
        alice.identity, alice.store, alice.relay, alice.vault, on_message=received.append
    )
    restarted._reply = reply
    try:
        assert [o.kind for o in restarted.pull()] == ["retry"]
        assert len(relay.streams[a]) == 2
        # the message was processed: its last receipt failure acks it without a quarantine
        # record (C3); the sender's retry would get a duplicate's receipt
        assert [o.kind for o in restarted.pull()] == ["duplicate", "delivered"]
        assert restarted.relay.inbox(restarted.identity).entries == []
        assert restarted.inbox.quarantined() == []
        assert restarted.store.list("inbox/attempts/") == []
        assert [m.message_id for m in received if m.type == "ace:text:1"] == [first, second]
    finally:
        restarted.close()


def test_successful_receipt_clears_previous_transport_failures(relay, pair):
    alice, bob = pair
    a = alice.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    bob.send(a, "ace:text:1", {"message": "hi"})
    real = alice._reply

    def fail(out):
        raise ACEError("relay_unavailable", "temporary")

    alice._reply = fail
    assert alice.pull()[0].kind == "retry"
    alice._reply = real
    assert alice.pull()[0].kind == "duplicate"
    assert alice.store.list("inbox/attempts/") == []
    assert alice.inbox.quarantined() == []


def test_relay_send_refuses_a_permit_for_another_packet():
    clock = Clock()
    a, b, c = (SoftwareIdentity.generate(now=clock.now) for _ in range(3))
    vault = PrekeyVault()
    pkt = create_packet(
        a,
        b.get_ace_id(),
        vault.current(clock.now),
        encode_content(
            "ace:text:1", TEXT.messages["ace:text:1"].digest, {"message": "x"}, prekey=PEER_PREKEY
        ),
        timestamp=clock.now,
    )
    wrong = create_permit(
        c, a.get_ace_id(), now=clock.now
    )  # issued by someone other than packet.to
    with raises("invalid_argument"):
        RelayClient("https://relay.example").send(pkt, wrong)


def test_lookup_never_presents_a_permit_without_the_issuers_descriptor(relay, pair):
    alice, bob = pair
    bob.peers.save_permit(create_permit(alice.identity, bob.identity.get_ace_id()))
    # descriptors resolve anonymously by ACE ID: a permit is never presented for resolution
    assert not hasattr(RelayClient, "resolve")
    a = alice.identity.get_ace_id()
    assert bob.lookup(a).ace_id == a
    assert bob.agent(a, refresh=True).ace_id == a
    assert all(path != "/v1/descriptor/resolve" for _, path in relay.requests)


def test_unpinned_admitted_peer_contact_is_authenticated_by_its_source():
    w = World(admitted=False)
    w.b.peers.set_status(w.a.id, "pending", "ace:text:1")
    assert w.b.peers.state(w.a.id) is None
    body = {
        "kind": "accepted",
        "profile": "ace:text:1",
        "note": "",
        "source": w.a.source(profiles=[TEXT.descriptor()]),
        "permit": create_permit(w.a.identity, w.b.id, now=w.clock.now),
    }
    out = w.inbox.receive(wire(w.packet("ace:contact:1", body, CONTACT_DIGEST)))
    assert out.kind == "delivered" and out.message.body["kind"] == "accepted"


def test_corrupt_peer_record_fails_closed():
    w = World()
    w.b.store.write(f"peers/{sha256_hex(w.a.id)}.json", b'{"version":1,"aceId":"x"}')
    with raises("storage_failed"):
        w.b.peers.is_admitted(w.a.id)
    out = w.inbox.receive(wire(w.packet()))
    assert out.kind == "retry" and not out.ack


def test_outbox_merges_an_unknown_prekey_receipt_during_flight_and_refuses_corrupt_entries():
    w = World()
    outbox, clock = w.outbox, w.clock
    mid = outbox.enqueue(w.b.id, "ace:text:1", {"message": "x"})
    agent = w.a.peers.agent(w.b.id)
    outbox.deliver(mid, lambda p, a: None, lambda to, refresh: agent)
    rejected = outbox.get(mid).prekey
    clock.now += 60

    def transport(
        packet, a
    ):  # the receipt for the first attempt arrives while this one is in flight
        outbox.settle(mid, "rejected", "unknown_prekey", sender=w.b.id, prekey=rejected)

    outbox.deliver(mid, transport, lambda to, refresh: agent)
    e = outbox.get(mid)
    assert (
        e.refresh
        and e.prekey == rejected
        and e.code == "unknown_prekey"
        and e.next_attempt_at <= clock.now
    )
    w.a.store.write(f"outbox/{sha256_hex(mid)}.json", b'{"version":1,"messageId":5}')
    with raises("storage_failed"):
        outbox.entries()


def test_send_only_client_takes_no_receive_lock(relay):
    a = client(relay)
    sender = NetworkClient.open(a.identity, a.store, a.relay, a.vault, receive=False)
    assert sender.inbox is None
    with raises("invalid_argument"):
        sender.pull()
    sender.publish()
    sender.close()
    a.close()


def test_registration_timestamp_is_persisted_across_clients(relay):
    identity = SoftwareIdentity.generate()
    store = MemoryStore()
    c1 = RelayClient(relay.url, allow_loopback=True, store=store)
    c2 = RelayClient(relay.url, allow_loopback=True, store=store)
    c1.register(identity)
    (key,) = store.list("relay/registration/")
    first = json.loads(store.read(key))["timestamp"]
    c2.register(identity)  # another client in the same second: still strictly increasing
    assert json.loads(store.read(key))["timestamp"] > first


def test_directory_skips_entries_failing_verification_or_the_query(relay, pair, monkeypatch):
    alice, bob = pair
    good = bob.relay.card(alice.identity.get_ace_id()).bundle
    forged = json.loads(json.dumps(good))
    forged["card"]["card"] = {"description": "Mallory"}  # changed after signing
    unlisted = bob.relay.card(bob.identity.get_ace_id()).bundle  # valid but not listed
    page = {"cards": [forged, unlisted, good], "cursor": None}
    monkeypatch.setattr(bob.relay, "_call", lambda *a, **k: page)
    cards, _ = bob.relay.directory()
    assert [x.ace_id for x in cards] == [alice.identity.get_ace_id()]  # the bad entries are skipped
    assert bob.relay.directory(tag="absent")[0] == []  # not carrying the tag


def test_contact_profile_and_errors_are_core():
    assert Profiles().message_digest("ace:contact:1") == CONTACT_DIGEST
    with pytest.raises(ACEError):
        Outbox(SoftwareIdentity.generate(), MemoryStore(), Profiles()).enqueue(
            "ace:sha256:" + "1" * 64, "ace:receipt:1", {}
        )


# --- 2026-10-14 receive-path authentication audit ---------------------------------------


def test_packet_naming_an_older_delegation_than_the_pin_is_dropped_without_refresh():
    w = World()
    old = w.packet()  # signed under a's first delegation
    w.a.identity.delegate(now=w.clock.now)
    w.b.peers.pin(w.a.identity.get_kel())
    out = w.inbox.receive(wire(old))
    assert out.kind == "dropped" and out.error.code == "stale_peer_binding"
    assert w.refreshes == [] and w.got == []


def test_stranger_contact_is_checked_against_an_existing_pin():
    w = World(admitted=False, contact="open")

    def request():
        body = {
            "kind": "request",
            "profile": "ace:text:1",
            "note": "",
            "source": w.a.source(profiles=[TEXT.descriptor()]),
            "permit": create_permit(w.a.identity, w.b.id, now=w.clock.now),
        }
        return w.packet("ace:contact:1", body, CONTACT_DIGEST)

    stale = request()
    w.a.identity.delegate(now=w.clock.now)
    w.b.peers.pin(w.a.identity.get_kel())  # imported, not admitted: still a stranger
    out = w.inbox.receive(wire(stale))
    assert out.kind == "dropped" and out.error.code == "stale_peer_binding"
    assert w.inbox.receive(wire(request())).kind == "delivered"


def test_pinned_kel_must_name_the_record_identity():
    w = World()
    other = SoftwareIdentity.generate()
    key = f"peers/{sha256_hex(w.a.id)}.json"
    rec = json.loads(w.b.store.read(key))
    rec["kel"] = other.get_kel()
    w.b.store.write(key, json.dumps(rec).encode())
    with raises("storage_failed"):
        w.b.peers.state(w.a.id)


def test_a_contact_from_a_pinned_peer_cannot_carry_another_identity_as_source():
    from tests.helpers import Party

    w = World()
    m = Party(w.clock)
    body = {
        "kind": "request",
        "profile": "ace:text:1",
        "note": "",
        "source": m.source(profiles=[TEXT.descriptor()]),
        "permit": create_permit(w.a.identity, w.b.id, now=w.clock.now),
    }
    out = w.inbox.receive(wire(w.packet("ace:contact:1", body, CONTACT_DIGEST)))
    assert out.kind == "dropped" and out.error.code in ("invalid_authorization", "kel_conflict")


def test_receipt_from_another_peer_does_not_settle_the_entry():
    w = World()
    mid = w.outbox.enqueue(w.b.id, "ace:text:1", {"message": "x"})
    w.outbox.settle(mid, "delivered", sender=SoftwareIdentity.generate().get_ace_id())
    assert w.outbox.get(mid).status == "pending"
    w.outbox.settle(mid, "delivered", sender=w.b.id)
    assert w.outbox.get(mid).status == "delivered"


# --- 2026-10-16 codex fixes: cached descriptors are bound to the current KEL pins ---


def test_a_rotated_holders_older_issued_descriptor_replaces_the_superseded_keys_one():
    from tests.helpers import NOW, Party

    clock = Clock()
    holder, viewer = Party(clock), Party(clock)
    attacker = PrekeyVault()
    # the old signing key (compromised) publishes an attacker prekey at the top of the skew window
    evil = holder.source(prekey=attacker.current(NOW), now=NOW + 300)
    holder.identity.delegate(now=NOW + 1)
    clock.now = NOW + 2
    viewer.peers.adopt(evil, NOW)
    viewer.peers.adopt(holder.source(), clock.now)  # smaller issuedAt, newer KEL: replaces
    assert viewer.peers.agent(holder.id).prekey.id == holder.vault.current().id
    ob = Outbox(viewer.identity, viewer.store, Profiles(), clock=clock)
    mid = ob.enqueue(holder.id, "ace:text:1", {"message": "hi"})
    ob.deliver(mid, lambda p, ag: None, lambda ace_id, refresh=False: viewer.peers.agent(ace_id))
    assert ob.get(mid).prekey == holder.vault.current().id != attacker.current().id


def test_a_kel_adopted_elsewhere_makes_the_cached_descriptor_stale(relay, pair):
    alice, bob = pair  # alice open, bob closed
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    old_prekey = bob.vault.current().id
    # bob changes signing key; alice learns the new KEL through another path (not a descriptor)
    bob.identity.delegate()
    bob.relay.register(bob.identity)
    alice.peers.pin(bob.identity.get_kel())
    assert alice.peers.agent(b) is None and alice.peers.cached(b).prekey.id == old_prekey
    # bob has not republished: refreshing fails, and the stale descriptor is never used
    posted = []
    real_post = alice._post
    alice._post = lambda packet, agent, *rest, **_: (  # a retry also passes ``admission``
        posted.append(packet),
        real_post(packet, agent, *rest),
    )
    with raises("not_permitted"):  # bob's permit is from his superseded key
        alice.send(b, "ace:text:1", {"message": "hi"})
    mid = alice.outbox.enqueue(b, "ace:text:1", {"message": "hi"})  # queued before the change
    alice.outbox.deliver(mid, alice._post, alice._resolve)
    assert posted == [] and alice.outbox.get(mid).code is not None
    with pytest.raises(ACEError):
        alice.lookup(b)
    # bob republishes with a fresh prekey and pushes a fresh permit: the next attempt refreshes
    bob.vault.rotate(bob._now())
    bob.maintain()
    alice.pull()
    alice.outbox.deliver(mid, alice._post, alice._resolve, force=True)
    assert [p["messageId"] for p in posted if p["messageId"] == mid] == [mid]
    assert alice.outbox.get(mid).prekey == bob.vault.current().id != old_prekey
    bob.pull()
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"


def test_a_delegation_issuer_key_change_makes_the_cached_descriptor_stale():
    from ace import issue_delegation
    from tests.helpers import NOW, Party

    clock = Clock()
    alice, dave, viewer = Party(clock), Party(clock), Party(clock)
    viewer.peers.pin(dave.identity.get_kel(), NOW)
    src = alice.source(delegations=[issue_delegation(dave.identity, alice.id, now=NOW - 5)])
    viewer.peers.adopt(src, NOW)
    assert viewer.peers.agent(alice.id).delegations == (dave.id,)
    dave.identity.delegate(now=NOW + 1)  # dave replaces its signing key
    viewer.peers.pin(dave.identity.get_kel(), NOW + 1)
    assert viewer.peers.agent(alice.id) is None  # stale: refresh, never report the delegation


def test_a_kel_stale_descriptors_relays_never_receive_the_permit(relay, pair):
    from ace import create_published_agent

    alice, bob = pair  # alice open, bob closed: alice holds bob's permit
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    assert alice.peers.permit_from(b) is not None
    evil_relay = "https://attacker.example"
    # bob's (later compromised) old key names an attacker relay; then bob changes key
    evil = create_published_agent(
        bob.identity,
        relays=[evil_relay],
        prekey=PrekeyVault().current(),
        profiles=[TEXT.descriptor()],
        now=bob._now() + 1,
    )
    alice.import_agent(evil)
    bob.identity.delegate()
    alice.peers.pin(bob.identity.get_kel())
    calls = []

    class Recorder:
        base_url = evil_relay

        def descriptor(self, ace_id):
            calls.append(("descriptor", None))
            raise ACEError("unknown_peer", "nope")

    real = alice._factory
    alice._factory = lambda url: Recorder() if url == evil_relay else real(url)
    with pytest.raises(ACEError):
        alice.lookup(b)
    assert calls == [("descriptor", None)]  # anonymous only, never the permit


def test_an_expired_newer_descriptor_is_never_rolled_back_under_the_same_kel():
    from tests.helpers import NOW, Party

    clock = Clock()
    holder, viewer = Party(clock), Party(clock)
    older = holder.source(now=NOW)  # the longest lifetime
    newer = holder.source(now=NOW + 10, lifetime=60)
    clock.now = NOW + 10
    viewer.peers.adopt(older, clock.now)
    viewer.peers.adopt(newer, clock.now)
    # while the newer one is usable, an older revision returns it
    assert viewer.peers.adopt(older, clock.now).descriptor == newer["descriptor"]
    clock.now = NOW + 100  # the newer one has expired, the older one has not
    with raises("stale_peer_binding"):
        viewer.peers.adopt(older, clock.now)
    assert viewer.peers.cached(holder.id).descriptor == newer["descriptor"]


def test_a_permit_from_the_issuers_superseded_key_is_never_presented(relay, pair):
    alice, bob = pair  # alice open, bob closed: alice holds bob's permit
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    assert alice.peers.permit_from(b) is not None
    # bob changes its signing key and republishes; alice imports it (bound to the advanced pin)
    bob.identity.delegate()
    bob.relay.register(bob.identity)
    alice.import_agent(bob.publish(force=True))
    assert alice.peers.agent(b) is not None
    calls = []
    for name in ("send", "descriptor"):
        real = getattr(alice.relay, name)

        def spy(first, *permit, _name=name, _real=real):
            calls.append((_name, *permit))
            return _real(first, *permit)

        setattr(alice.relay, name, spy)
    with raises("not_permitted"):  # no permit valid under bob's current pin
        alice.send(b, "ace:text:1", {"message": "hi"})
    mid = alice.outbox.enqueue(b, "ace:text:1", {"message": "hi"})  # queued before the change
    alice.outbox.deliver(mid, alice._post, alice._resolve)
    # the refresh is the anonymous lookup (bob is resolvable by ACE ID), never with the permit
    assert alice.agent(b, refresh=True).ace_id == b
    assert calls == [("send", None), ("descriptor",)], calls  # never the permit


def test_a_cached_descriptor_never_reports_an_expired_delegation():
    from ace import issue_delegation
    from tests.helpers import NOW, Party

    clock = Clock()
    alice, dave, viewer = Party(clock), Party(clock), Party(clock)
    src = alice.source(
        delegations=[issue_delegation(dave.identity, alice.id, now=NOW - 5, lifetime=60)]
    )
    viewer.peers.adopt(src, NOW)
    assert viewer.peers.agent(alice.id).delegations == (dave.id,)
    clock.now = NOW + 55  # the credential expired; the descriptor has not
    cached = viewer.peers.agent(alice.id)
    assert cached is not None and cached.delegations == () and cached.source == src


def test_an_admitted_peers_contact_source_extends_the_pin_but_does_not_confirm_it_live():
    w = World()
    w.a.identity.delegate(now=w.clock.now)  # signed under a newer delegation than b's pin
    body = {
        "kind": "request",
        "profile": "ace:text:1",
        "note": "",
        "source": w.a.source(profiles=[TEXT.descriptor()]),
        "permit": create_permit(w.a.identity, w.b.id, now=w.clock.now),
    }
    # The refresh does not reach the packet's delegation: the contact authenticates by its source.
    out = w.inbox.receive(wire(w.packet("ace:contact:1", body, CONTACT_DIGEST)))
    assert out.kind == "delivered" and w.refreshes == [w.a.id]
    assert list(w.b.peers.state(w.a.id).events) == w.a.identity.get_kel()
    # Self-signed by the sender: a holder of a superseded key could sign one too.
    assert w.b.peers.kel_live(w.a.id) is False
