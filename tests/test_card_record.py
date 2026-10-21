"""Card records (04 § Card record): the signed CardBundle, and its use over a relay
(07 § Descriptors and cards) and by the NetworkClient (set-once handles per home, contact
open/closed)."""

from __future__ import annotations

import copy
import json
from urllib.parse import urlsplit

import pytest

from ace import (
    CORE,
    TEXT,
    ACEError,
    MemoryStore,
    NetworkClient,
    PrekeyVault,
    RelayClient,
    SoftwareIdentity,
    create_card_record,
    create_packet,
    create_permit,
    create_published_agent,
    encode_content,
    is_caip10_account,
    sha256_hex,
    verify_card_bundle,
    verify_kel,
)
from ace.limits import MAX_CARD_RECORD_BYTES
from ace.profiles import CONTACT_TYPE
from ace.store import load_record, write_record

from .fake_relay import FakeRelay
from .helpers import NOW, Clock, raises

RELAY = "https://relay.test"
SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"


def alice_card(**extra):
    identity = SoftwareIdentity.generate(now=NOW - 10)
    kw = {
        "home": RELAY,
        "handle": "alice",
        "card": {"name": "Alice"},
        "pay": [SOL],
        "contact": "open",
        "listed": False,
        "now": NOW,
        **extra,
    }
    return identity, create_card_record(identity, **kw)


def with_record(bundle: dict, **patch) -> dict:
    return {"kel": bundle["kel"], "card": {**bundle["card"], **patch}}


# --- the record ---------------------------------------------------------------------------


def test_round_trips_a_signed_card():
    identity, bundle = alice_card()
    v = verify_card_bundle(bundle, now=NOW)
    assert v.ace_id == identity.get_ace_id()
    assert v.handle == "alice" and v.record["handle"] == "alice"
    assert v.contact == "open"
    assert v.pay == [SOL]
    assert v.state.ace_id == identity.get_ace_id()
    # no expiry: a year later it still verifies
    assert verify_card_bundle(bundle, now=NOW + 365 * 86400 - 1).listed is False
    with raises("invalid_authorization"):
        verify_card_bundle(with_record(bundle, listed=True), now=NOW)


def test_rejects_unknown_member():
    _, bundle = alice_card()
    with raises("invalid_authorization"):
        verify_card_bundle(with_record(bundle, visibility="public"), now=NOW)
    with raises("invalid_authorization"):
        verify_card_bundle({**bundle, "extra": 1}, now=NOW)
    with raises("invalid_authorization"):
        verify_card_bundle(with_record(bundle, contact="public"), now=NOW)


def test_rejects_9_pay_accounts():
    _, bundle = alice_card()
    nine = [f"eip155:1:0x{str(i).rjust(40, '0')}" for i in range(9)]
    with raises("invalid_authorization"):
        verify_card_bundle(with_record(bundle, pay=nine), now=NOW)
    with raises("invalid_authorization"):
        alice_card(pay=nine)
    with raises("invalid_authorization"):
        alice_card(pay=[])


def test_rejects_duplicate_pay():
    _, bundle = alice_card()
    with raises("invalid_authorization"):
        verify_card_bundle(with_record(bundle, pay=[SOL, SOL]), now=NOW)


def test_rejects_bad_caip10():
    _, bundle = alice_card()
    assert is_caip10_account(SOL)
    assert not is_caip10_account("solana:7xKX")
    with raises("invalid_authorization"):
        verify_card_bundle(with_record(bundle, pay=["solana:7xKX"]), now=NOW)


def test_rejects_oversized_record():
    _, bundle = alice_card()
    big = with_record(bundle, card={"name": "Alice", "description": "x" * MAX_CARD_RECORD_BYTES})
    with raises("invalid_authorization") as info:
        verify_card_bundle(big, now=NOW)
    assert "16384" in info.value.message


def test_rejects_a_future_issued_at_a_bad_home_and_a_bad_handle():
    _, bundle = alice_card(now=NOW + 301)
    with raises("invalid_authorization"):
        verify_card_bundle(bundle, now=NOW)
    with raises("invalid_authorization"):
        alice_card(home="https://Relay.test/")
    with raises("invalid_authorization"):
        alice_card(handle="Al")


def test_card_signed_by_superseded_key_is_stale():
    identity, bundle = alice_card()
    identity.delegate(now=NOW)
    with raises("stale_peer_binding"):
        verify_card_bundle({"kel": identity.get_kel(), "card": bundle["card"]}, now=NOW)


# --- over the relay -----------------------------------------------------------------------


class World:
    """A fake relay and NetworkClients sharing one settable clock."""

    def __init__(self) -> None:
        self.clock = Clock()
        self.relay = FakeRelay(clock=self.clock)
        self.host = urlsplit(self.relay.url).netloc
        self.clients: list[NetworkClient] = []

    def rc(self) -> RelayClient:
        return RelayClient(self.relay.url, allow_loopback=True, clock=self.clock)

    def agent(self, *, publish: bool = True, **kw) -> NetworkClient:
        identity = SoftwareIdentity.generate(now=self.clock.now - 10)
        c = NetworkClient.open(
            identity,
            MemoryStore(),
            self.rc(),
            PrekeyVault(clock=self.clock),
            clock=self.clock,
            **kw,
        )
        self.clients.append(c)
        if publish:
            c.publish()
        return c

    def card(self, client: NetworkClient, *, home: str | None = None, **kw) -> dict:
        kw = {"contact": "closed", "listed": False, "now": self.clock.now + 1, **kw}
        return create_card_record(
            client.identity, home=home or self.relay.url, allow_loopback_relays=True, **kw
        )

    def close(self) -> None:
        for c in self.clients:
            c.close()
        self.relay.close()


@pytest.fixture
def world():
    w = World()
    yield w
    w.close()


def test_resolve_handle_rejects_foreign_home(world):
    alice = world.agent(contact="open")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    # A relay serving, under @alice@<this relay>, a record whose home is another relay.
    foreign = world.card(alice, home="https://relay.b", handle="alice", contact="open")
    world.relay.cards[a] = foreign
    world.relay.handles["alice"] = a
    with raises("unknown_peer"):
        bob.lookup_card(f"@alice@{world.host}")
    # also when the relay itself serves it (the client checks home and handle)
    world.relay.raw_responses["/v1/handles/alice"] = (
        200,
        json.dumps(foreign).encode(),
        "application/json",
    )
    with raises("unknown_peer"):
        bob.lookup_card(f"@alice@{world.host}")
    with raises("unknown_peer"):
        world.rc().handle("alice")


def test_pinned_handle_mismatch_is_invalid_authorization(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    assert bob.lookup_card(f"@alice@{world.host}").handle == "alice"
    # A record of the same identity without the pinned handle (a conformant relay refuses it).
    world.relay.cards[a] = world.card(alice, contact="open")
    with raises("invalid_authorization"):
        bob.lookup_card(a)


def test_handles_are_set_once_another_or_none_is_refused_and_a_taken_one_is_handle_taken(world):
    alice = world.agent(handle="alice")
    mallory = world.agent()
    rc = world.rc()
    t = world.clock.now
    with raises("relay_rejected") as info:
        rc.publish_card(world.card(alice, handle="alice2", now=t + 1))
    assert info.value.relay_code == "invalid_argument"
    with raises("relay_rejected") as info:
        rc.publish_card(world.card(alice, now=t + 2))
    assert info.value.relay_code == "invalid_argument"
    with raises("relay_rejected") as info:
        rc.publish_card(world.card(mallory, handle="alice", now=t + 3))
    assert info.value.relay_code == "handle_taken"
    rc.publish_card(world.card(alice, handle="alice", now=t + 4))
    assert rc.handle("alice").ace_id == alice.identity.get_ace_id()


def test_a_handle_lookup_is_checked_against_the_handle_pin_too(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    assert bob.lookup(f"@alice@{world.host}").ace_id == a  # pins a -> alice
    # A relay that binds a second handle to the same identity at the same home.
    world.relay.cards[a] = world.card(alice, handle="alice2", contact="open")
    world.relay.handles["alice2"] = a
    with raises("invalid_authorization"):
        bob.lookup(f"@alice2@{world.host}")
    with raises("invalid_authorization"):
        bob.lookup_card(f"@alice2@{world.host}")


def test_moving_home_keeps_the_old_binding_resolves_unknown_peer_and_never_reassigns(world):
    alice = world.agent(handle="alice")
    mallory = world.agent()
    bob = world.agent()
    a = alice.identity.get_ace_id()
    assert bob.lookup_card(f"@alice@{world.host}").handle == "alice"  # bob pins alice here
    rc = world.rc()
    rc.publish_card(world.card(alice, home="https://relay-b.test"))
    assert rc.card(a).home == "https://relay-b.test"
    assert world.relay.handles["alice"] == a
    with raises("unknown_peer"):
        rc.handle("alice")
    with raises("relay_rejected") as info:
        rc.publish_card(world.card(mallory, handle="alice", now=world.clock.now + 2))
    assert info.value.relay_code == "handle_taken"
    # a client that pinned alice at the old home accepts the record at the new home
    assert bob.lookup_card(a).home == "https://relay-b.test"


def test_lookup_card_pins_the_kel_before_trusting_the_card(world):
    alice = world.agent(contact="open", pay=[SOL])
    a = alice.identity.get_ace_id()
    old = world.relay.cards[a]
    # A new dlg replaces the signing key (say, stolen); the owner re-signs the card.
    world.clock.now += 10
    alice.identity.delegate(now=world.clock.now)
    alice.maintain()
    # A relay replays the record signed under the superseded delegation, with its KEL prefix.
    world.relay.raw_responses[f"/v1/card/{a}"] = (200, json.dumps(old).encode(), "application/json")
    bob = world.agent()
    assert bob.peers.state(a) is None
    with raises("stale_peer_binding"):
        bob.lookup_card(a)
    # The KEL was pinned from the descriptor lookup, before the card was checked.
    assert len(bob.peers.state(a).events) == len(alice.identity.get_kel())


def test_lookup_card_falls_back_to_the_bundle_kel_when_no_live_descriptor(world):
    alice = world.agent(contact="open", handle="alice", pay=[SOL])
    a = alice.identity.get_ace_id()
    # Alice is offline past her descriptor's lifetime: the relay serves her card but no descriptor.
    world.clock.now += 8 * 86400
    with raises("unknown_peer"):
        world.rc().descriptor(a)
    for target in (a, f"@alice@{world.host}"):
        bob = world.agent()
        v = bob.lookup_card(target)
        assert v.kel_live is False
        assert (v.ace_id, v.handle, v.pay) == (a, "alice", [SOL])
        # The bundle's KEL is pinned, under the same rules as a descriptor's.
        assert (
            bob.peers.state(a).last_hash
            == verify_kel(alice.identity.get_kel(), world.clock.now).last_hash
        )
        # The card pin still applies: a rollback is refused.
        world.relay.cards[a] = world.card(
            alice, handle="alice", contact="closed", now=v.issued_at - 1
        )
        with raises("stale_descriptor"):
            bob.lookup_card(target)
        world.relay.cards[a] = v.bundle
    # Any other descriptor failure (here a tampered one) still fails the lookup, pinning nothing.
    carol = world.agent()
    tampered = copy.deepcopy(world.relay.descriptors[a])
    tampered["descriptor"]["expiresAt"] = world.clock.now + 3600
    world.relay.descriptors[a] = tampered
    with raises("relay_protocol_error"):
        carol.lookup_card(a)
    assert carol.peers.state(a) is None


def test_kel_live_is_true_with_a_live_descriptor(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    assert bob.lookup_card(alice.identity.get_ace_id()).kel_live is True
    carol = world.agent()
    assert carol.lookup_card(f"@alice@{world.host}").kel_live is True


def test_a_handle_lookup_reuses_the_card_record_it_resolved_through(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    del world.relay.requests[:]
    agent, card = bob.lookup_with_card(f"@alice@{world.host}")
    assert agent.ace_id == alice.identity.get_ace_id()
    assert card.contact == "open" and card.kel_live is True
    bob.connect(f"@alice@{world.host}", profile=TEXT.id)
    paths = [p for _, p in world.relay.requests]
    assert [p for p in paths if p.startswith("/v1/card/")] == []
    assert len([p for p in paths if p.startswith("/v1/handles/")]) == 2
    # By ACE ID, the card record is looked up after the descriptor.
    assert bob.lookup_with_card(alice.identity.get_ace_id())[1].handle == "alice"


def test_a_relay_serving_an_unverifiable_document_is_relay_protocol_error(world):
    # Never a verdict on the peer: a conformant relay refused it on input.
    alice = world.agent(contact="open", handle="alice")
    a = alice.identity.get_ace_id()
    world.relay.cards[a] = with_record(world.relay.cards[a], listed=True)  # signature broken
    with raises("relay_protocol_error"):
        world.rc().card(a)
    with raises("relay_protocol_error"):
        world.rc().handle("alice")


def test_accepting_an_expired_source_pins_its_kel_unconfirmed_until_a_descriptor_confirms(world):
    alice = world.agent(contact="open")
    bob = world.agent(publish=False)
    b = bob.identity.get_ace_id()
    world.clock.now = bob.publish()["descriptor"]["expiresAt"] - 3601
    bob.connect(alice.identity.get_ace_id(), profile=TEXT.id)
    alice.pull()
    assert [r.from_id for r in alice.requests()] == [b]
    # Bob goes offline past his descriptor's lifetime: the held request outlives its source.
    world.clock.now += 7200
    del world.relay.descriptors[b]
    with raises("unknown_peer"):
        alice.accept(b)
    assert alice.peers.state(b) is not None
    assert alice.lookup_card(b).kel_live is False
    # Bob republishes: the next card lookup sees a live descriptor and confirms the pin, durably.
    bob.publish()
    assert alice.lookup_card(b).kel_live is True
    del world.relay.descriptors[b]
    assert alice.lookup_card(b).kel_live is True


def test_unparseable_pin_is_storage_failed(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    bob.lookup_card(f"@alice@{world.host}")
    # A damaged pin is a storage failure, never "no pin" (which would accept a rollback).
    card_pin = f"network/handles/{sha256_hex(a)}.json"
    owner_pin = f"network/handle-owners/{sha256_hex(f'{world.relay.url} alice')}.json"
    for key in (card_pin, owner_pin):
        good = bob.store.read(key)
        assert good is not None
        for bad in (b"not json", b"[]", b"null", b'"x"'):
            bob.store.write(key, bad)
            with raises("storage_failed"):
                bob.lookup_card(f"@alice@{world.host}")
        bob.store.write(key, good)
    assert bob.lookup_card(f"@alice@{world.host}").ace_id == a


def reopened(world, client: NetworkClient) -> NetworkClient:
    c = NetworkClient.open(
        client.identity, client.store, world.rc(), client.vault, receive=False, clock=world.clock
    )
    world.clients.append(c)
    return c


def test_fallback_pinned_kel_stays_kel_live_false_on_later_lookups(world):
    alice = world.agent(contact="open", handle="alice")
    a = alice.identity.get_ace_id()
    world.clock.now += 8 * 86400
    bob = world.agent()
    assert bob.lookup_card(a).kel_live is False
    # The pin exists now, but no live descriptor ever confirmed it: every later lookup says so.
    assert bob.lookup_card(a).kel_live is False
    assert bob.lookup_card(f"@alice@{world.host}").kel_live is False
    assert reopened(world, bob).lookup_card(a).kel_live is False


def test_a_later_live_descriptor_confirms_a_fallback_pinned_kel(world):
    alice = world.agent(contact="open", handle="alice")
    a = alice.identity.get_ace_id()
    world.clock.now += 8 * 86400
    bob = world.agent()
    assert bob.lookup_card(f"@alice@{world.host}").kel_live is False
    # Alice comes back online: her new descriptor reconciles with the pin and confirms it.
    alice.publish()
    assert bob.lookup_card(f"@alice@{world.host}").kel_live is True
    # Confirmed for good, durably: even after she goes offline again.
    world.clock.now += 8 * 86400
    assert bob.lookup_card(a).kel_live is True
    assert reopened(world, bob).lookup_card(a).kel_live is True


def test_transient_on_one_route_plus_unknown_peer_on_another_does_not_fall_back(world):
    relay_b = FakeRelay(clock=world.clock)
    try:
        alice = world.agent(contact="open")
        a = alice.identity.get_ace_id()
        path = f"/v1/descriptor/{a}"
        # Without a pin, an unreachable home relay is a failure, never "no live descriptor".
        carol = world.agent()
        world.relay.inject.append((path, 503, "internal_error", {}))
        with pytest.raises(ACEError) as info:
            carol.lookup_card(a)
        assert info.value.is_transient
        assert carol.peers.state(a) is None
        # Alice's descriptor names relay B first; her home relay has lost it, so bob pins her
        # card's KEL.
        two_routes = create_published_agent(
            alice.identity,
            relays=[relay_b.url, world.relay.url],
            prekey=alice.vault.current(world.clock.now),
            profiles=alice.profiles.entries(),
            now=world.clock.now,
            allow_loopback_relays=True,
        )
        del world.relay.descriptors[a]
        bob = world.agent(
            relay_factory=lambda url: RelayClient(url, allow_loopback=True, clock=world.clock)
        )
        assert bob.lookup_card(a).kel_live is False
        bob.import_agent(two_routes)  # shared out of band; it expires before bob looks again
        # Self-signed, not served by a relay: it does not confirm the pin.
        assert bob.peers.kel_live(a) is False
        world.clock.now += 8 * 86400
        # Relay B is unreachable and the home relay answers unknown_peer: the lookup fails.
        relay_b.inject.append((path, 503, "internal_error", {}))
        with pytest.raises(ACEError) as info:
            bob.lookup_card(a)
        assert info.value.is_transient
        # Both routes answering unknown_peer: no live descriptor, still not confirmed.
        assert bob.lookup_card(a).kel_live is False
    finally:
        relay_b.close()


def test_pin_missing_required_fields_is_storage_failed(world):
    alice = world.agent(contact="open", handle="alice")
    a = alice.identity.get_ace_id()
    bob = world.agent()
    seen = bob.lookup_card(f"@alice@{world.host}")
    card_pin = f"network/handles/{sha256_hex(a)}.json"
    owner_pin = f"network/handle-owners/{sha256_hex(f'{world.relay.url} alice')}.json"
    full = {"home": world.relay.url, "handle": "alice", "issuedAt": seen.issued_at, "digest": "x"}
    cases = [(card_pin, {})]
    cases += [
        (card_pin, {k: v for k, v in full.items() if k != m})
        for m in ("issuedAt", "digest", "home")
    ]
    cases += [(owner_pin, {"home": world.relay.url, "handle": "alice"})]
    for key, bad in cases:
        good = bob.store.read(key)
        write_record(bob.store, key, bad)
        with raises("storage_failed"):
            bob.lookup_card(f"@alice@{world.host}")
        bob.store.write(key, good)
    # A peer record whose live-confirmation flag is not a boolean.
    world.clock.now += 8 * 86400
    carol = world.agent()
    assert carol.lookup_card(a).kel_live is False
    peer_key = f"peers/{sha256_hex(a)}.json"
    write_record(carol.store, peer_key, {**load_record(carol.store, peer_key), "kelLive": None})
    with raises("storage_failed"):
        carol.lookup_card(a)


def test_handle_resolving_to_a_new_ace_id_is_invalid_authorization(world):
    alice = world.agent(contact="open", handle="alice")
    mallory = world.agent(contact="open")
    bob = world.agent()
    m = mallory.identity.get_ace_id()
    assert bob.lookup_card(f"@alice@{world.host}").ace_id == alice.identity.get_ace_id()
    # The relay rebinds the handle to another identity (bindings are permanent: detectable).
    world.relay.cards[m] = world.card(mallory, handle="alice", contact="open")
    world.relay.handles["alice"] = m
    with raises("invalid_authorization"):
        bob.lookup_card(f"@alice@{world.host}")
    with raises("invalid_authorization"):
        bob.lookup(f"@alice@{world.host}")
    # The reverse pin is durable.
    again = NetworkClient.open(
        bob.identity, bob.store, world.rc(), bob.vault, receive=False, clock=world.clock
    )
    with raises("invalid_authorization"):
        again.lookup_card(f"@alice@{world.host}")
    again.close()


def test_refused_card_leaves_descriptor_unpublished(world):
    world.agent(handle="alice")
    late = world.agent(publish=False, handle="alice")
    late_id = late.identity.get_ace_id()
    with raises("relay_rejected") as info:
        late.publish()
    assert info.value.relay_code == "handle_taken"
    assert late_id not in world.relay.cards
    assert late_id not in world.relay.descriptors


def test_a_new_dlg_re_signs_the_card_at_upkeep(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    before = bob.lookup_card(a).record["signature"]["seq"]
    world.clock.now += 10
    alice.identity.delegate(now=world.clock.now)
    alice.maintain()
    after = bob.lookup_card(a)
    assert after.record["signature"]["seq"] > before
    assert after.handle == "alice"


def test_older_card_is_rejected_after_a_newer_one(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    seen = bob.lookup_card(a)
    # A relay rolling back to an older record (contact closed) is refused on every path.
    world.relay.cards[a] = world.card(
        alice, handle="alice", pay=[SOL], contact="closed", now=seen.issued_at - 1
    )
    with raises("stale_descriptor"):
        bob.lookup_card(a)
    with raises("stale_descriptor"):
        bob.lookup_card(f"@alice@{world.host}")
    with raises("stale_descriptor"):
        bob.lookup(f"@alice@{world.host}")


def test_equal_issued_at_with_different_claims_is_rejected(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    seen = bob.lookup_card(a)
    assert bob.lookup_card(a).record == seen.record  # the identical record again is fine
    world.relay.cards[a] = world.card(
        alice, handle="alice", contact="open", listed=True, now=seen.issued_at
    )
    with raises("stale_descriptor"):
        bob.lookup_card(a)


def test_newer_card_updates_the_pin(world):
    alice = world.agent(contact="open", handle="alice")
    bob = world.agent()
    a = alice.identity.get_ace_id()
    first = world.relay.cards[a]
    bob.lookup_card(a)
    world.relay.cards[a] = world.card(
        alice, handle="alice", pay=[SOL], contact="closed", now=first["card"]["issuedAt"] + 5
    )
    assert bob.lookup_card(a).contact == "closed"
    # the pin moved to the newer record and persists in the store: the first one is now a rollback
    world.relay.cards[a] = first
    with raises("stale_descriptor"):
        bob.lookup_card(a)
    again = NetworkClient.open(
        bob.identity, bob.store, world.rc(), bob.vault, receive=False, clock=world.clock
    )
    with raises("stale_descriptor"):
        again.lookup_card(a)


def test_no_card_means_closed(world):
    # Bob is configured open but has published only a descriptor, no card record.
    bob = world.agent(contact="open", publish=False)
    b = bob.identity.get_ace_id()
    bob.relay.register(bob.identity)
    desc = create_published_agent(
        bob.identity,
        relays=[world.relay.url],
        prekey=bob.vault.current(world.clock.now),
        profiles=bob.profiles.entries(),
        now=world.clock.now,
        allow_loopback_relays=True,
    )
    bob.relay.publish(desc)
    alice = world.agent()
    alice.import_agent(desc)
    # connect refuses: no card record means closed
    with raises("not_permitted"):
        alice.connect(b, profile=TEXT.id)
    # a stranger's contact request that reaches bob anyway is dropped by the endpoint
    body = {
        "kind": "request",
        "profile": TEXT.id,
        "note": "",
        "source": alice.publish(),
        "permit": create_permit(alice.identity, b, now=world.clock.now),
    }
    plaintext = encode_content(CONTACT_TYPE, CORE.messages[CONTACT_TYPE].digest, body)
    packet = create_packet(
        alice.identity, b, desc["descriptor"]["prekey"], plaintext, timestamp=world.clock.now
    )
    world.relay.enqueue_raw(b, packet)
    [outcome] = bob.pull()
    assert outcome.kind == "dropped"
    assert outcome.error.code == "not_permitted"
    assert "sender is not admitted" in outcome.error.message
    assert bob.requests() == []


def test_closed_agent_can_still_connect_to_an_open_owner(world):
    b = world.agent(contact="open")
    a = world.agent()  # closed by default
    b_id, a_id = b.identity.get_ace_id(), a.identity.get_ace_id()
    a.connect(b_id, profile=TEXT.id)
    b.pull()
    assert [r.from_id for r in b.requests()] == [a_id]
    # and the closed one is not reachable by strangers
    with raises("not_permitted"):
        b.connect(a_id, profile=TEXT.id)


def test_a_relay_served_descriptor_by_any_lookup_confirms_a_fallback_pinned_kel(world):
    alice = world.agent(contact="open", handle="alice")
    a = alice.identity.get_ace_id()
    world.clock.now += 8 * 86400
    bob = world.agent()
    assert bob.lookup_card(a).kel_live is False
    # Alice is back: bob's plain descriptor lookup (no card lookup) fetches it from her relay and
    # confirms the pin, so the next card lookup needs no descriptor request of its own.
    alice.publish()
    bob.agent(a)
    assert bob.peers.kel_live(a) is True
    world.relay.requests.clear()
    assert bob.lookup_card(a).kel_live is True
    assert [p for _, p in world.relay.requests if p.startswith("/v1/descriptor/")] == []
