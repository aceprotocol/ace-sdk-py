"""Card records (04 § Card record): the signed CardBundle, and its use over a relay
(07 § Descriptors and cards) and by the NetworkClient (set-once handles per home, contact
open/closed)."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import pytest

from ace import (
    CORE,
    TEXT,
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
    verify_card_bundle,
)
from ace.limits import MAX_CARD_RECORD_BYTES
from ace.profiles import CONTACT_TYPE

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
