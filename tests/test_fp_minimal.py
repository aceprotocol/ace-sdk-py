"""Review-focus regressions of the fp-minimal revision (A4-A6, A12, review I1, I3, I9)."""

from __future__ import annotations

import pytest

from ace import (
    CORE,
    TEXT,
    Inbox,
    MemoryStore,
    NetworkClient,
    PrekeyVault,
    Profiles,
    RelayClient,
    SoftwareIdentity,
    create_packet,
    create_permit,
    encode_content,
)
from ace.limits import CONTACT_REQUEST_TTL_SECONDS, OFFLINE_WINDOW_SECONDS
from ace.profiles import CONTACT_TYPE

from .fake_relay import FakeRelay
from .helpers import PEER_PREKEY, Clock, Party, raises, wire

TEXT_DIGEST = TEXT.messages["ace:text:1"].digest


def _text(a: Party, b: Party, ts: int) -> bytes:
    plain = encode_content("ace:text:1", TEXT_DIGEST, {"message": "hi"}, prekey=PEER_PREKEY)
    return wire(create_packet(a.identity, b.id, b.vault.current(), plain, timestamp=ts))


def _inbox(b: Party, clock: Clock, got=None, **kw) -> Inbox:
    on_message = (lambda m: None) if got is None else got if callable(got) else got.append
    return Inbox.open(
        b.identity, b.store, b.vault, b.peers, Profiles(), on_message=on_message, clock=clock, **kw
    )


def _admitted_pair(clock: Clock, **source) -> tuple[Party, Party]:
    a, b = Party(clock, born=clock.now - 60), Party(clock, born=clock.now - 60)
    b.peers.adopt(a.source(**source))
    b.peers.set_status(a.id, "admitted")
    return a, b


@pytest.fixture
def world():
    clock = Clock()
    relay = FakeRelay(clock=clock)
    clients: list[NetworkClient] = []

    def net(**kw) -> NetworkClient:
        identity = SoftwareIdentity.generate(now=clock.now)
        rc = RelayClient(relay.url, allow_loopback=True, clock=clock)
        received: list = []
        c = NetworkClient.open(
            identity,
            MemoryStore(),
            rc,
            PrekeyVault(clock=clock),
            on_message=received.append,
            clock=clock,
            **kw,
        )
        c.publish()  # registers on demand
        c.received = received  # type: ignore[attr-defined]
        clients.append(c)
        return c

    yield clock, relay, net
    for c in clients:
        c.close()
    relay.close()


# --- A4: beyond the replay horizon is dropped, never receipted -----------------------------


def test_beyond_horizon_dropped_without_receipt():
    clock = Clock()
    a, b = _admitted_pair(clock)
    inbox = _inbox(b, clock, capacity=16)  # sender quota Q = 1
    first, second = _text(a, b, clock.now - 20), _text(a, b, clock.now - 10)
    assert inbox.receive(first).kind == "delivered"
    assert inbox.receive(second).kind == "delivered"  # evicts `first`: H[a] = now - 20
    out = inbox.receive(_text(a, b, clock.now - 20))
    assert (out.kind, out.ack, out.receipt) == ("dropped", True, None)
    assert out.error.code == "replay_horizon"
    again = inbox.receive(first)  # evicted: beyond the horizon too, not a duplicate
    assert (again.kind, again.receipt, again.error.code) == ("dropped", None, "replay_horizon")
    dup = inbox.receive(second)
    assert dup.kind == "duplicate" and dup.receipt is not None  # a duplicate is receipted
    inbox.close()


# --- A5: no contact window; outgoing pending entries expire -------------------------------


def test_contact_request_accepted_after_hours(world):
    clock, _, net = world
    alice, bob = net(contact="open", listed=True), net()
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    clock.now += 3 * 3600  # alice is offline for hours
    alice.pull()
    assert [r.from_id for r in alice.requests()] == [b]
    clock.now += 3 * 3600
    alice.accept(b)
    bob.pull()
    assert bob.peers.status(a) == "admitted" and alice.peers.status(b) == "admitted"


def test_pending_entry_expires_and_a_late_accepted_is_ignored(world):
    clock, _, net = world
    alice, bob = net(contact="open", listed=True), net()
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    sent_at = clock.now
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    clock.now += CONTACT_REQUEST_TTL_SECONDS - 10
    alice.accept(b)  # just before alice's held request expires
    assert bob.peers.status(a) == "pending"
    clock.now = sent_at + OFFLINE_WINDOW_SECONDS  # bob's pending entry has expired
    assert bob.peers.status(a) is None
    bob.pull()
    assert bob.peers.status(a) is None


# --- A6: a back-dated signature from a key past notAfter ----------------------------------


def test_backdated_after_not_after_dropped():
    clock = Clock()
    a, b = Party(clock), Party(clock)
    a.identity.delegate(now=clock.now, not_after=clock.now + 100)
    b.peers.adopt(a.source())
    b.peers.set_status(a.id, "admitted")
    inbox = _inbox(b, clock)
    packet = _text(a, b, clock.now + 50)  # signed while live
    clock.now += 200  # but the key is no longer usable now
    out = inbox.receive(packet)
    assert (out.kind, out.receipt) == ("dropped", None)
    assert out.error.code == "stale_peer_binding"
    inbox.close()


# --- I3: a permit counts as issued only once the packet carrying it was sent ----------------


def test_refresh_permits_retried_after_transient(world):
    clock, relay, net = world
    alice, bob = net(contact="open", listed=True, accept_profiles=[TEXT.id]), net()
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    assert alice.peers.status(b) == bob.peers.status(a) == "admitted"
    clock.now += 10
    bob.identity.delegate(now=clock.now)
    seq = bob.identity.get_signing_seq()
    relay.inject.append(("/v1/send", 503, "internal_error", {}))
    bob.maintain()  # the permit push hits a 503
    assert bob.peers.issued(a)["signature"]["seq"] != seq
    bob.maintain()  # retried
    assert bob.peers.issued(a)["signature"]["seq"] == seq
    alice.pull()
    assert alice.peers.permit_from(b)["signature"]["seq"] == seq


# --- block is local-first; maintain re-syncs it ---------------------------------------------


def test_block_local_first_when_relay_down(world):
    _, relay, net = world
    alice, bob = net(), net()
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    relay.inject.append(("/v1/blocks", 503, "internal_error", {}))
    alice.block(b)  # the relay is down: the local block still holds
    assert alice.peers.is_blocked(b) and (a, b) not in relay.blocks
    alice.maintain()
    assert relay.blocks[(a, b)][0] is True


# --- I1: publish registers again after a signing-key change ---------------------------------


def test_publish_reregisters_after_delegate(world):
    clock, relay, net = world
    alice = net()
    a = alice.identity.get_ace_id()
    clock.now += 10
    alice.identity.delegate(now=clock.now)
    alice.publish(force=True)
    assert relay.states[a].signing.seq == alice.identity.get_signing_seq()
    assert relay.descriptors[a]["kel"] == alice.identity.get_kel()


# --- I9: step 3 without a refresh hook continues as a contact candidate ---------------------


def test_step3_without_refresh_continues_as_candidate():
    clock = Clock()
    a, b = _admitted_pair(clock, profiles=[TEXT.descriptor()])
    got: list = []
    inbox = _inbox(b, clock, got)  # no refresh hook wired
    clock.now += 10
    a.identity.delegate(now=clock.now)
    body = {
        "kind": "request",
        "profile": TEXT.id,
        "note": "",
        "source": a.source(profiles=[TEXT.descriptor()]),
        "permit": create_permit(a.identity, b.id, now=clock.now),
    }
    plain = encode_content(
        CONTACT_TYPE, CORE.messages[CONTACT_TYPE].digest, body, prekey=PEER_PREKEY
    )
    packet = create_packet(a.identity, b.id, b.vault.current(), plain, timestamp=clock.now)
    out = inbox.receive(wire(packet))
    assert out.kind == "delivered" and [m.type for m in got] == [CONTACT_TYPE]
    inbox.close()


# --- review findings: persisted poison counter, hooks, follow, relay policy -----------------


def test_fetch_attempts_survive_reopening_and_the_quarantine_keeps_the_header():
    import json

    from ace._encoding import sha256_hex

    def boom(m):
        raise RuntimeError("host bug")

    clock = Clock()
    a, b = _admitted_pair(clock)
    raw = _text(a, b, clock.now)
    inbox = _inbox(b, clock, boom)
    assert inbox.receive(raw).kind == "retry"
    inbox.close()
    for kind in ("retry", "quarantined"):  # the count persists across restarts
        inbox = _inbox(b, clock, boom)
        assert inbox.receive(raw).kind == kind
        inbox.close()
    (record,) = inbox.quarantined()
    assert record["packet"]["messageId"] == json.loads(raw)["messageId"]
    assert record["fingerprint"] == sha256_hex(raw) and b.store.list("inbox/attempts/") == []


def test_on_receipt_follow_and_the_receipt_permit_counts_once_sent(world):
    import threading

    _, relay, net = world
    seen: list = []
    alice = net(contact="open", listed=True, accept_profiles=[TEXT.id])
    bob = net(on_receipt=lambda frm, body, entry: seen.append((frm, body["outcome"], entry)))
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    mid = bob.send(a, "ace:text:1", {"message": "hi"})
    issued = alice.peers.issued(b)
    stop = threading.Event()
    follow = alice.follow(stop=stop)
    out = next(follow)  # processed, receipted and acknowledged before it is yielded
    stop.set()
    assert out.kind == "delivered" and relay.streams[a] == []
    assert alice.peers.issued(b) == issued  # the permit it still holds is fresh: no renewal
    bob.pull()
    ((frm, outcome, entry),) = seen
    assert (frm, outcome, entry.message_id, entry.status) == (a, "delivered", mid, "delivered")


def test_the_default_foreign_relay_factory_honors_the_loopback_policy():
    clock = Clock()
    relay = FakeRelay(clock=clock)
    try:
        dev = NetworkClient.open(
            SoftwareIdentity.generate(now=clock.now),
            MemoryStore(),
            RelayClient(relay.url, allow_loopback=True, clock=clock),
            PrekeyVault(clock=clock),
            receive=False,
        )
        prod = NetworkClient.open(
            SoftwareIdentity.generate(now=clock.now),
            MemoryStore(),
            RelayClient("https://relay.example"),
            PrekeyVault(),
            receive=False,
        )
        assert dev._relay_for("http://127.0.0.1:1").allow_loopback is True
        assert prod._relay_for("https://other.example").allow_loopback is False
    finally:
        relay.close()


# --- fix round 1 ----------------------------------------------------------------------------


def test_maintain_keeps_a_delivered_entry_visible_for_the_offline_window(world):

    clock, _, net = world
    alice, bob = net(contact="open", listed=True, accept_profiles=[TEXT.id]), net()
    a = alice.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    mid = bob.send(a, "ace:text:1", {"message": "hi"})
    alice.pull()
    bob.pull()  # the receipt settles it at t
    t = clock.now
    clock.now = t + 60
    bob.maintain()
    assert bob.outbox.get(mid).status == "delivered"
    clock.now = t + OFFLINE_WINDOW_SECONDS
    bob.outbox.prune()
    assert bob.outbox.get(mid) is None


def test_an_expired_pending_entry_is_reset_to_a_stranger():
    clock = Clock()
    a, b = Party(clock), Party(clock)
    b.peers.adopt(a.source())
    b.peers.set_status(a.id, "pending", TEXT.id)
    b.peers.save_permit(create_permit(a.identity, b.id, now=clock.now))
    clock.now += OFFLINE_WINDOW_SECONDS - 1  # outlives a held request: the relay's retention
    assert b.peers.status(a.id) == "pending"
    clock.now += 1
    assert b.peers.status(a.id) is None
    rec = b.peers.get(a.id)  # deleted from the admission table, not only reported (05 step 4)
    assert (rec.status, rec.profile) == (None, None)
    assert rec.kel is not None and rec.held_permit is not None  # pin and permit are kept


def test_stale_fetch_attempt_counters_are_reclaimed():

    def boom(m):
        raise RuntimeError("host bug")

    clock = Clock()
    a, b = _admitted_pair(clock)
    inbox = _inbox(b, clock, boom)
    assert inbox.receive(_text(a, b, clock.now)).kind == "retry"
    inbox.close()
    assert len(b.store.list("inbox/attempts/")) == 1
    clock.now += OFFLINE_WINDOW_SECONDS - 1
    _inbox(b, clock, boom).close()  # still within the relay's retention: kept
    assert len(b.store.list("inbox/attempts/")) == 1
    clock.now += 1
    _inbox(b, clock, boom).close()
    assert b.store.list("inbox/attempts/") == []


# --- final review fix wave (F2-F4, F9, F11-F13) ----------------------------------------------


def _admitted_clients(net, **alice_kw):
    alice = net(contact="open", listed=True, accept_profiles=[TEXT.id], **alice_kw)
    bob = net()
    bob.connect(alice.identity.get_ace_id(), profile=TEXT.id)
    alice.pull()
    bob.pull()
    return alice, bob


def test_maintain_runs_every_step_and_raises_the_first_failure(world):
    from ace import ACEError

    clock, relay, net = world
    alice, bob = _admitted_clients(net)
    a = alice.identity.get_ace_id()
    relay.inject.append(("/v1/send", 503, "internal_error", {}))
    mid = bob.send(a, "ace:text:1", {"message": "hi"})
    assert bob.outbox.get(mid).attempts == 1
    clock.now += 61

    def down(**kw):
        raise ACEError("relay_unavailable", "home relay down")

    bob.publish = down
    with pytest.raises(ACEError) as info:
        bob.maintain()
    assert info.value.code == "relay_unavailable"
    assert bob.outbox.get(mid).attempts == 2  # the flush still ran
    alice.pull()
    assert [m.body for m in alice.received if m.type == "ace:text:1"] == [{"message": "hi"}]


def test_send_without_a_permit_from_the_peer_is_not_permitted_and_stores_nothing(world):
    _, relay, net = world
    alice, bob = net(), net()
    b = bob.identity.get_ace_id()
    alice.import_agent(bob.publish())
    invitation = alice.create_invitation(b)  # admitted, yet bob issued alice no permit
    assert alice.peers.status(b) == "admitted"
    with raises("not_permitted"):
        alice.send(b, "ace:text:1", {"message": "too early"})
    assert alice.outbox.entries() == []
    bob.connect(bob.import_invitation(invitation).ace_id, profile=TEXT.id)
    alice.pull()  # auto-accepts the invited peer and keeps its permit
    mid = alice.send(b, "ace:text:1", {"message": "now"})
    assert alice.outbox.get(mid).status == "pending"


def test_block_retries_reuse_the_allocated_revision_and_stale_revision_settles(world):
    _, relay, net = world
    alice, bob = net(), net()
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    relay.inject.append(("/v1/blocks", 503, "internal_error", {}))
    alice.block(b)
    (key,) = alice.store.list("network/blocks/")
    from ace.store import load_record

    revision = load_record(alice.store, key)["revision"]
    relay.inject.append(("/v1/blocks", 503, "internal_error", {}))
    alice.maintain()  # still down
    alice.maintain()
    assert relay.blocks[(a, b)] == (True, revision)  # exactly the allocated revision
    # a relay already holding a later revision settles the block (no endless re-sync)
    relay.inject.append(("/v1/blocks", 503, "internal_error", {}))
    alice.unblock(b)
    alice.block(b)
    relay.blocks[(a, b)] = (False, revision + 10)
    alice.maintain()
    assert load_record(alice.store, key)["unsynced"] is None
    calls = []
    real = alice.relay.set_block
    alice.relay.set_block = lambda *args: (calls.append(args), real(*args))
    alice.maintain()
    assert calls == []


def test_block_and_unblock_interleaved_leave_local_and_relay_state_equal(world):
    _, relay, net = world
    alice, bob = net(), net()
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    real = alice.relay.set_block
    nested = []

    def racing(identity, peer, blocked, revision):
        if blocked and not nested:  # an unblock lands while the block is in flight
            nested.append(revision)
            alice.unblock(peer)
        return real(identity, peer, blocked, revision)

    alice.relay.set_block = racing
    alice.block(b)
    assert alice.peers.status(b) is None
    assert relay.blocks[(a, b)] == (False, nested[0] + 1)
    sent = []
    alice.relay.set_block = lambda *args: (sent.append(args), real(*args))
    alice.maintain()
    assert sent == []  # nothing left to re-sync


def test_pending_expiry_and_block_keep_the_held_permit():
    clock = Clock()
    a, b = Party(clock), Party(clock)
    b.peers.adopt(a.source())
    b.peers.set_status(a.id, "pending", TEXT.id)
    b.peers.save_permit(create_permit(a.identity, b.id, now=clock.now))
    clock.now += OFFLINE_WINDOW_SECONDS
    assert b.peers.status(a.id) is None and b.peers.permit_from(a.id) is not None
    b.peers.set_status(a.id, "blocked")
    assert b.peers.permit_from(a.id) is not None


def test_refresh_permits_uses_a_profile_the_peer_still_lists(world):
    from ace import COMMERCE

    clock, relay, net = world
    both = Profiles((TEXT, COMMERCE))
    alice = net(contact="open", listed=True, accept_profiles=[COMMERCE.id], profiles=both)
    bob = net(profiles=Profiles((TEXT, COMMERCE)))
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=COMMERCE.id)
    alice.pull()
    bob.pull()
    assert bob.peers.get(a).profile == COMMERCE.id
    alice.profiles = Profiles((TEXT,))  # alice drops commerce
    alice.publish(force=True)
    bob.agent(a, refresh=True)
    clock.now += 10
    bob.identity.delegate(now=clock.now)
    real, kinds = bob._contact, []
    bob._contact = lambda kind, profile, *args, **kw: (
        kinds.append((kind, profile)),
        real(kind, profile, *args, **kw),
    )[1]
    bob.maintain()
    assert kinds == [("request", TEXT.id)]
    alice.pull()
    assert alice.peers.permit_from(b)["signature"]["seq"] == bob.identity.get_signing_seq()


def test_post_stops_at_a_permanent_relay_error():
    from types import SimpleNamespace

    from ace import ACEError

    clock = Clock()
    c = NetworkClient(
        SoftwareIdentity.generate(now=clock.now),
        MemoryStore(),
        RelayClient("https://home.example", clock=clock),
        PrekeyVault(clock=clock),
        clock=clock,
    )
    calls = []

    def factory(code):
        def make(url):
            def send(packet, permit):
                calls.append(url)
                raise ACEError(code, "refused")

            return SimpleNamespace(send=send)

        return make

    agent = SimpleNamespace(ace_id="x", relays=["https://r1.example", "https://r2.example"])
    c._factory = factory("not_permitted")
    with pytest.raises(ACEError):
        c._post({}, agent, {})
    assert calls == ["https://r1.example"]
    calls.clear()
    c._factory = factory("relay_unavailable")
    with pytest.raises(ACEError):
        c._post({}, agent, {})
    assert calls == ["https://r1.example", "https://r2.example"]


def test_the_client_advertises_only_its_home_relay(world):
    _, relay, net = world
    alice = net()
    assert alice.publish()["descriptor"]["relays"] == [relay.url]
    with pytest.raises(TypeError):
        net(relays=[relay.url, "https://other.example"])
