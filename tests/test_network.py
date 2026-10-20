"""NetworkClient end to end over the fake relay: contact flow, messages, receipts, permits."""

import pytest

from ace import (
    TEXT,
    MemoryStore,
    NetworkClient,
    PrekeyVault,
    RelayClient,
    SoftwareIdentity,
)

from .helpers import raises, retained


def client(relay, **kw):
    identity = SoftwareIdentity.generate()
    received = []
    nc = NetworkClient.open(
        identity,
        MemoryStore(),
        RelayClient(relay.url, allow_loopback=True),
        PrekeyVault(),
        on_message=received.append,
        **kw,
    )
    nc.publish()  # registers on demand
    nc.received = received
    return nc


@pytest.fixture
def pair(relay):
    alice = client(relay, contact="open", listed=True, handle="alice")
    bob = client(relay)
    yield alice, bob
    alice.close()
    bob.close()


def test_contact_flow_messages_and_receipts(relay, pair):
    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    target = bob.lookup(f"@alice@{relay.url.split('://')[1]}")
    assert target.ace_id == a
    bob.connect(a, profile=TEXT.id, note="hi, let's talk")
    assert bob.peers.status(a) == "pending"
    alice.pull()
    # a remote request never changes admission by itself
    assert alice.peers.status(b) is None and [r.from_id for r in alice.requests()] == [b]
    assert alice.requests()[0].note == "hi, let's talk"
    alice.accept(b)
    assert alice.peers.status(b) == "admitted"
    bob.pull()
    assert bob.peers.status(a) == "admitted" and bob.peers.permit_from(a) is not None
    # bob is closed: alice reaches him with his permit
    mid = alice.send(b, "ace:text:1", {"message": "hello bob"})
    assert alice.outbox.get(mid).status == "pending"
    bob.pull()  # delivers and sends the receipt
    assert [m.body for m in bob.received if m.type == "ace:text:1"] == [{"message": "hello bob"}]
    alice.pull()  # applies the receipt
    assert alice.outbox.get(mid).status == "delivered"
    mid2 = bob.send(a, "ace:text:1", {"message": "hello alice"})
    alice.pull()
    bob.pull()
    assert bob.outbox.get(mid2).status == "delivered"
    # relay queues were acknowledged
    assert alice.relay.inbox(alice.identity).entries == []


def test_a_retry_without_a_valid_permit_is_not_permitted_never_permit_less(relay, monkeypatch):
    import time

    now = [int(time.time())]
    alice = client(relay, contact="open", listed=True, clock=lambda: now[0])
    bob = client(relay, clock=lambda: now[0])
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    alice.accept(b)
    bob.pull()
    relay.inject.append(("/v1/send", 503, "unavailable", {}))  # the first attempt fails
    mid = bob.send(a, "ace:text:1", {"message": "hi"})
    assert bob.outbox.get(mid).code == "relay_unavailable"
    monkeypatch.setattr(bob.peers, "presentable_permit", lambda *a, **kw: None)  # it lapsed
    sent = len(relay.sent)
    now[0] += 61
    (attempt,) = bob.flush()
    assert attempt.result == "failed" and attempt.error.code == "not_permitted"
    assert len(relay.sent) == sent and bob.outbox.get(mid).status == "pending"
    alice.close()
    bob.close()


def test_pull_acks_once_through_the_last_final_disposition(relay, pair):
    alice, bob = pair
    a = alice.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    for i in range(3):
        bob.send(a, "ace:text:1", {"message": f"m{i}"})
    acks = []
    real = alice.relay.ack
    alice.relay.ack = lambda identity, through: (acks.append(through), real(identity, through))
    assert [o.kind for o in alice.pull()] == ["delivered"] * 3
    assert len(acks) == 1 and alice.relay.inbox(alice.identity).entries == []


def test_vault_dates_its_first_prekey_with_the_injected_clock():
    vault = PrekeyVault(clock=lambda: 1_700_000_000)
    vault.current()
    assert vault.current_created_at == 1_700_000_000


def test_accept_profiles_rule_and_block(relay, pair):
    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()  # local rule accepts
    assert alice.peers.status(b) == "admitted" and alice.requests() == []
    bob.pull()
    assert bob.peers.status(a) == "admitted"
    alice.block(b)
    assert alice.peers.is_blocked(b)
    mid = bob.send(a, "ace:text:1", {"message": "still there?"})
    att = bob.outbox.get(mid)
    assert att.status == "pending" and att.code == "not_permitted"  # relay refuses blocked sender


def test_private_agents_ignore_strangers(relay):
    carol = client(relay)  # private
    dave = client(relay)
    c = carol.identity.get_ace_id()
    try:
        dave.import_agent(carol.publish())
        with raises("not_permitted"):
            dave.connect(c, profile=TEXT.id)  # a private target needs a permit it issued
        assert carol.pull() == [] and relay.sent == []
    finally:
        carol.close()
        dave.close()


def test_prekey_rotation_on_publish(relay, pair):
    alice, _ = pair
    first = alice.publish()
    created = alice.vault.current_created_at
    alice.vault._state.current.at = created - 86400  # pretend it is a day old
    rotated = alice.publish()
    assert rotated["descriptor"]["prekey"]["id"] != first["descriptor"]["prekey"]["id"]
    assert first["descriptor"]["prekey"]["id"] in retained(alice.vault)


def test_invitation_pairs_two_private_agents_and_import_never_admits(relay):
    import ace
    from ace.invitation import verify_invitation

    # internal, as in sdk-ts: import_invitation verifies, pins and stores the permit
    assert "verify_invitation" not in ace.__all__ and not hasattr(ace, "verify_invitation")

    alice, bob, carol = client(relay), client(relay), client(relay)
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    inv = alice.create_invitation(bob.publish(), profile=TEXT.id)
    assert inv["agent"]["descriptor"]["aceId"] == a
    assert (inv["permit"]["issuer"], inv["permit"]["subject"]) == (a, b)
    assert alice.peers.status(b) == "admitted"
    with raises("invalid_authorization"):  # addressed to bob only
        carol.import_invitation(inv)
    with raises("invalid_authorization"):
        bob.import_invitation({**inv, "extra": 1})
    assert bob.import_invitation(inv).ace_id == a
    assert bob.peers.status(a) is None and bob.peers.permit_from(a) is not None
    bob.connect(a, profile=TEXT.id)
    alice.pull()  # bob is admitted at alice: the request is accepted
    bob.pull()
    assert bob.peers.status(a) == "admitted"
    bob.send(a, "ace:text:1", {"message": "paired"})
    alice.pull()
    assert [m.body["message"] for m in alice.received if m.type == "ace:text:1"] == ["paired"]
    assert (
        verify_invitation(inv, b, now=alice._now(), allow_loopback_relays=True)[1] == inv["permit"]
    )
    with raises("invalid_authorization"):
        verify_invitation(
            {"agent": bob.publish(), "permit": inv["permit"]},
            b,
            now=alice._now(),
            allow_loopback_relays=True,
        )
    for c in (alice, bob, carol):
        c.close()


def test_enqueue_without_any_resolvable_descriptor_is_unknown_peer(relay):
    alice = client(relay)
    b = SoftwareIdentity.generate().get_ace_id()  # never published anywhere
    with raises("unknown_peer"):
        alice.outbox.enqueue(b, "ace:text:1", {"message": "x"})
    assert alice.outbox.entries() == []
    alice.close()


def test_connect_never_clears_a_block_only_unblock_does(relay, pair):
    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.block(b)
    alice.import_agent(bob.publish())
    with raises("not_permitted"):  # the relay refuses the blocked sender
        bob.connect(a, profile=TEXT.id)
    alice.pull()
    assert alice.requests() == [] and alice.peers.is_blocked(b)
    with raises("not_permitted"):  # M1: connect is not an unblock
        alice.connect(b, profile=TEXT.id)
    assert alice.peers.is_blocked(b)
    alice.unblock(b)  # the explicit admission action
    assert alice.peers.status(b) is None
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    assert [r.from_id for r in alice.requests()] == [b]


def test_pending_requests_one_slot_per_sender_ttl_and_oldest_evicted(relay, pair):
    from ace import CORE, PrivateMessage
    from ace.limits import CONTACT_REQUEST_TTL_SECONDS, MAX_PENDING_CONTACT_REQUESTS
    from ace.profiles import CONTACT_TYPE

    alice, _ = pair
    t = [alice._now()]
    alice._clock = lambda: t[0]
    me = alice.identity.get_ace_id()

    def request(sender: str, note: str = "") -> None:
        t[0] += 1
        alice._on_contact(
            PrivateMessage(
                "6f9619ff-8b86-4011-b42d-00c04fc964ff",
                sender,
                me,
                t[0],
                CONTACT_TYPE,
                CORE.messages[CONTACT_TYPE].digest,
                None,
                {"kind": "request", "profile": TEXT.id, "note": note, "source": {}, "permit": {}},
            )
        )

    senders = [f"ace:sha256:{i:064x}" for i in range(1, MAX_PENDING_CONTACT_REQUESTS + 2)]
    for s in senders[:-1]:
        request(s)
    request(senders[0], "again")  # one slot per sender: replaced, now the newest
    assert len(alice.requests()) == MAX_PENDING_CONTACT_REQUESTS
    request(senders[-1])  # full: the oldest (senders[1]) is evicted
    held = [r.from_id for r in alice.requests()]
    assert senders[1] not in held and senders[0] in held and senders[-1] in held
    assert held[-2] == senders[0] and alice.requests()[-2].note == "again"
    t[0] += CONTACT_REQUEST_TTL_SECONDS - MAX_PENDING_CONTACT_REQUESTS + 2
    assert 0 < len(alice.requests()) < len(held)  # the oldest have expired
    t[0] += 100
    assert alice.requests() == []
    with raises("invalid_argument"):
        alice.accept(senders[-1])


def test_signing_key_change_pushes_fresh_permits_to_admitted_peers(relay, pair):
    alice, bob = pair  # alice open, bob closed
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    alice.accept_profiles = (TEXT.id,)
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    bob.pull()
    assert alice.peers.status(b) == "admitted" and bob.peers.status(a) == "admitted"
    old = alice.peers.permit_from(b)["signature"]["seq"]
    bob.identity.delegate()
    bob.maintain()  # re-registers, republishes and re-sends a request with a fresh permit
    alice.accept_profiles = ()  # the refresh is accepted because bob is admitted, not by rule
    alice.pull()
    assert alice.peers.permit_from(b)["signature"]["seq"] == bob.identity.get_signing_seq() != old
    bob.pull()  # alice's `accepted` only refreshes bob's held permit
    assert bob.peers.status(a) == "admitted"
    mid = alice.send(b, "ace:text:1", {"message": "still reachable"})
    bob.pull()
    alice.pull()
    assert alice.outbox.get(mid).status == "delivered"
    assert bob._refresh_permits() == []  # once per delegation


def test_accept_never_clears_a_block(relay, pair):
    """05 § Blocks: a residual request from a blocked peer is not_permitted; the relay block
    stays."""
    from ace.network import _incoming_key

    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    held = alice.store.read(_incoming_key(b))
    alice.block(b)
    assert alice.requests() == []  # blocking discards the held request
    # a residual request (e.g. stored by a racing receive)
    alice.store.write(_incoming_key(b), held)
    with raises("not_permitted"):
        alice.accept(b)
    assert alice.peers.is_blocked(b) and relay.blocks[(a, b)] == (True, 0)


@pytest.mark.parametrize("block_first", [False, True])
def test_concurrent_block_and_accept_never_end_admitted(relay, pair, block_first):
    import threading

    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()

    def quiet(f):
        try:
            f(b)
        except Exception:
            pass

    ops = [alice.accept, alice.block]
    if block_first:
        ops.reverse()
    threads = [threading.Thread(target=quiet, args=(f,)) for f in ops]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert alice.peers.is_blocked(b) and relay.blocks[(a, b)][0] is True


def test_wake_uses_the_home_relay(relay, pair):
    alice, _ = pair
    a = alice.identity.get_ace_id()
    alice.set_wake("https://push.example/ace", "w" * 32)
    assert relay.wakes[a] == {"gateway": "https://push.example/ace", "token": "w" * 32}
    alice.clear_wake()
    assert a not in relay.wakes


def test_attempt_retries_a_pending_message_now(relay, pair):
    alice, bob = pair
    a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
    bob.connect(a, profile=TEXT.id)
    alice.pull()
    alice.accept(b)
    bob.pull()
    relay.inject.append(("/v1/send", 503, "unavailable", {}))  # the first attempt fails
    mid = bob.send(a, "ace:text:1", {"message": "hi"})
    assert bob.outbox.get(mid).code == "relay_unavailable"
    sent = len(relay.sent)
    entry = bob.attempt(mid)  # not due yet: attempted anyway
    assert entry.status == "pending" and len(relay.sent) == sent + 1
    assert bob.attempt("0" * 32) is None and bob.attempt("not-an-id") is None
    bob.outbox.abandon(mid)
    assert bob.attempt(mid).status == "expired" and len(relay.sent) == sent + 1  # final: as is
