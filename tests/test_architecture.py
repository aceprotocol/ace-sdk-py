"""Regression tests for the mechanism-level fixes (parity with sdk-ts tests/architecture.test.ts):
one caching predicate, one permit slot, one step-10 transaction, accepting a held request whose
source expired, and KEL verification resumed from a verified prefix."""

from __future__ import annotations

import copy

import pytest

from ace import (
    TEXT,
    ACEError,
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
    verify_kel,
)

from .fake_relay import FakeRelay
from .helpers import Clock, Party, wire

TEXT_DIGEST = TEXT.messages["ace:text:1"].digest


# --- 04 § Caching: one usability predicate -------------------------------------------------


def test_a_cached_descriptor_whose_subject_delegation_passed_not_after_is_stale():
    """01 § Verifier rules 5: never send to an unusable identity, even under an unexpired
    descriptor."""
    clock = Clock()
    alice, bob = Party(clock), Party(clock)
    bob.identity.delegate(now=clock.now, not_after=clock.now + 3600)
    alice.peers.adopt(bob.source())
    assert alice.peers.current(bob.id, clock.now) is not None
    clock.now += 3601  # the descriptor is unexpired, the subject's signing key is not
    assert alice.peers.current(bob.id, clock.now) is None


# --- one permit slot per issuer ------------------------------------------------------------


def test_the_held_permit_is_the_newest_by_issued_at():
    clock = Clock()
    issuer, me = Party(clock), Party(clock)
    me.peers.adopt(issuer.source())
    older = create_permit(issuer.identity, me.id, now=clock.now)
    newer = create_permit(issuer.identity, me.id, now=clock.now + 10)
    me.peers.hold_permit(issuer.id, newer, me.id, clock.now + 10)
    me.peers.hold_permit(issuer.id, older, me.id, clock.now + 10)
    assert me.peers.permit_from(issuer.id, clock.now + 10) == newer


def test_a_newer_held_permit_that_no_longer_verifies_does_not_shadow_a_valid_one():
    clock = Clock()
    issuer, me = Party(clock), Party(clock)
    me.peers.adopt(issuer.source())
    stale = create_permit(issuer.identity, me.id, now=clock.now + 10)
    me.peers.save_permit(stale)
    clock.now += 20
    issuer.identity.delegate(now=clock.now)  # supersedes the key that signed `stale`
    me.peers.adopt(issuer.source())
    valid = create_permit(issuer.identity, me.id, now=clock.now - 15)  # issued before `stale`
    me.peers.hold_permit(issuer.id, valid, me.id, clock.now)
    assert me.peers.permit_from(issuer.id, clock.now) == valid


def test_a_conditional_hold_checks_the_issuer_record_under_the_peers_lock():
    clock = Clock()
    issuer, me = Party(clock), Party(clock)
    me.peers.adopt(issuer.source())
    permit = create_permit(issuer.identity, me.id, now=clock.now)
    me.peers.hold_permit(
        issuer.id, permit, me.id, clock.now, when=lambda r: r is not None and r.status == "admitted"
    )
    assert me.peers.permit_from(issuer.id, clock.now) is None


# --- 06 step 10: one transaction on every path ----------------------------------------------


class Rule:
    types = frozenset({"ace:text:1"})

    def __init__(self, fail=None):
        self.fail, self.commits = fail, 0

    def check(self, event, body):
        pass

    def commit(self, event, body):
        self.commits += 1
        if self.fail is not None:
            raise self.fail


def _world(rule=None, on_message=None):
    clock = Clock()
    a, b = Party(clock), Party(clock)
    b.peers.adopt(a.source())
    b.peers.set_status(a.id, "admitted")
    got = []
    opts = dict(on_message=on_message or got.append, rules=[rule] if rule else [], clock=clock)
    inbox = Inbox.open(b.identity, b.store, b.vault, b.peers, Profiles(), **opts)

    def packet():
        plain = encode_content("ace:text:1", TEXT_DIGEST, {"message": "hi"})
        return wire(create_packet(a.identity, b.id, b.vault.current(), plain, timestamp=clock.now))

    return clock, a, b, inbox, got, packet, opts


def test_a_permanent_commit_failure_aborts_step_10_rejected_nothing_handed_over_or_seen():
    rule = Rule(ACEError("wrong_role", "no"))
    _, _, b, inbox, got, packet, _ = _world(rule)
    p = packet()
    out = inbox.receive(p)
    assert out.kind == "rejected" and out.error.code == "wrong_role" and out.ack
    assert got == [] and b.store.list("inbox/deliveries/") == []
    rule.fail = None  # not seen: a later copy is processed anew
    assert inbox.receive(p).kind == "delivered"
    assert len(got) == 1


def test_a_transient_commit_failure_stays_pending_and_the_resent_copy_finishes_it():
    rule = Rule(ACEError("storage_failed", "down"))
    _, _, _, inbox, got, packet, _ = _world(rule)
    p = packet()
    assert inbox.receive(p).kind == "retry"
    assert got == []
    rule.fail = None
    assert inbox.receive(p).kind == "duplicate"
    assert len(got) == 1 and rule.commits == 2


def test_an_entry_that_keeps_failing_never_blocks_opening_the_inbox():
    calls = []

    def refuse(m):
        calls.append(m)
        raise ACEError("invalid_argument", "host refuses")

    _, _, b, inbox, _, packet, opts = _world(on_message=refuse)
    assert inbox.receive(packet()).kind == "retry"
    inbox.close()
    reopened = Inbox.open(b.identity, b.store, b.vault, b.peers, Profiles(), **opts)
    assert len(calls) == 2 and len(b.store.list("inbox/deliveries/")) == 1
    reopened.close()


# --- 05 § Flow step 3: accept a held request whose source expired ----------------------------


def test_accept_after_the_source_descriptor_expired_pins_and_refreshes_with_the_permit():
    clock = Clock()
    relay = FakeRelay(clock=clock)
    try:

        def client(**kw):
            identity = SoftwareIdentity.generate(now=clock.now)
            rc = RelayClient(relay.url, allow_loopback=True, clock=clock)
            return NetworkClient.open(
                identity, MemoryStore(), rc, PrekeyVault(clock=clock), clock=clock, **kw
            )

        alice, bob = client(contact="open", listed=True), client()  # bob is closed
        a, b = alice.identity.get_ace_id(), bob.identity.get_ace_id()
        alice.publish()
        first = bob.publish()
        clock.now = first["descriptor"]["expiresAt"] - 3601  # publish still reuses it
        bob.connect(a, profile=TEXT.id)
        alice.pull()
        held = alice.requests()[0].source["descriptor"]
        assert held["expiresAt"] == first["descriptor"]["expiresAt"]
        clock.now += 7200  # the held request (24 h) outlived its source descriptor
        bob.publish()
        alice.accept(b)
        bob.pull()
        assert bob.peers.status(a) == "admitted"
        alice.close()
        bob.close()
    finally:
        relay.close()


# --- KEL verification resumed from a verified prefix ----------------------------------------


def test_kel_resume_still_verifies_every_new_event_and_every_prefix_signature():
    clock = Clock()
    identity = SoftwareIdentity.generate(now=clock.now)
    verify_kel(identity.get_kel(), clock.now)  # cached
    clock.now += 10
    identity.delegate(now=clock.now)
    full = identity.get_kel()
    assert verify_kel(full, clock.now).seq == len(full) - 1
    forged = copy.deepcopy(full)
    forged[-1]["sig"]["value"] = full[0]["sig"]["value"]
    with pytest.raises(ACEError):
        verify_kel(forged, clock.now)
    tampered = copy.deepcopy(full)
    tampered[0]["sig"]["value"] = full[-1]["sig"]["value"]
    with pytest.raises(ACEError):
        verify_kel(tampered, clock.now)
