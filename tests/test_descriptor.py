import copy

import pytest

from ace import (
    COMMERCE,
    TEXT,
    MemoryStore,
    PeerStore,
    create_permit,
    issue_delegation,
    validate_card,
    verify_erc8004_registration,
    verify_kel,
    verify_permit,
    verify_published_agent,
)
from ace.identity import sign_claims
from ace.limits import MAX_DESCRIPTOR_LIFETIME, MAX_PERMIT_LIFETIME
from tests.helpers import NOW, Clock, Party, raises


@pytest.fixture
def p():
    return Party(Clock())


def test_create_and_verify(p):
    src = p.source(profiles=[TEXT.descriptor()])
    a = verify_published_agent(src, now=NOW)
    assert a.ace_id == p.id and a.prekey == p.vault.current()
    assert set(src["descriptor"]) == {
        "aceId",
        "issuedAt",
        "expiresAt",
        "relays",
        "prekey",
        "profiles",
        "signature",
    }
    with raises("invalid_authorization"):
        verify_published_agent(src, now=NOW + 86400)  # expired (the default lifetime)
    tampered = copy.deepcopy(src)
    tampered["descriptor"]["expiresAt"] -= 1
    with raises("invalid_authorization"):
        verify_published_agent(tampered, now=NOW)


def test_lifetime_is_at_most_seven_days(p):
    src = p.source(lifetime=MAX_DESCRIPTOR_LIFETIME)
    assert src["descriptor"]["expiresAt"] - src["descriptor"]["issuedAt"] == 604800
    with raises("invalid_argument"):
        p.source(lifetime=MAX_DESCRIPTOR_LIFETIME + 1)


@pytest.mark.parametrize(
    "member",
    [{"visibility": "public"}, {"handle": "alice"}, {"card": {}}],
)
def test_retired_members_are_unknown(p, member):
    """visibility, handle and card moved to the card record (04 § Card record)."""
    d = {k: v for k, v in p.source()["descriptor"].items() if k != "signature"}
    signed = sign_claims(p.identity, "agent-descriptor", {**d, **member})
    with raises("invalid_authorization"):
        verify_published_agent({"kel": p.identity.get_kel(), "descriptor": signed}, now=NOW)


@pytest.mark.parametrize(
    "card",
    [
        {"name": ""},
        {"name": None},  # absent is fine, null is not a string
        {"description": None},
        {"image": "http://x.example/i.png"},
        {"tags": ["UPPER"]},
        {"extra": 1},
    ],
)
def test_invalid_cards(card):
    with raises("invalid_authorization"):
        validate_card(card)
    assert validate_card({"name": "Alice", "tags": ["hosted", "-x"]})


@pytest.mark.parametrize(
    "kw",
    [
        {"relays": ["http://relay.example"]},
        {"relays": ["https://relay.example/"]},
        {"profiles": [{"id": "ace:core:1", "digest": "0" * 64}]},
        {"profiles": [TEXT.descriptor()], "ext": {"ace:text:1": {}}},  # text defines no ext
        {"profiles": [TEXT.descriptor()], "ext": {"urn:x:1": {}}},  # not announced
        {"profiles": [{"id": "urn:x:1", "digest": "0" * 64}], "ext": {"urn:x:1": 1}},
        {"profiles": [COMMERCE.descriptor()], "ext": {"ace:commerce:1": {"settlement": []}}},
        {"erc8004": [{"agentRegistry": "eip155:8453:0xabc", "agentId": "01"}]},
    ],
)
def test_invalid_fields_invalidate_the_descriptor(p, kw):
    with raises("invalid_authorization"):
        p.source(**kw)


def test_ext_and_erc8004(p):
    ext = {
        "ace:commerce:1": {
            "settlement": [
                {"method": "stablecoin", "asset": "eip155:8453/erc20:0xabc"},
                {"method": "stripe-link"},
            ]
        },
        "urn:x:1": {"anything": [1, 2]},
    }
    src = p.source(
        profiles=[COMMERCE.descriptor(), {"id": "urn:x:1", "digest": "1" * 64}],
        ext=ext,
        erc8004=[{"agentRegistry": "eip155:8453:0x" + "a" * 40, "agentId": "42"}],
    )
    assert verify_published_agent(src, now=NOW).ext == ext
    reg = {
        "services": [{"name": "web", "endpoint": "https://x"}, {"name": "ACE", "endpoint": p.id}]
    }
    assert verify_erc8004_registration(reg, p.id)
    # only ``services`` (04 § ERC-8004)
    assert not verify_erc8004_registration({"endpoints": [{"name": "ACE", "endpoint": p.id}]}, p.id)
    assert not verify_erc8004_registration({"services": [{"name": "ACE", "endpoint": "x"}]}, p.id)
    assert not verify_erc8004_registration("{not json", p.id)
    assert not verify_erc8004_registration([], p.id)


def test_delegations(p):
    clock = p.clock
    boss, other = Party(clock), Party(clock)
    live = issue_delegation(boss.identity, p.id, now=NOW)
    a = verify_published_agent(p.source(delegations=[live]), now=NOW)
    assert a.delegations == (boss.id,)
    # expired entries are dropped, not fatal
    expired = issue_delegation(other.identity, p.id, now=NOW - 700000, lifetime=3600)
    a = verify_published_agent(p.source(delegations=[live, expired]), now=NOW)
    assert a.delegations == (boss.id,)
    # wrong subject, tampered, duplicate issuer: the whole descriptor is invalid
    with raises("invalid_authorization"):
        p.source(delegations=[issue_delegation(boss.identity, other.id, now=NOW)])
    bad = copy.deepcopy(live)
    bad["credential"]["expiresAt"] -= 1
    with raises("invalid_authorization"):
        p.source(delegations=[bad])
    with raises("invalid_authorization"):
        p.source(delegations=[live, issue_delegation(boss.identity, p.id, now=NOW)])
    with raises("invalid_authorization"):
        issue_delegation(boss.identity, p.id, now=NOW, lifetime=604801)


def test_permits(p):
    q = Party(p.clock)
    permit = create_permit(p.identity, q.id, now=NOW)
    assert permit["expiresAt"] - permit["issuedAt"] == MAX_PERMIT_LIFETIME
    state = verify_kel(p.identity.get_kel(), NOW)
    assert verify_permit(permit, state, q.id, now=NOW + 100) == permit
    with raises("invalid_authorization"):
        verify_permit(permit, state, q.id, now=NOW + MAX_PERMIT_LIFETIME)
    with raises("invalid_authorization"):
        verify_permit(permit, state, p.id, now=NOW)  # wrong subject
    with raises("invalid_authorization"):
        create_permit(p.identity, q.id, now=NOW, lifetime=MAX_PERMIT_LIFETIME + 1)
    # a signing-key change invalidates earlier permits
    p.identity.delegate(now=NOW + 1)
    with raises("stale_peer_binding"):
        verify_permit(permit, verify_kel(p.identity.get_kel(), NOW + 2), q.id, now=NOW + 2)


def test_descriptor_pinning_keeps_the_newest(p):
    peers = PeerStore(MemoryStore(), clock=p.clock)
    new = p.source(now=NOW, relays=["https://new.example"])
    old = p.source(now=NOW - 10, relays=["https://old.example"])
    peers.adopt(new)
    assert peers.adopt(old).relays == ["https://new.example"]  # an older descriptor is ignored
    assert peers.agent(p.id).relays == ["https://new.example"]


def test_delegation_issuer_is_reconciled_with_its_pin():
    """M2: a delegation entry carrying an older issuer KEL, signed by a delegation the verifier's
    pin of the issuer has superseded, is invalid (01 § Pinning, 04 § Delegations)."""
    clock = Clock()
    alice, dave, viewer = Party(clock), Party(clock), Party(clock)
    stale = issue_delegation(dave.identity, alice.id, now=NOW - 5)
    dave.identity.delegate(now=NOW - 4)  # dave replaces its signing key
    src = alice.source(delegations=[stale])
    assert verify_published_agent(src, now=NOW).delegations == (dave.id,)  # standalone: passes
    viewer.peers.pin(dave.identity.get_kel(), NOW)
    with raises("invalid_authorization"):
        viewer.peers.adopt(src, NOW)
    fresh = issue_delegation(dave.identity, alice.id, now=NOW - 3)
    assert viewer.peers.adopt(alice.source(delegations=[fresh]), NOW).delegations == (dave.id,)
