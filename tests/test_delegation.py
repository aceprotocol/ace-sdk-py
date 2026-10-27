"""The ``ace:delegation:1`` profile (profiles/delegation.md): credentials, the descriptor
extension, the hand-over message rule and ``NetworkClient.verify_delegation``; plus the core
changes that came with it: ERC-8004 on the card record, signers at the log tail (01 §
Operational signatures), card lookups that need a live descriptor (04 § Card record) and the
one page default."""

from __future__ import annotations

import copy

from ace import (
    DELEGATION,
    DELEGATION_PROFILE_ID,
    DELEGATION_TYPE,
    MAX_DELEGATION_CREDENTIAL_LIFETIME,
    MAX_DELEGATION_CREDENTIALS,
    TEXT,
    MessageEvent,
    Prekey,
    Profiles,
    SoftwareIdentity,
    check_stranger_source,
    create_auth_headers,
    create_card_record,
    create_delegation_credential,
    create_packet,
    create_permit,
    decode_packet,
    delegation_rules,
    encode_payload,
    from_base64,
    prekey_id,
    signing_message,
    to_base64,
    validate_delegation_ext,
    verify_card_bundle,
    verify_delegation_credential,
    verify_kel,
    verify_packet,
    verify_permit,
    verify_signature,
)
from ace.identity import sign_operational
from ace.limits import MAX_INBOX_PAGE
from ace.packet import packet_sign_payload

from .helpers import NOW, PEER_PREKEY, Clock, Party, raises
from .test_card_record import World

SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
REGISTRY = "eip155:1:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432"


def identity() -> SoftwareIdentity:
    return SoftwareIdentity.generate(now=NOW - 10)


def state(i: SoftwareIdentity, now: int = NOW):
    return verify_kel(i.get_kel(), now)


def test_credential_round_trip_and_ext_shape():
    subject = identity()
    s = subject.get_ace_id()
    issuers = [identity() for _ in range(MAX_DELEGATION_CREDENTIALS + 1)]
    creds = [create_delegation_credential(i, s, now=NOW) for i in issuers]
    c = creds[0]
    assert set(c) == {"issuer", "subject", "issuedAt", "expiresAt", "signature"}
    assert (c["issuer"], c["subject"]) == (issuers[0].get_ace_id(), s)
    assert c["expiresAt"] - c["issuedAt"] == MAX_DELEGATION_CREDENTIAL_LIFETIME
    assert verify_delegation_credential(c, state(issuers[0]), NOW) == c
    # signed with the profile's own action, never a core one
    with raises("invalid_authorization"):
        verify_delegation_credential(c, state(issuers[1]), NOW)
    assert validate_delegation_ext({"credentials": creds[:4]}, s, NOW) == creds[:4]
    for bad in (
        {"credentials": creds},  # five
        {"credentials": []},
        {"credentials": [c, c]},  # one issuer twice
        {"credentials": creds[:1], "x": 1},
        [c],
    ):
        with raises("invalid_authorization"):
            validate_delegation_ext(bad, s, NOW)
    with raises("invalid_authorization"):  # another subject
        validate_delegation_ext({"credentials": [c]}, issuers[1].get_ace_id(), NOW)
    with raises("invalid_authorization"):  # issuer == subject
        validate_delegation_ext({"credentials": [{**c, "subject": c["issuer"]}]}, c["issuer"], NOW)
    with raises("invalid_authorization"):  # lifetime above the max
        validate_delegation_ext(
            {"credentials": [{**c, "expiresAt": c["issuedAt"] + 604_801}]}, s, NOW
        )
    with raises("invalid_argument"):
        create_delegation_credential(issuers[0], s, now=NOW, ttl=604_801)
    with raises("invalid_argument"):
        create_delegation_credential(issuers[0], issuers[0].get_ace_id(), now=NOW)
    assert create_delegation_credential(issuers[0], s, now=NOW, ttl=60)["expiresAt"] == NOW + 60
    # the extension is checked by descriptor verification (shape only)
    subj = Party(Clock(), profiles=[DELEGATION.descriptor()])
    ext = {
        DELEGATION_PROFILE_ID: {
            "credentials": [create_delegation_credential(issuers[0], subj.id, now=NOW)]
        }
    }
    assert subj.source(ext=ext)["descriptor"]["ext"] == ext
    with raises("invalid_authorization"):
        subj.source(
            ext={DELEGATION_PROFILE_ID: {"credentials": [c]}}
        )  # subject is not the descriptor's


def test_verify_rejects_expired_and_tampered():
    issuer, s = identity(), identity().get_ace_id()
    c = create_delegation_credential(issuer, s, now=NOW, ttl=60)
    with raises("invalid_authorization"):
        verify_delegation_credential(c, state(issuer), NOW + 60)
    # the descriptor extension does not check expiry
    assert validate_delegation_ext({"credentials": [c]}, s, NOW + 60) == [c]
    sig = from_base64(c["signature"]["value"])
    tampered = copy.deepcopy(c)
    tampered["signature"]["value"] = to_base64(bytes([sig[0] ^ 1]) + sig[1:])
    with raises("invalid_authorization"):
        verify_delegation_credential(tampered, state(issuer), NOW)
    # a new dlg supersedes the key: stale_peer_binding passes through
    issuer.delegate(now=NOW + 1)
    with raises("stale_peer_binding"):
        verify_delegation_credential(c, state(issuer, NOW + 1), NOW + 1)


def test_rule_requires_issuer_from_and_subject_to():
    clock = Clock()
    dave, bob, carol = Party(clock), Party(clock), Party(clock)
    rules = delegation_rules(bob.peers, bob.id)
    assert rules.types == frozenset({DELEGATION_TYPE})
    c = create_delegation_credential(dave.identity, bob.id, now=NOW)

    def event(direction: str, from_id: str, to_id: str) -> MessageEvent:
        mid = "8a4f6a2e-3c0b-4d1e-9f7a-1b2c3d4e5f60"
        return MessageEvent(direction, mid, from_id, to_id, NOW, DELEGATION_TYPE, None)

    with raises("invalid_body"):  # the sender is not pinned
        rules.check(event("receive", dave.id, bob.id), {"credential": c})
    bob.peers.pin(dave.identity.get_kel(), NOW)
    rules.check(event("receive", dave.id, bob.id), {"credential": c})
    rules.commit(event("receive", dave.id, bob.id), {"credential": c})
    carol_c = create_delegation_credential(carol.identity, bob.id, now=NOW)
    bob.peers.pin(carol.identity.get_kel(), NOW)
    with raises("invalid_body"):  # issuer != from
        rules.check(event("receive", dave.id, bob.id), {"credential": carol_c})
    with raises("invalid_body"):  # subject != to
        rules.check(event("receive", dave.id, carol.id), {"credential": c})
    with raises("invalid_body"):  # not the issuer's signature
        forged = {**carol_c, "issuer": dave.id}
        rules.check(event("receive", dave.id, bob.id), {"credential": forged})
    clock.now = c["expiresAt"]
    with raises("invalid_body"):  # expired
        rules.check(event("receive", dave.id, bob.id), {"credential": c})
    # on send: the sender is the issuer (its own credential), no pin needed
    sender_rules = delegation_rules(dave.peers, dave.id)
    clock.now = NOW
    sender_rules.check(event("send", dave.id, bob.id), {"credential": c})
    with raises("invalid_body"):
        sender_rules.check(event("send", dave.id, carol.id), {"credential": c})


def test_network_verify_delegation_pins_the_issuer():
    world = World()
    try:
        dave = world.agent(contact="open")
        bob = world.agent()
        d, b = dave.identity.get_ace_id(), bob.identity.get_ace_id()
        c = create_delegation_credential(dave.identity, b, now=world.clock.now)
        assert bob.peers.state(d) is None
        assert bob.verify_delegation(c) == c
        assert bob.peers.state(d) is not None
        stranger = SoftwareIdentity.generate(now=world.clock.now - 10)
        unknown = create_delegation_credential(stranger, b, now=world.clock.now)
        with raises("unknown_peer"):
            bob.verify_delegation(unknown)
        with raises("invalid_authorization"):
            bob.verify_delegation({**c, "expiresAt": "x"})
    finally:
        world.close()


def test_network_client_installs_the_delegation_rule():
    world = World()
    try:
        dave = world.agent(contact="open", profiles=Profiles([TEXT, DELEGATION]))
        bob = world.agent(profiles=Profiles([TEXT, DELEGATION]))
        d, b = dave.identity.get_ace_id(), bob.identity.get_ace_id()
        bob.connect(d, profile=DELEGATION_PROFILE_ID)
        dave.pull()
        dave.accept(b)
        bob.pull()
        c = create_delegation_credential(dave.identity, b, now=world.clock.now)
        with raises("invalid_body"):  # checked on send: subject must be the recipient
            dave.send(b, DELEGATION_TYPE, {"credential": {**c, "subject": d}})
        received = []
        bob._user_on_message = received.append
        dave.send(b, DELEGATION_TYPE, {"credential": c})
        bob.pull()
        assert [m.body for m in received if m.type == DELEGATION_TYPE] == [{"credential": c}]
    finally:
        world.close()


def test_signer_timestamp_is_the_log_tail():
    me, peer = identity(), identity()
    me.delegate(now=NOW + 100)
    st = state(me, NOW + 100)
    prekey = Prekey(prekey_id(PEER_PREKEY), PEER_PREKEY)
    p = create_packet(me, peer.get_ace_id(), prekey, b"{}", timestamp=NOW)
    assert p["timestamp"] == NOW + 100
    verify_packet(decode_packet(p), st, NOW + 100)
    permit = create_permit(me, peer.get_ace_id(), now=NOW)
    assert permit["issuedAt"] == NOW + 100
    verify_permit(permit, st, peer.get_ace_id(), now=NOW + 100)
    aud = "https://relay.example"
    h = create_auth_headers(me, "inbox", b"", NOW, audience=aud)
    assert h["X-ACE-Timestamp"] == str(NOW + 100)
    message = signing_message(
        me.get_ace_id(), NOW + 100, int(h["X-ACE-Seq"]), encode_payload(aud, h["X-ACE-Nonce"], b"")
    )
    assert verify_signature(
        message, "inbox", from_base64(h["X-ACE-Signature"]), st.signing.public_key
    )
    # a packet signed one second before the dlg's ts does not verify (signed while live)
    q = decode_packet(p)
    early = {
        **p,
        "timestamp": NOW + 99,
        "signature": sign_operational(
            me,
            NOW + 99,
            packet_sign_payload(q.to_id, q.message_id, q.prekey_id, q.kem_ciphertext, q.payload),
            "packet",
        ),
    }
    with raises("stale_peer_binding"):
        verify_packet(decode_packet(early), st, NOW + 100)


def test_card_record_erc8004():
    i = identity()
    entry = {"agentRegistry": REGISTRY, "agentId": "42"}
    native = {"agentRegistry": SOL, "agentId": "Ab12"}
    bundle = create_card_record(
        i,
        home="https://relay.test",
        contact="closed",
        listed=False,
        erc8004=[entry, native],
        now=NOW,
    )
    v = verify_card_bundle(bundle, NOW)
    assert v.erc8004 == [entry, native]
    assert (
        verify_card_bundle(
            create_card_record(
                i, home="https://relay.test", contact="closed", listed=False, now=NOW + 1
            ),
            NOW + 1,
        ).erc8004
        is None
    )
    for bad in (
        [{"agentRegistry": REGISTRY, "agentId": "042"}],  # leading zero under eip155
        [{"agentRegistry": SOL, "agentId": "a-b"}],
        [entry, entry],
        [{"agentRegistry": REGISTRY, "agentId": str(n)} for n in range(5)],
        [],
    ):
        record = {**bundle["card"], "erc8004": bad}
        with raises("invalid_authorization"):
            verify_card_bundle({"kel": bundle["kel"], "card": record}, NOW)
        with raises("invalid_authorization"):
            create_card_record(
                i, home="https://relay.test", contact="closed", listed=False, erc8004=bad, now=NOW
            )


def test_lookup_card_needs_a_live_descriptor():
    world = World()
    try:
        alice = world.agent(contact="open", handle="alice", pay=[SOL])
        a = alice.identity.get_ace_id()
        # Alice is offline past her descriptor's lifetime: her card is served, no descriptor.
        world.clock.now += 8 * 86400
        for target in (a, f"@alice@{world.host}"):
            bob = world.agent()
            with raises("unknown_peer"):
                bob.lookup_card(target)
            assert bob.peers.state(a) is None
    finally:
        world.close()


def test_directory_default_limit_is_max_inbox_page():
    world = World()
    try:
        bob = world.agent()
        bob.discover()
        world.rc().directory()
        limits = [q.get("limit") for p, q in world.relay.queries if p == "/v1/cards"]
        assert limits == [str(MAX_INBOX_PAGE)] * 2
    finally:
        world.close()


def test_stranger_source_with_delegation_ext_costs_only_its_own_kel():
    subj = Party(Clock(), profiles=[DELEGATION.descriptor()])
    creds = [create_delegation_credential(identity(), subj.id, now=NOW) for _ in range(4)]
    source = subj.source(ext={DELEGATION_PROFILE_ID: {"credentials": creds}})
    check_stranger_source(source)
    long = {**source, "kel": [source["kel"][0]] * 33}
    with raises("not_permitted"):
        check_stranger_source(long)


def test_ext_size_bound_is_32768():
    subj = Party(Clock(), profiles=[{"id": "x:big:1", "digest": "0" * 64}])
    # {"x:big:1":{"v":"…"}} is 20 bytes around the string
    with raises("invalid_authorization"):
        subj.source(ext={"x:big:1": {"v": "a" * (32768 - 19)}})
    assert subj.source(ext={"x:big:1": {"v": "a" * (32768 - 20)}})["descriptor"]["ext"]
