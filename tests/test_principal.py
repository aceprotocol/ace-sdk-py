"""Principal binding (09-principal): types, bodies, records, rules, pipeline."""

# ruff: noqa: E501

from __future__ import annotations

import dataclasses
import json

import pytest

from ace import (
    ECONOMIC_TYPES,
    MESSAGE_TYPES,
    ACEError,
    MemoryStore,
    SoftwareIdentity,
    validate_body,
)
from ace._encoding import to_base64
from ace._signing import build_sign_data, encode_payload
from ace.errors import _category
from ace.principal import (
    PRINCIPAL_ROLES,
    PrincipalContext,
    PrincipalSigner,
    check_principal_rules,
    create_principal_record,
    fill_decision,
    is_caip10,
    load_request_record,
    open_request_to,
    principal_payload,
    principal_sign_data,
    record_request,
    request_key,
    validate_principal_record,
)
from ace.types import (
    PRINCIPAL_TYPES,
    ParsedMessage,
    PrincipalKey,
    PrincipalRecord,
    is_economic_type,
    is_principal_type,
)

from .helpers import raises

CONV = "ab" * 32
MID = "00000000-0000-4000-8000-000000000001"


def test_type_lists():
    assert MESSAGE_TYPES[-3:] == ("request", "decision", "report") and len(MESSAGE_TYPES) == 13
    assert len(ECONOMIC_TYPES) == 8 and PRINCIPAL_TYPES == ("request", "decision", "report")
    assert all(is_principal_type(t) and not is_economic_type(t) for t in PRINCIPAL_TYPES)
    assert not is_principal_type("text") and not is_principal_type(3)


def test_error_codes_permanent():
    assert _category("invalid_principal") == "permanent" and _category("wrong_principal") == "permanent"
    assert ACEError("wrong_principal").category == "permanent"


@pytest.mark.parametrize("type_,body", [
    ("request", {"action": "pay", "summary": "Pay 1 USDC"}),
    ("request", {"action": "x402.pay", "summary": "s", "amount": "1", "currency": "USDC", "ttl": 60,
                 "details": {"payTo": "x"}, "ref": {"conversationId": CONV, "messageId": MID, "threadId": "t"}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV, "messageId": MID, "threadId": None}}),
    ("decision", {"requestId": MID, "outcome": "approve"}),
    ("decision", {"requestId": MID, "outcome": "deny", "reason": "no", "result": {"x": 1}}),
    ("report", {"action": "pay", "summary": "paid", "outcome": "skipped", "proof": {}, "requestId": MID}),
])
def test_valid_bodies(type_, body):
    validate_body(type_, body)


@pytest.mark.parametrize("type_,body", [
    ("request", {"action": "a"}),
    ("request", {"action": "a", "summary": "s", "details": "x"}),
    ("request", {"action": "a", "summary": "s", "ttl": 1.5}),
    ("request", {"action": "a", "summary": "s", "ref": []}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV.upper(), "messageId": MID}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV, "messageId": "AAAAAAAA-0000-4000-8000-000000000001"}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV, "messageId": MID, "threadId": ""}}),
    ("decision", {"requestId": MID, "outcome": "maybe"}),
    ("decision", {"requestId": MID, "outcome": "APPROVE"}),
    ("decision", {"requestId": MID, "outcome": "approve", "result": []}),
    ("report", {"action": "a", "summary": "s", "outcome": "done"}),
    ("report", {"action": "a", "summary": "s", "outcome": "ok", "proof": "x"}),
])
def test_invalid_bodies(type_, body):
    with raises("invalid_body"):
        validate_body(type_, body)


# --- principal records ---------------------------------------------------------------

ACC = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
NOW = 1_800_000_000
YEAR = 31622400


def _owner(scheme="ed25519"):
    return SoftwareIdentity.generate(scheme)


def _rec(owner, subject, **kw):
    args = dict(subject_signing_public_key=subject.get_signing_public_key(), account=ACC,
                roles=["delegate", "controller", "delegate"], issued_at=NOW - 10, expires_at=NOW + 3600)
    args.update(kw)
    return create_principal_record(PrincipalSigner.from_identity(owner), **args)


def test_constants_and_caip10():
    assert PRINCIPAL_ROLES == ("controller", "delegate")
    assert is_caip10(ACC) and is_caip10("eip155:1:0xabc")
    assert not is_caip10("solana:abc") and not is_caip10("Solana:x:y") and not is_caip10(3)
    assert not is_caip10(ACC + "\n")


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_create_and_validate(scheme):
    owner, subject = _owner(scheme), SoftwareIdentity.generate("ed25519")
    rec = _rec(owner, subject, scope="copy:solana,hl", expires_at=NOW + 3600)
    assert rec.roles == ("controller", "delegate")  # canonicalized before signing
    assert rec.signer == PrincipalKey(scheme, to_base64(owner.get_signing_public_key()))
    assert validate_principal_record(rec.to_dict(), subject.get_signing_public_key(), NOW) == rec
    assert validate_principal_record(rec, subject.get_signing_public_key(), NOW) == rec
    assert PrincipalRecord.from_dict(json.loads(json.dumps(rec.to_dict()))) == rec
    spk_b64 = to_base64(subject.get_signing_public_key())
    assert principal_payload(rec, subject.get_signing_public_key()) == encode_payload(
        ACC, "controller,delegate", scheme, rec.signer.public_key, spk_b64, "copy:solana,hl", str(NOW + 3600))
    assert principal_sign_data(rec, subject.get_signing_public_key()) == build_sign_data(
        "principal", subject.get_ace_id(), NOW - 10, principal_payload(rec, subject.get_signing_public_key()))


def test_scope_absent_encodes_empty_and_null_members_are_absent():
    owner, subject = _owner(), SoftwareIdentity.generate("secp256k1")
    rec = _rec(owner, subject, roles=["delegate"])
    d = rec.to_dict()
    assert "scope" not in d and d["expiresAt"] == NOW + 3600 and d["roles"] == ["delegate"]
    assert principal_payload(rec, subject.get_signing_public_key()).endswith(encode_payload("", str(NOW + 3600)))
    d["scope"] = None
    d["unknown"] = {"x": 1}
    assert validate_principal_record(d, subject.get_signing_public_key(), NOW) == rec


def test_lifetime_bound():
    owner, subject = _owner(), SoftwareIdentity.generate("ed25519")
    rec = _rec(owner, subject, issued_at=NOW, expires_at=NOW + YEAR)
    validate_principal_record(rec, subject.get_signing_public_key(), NOW)
    with raises("invalid_principal"):
        _rec(owner, subject, issued_at=NOW, expires_at=NOW + YEAR + 1)
    with raises("invalid_principal"):
        _rec(owner, subject, issued_at=NOW, expires_at=NOW)


def test_create_rejects_bad_roles_and_requires_expiry():
    owner, subject = _owner(), SoftwareIdentity.generate("ed25519")
    with raises("invalid_argument"):
        _rec(owner, subject, roles=["owner"])
    with raises("invalid_argument"):
        _rec(owner, subject, roles="controller")
    with raises("invalid_principal"):
        _rec(owner, subject, roles=[])
    with raises("invalid_principal"):
        _rec(owner, subject, account="nope")
    with pytest.raises(TypeError):
        create_principal_record(PrincipalSigner.from_identity(owner),
                                subject_signing_public_key=subject.get_signing_public_key(),
                                account=ACC, roles=["delegate"])


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(account="solana:abc"),
    lambda d: d.update(account="Solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x"),
    lambda d: d.update(account=7),
    lambda d: d.update(roles=[]),
    lambda d: d.update(roles=["delegate", "controller"]),
    lambda d: d.update(roles=["controller", "controller"]),
    lambda d: d.update(roles=["owner"]),
    lambda d: d.update(roles="controller"),
    lambda d: d.update(roles=[1]),
    lambda d: d.update(signer="x"),
    lambda d: d["signer"].update(scheme="p256"),
    lambda d: d["signer"].update(publicKey="QQ=="),
    lambda d: d["signer"].update(publicKey="not base64"),
    lambda d: d.update(issuedAt="1"),
    lambda d: d.update(issuedAt=True),
    lambda d: d.update(issuedAt=-1),
    lambda d: d.pop("expiresAt"),
    lambda d: d.update(expiresAt=None),
    lambda d: d.update(expiresAt="1"),
    lambda d: d.update(expiresAt=d["issuedAt"]),
    lambda d: d.update(expiresAt=d["issuedAt"] + YEAR + 1),
    lambda d: d.update(expiresAt=d["expiresAt"] + 1),
    lambda d: d.update(scope=""),
    lambda d: d.update(scope="x" * 257),
    lambda d: d.update(scope="a\nb"),
    lambda d: d.update(scope="a\x7fb"),
    lambda d: d.update(scope=1),
    lambda d: d.update(scope="changed"),
    lambda d: d.pop("signature"),
    lambda d: d.update(signature="0x" + "11" * 65),
    lambda d: d.update(signature="A" * 88),
])
def test_invalid_records(mutate):
    owner, subject = _owner(), SoftwareIdentity.generate("ed25519")
    d = _rec(owner, subject, scope="s", expires_at=NOW + 10).to_dict()
    mutate(d)
    with raises("invalid_principal"):
        validate_principal_record(d, subject.get_signing_public_key(), NOW)


@pytest.mark.parametrize("bad", [None, [], "x", 3])
def test_non_object_record(bad):
    with raises("invalid_principal"):
        validate_principal_record(bad, SoftwareIdentity.generate("ed25519").get_signing_public_key(), NOW)


def test_scope_counts_code_points():
    owner, subject = _owner(), SoftwareIdentity.generate("ed25519")
    _rec(owner, subject, scope="\u00e9" * 256)
    with raises("invalid_principal"):
        _rec(owner, subject, scope="\u00e9" * 257)


def test_subject_mismatch_and_time_bounds():
    owner, subject, other = _owner(), SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    rec = _rec(owner, subject, expires_at=NOW + 10)
    with raises("invalid_principal"):
        validate_principal_record(rec, other.get_signing_public_key(), NOW)
    with raises("invalid_principal"):
        validate_principal_record(rec, subject.get_signing_public_key(), NOW + 10)  # expired
    validate_principal_record(rec, subject.get_signing_public_key(), NOW + 9)
    future = _rec(owner, subject, issued_at=NOW + 300, expires_at=NOW + 900)
    validate_principal_record(future, subject.get_signing_public_key(), NOW)
    with raises("invalid_principal"):
        validate_principal_record(future, subject.get_signing_public_key(), NOW - 1)


# --- same-account rules --------------------------------------------------------------


def _key(identity):
    return PrincipalKey(identity.get_signing_scheme(), to_base64(identity.get_signing_public_key()))


def test_rules():
    owner = _owner()
    ctrl, agent = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("secp256k1")
    p_ctrl = _rec(owner, ctrl, roles=["controller"]).to_dict()
    p_agent = _rec(owner, agent, roles=["delegate"]).to_dict()
    open_ = {MID: ctrl.get_ace_id()}
    seen = []

    def open_to(c, r, now):
        seen.append(now)
        return open_.get(r) if c == CONV else None

    def chk(t, body, p, key, account=ACC, now=NOW, lookup=open_to):
        check_principal_rules(t, body, conversation_id=CONV, sender_principal=p,
                              sender_signing_public_key=key.get_signing_public_key(), self_account=account,
                              self_signer=_key(owner), open_request_to=lookup, now=now)

    req = {"action": "pay", "summary": "s"}
    rep = {"action": "pay", "summary": "s", "outcome": "ok"}
    chk("request", req, p_agent, agent)
    chk("report", rep, p_ctrl, ctrl)  # either direction (R-P3)
    chk("report", rep, p_agent, agent)
    with raises("wrong_principal"):
        chk("request", req, p_agent, agent, account=None)
    with raises("wrong_principal"):
        chk("request", req, None, agent)
    with raises("wrong_principal"):
        chk("request", req, p_agent, ctrl)  # principal of another subject
    with raises("wrong_principal"):
        chk("request", req, {"account": ACC}, agent)  # malformed record
    with raises("wrong_principal"):
        chk("request", req, p_agent, agent, now=NOW + 3600)  # expired since pinning
    with raises("wrong_principal"):
        chk("request", req, p_agent, agent, account="eip155:1:0xabc")
    with raises("wrong_principal"):
        chk("decision", {"requestId": MID, "outcome": "approve"}, p_agent, agent)
    with raises("bad_reference"):
        chk("decision", {"requestId": "00000000-0000-4000-8000-000000000009", "outcome": "approve"}, p_ctrl, ctrl)
    chk("decision", {"requestId": MID, "outcome": "approve"}, p_ctrl, ctrl)
    assert seen[-1] == NOW
    with raises("bad_reference"):
        chk("decision", {"requestId": MID, "outcome": "approve"}, p_ctrl, ctrl, lookup=None)
    with raises("invalid_argument"):
        chk("offer", {"price": "1", "currency": "USDC"}, p_ctrl, ctrl)


def test_decision_only_from_the_controller_the_request_went_to():
    """R-P22: a second controller of the same account cannot decide another's request."""
    owner = _owner()
    ctrl1, ctrl2 = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    p2 = _rec(owner, ctrl2, roles=["controller"]).to_dict()
    with raises("wrong_principal") as info:
        check_principal_rules("decision", {"requestId": MID, "outcome": "approve"}, conversation_id=CONV,
                              sender_principal=p2, sender_signing_public_key=ctrl2.get_signing_public_key(),
                              self_account=ACC, self_signer=_key(owner),
                              open_request_to=lambda c, r, n: ctrl1.get_ace_id(), now=NOW)
    assert "different controller" in info.value.message


def _authority_check(rec, subject, account=ACC, self_signer=None, trusted=frozenset()):
    check_principal_rules("request", {"action": "a", "summary": "s"}, conversation_id=CONV,
                          sender_principal=rec, sender_signing_public_key=subject.get_signing_public_key(),
                          self_account=account, self_signer=self_signer, trusted_signers=trusted,
                          open_request_to=None, now=NOW)


def test_signer_authority_same_signer_and_forged_account():
    """R-P21: the account string alone binds nothing; the signer must be an authority."""
    owner, mallory = _owner(), _owner()
    agent = SoftwareIdentity.generate("ed25519")
    _authority_check(_rec(owner, agent, roles=["delegate"]), agent, self_signer=_key(owner))
    forged = _rec(mallory, agent, roles=["delegate"])  # same account string, attacker's key
    with raises("wrong_principal") as info:
        _authority_check(forged, agent, self_signer=_key(owner))
    assert "authority" in info.value.message
    with raises("wrong_principal"):
        _authority_check(forged, agent)  # no self signer, no trusted set
    _authority_check(forged, agent, self_signer=_key(owner), trusted=frozenset({_key(mallory)}))
    _authority_check(forged, agent, trusted=frozenset({_key(mallory)}))
    ctx = PrincipalContext(ACC, self_signer=_key(owner), trusted_signers=frozenset({_key(mallory)}))
    assert ctx.trusted_signers == frozenset({_key(mallory)})


def test_signer_authority_eip155_derivation():
    from ace.identity import signing_address
    eoa, other = _owner("secp256k1"), _owner("secp256k1")
    agent = SoftwareIdentity.generate("ed25519")
    addr = signing_address("secp256k1", eoa.get_signing_public_key())
    for account in (f"eip155:1:{addr}", f"eip155:8453:{addr.lower()}"):
        _authority_check(_rec(eoa, agent, roles=["delegate"], account=account), agent, account=account)
    acc = f"eip155:1:{addr}"
    with raises("wrong_principal"):
        _authority_check(_rec(other, agent, roles=["delegate"], account=acc), agent, account=acc)
    sol = f"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:{addr}"  # derivation only for eip155
    with raises("wrong_principal"):
        _authority_check(_rec(eoa, agent, roles=["delegate"], account=sol), agent, account=sol)


def test_rules_pure_and_retryable_after_refresh():
    """A failed check has no side effects, so it can be re-run after a peer refresh (R-P20)."""
    owner, agent = _owner(), SoftwareIdentity.generate("ed25519")
    stale = _rec(owner, agent, roles=["delegate"], account="eip155:1:0xabc").to_dict()
    fresh = _rec(owner, agent, roles=["delegate"]).to_dict()
    kw = dict(conversation_id=CONV, sender_signing_public_key=agent.get_signing_public_key(),
              self_account=ACC, self_signer=_key(owner), open_request_to=None, now=NOW)
    with raises("wrong_principal"):
        check_principal_rules("request", {"action": "a", "summary": "s"}, sender_principal=stale, **kw)
    check_principal_rules("request", {"action": "a", "summary": "s"}, sender_principal=fresh, **kw)


def test_principal_context():
    ctx = PrincipalContext(ACC)
    assert ctx.account == ACC and ctx.open_request_to is None
    assert ctx.self_signer is None and ctx.trusted_signers == frozenset()


# --- requests/ ledger ----------------------------------------------------------------


class _Msg:
    def __init__(self, ts=NOW, conv=CONV, mid=MID, to="ace:sha256:" + "cd" * 32):
        self.conversation_id, self.message_id, self.to_id, self.timestamp = conv, mid, to, ts


def _decision(mid=MID, outcome="approve", ts=NOW + 5, own="00000000-0000-4000-8000-0000000000aa"):
    return ParsedMessage(schema_digest="00" * 32, message_id=own, from_id="ace:sha256:" + "cd" * 32, to_id="ace:sha256:" + "ef" * 32,
                         conversation_id=CONV, type="decision", thread_id=None, timestamp=ts,
                         body={"requestId": mid, "outcome": outcome})


def test_request_key_shape():
    import hashlib
    assert request_key(CONV, MID) == "requests/" + hashlib.sha256(f"{CONV}\x00{MID}".encode()).hexdigest() + ".json"


def test_record_request_and_fill_decision():
    store = MemoryStore()
    assert load_request_record(store, CONV, MID) is None
    record_request(store, _Msg(), NOW + 1, ttl=60)
    raw = store.read(request_key(CONV, MID))
    assert json.loads(raw) == {"conversationId": CONV, "decision": None, "expiresAt": NOW + 60, "messageId": MID,
                               "sentAt": NOW + 1, "to": "ace:sha256:" + "cd" * 32, "version": 1}
    assert raw.startswith(b'{"conversationId"')  # canonical sorted keys
    record_request(store, _Msg(), NOW + 99, ttl=1)  # idempotent
    assert load_request_record(store, CONV, MID)["sentAt"] == NOW + 1
    to = "ace:sha256:" + "cd" * 32
    assert open_request_to(store, CONV, MID, NOW + 60) == to
    assert open_request_to(store, CONV, MID, NOW + 61) is None  # timestamp + ttl < now
    assert open_request_to(store, CONV, "00000000-0000-4000-8000-000000000009", NOW) is None
    fill_decision(store, _decision())
    rec = load_request_record(store, CONV, MID)
    assert rec["decision"] == {"messageId": "00000000-0000-4000-8000-0000000000aa", "outcome": "approve",
                               "timestamp": NOW + 5}
    assert open_request_to(store, CONV, MID, NOW) is None
    with raises("bad_reference"):  # R-P25: a second, different decision; the first wins
        fill_decision(store, _decision(outcome="deny", own="00000000-0000-4000-8000-0000000000bb"))
    fill_decision(store, _decision())  # replay of the accepted decision: no-op
    assert load_request_record(store, CONV, MID)["decision"]["outcome"] == "approve"
    fill_decision(store, _decision(mid="00000000-0000-4000-8000-000000000009"))  # unknown: no-op
    store2 = MemoryStore()
    record_request(store2, _Msg(), NOW)
    with raises("wrong_principal"):  # R-P22: decided by someone the request did not go to
        fill_decision(store2, dataclasses.replace(_decision(), from_id="ace:sha256:" + "99" * 32))
    assert load_request_record(store2, CONV, MID)["decision"] is None
    assert load_request_record(store, CONV, "00000000-0000-4000-8000-000000000009") is None


def test_record_request_without_ttl_never_expires():
    store = MemoryStore()
    record_request(store, _Msg(), NOW)
    assert load_request_record(store, CONV, MID)["expiresAt"] is None
    assert open_request_to(store, CONV, MID, NOW + 10 ** 9) == "ace:sha256:" + "cd" * 32


def test_record_request_rejects_bad_ids():
    with raises("invalid_argument"):
        record_request(MemoryStore(), _Msg(conv="xy"), NOW)
    with raises("invalid_argument"):
        record_request(MemoryStore(), _Msg(mid="nope"), NOW)
    with raises("invalid_argument"):
        record_request(MemoryStore(), _Msg(), NOW, ttl=-1)


@pytest.mark.parametrize("patch", [
    {"conversationId": "cd" * 32},
    {"messageId": "00000000-0000-4000-8000-000000000002"},
    {"to": "bob"},
    {"sentAt": "1"},
    {"expiresAt": "1"},
    {"decision": {"messageId": MID, "outcome": "maybe", "timestamp": 1}},
    {"decision": []},
])
def test_load_request_record_rejects_corrupt(patch):
    store = MemoryStore()
    record_request(store, _Msg(), NOW, ttl=5)
    d = json.loads(store.read(request_key(CONV, MID)))
    d.update(patch)
    store.write(request_key(CONV, MID), json.dumps(d).encode())
    with raises("storage_failed"):
        load_request_record(store, CONV, MID)


# --- profile / registration file / registration request / peer record -----------------

import json as _json  # noqa: E402

from ace import (  # noqa: E402
    AgentProfile,
    PeerStore,
    create_registration_file,
    create_registration_request,
    validate_profile,
    verify_peer_record,
    verify_registration_file,
    verify_registration_request,
)
from ace.registration import registration_payload  # noqa: E402


def _peer_record(ident, profile, ts=NOW):
    req = create_registration_request(ident, profile, timestamp=ts)
    return {"aceId": req["aceId"], "scheme": req["scheme"], "encryptionPublicKey": req["encryptionPublicKey"],
            "signingPublicKey": req["signingPublicKey"], "registrationSignature": req["signature"],
            "registeredAt": ts, "profile": req["profile"]}


def test_registration_payload_principal_group():
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    rec = _rec(owner, me, scope="s", expires_at=NOW + 99)
    prof = AgentProfile(name="A", principal=rec)
    p = registration_payload("E", "S", "ed25519", prof)
    tail = encode_payload("present", ACC, "controller,delegate", "ed25519", rec.signer.public_key,
                          str(NOW - 10), str(NOW + 99), "s", rec.signature)
    assert p.endswith(tail)
    assert registration_payload("E", "S", "ed25519", AgentProfile(name="A")).endswith(
        encode_payload("absent", "", "", "", "", "", "", "", ""))


def test_registration_request_round_trip_and_rejection():
    owner, me, other = _owner(), SoftwareIdentity.generate("secp256k1"), SoftwareIdentity.generate("ed25519")
    good = _rec(owner, me).to_dict()
    req = create_registration_request(me, {"name": "A", "principal": good}, timestamp=NOW)
    v = verify_registration_request(_json.loads(_json.dumps(req)), clock=lambda: NOW)
    assert v.peer.principal is not None and v.peer.principal.account == ACC
    with raises("invalid_principal"):
        create_registration_request(me, {"name": "A", "principal": _rec(owner, other).to_dict()}, timestamp=NOW)
    bad = dict(req)
    bad["profile"] = {"name": "A", "principal": {**good, "roles": ["delegate", "controller"]}}
    with raises("invalid_principal"):
        verify_registration_request(bad, clock=lambda: NOW)


def test_peer_record_principal_verified():
    owner, me, other = _owner(), SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    rec = _peer_record(me, {"name": "A", "principal": _rec(owner, me, expires_at=NOW + 50).to_dict()})
    assert verify_peer_record(rec, clock=lambda: NOW).principal.roles == ("controller", "delegate")
    # Expired-only: treated as absent, the rest of the peer is kept (R-P40).
    expired = verify_peer_record(rec, clock=lambda: NOW + 50)
    assert expired.principal is None and expired.profile.name == "A"
    rec["profile"]["principal"] = _rec(owner, other).to_dict()
    with raises("invalid_principal"):
        verify_peer_record(rec, clock=lambda: NOW)


def test_registration_file_principal():
    # create_registration_file validates against the wall clock, so issue relative to it.
    import time

    t = int(time.time())
    owner, me, other = _owner(), SoftwareIdentity.generate("secp256k1"), SoftwareIdentity.generate("ed25519")
    rec = _rec(owner, me, issued_at=t - 10, expires_at=t + 3600)
    reg = create_registration_file(me, name="M", endpoint="https://m.example/ace", principal=rec)
    assert reg.to_dict()["principal"]["account"] == ACC
    peer = verify_registration_file(reg.to_dict(), clock=lambda: t)
    assert peer.principal.account == ACC and peer.profile.to_dict() == {"principal": reg.principal.to_dict()}
    assert verify_registration_file(create_registration_file(me, name="M", endpoint="https://m.example/ace")).profile is None
    d = reg.to_dict()
    d["principal"] = _rec(owner, other, issued_at=t - 10, expires_at=t + 3600).to_dict()
    with raises("invalid_principal"):
        verify_registration_file(d, clock=lambda: t)
    gone = verify_registration_file(reg.to_dict(), clock=lambda: t + 3600)
    assert gone.principal is None and gone.profile is None  # expired-only: absent (R-P40)


def test_registration_file_rejects_expired_or_future_principal():
    # R-P44: publishing validates the principal at the real now, expiry included.
    import time

    t = int(time.time())
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    expired = _rec(owner, me, issued_at=t - 7200, expires_at=t - 60)
    future = _rec(owner, me, issued_at=t + 3600, expires_at=t + 7200)
    for rec in (expired, future):
        with raises("invalid_principal"):
            create_registration_file(me, name="M", endpoint="https://m.example/ace", principal=rec)


def test_profile_checks_precede_principal_parse():
    # R-P45: other members are checked before the principal (08 order).
    with raises("invalid_profile"):
        validate_profile({"name": "x" * 100, "principal": 5})
    with raises("invalid_profile"):
        AgentProfile.from_dict({"name": 5, "principal": 5})
    with raises("invalid_principal"):
        validate_profile({"name": "ok", "principal": 5})


def test_expired_only_principal_is_absent_in_fetched_records():
    owner, me, other = _owner(), SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    prof = {"name": "A", "tags": ["x"], "principal": _rec(owner, me, expires_at=NOW + 50).to_dict()}
    v = verify_peer_record(_peer_record(me, prof), clock=lambda: NOW + 50)
    assert v.principal is None and v.profile.name == "A" and list(v.profile.tags) == ["x"]
    # Wrong subject / forged principal that is also expired is still invalid, not merely expired.
    forged = {"name": "A", "principal": _rec(owner, other, expires_at=NOW + 50).to_dict()}
    rec = _peer_record(me, {"name": "A"})
    rec["profile"] = forged
    with raises("invalid_principal"):
        verify_peer_record(rec, clock=lambda: NOW + 50)
    # Relay-side registration still rejects an expired principal.
    req = create_registration_request(me, {"name": "A", "principal": _rec(owner, me, expires_at=NOW + 50).to_dict()},
                                      timestamp=NOW)
    with raises("invalid_principal"):
        verify_registration_request(req, clock=lambda: NOW + 50)


def test_pin_expired_at_fetch_is_dropped_on_load():
    # Loads re-verify with fetchedAt as now: a principal already expired at fetch time is dropped.
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    store = MemoryStore()
    peers = PeerStore(store, clock=lambda: NOW)
    peers.adopt(verify_peer_record(_peer_record(me, {"name": "A", "principal": _rec(owner, me, expires_at=NOW + 5).to_dict()}),
                                   clock=lambda: NOW))
    import json as j

    for k in list(store._data):
        d = j.loads(store.read(k))
        d["fetchedAt"] = NOW + 100  # rewrite fetchedAt past the expiry
        store.write(k, j.dumps(d).encode())
    loaded = PeerStore(store, clock=lambda: NOW + 100).get(me.get_ace_id())
    assert loaded.principal is None and loaded.profile.name == "A"


def test_expired_pin_still_loads():
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    store = MemoryStore()
    peers = PeerStore(store, clock=lambda: clock[0])
    peers.adopt(verify_peer_record(_peer_record(me, {"principal": _rec(owner, me, expires_at=NOW + 5).to_dict()}),
                                   clock=lambda: NOW))
    clock[0] = NOW + 10_000
    assert PeerStore(store, clock=lambda: clock[0]).get(me.get_ace_id()).principal is not None


def _pin_with_principal(owner, me, clock, **kw):
    peers = PeerStore(MemoryStore(), clock=lambda: clock[0])
    prof = {"name": "Old", "tags": ["a"], "principal": _rec(owner, me, **kw).to_dict()}
    pin = peers.adopt(verify_peer_record(_peer_record(me, prof), clock=lambda: NOW)).peer
    return peers, pin


def _file_candidate(me, profile, t=NOW):
    from ace.discovery import _make_peer

    reg = create_registration_file(me, name="M", endpoint="https://m.example/ace", timestamp=t)
    base = verify_registration_file(reg, clock=lambda: t)
    return _make_peer(ace_id=base.ace_id, scheme=base.scheme, signing_public_key=base.signing_public_key,
                      encryption_public_key=base.encryption_public_key, registered_at=t,
                      registration_signature=base.registration_signature, source="registration", profile=profile)


def test_file_candidate_without_principal_keeps_cached_principal():
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    peers, pin = _pin_with_principal(owner, me, clock)
    clock[0] = NOW + 100
    out = peers.adopt(_file_candidate(me, AgentProfile(name="New", tags=["b"]))).peer
    assert out.principal == pin.principal and out.profile.name == "New" and out.profile.tags == ["b"]
    assert out.encryption_public_key == pin.encryption_public_key
    assert out.registered_at == pin.registered_at and out.source == pin.source
    assert out.registration_signature == pin.registration_signature
    assert peers.get(me.get_ace_id()).principal == pin.principal
    out = peers.adopt(_file_candidate(me, None)).peer
    assert out.principal == pin.principal


def test_file_candidate_principal_older_or_newer():
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    peers, pin = _pin_with_principal(owner, me, clock)
    older = PrincipalRecord.from_dict(_rec(owner, me, issued_at=NOW - 20, scope="old").to_dict())
    assert peers.adopt(_file_candidate(me, AgentProfile(principal=older))).peer.principal == pin.principal
    newer = PrincipalRecord.from_dict(_rec(owner, me, issued_at=NOW - 5, scope="new").to_dict())
    out = peers.adopt(_file_candidate(me, AgentProfile(principal=newer))).peer
    assert out.principal == newer and peers.get(me.get_ace_id()).principal == newer


def test_relay_candidate_without_principal_clears_it():
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    peers, _ = _pin_with_principal(owner, me, clock)
    rec = _peer_record(me, {"name": "New"}, ts=NOW + 10)
    clock[0] = NOW + 20
    out = peers.adopt(verify_peer_record(rec, clock=lambda: NOW + 10)).peer
    assert out.principal is None and peers.get(me.get_ace_id()).principal is None


# --- Task 6: pipeline step 7, Inbox principal context, requests/ ledger ------------------

import base64 as _b64  # noqa: E402

from ace import (  # noqa: E402
    Outbox,
    ReplayDetector,
    ThreadStateMachine,
    create_message,
    parse_message,
)

from .helpers import wire  # noqa: E402
from .pipeline import Agent, Clock, CountingStore  # noqa: E402

RID2 = "00000000-0000-4000-8000-0000000000bb"


def _signer_dict(owner):
    return {"scheme": owner.get_signing_scheme(), "publicKey": to_base64(bytes(owner.get_signing_public_key()))}


def _pin_relay(peers, ident, principal=None, name=None, ts=NOW):
    prof = {} if name is None else {"name": name}
    if principal is not None:
        prof["principal"] = principal.to_dict()
    return peers.adopt(verify_peer_record(_peer_record(ident, prof, ts=ts), clock=lambda: ts)).peer


def _pair_with_principals(roles_a=("controller", "delegate"), roles_b=("delegate",), acc_b=ACC, relay=None, pin_b_principal=True):
    clock = Clock(NOW)
    owner = _owner()
    a, b = Agent("a", "ed25519", clock, relay=relay), Agent("b", "secp256k1", clock)
    pa = _rec(owner, a.identity, roles=list(roles_a))
    pb = _rec(owner, b.identity, roles=list(roles_b), account=acc_b)
    _pin_relay(a.peers, b.identity, pb if pin_b_principal else None, name="b")
    _pin_relay(b.peers, a.identity, pa, name="a")
    return clock, owner, a, b, pb


def _open(agent, owner=None, account=ACC, **kw):
    if account is None:
        return agent.open(**kw)
    principal = {"account": account}
    if owner is not None:
        principal["selfSigner"] = _signer_dict(owner)
    return agent.open(principal=principal, **kw)


def _send(sender, receiver_inbox, recipient, type_, body, n):
    p = sender.outbox.stage(sender.peers.get(recipient.id), type_, body)
    out = sender.outbox.deliver(p.request_id, lambda env: receiver_inbox.receive(wire(env)))
    return out, p


def test_parse_message_without_policy_delivers_data():
    clock, owner, a, b, _ = _pair_with_principals()
    env = create_message(b.identity, b.peers.get(a.id), "request", {"action": "pay", "summary": "s"},
                         ThreadStateMachine(b.id), timestamp=NOW)
    assert parse_message(env, a.identity, a.peers.get(b.id), threads=ThreadStateMachine(a.id),
                         replay=ReplayDetector(horizon=NOW - 100), clock=clock).type == "request"
    ctx = PrincipalContext(ACC, self_signer=PrincipalKey(**{"scheme": "ed25519", "public_key": _signer_dict(owner)["publicKey"]}))
    parsed = parse_message(env, a.identity, a.peers.get(b.id), threads=ThreadStateMachine(a.id),
                           replay=ReplayDetector(horizon=NOW - 100), clock=clock, principal=ctx)
    assert parsed.type == "request"


def test_request_decision_round_trip_and_second_decision():
    clock, owner, a, b, _ = _pair_with_principals()
    ia, ib = _open(a, owner), _open(b, owner)
    out, req = _send(b, ia, a, "request", {"action": "pay", "summary": "Pay 1 USDC", "ttl": 600}, 1)
    assert out.kind == "delivered"
    rec = load_request_record(b.store, out.message.conversation_id, req.message.message_id)
    assert rec["decision"] is None and rec["to"] == a.id and rec["expiresAt"] == req.message.timestamp + 600
    assert b.outbox.pending() == []
    d1, p1 = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "approve", "result": {"tx": "0x1"}}, 1)
    assert d1.kind == "delivered" and b.host.effects[(a.id, p1.message.message_id)].type == "decision"
    dec = load_request_record(b.store, out.message.conversation_id, req.message.message_id)["decision"]
    assert dec == {"messageId": p1.message.message_id, "outcome": "approve", "timestamp": p1.message.timestamp}
    d2, _ = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "deny"}, 2)
    assert d2.kind == "quarantined" and d2.error.code == "bad_reference"
    assert load_request_record(b.store, out.message.conversation_id, req.message.message_id)["decision"] == dec


def test_decision_for_expired_or_unknown_request_is_bad_reference():
    clock, owner, a, b, _ = _pair_with_principals()
    ia, ib = _open(a, owner), _open(b, owner)
    _, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s", "ttl": 10}, 1)
    clock.t = NOW + 11
    d, _ = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 1)
    assert d.kind == "quarantined" and d.error.code == "bad_reference"
    d, _ = _send(a, ib, b, "decision", {"requestId": RID2, "outcome": "approve"}, 2)
    assert d.kind == "quarantined" and d.error.code == "bad_reference"


def test_decision_from_agent_and_other_account_rejected():
    clock, owner, a, b, _ = _pair_with_principals(roles_a=("delegate",))
    ia, ib = _open(a, owner), _open(b, owner)
    _, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    d, _ = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 1)
    assert d.kind == "quarantined" and d.error.code == "wrong_principal"
    clock2, owner2, c, e, _ = _pair_with_principals(acc_b="eip155:1:0x" + "ab" * 20)
    ic = _open(c, owner2)
    r, _ = _send(e, ic, c, "report", {"action": "pay", "summary": "s", "outcome": "ok"}, 1)
    assert r.kind == "quarantined" and r.error.code == "wrong_principal"


def test_inbox_without_policy_delivers_data_and_open_validates_option():
    clock, owner, a, b, _ = _pair_with_principals()
    ia, ib = _open(a, account=None), _open(b, account=None)
    r, _ = _send(b, ia, a, "report", {"action": "pay", "summary": "s", "outcome": "ok"}, 1)
    assert r.kind == "delivered"
    # without a policy a decision is plain data: delivered, and it never fills the request ledger
    _, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 2)
    d, _ = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 1)
    assert d.kind == "delivered"
    conv, mid = req.message.conversation_id, req.message.message_id
    assert load_request_record(b.store, conv, mid)["decision"] is None
    ia.close()
    ib.close()
    for bad in ({"account": "nope"}, "solana:x:y", {"account": ACC, "selfSigner": {"scheme": "rsa", "publicKey": "AA=="}},
                {"account": ACC, "selfSigner": "k"}, {"account": ACC, "trustedSigners": {"scheme": "ed25519"}},
                {"account": ACC, "trustedSigners": [{"scheme": "ed25519", "publicKey": 3}]}, {"account": ACC, "selfsigner": None}):
        with raises("invalid_argument"):
            a.open(principal=bad)
    _open(a, account=ACC, ).close()
    a.open(principal={"account": ACC, "selfSigner": None, "trustedSigners": []}).close()


def test_without_self_signer_fails_closed():
    clock, owner, a, b, _ = _pair_with_principals()
    ia = _open(a)  # account only: neither selfSigner nor trustedSigners, solana account
    r, _ = _send(b, ia, a, "report", {"action": "pay", "summary": "s", "outcome": "ok"}, 1)
    assert r.kind == "quarantined" and r.error.code == "wrong_principal"
    ia.close()
    ia = a.open(principal={"account": ACC, "trustedSigners": [_signer_dict(owner)]})
    r, _ = _send(b, ia, a, "report", {"action": "pay", "summary": "s2", "outcome": "ok"}, 2)
    assert r.kind == "delivered"


def test_eip155_account_passes_without_self_signer():
    from ace.identity import signing_address

    clock = Clock(NOW)
    owner = _owner("secp256k1")
    acc = "eip155:1:" + signing_address("secp256k1", bytes(owner.get_signing_public_key()))
    a, b = Agent("a", "ed25519", clock), Agent("b", "ed25519", clock)
    _pin_relay(a.peers, b.identity, _rec(owner, b.identity, account=acc))
    _pin_relay(b.peers, a.identity, _rec(owner, a.identity, account=acc))
    ia = a.open(principal={"account": acc})
    r, _ = _send(b, ia, a, "report", {"action": "pay", "summary": "s", "outcome": "ok"}, 1)
    assert r.kind == "delivered"


class _FakeRelay:
    def __init__(self, record=None, error=None):
        self.record, self.error, self.calls = record, error, 0

    def lookup_peer(self, ace_id):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return verify_peer_record(self.record, clock=lambda: NOW)


def test_wrong_principal_refreshes_peer_once_then_accepts():
    relay = _FakeRelay()
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    relay.record = _peer_record(b.identity, {"name": "b2", "principal": pb.to_dict()}, ts=NOW)
    ia = _open(a, owner)
    r, _ = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    assert r.kind == "delivered" and relay.calls == 1
    assert a.peers.get(b.id).principal == pb and a.peers.get(b.id).profile.name == "b2"
    r, _ = _send(b, ia, a, "report", {"action": "pay", "summary": "s", "outcome": "ok"}, 2)
    assert r.kind == "delivered" and relay.calls == 1  # pin now valid: no refresh


def test_cheap_prechecks_skip_the_refresh():
    relay = _FakeRelay()
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    relay.record = _peer_record(b.identity, {"name": "b2", "principal": pb.to_dict()}, ts=NOW)
    ia = _open(a, owner)
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s"})
    other = dataclasses.replace(p.message, to_id="ace:sha256:" + "ee" * 32)
    r = ia.receive(wire(other))
    assert r.kind == "quarantined" and r.error.code == "wrong_recipient" and relay.calls == 0
    stale = dataclasses.replace(p.message, timestamp=NOW - 10_000_000)
    r = ia.receive(wire(stale))
    assert r.kind == "quarantined" and r.error.code == "stale_timestamp" and relay.calls == 0
    r, p2 = _send(b, ia, a, "request", {"action": "pay", "summary": "s2"}, 3)
    assert r.kind == "delivered" and relay.calls == 1
    r = ia.receive(wire(p2.message))
    assert r.kind == "duplicate" and relay.calls == 1


def test_replay_precheck_is_a_read_not_a_commit():
    relay = _FakeRelay()
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    relay.record = _peer_record(b.identity, {"principal": pb.to_dict()}, ts=NOW)
    ia = _open(a, owner)
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s"})
    ia._replay.commit(p.message.message_id, b.id, p.message.timestamp, 0)
    r = ia.receive(wire(p.message))
    assert r.kind == "duplicate" and relay.calls == 0


def test_open_rejects_malformed_principal_keys():
    clock, owner, a, b, _ = _pair_with_principals()
    good = _signer_dict(owner)
    pk = good["publicKey"]
    bad_keys = [
        {"scheme": "rsa", "publicKey": pk},
        {"scheme": "ed25519", "publicKey": ""},
        {"scheme": "ed25519", "publicKey": 3},
        {"scheme": "ed25519", "publicKey": None},
        {"scheme": "ed25519", "publicKey": "QR=="},
        {"scheme": "ed25519", "publicKey": pk.rstrip("=")},
        {"scheme": "ed25519", "publicKey": "_-_-"},
        # canonical Base64 but not a valid key for the scheme
        {"scheme": "ed25519", "publicKey": to_base64(b"\x01" * 31)},
        {"scheme": "secp256k1", "publicKey": pk},
        {"scheme": "secp256k1", "publicKey": to_base64(b"\x04" + b"\x01" * 32)},
        {"scheme": "secp256k1", "publicKey": to_base64(b"\x02" + b"\xff" * 32)},
    ]
    for bad_key in bad_keys:
        for field in ({"selfSigner": bad_key}, {"trustedSigners": [good, bad_key]}):
            with raises("invalid_argument"):
                a.open(principal={"account": ACC, **field})
    a.open(principal={"account": ACC, "selfSigner": good, "trustedSigners": [good]}).close()


def test_transient_refresh_failure_is_retryable_then_accepted():
    relay = _FakeRelay(error=ACEError("relay_unavailable", "down"))
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    ia = _open(a, owner)
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s"})
    r = ia.receive(wire(p.message))
    assert r.kind == "retryable" and r.error.code == "relay_unavailable" and relay.calls == 1
    assert not ia._failed
    relay.error = RuntimeError("socket closed")  # a non-ACE exception is relay_unavailable too
    r = ia.receive(wire(p.message))
    assert r.kind == "retryable" and r.error.code == "relay_unavailable"
    relay.error, relay.record = None, _peer_record(b.identity, {"principal": pb.to_dict()}, ts=NOW)
    r = ia.receive(wire(p.message))
    assert r.kind == "delivered" and relay.calls == 3


def test_permanent_error_in_principal_sender_refresh_is_quarantined_not_retried(monkeypatch):
    relay = _FakeRelay()
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    ia = _open(a, owner)

    def boom(env, peer, now):
        raise ACEError("invalid_principal", "unusable")

    monkeypatch.setattr(ia, "_refresh_principal_sender", boom)
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s"})
    r = ia.receive(wire(p.message))
    assert r.kind == "quarantined" and r.error.code == "invalid_principal"
    assert not ia._failed


def test_wrong_principal_after_permanent_or_useless_refresh():
    relay = _FakeRelay(error=ACEError("unknown_peer", "gone"))
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    ia = _open(a, owner)
    r, _ = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    assert r.kind == "quarantined" and r.error.code == "wrong_principal" and relay.calls == 1
    relay.error, relay.record = None, _peer_record(b.identity, {"name": "b"}, ts=NOW)
    r, _ = _send(b, ia, a, "request", {"action": "pay", "summary": "s2"}, 2)
    assert r.kind == "quarantined" and r.error.code == "wrong_principal" and relay.calls == 2
    # another account: refreshed once, still the other account
    relay2 = _FakeRelay()
    clock, owner, c, e, pe = _pair_with_principals(acc_b="solana:x:other", relay=relay2)
    relay2.record = _peer_record(e.identity, {"principal": pe.to_dict()}, ts=NOW)
    ic = _open(c, owner)
    r, _ = _send(e, ic, c, "report", {"action": "pay", "summary": "s", "outcome": "ok"}, 1)
    assert r.error.code == "wrong_principal" and relay2.calls == 1


class _LockAudit(CountingStore):
    """Records whether lock ``requests`` was held on every ``requests/`` access."""

    def __init__(self, inner):
        super().__init__(inner)
        self.held = 0
        self.accesses: list[tuple[str, bool]] = []

    def read(self, key):
        if key.startswith("requests/"):
            self.accesses.append(("read", self.held > 0))
        return super().read(key)

    def write(self, key, value):
        if key.startswith("requests/"):
            self.accesses.append(("write", self.held > 0))
        return super().write(key, value)

    def lock(self, name, timeout=10.0):
        inner = super().lock(name, timeout)
        audit = self

        class _Ctx:
            def __enter__(self):
                r = inner.__enter__()
                if name == "requests":
                    audit.held += 1
                return r

            def __exit__(self, *exc):
                if name == "requests":
                    audit.held -= 1
                return inner.__exit__(*exc)

        return _Ctx()


def test_decision_check_and_fill_under_requests_lock():
    clock, owner, a, b, _ = _pair_with_principals()
    ia = _open(a, owner)
    _, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    audit = _LockAudit(b.store)
    ib = b.open(store=audit, principal={"account": ACC, "selfSigner": _signer_dict(owner)})
    d, _ = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 1)
    assert d.kind == "delivered"
    kinds = [k for k, _ in audit.accesses]
    assert "read" in kinds and "write" in kinds and all(held for _, held in audit.accesses)


def test_fill_decision_second_different_decision_is_bad_reference():
    store = MemoryStore()
    record_request(store, _Msg(), NOW)
    first = _decision()
    fill_decision(store, first)
    before = load_request_record(store, CONV, MID)
    fill_decision(store, first)  # replay of the same decision: no-op
    assert load_request_record(store, CONV, MID) == before
    with raises("bad_reference"):
        fill_decision(store, dataclasses.replace(first, message_id=RID2, body={"requestId": MID, "outcome": "deny"}))
    assert load_request_record(store, CONV, MID) == before


class _OrderStore(CountingStore):
    def __init__(self, inner, fail_key_prefix=None):
        super().__init__(inner)
        self.log: list[tuple[str, str]] = []
        self.fail_key_prefix = fail_key_prefix

    def write(self, key, value):
        if self.fail_key_prefix and key.startswith(self.fail_key_prefix):
            self.fail_key_prefix = None
            raise ACEError("storage_failed", "injected")
        self.log.append(("write", key))
        return super().write(key, value)

    def delete(self, key):
        self.log.append(("delete", key))
        return super().delete(key)


def test_request_record_written_before_ack():
    clock, owner, a, b, _ = _pair_with_principals()
    ia = _open(a, owner)
    store = _OrderStore(b.store, fail_key_prefix="requests/")
    outbox = Outbox.open(b.identity, store, clock=clock)
    p = outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s", "ttl": 30})
    transport = lambda env: ia.receive(wire(env))  # noqa: E731
    # The requests/ write fails before transport: nothing is sent; the request stays pending.
    with raises("storage_failed"):
        outbox.deliver(p.request_id, transport)
    conv = p.message.conversation_id
    assert load_request_record(b.store, conv, p.message.message_id) is None
    assert [x.request_id for x in outbox.pending()] == [p.request_id]
    # A process restart keeps ttl with the pending send; the retry writes the record, then clears.
    outbox = Outbox.open(b.identity, store, clock=clock)
    assert outbox.pending()[0].request_ttl == 30
    res = outbox.deliver(p.request_id, transport)
    assert res.kind == "delivered"
    rec = load_request_record(b.store, conv, p.message.message_id)
    assert rec["to"] == a.id and rec["expiresAt"] == p.message.timestamp + 30 and rec["sentAt"] == NOW
    i_req = store.log.index(("write", request_key(conv, p.message.message_id)))
    i_del = [i for i, (op, k) in enumerate(store.log) if op == "delete" and k.startswith("outbox/")]
    assert i_del and i_req < i_del[0] and outbox.pending() == []


def test_transport_retry_cannot_renew_request_deadline():
    clock, owner, a, b, _ = _pair_with_principals()
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s", "ttl": 30})
    with raises("envelope_expired"):
        b.outbox.deliver(p.request_id, lambda env: (_ for _ in ()).throw(ACEError("envelope_expired", "x")))
    clock.t = NOW + 50
    with raises("invalid_argument"):
        b.outbox.resign(p.request_id)
    rec = load_request_record(b.store, p.message.conversation_id, p.message.message_id)
    assert rec["expiresAt"] == NOW + 30


def test_decision_fill_recovered_after_crash():
    clock, owner, a, b, _ = _pair_with_principals()
    ia = _open(a, owner)
    out, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    conv = out.message.conversation_id
    principal = {"account": ACC, "selfSigner": _signer_dict(owner)}
    b.open(principal=principal).close()  # replay.json exists
    store = CountingStore(b.store)
    ib = b.open(store=store, principal=principal)
    # Crash: the decision's delivery record is written, the requests/ fill fails.
    store.fail_at = len(store.writes) + 2
    p = a.outbox.stage(a.peers.get(b.id), "decision", {"requestId": req.message.message_id, "outcome": "approve"})
    res = ib.receive(wire(p.message))
    assert res.kind == "retryable"
    assert store.writes[-2].startswith("deliveries/") and store.writes[-1].startswith("requests/")
    ib.close()
    assert load_request_record(b.store, conv, req.message.message_id)["decision"] is None
    assert b.host.effects == {}
    ib2 = b.open(principal=principal)  # recovery fills it, then hands over
    dec = load_request_record(b.store, conv, req.message.message_id)["decision"]
    assert dec["messageId"] == p.message.message_id and dec["outcome"] == "approve"
    assert (a.id, p.message.message_id) in b.host.effects
    res = ib2.receive(wire(p.message))
    assert res.kind == "duplicate"
    ib2.close()
    b.open(principal=principal).close()  # recovery again: same decision is a no-op


def test_registration_file_refresh_keeps_cached_members():
    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    peers, pin = _pin_with_principal(owner, me, clock)
    out = peers.adopt(_file_candidate(me, AgentProfile(principal=pin.principal))).peer
    assert out.profile.name == "Old" and out.profile.tags == ["a"] and out.principal == pin.principal
    out = peers.adopt(_file_candidate(me, None)).peer
    assert out.profile.name == "Old" and out.profile.tags == ["a"]
    out = peers.adopt(_file_candidate(me, AgentProfile(description="d"))).peer
    assert out.profile.name == "Old" and out.profile.description == "d" and out.principal == pin.principal
    assert peers.get(me.get_ace_id()).profile.name == "Old"


def test_concurrent_different_decisions_accept_exactly_one():
    import threading

    clock, owner, a, b, _ = _pair_with_principals()
    ia, ib = _open(a, owner), _open(b, owner)
    _, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    ps = [a.outbox.stage(a.peers.get(b.id), "decision", {"requestId": req.message.message_id, "outcome": o})
          for o in ("approve", "deny")]
    results = [None, None]
    start = threading.Barrier(2)

    def run(i):
        start.wait()
        results[i] = ib.receive(wire(ps[i].message))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    kinds = sorted((r.kind, None if r.error is None else r.error.code) for r in results)
    assert kinds == [("delivered", None), ("quarantined", "bad_reference")]
    winner = next(p for p, r in zip(ps, results) if r.kind == "delivered")
    dec = load_request_record(b.store, req.message.conversation_id, req.message.message_id)["decision"]
    assert dec["messageId"] == winner.message.message_id


def test_decision_refresh_runs_outside_requests_lock():
    relay = _FakeRelay()
    clock = Clock(NOW)
    owner = _owner()
    a, b = Agent("a", "ed25519", clock), Agent("b", "secp256k1", clock, relay=relay)
    pa = _rec(owner, a.identity)
    _pin_relay(a.peers, b.identity, _rec(owner, b.identity, roles=["delegate"]), name="b")
    _pin_relay(b.peers, a.identity, None, name="a")  # b's pin of a lacks the principal
    relay.record = _peer_record(a.identity, {"principal": pa.to_dict()}, ts=NOW)
    ia = _open(a, owner)
    _, req = _send(b, ia, a, "request", {"action": "pay", "summary": "s"}, 1)
    audit = _LockAudit(b.store)
    held_at_lookup = []
    orig = relay.lookup_peer
    relay.lookup_peer = lambda ace_id: (held_at_lookup.append(audit.held), orig(ace_id))[1]
    ib = b.open(store=audit, principal={"account": ACC, "selfSigner": _signer_dict(owner)})
    d, _ = _send(a, ib, b, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 1)
    assert d.kind == "delivered" and held_at_lookup == [0]


def test_pending_request_ttl_normalized_and_typed():
    from ace.threads import PendingSend

    clock, owner, a, b, _ = _pair_with_principals()
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s", "ttl": 30.0})
    assert type(p.request_ttl) is int and p.request_ttl == 30
    d = p.to_dict()
    assert type(PendingSend.from_dict({**d, "requestTtl": 30.0}).request_ttl) is int
    for bad in (-1, "30", True, 1.5):
        with raises("storage_failed"):
            PendingSend.from_dict({**d, "requestTtl": bad})
    t = b.outbox.stage(b.peers.get(a.id), "report", {"action": "pay", "summary": "s", "outcome": "ok"}).to_dict()
    assert "requestTtl" not in t
    with raises("storage_failed"):
        PendingSend.from_dict({**t, "requestTtl": 30})


def test_forged_principal_envelope_triggers_no_refresh():
    relay = _FakeRelay()
    clock, owner, a, b, pb = _pair_with_principals(relay=relay, pin_b_principal=False)
    relay.record = _peer_record(b.identity, {"principal": pb.to_dict()}, ts=NOW)
    ia = _open(a, owner)
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s"})
    forged = p.message.to_dict()
    sig = bytearray(_b64.b64decode(forged["signature"]["value"]))
    sig[5] ^= 0x01
    forged["signature"]["value"] = _b64.b64encode(bytes(sig)).decode()
    r = ia.receive(wire(forged))
    assert r.kind == "quarantined" and r.error.code == "invalid_signature" and relay.calls == 0
    r = ia.receive(wire(p.message))
    assert r.kind == "delivered" and relay.calls == 1


@pytest.mark.parametrize("lost_ack", [False, True])
def test_controller_reply_before_request_ack(lost_ack):
    _, owner, a, b, _ = _pair_with_principals()
    ia, ib = _open(a, owner), _open(b, owner)
    p = b.outbox.stage(b.peers.get(a.id), "request", {"action": "pay", "summary": "s", "ttl": 60})
    def transport(env):
        assert ia.receive(wire(env)).kind == "delivered"
        result, _ = _send(a, ib, b, "decision", {"requestId": env.message_id, "outcome": "approve"}, 1)
        assert result.kind == "delivered"
        if lost_ack:
            raise RuntimeError("ACK lost")
    if lost_ack:
        with pytest.raises(RuntimeError, match="ACK lost"):
            b.outbox.deliver(p.request_id, transport)
    else:
        b.outbox.deliver(p.request_id, transport)
    assert load_request_record(b.store, p.message.conversation_id, p.message.message_id)["decision"]["outcome"] == "approve"
    ia.close()
    ib.close()


@pytest.mark.parametrize("event", ["strip", "expire", "remove", "rotate"])
def test_durable_principal_horizon_survives_omission_expiry_and_restart(event):
    from ace import MemoryStore, PeerStore
    owner, subject = _owner(), SoftwareIdentity.generate("ed25519")
    store = MemoryStore()
    now = NOW
    peers = PeerStore(store, clock=lambda: now)
    latest = _rec(owner, subject, issued_at=NOW - 5, expires_at=NOW + 10, roles=["delegate"])
    older = _rec(owner, subject, issued_at=NOW - 10, roles=["controller"])
    def peer(identity, principal=None):
        return verify_peer_record(_peer_record(identity, {"principal": principal.to_dict()} if principal else {}, ts=now), clock=lambda: now)
    peers.adopt(peer(subject, latest))
    now += 20
    identity = subject
    if event == "remove":
        peers.remove(subject.get_ace_id())
    else:
        if event == "rotate":
            exported = subject.export_private_key()
            exported["encryptionPrivateKey"] = to_base64(bytes([42]) * 32)
            identity = SoftwareIdentity.from_export(exported)
        peers.adopt(peer(identity))
    peers = PeerStore(store, clock=lambda: now)
    with raises("invalid_principal"):
        peers.adopt(peer(identity, older))
    saved = peers.get(subject.get_ace_id())
    assert saved is None or saved.principal is None


def test_opaque_scope_does_not_grant_unrestricted_authority():
    owner, subject = _owner(), SoftwareIdentity.generate("ed25519")
    with raises("wrong_principal"):
        check_principal_rules("request", {"action": "pay", "summary": "s"}, conversation_id="ab" * 32,
            sender_principal=_rec(owner, subject, scope="read-only"), sender_signing_public_key=subject.get_signing_public_key(),
            self_account=ACC, self_signer=PrincipalKey(owner.get_signing_scheme(), to_base64(owner.get_signing_public_key())), open_request_to=None, now=NOW)


def test_unrelated_issuer_cannot_poison_principal_horizon():
    from ace import MemoryStore, PeerStore
    owner, attacker, subject = _owner(), SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    peers = PeerStore(MemoryStore(), clock=lambda: NOW)
    valid = _rec(owner, subject, roles=["delegate"])
    poison = _rec(attacker, subject, issued_at=NOW + 100, roles=["controller"])
    for principal in [valid, poison, valid]:
        adopted = peers.adopt(verify_peer_record(_peer_record(subject, {"principal": principal.to_dict()}), clock=lambda: NOW))
    assert adopted.peer.principal == valid


# --- principal recovery replays the account rules (06 step 1a, 09 § Persistence) ---------


def test_recovery_decision_delivered_as_data_never_fills_requests():
    clock, owner, a, b, _ = _pair_with_principals()  # b is a delegate, not a controller
    ib = _open(b, account=None)
    ia0 = _open(a, account=None)
    _, req = _send(a, ib, b, "request", {"action": "pay", "summary": "s"}, 1)
    d, _ = _send(b, ia0, a, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 1)
    assert d.kind == "delivered"
    ia0.close()
    ia1 = _open(a, owner)
    assert load_request_record(a.store, req.message.conversation_id, req.message.message_id)["decision"] is None
    ia1.close()
    ib.close()


def test_recovery_two_data_only_decisions_do_not_fail_open_with_a_principal():
    clock, owner, a, b, _ = _pair_with_principals(roles_b=("controller",))
    ib = _open(b, account=None)
    ia0 = _open(a, account=None)
    _, req = _send(a, ib, b, "request", {"action": "pay", "summary": "s"}, 1)
    _send(b, ia0, a, "decision", {"requestId": req.message.message_id, "outcome": "deny"}, 1)
    clock.t += 1
    _send(b, ia0, a, "decision", {"requestId": req.message.message_id, "outcome": "approve"}, 2)
    ia0.close()
    ia1 = _open(a, owner)
    # the first decision passes the rules at the replayed processing; the second finds the request decided
    rec = load_request_record(a.store, req.message.conversation_id, req.message.message_id)
    assert rec["decision"]["outcome"] == "deny"
    ia1.close()
    ib.close()
