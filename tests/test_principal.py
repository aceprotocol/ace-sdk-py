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
                roles=["agent", "controller", "agent"], issued_at=NOW - 10, expires_at=NOW + 3600)
    args.update(kw)
    return create_principal_record(PrincipalSigner.from_identity(owner), **args)


def test_constants_and_caip10():
    assert PRINCIPAL_ROLES == ("controller", "agent")
    assert is_caip10(ACC) and is_caip10("eip155:1:0xabc")
    assert not is_caip10("solana:abc") and not is_caip10("Solana:x:y") and not is_caip10(3)
    assert not is_caip10(ACC + "\n")


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_create_and_validate(scheme):
    owner, subject = _owner(scheme), SoftwareIdentity.generate("ed25519")
    rec = _rec(owner, subject, scope="copy:solana,hl", expires_at=NOW + 3600)
    assert rec.roles == ("controller", "agent")  # canonicalized before signing
    assert rec.signer == PrincipalKey(scheme, to_base64(owner.get_signing_public_key()))
    assert validate_principal_record(rec.to_dict(), subject.get_signing_public_key(), NOW) == rec
    assert validate_principal_record(rec, subject.get_signing_public_key(), NOW) == rec
    assert PrincipalRecord.from_dict(json.loads(json.dumps(rec.to_dict()))) == rec
    spk_b64 = to_base64(subject.get_signing_public_key())
    assert principal_payload(rec, subject.get_signing_public_key()) == encode_payload(
        ACC, "controller,agent", scheme, rec.signer.public_key, spk_b64, "copy:solana,hl", str(NOW + 3600))
    assert principal_sign_data(rec, subject.get_signing_public_key()) == build_sign_data(
        "principal", subject.get_ace_id(), NOW - 10, principal_payload(rec, subject.get_signing_public_key()))


def test_scope_absent_encodes_empty_and_null_members_are_absent():
    owner, subject = _owner(), SoftwareIdentity.generate("secp256k1")
    rec = _rec(owner, subject, roles=["agent"])
    d = rec.to_dict()
    assert "scope" not in d and d["expiresAt"] == NOW + 3600 and d["roles"] == ["agent"]
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
                                account=ACC, roles=["agent"])


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(account="solana:abc"),
    lambda d: d.update(account="Solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x"),
    lambda d: d.update(account=7),
    lambda d: d.update(roles=[]),
    lambda d: d.update(roles=["agent", "controller"]),
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
    p_agent = _rec(owner, agent, roles=["agent"]).to_dict()
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
    _authority_check(_rec(owner, agent, roles=["agent"]), agent, self_signer=_key(owner))
    forged = _rec(mallory, agent, roles=["agent"])  # same account string, attacker's key
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
        _authority_check(_rec(eoa, agent, roles=["agent"], account=account), agent, account=account)
    acc = f"eip155:1:{addr}"
    with raises("wrong_principal"):
        _authority_check(_rec(other, agent, roles=["agent"], account=acc), agent, account=acc)
    sol = f"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:{addr}"  # derivation only for eip155
    with raises("wrong_principal"):
        _authority_check(_rec(eoa, agent, roles=["agent"], account=sol), agent, account=sol)


def test_rules_pure_and_retryable_after_refresh():
    """A failed check has no side effects, so it can be re-run after a peer refresh (R-P20)."""
    owner, agent = _owner(), SoftwareIdentity.generate("ed25519")
    stale = _rec(owner, agent, roles=["agent"], account="eip155:1:0xabc").to_dict()
    fresh = _rec(owner, agent, roles=["agent"]).to_dict()
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
    return ParsedMessage(message_id=own, from_id="ace:sha256:" + "cd" * 32, to_id="ace:sha256:" + "ef" * 32,
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
    fill_decision(store, _decision(outcome="deny", own="00000000-0000-4000-8000-0000000000bb"))  # first wins
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
    tail = encode_payload("present", ACC, "controller,agent", "ed25519", rec.signer.public_key,
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
    bad["profile"] = {"name": "A", "principal": {**good, "roles": ["agent", "controller"]}}
    with raises("invalid_principal"):
        verify_registration_request(bad, clock=lambda: NOW)


def test_peer_record_principal_verified():
    owner, me, other = _owner(), SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    rec = _peer_record(me, {"name": "A", "principal": _rec(owner, me, expires_at=NOW + 50).to_dict()})
    assert verify_peer_record(rec, clock=lambda: NOW).principal.roles == ("controller", "agent")
    with raises("invalid_principal"):
        verify_peer_record(rec, clock=lambda: NOW + 50)
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
    peer = verify_registration_file(reg.to_dict(), pinned_at=t, clock=lambda: t)
    assert peer.principal.account == ACC and peer.profile.to_dict() == {"principal": reg.principal.to_dict()}
    assert verify_registration_file(create_registration_file(me, name="M", endpoint="https://m.example/ace"),
                                    pinned_at=0).profile is None
    d = reg.to_dict()
    d["principal"] = _rec(owner, other, issued_at=t - 10, expires_at=t + 3600).to_dict()
    with raises("invalid_principal"):
        verify_registration_file(d, clock=lambda: t)
    with raises("invalid_principal"):
        verify_registration_file(reg.to_dict(), clock=lambda: t + 3600)


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

    reg = create_registration_file(me, name="M", endpoint="https://m.example/ace")
    base = verify_registration_file(reg, pinned_at=t, clock=lambda: t)
    return _make_peer(ace_id=base.ace_id, scheme=base.scheme, signing_public_key=base.signing_public_key,
                      encryption_public_key=base.encryption_public_key, registered_at=t,
                      registration_signature=None, source="registration", profile=profile)


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
