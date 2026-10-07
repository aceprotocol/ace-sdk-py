"""Shared cross-language vectors (ace-spec/test-vectors.json, version 2)."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from ace import (
    MAX_DIRECT_BODY_BYTES,
    ACEError,
    Inbox,
    MemoryStore,
    PeerStore,
    ReplayDetector,
    ThreadEvent,
    ThreadStateMachine,
    _xwing,
    compute_ace_id,
    compute_conversation_id,
    decode_envelope,
    decrypt_with_seed,
    envelope_fingerprint,
    from_base64,
    kem_public_key_from_seed,
    parse_message,
    verify_peer_record,
    verify_registration_file,
    verify_registration_request,
    verify_webhook_notification,
)
from ace._encoding import canonical_state_bytes, decode_signature, is_https_url
from ace._signing import build_sign_data, encode_payload, verify_signature
from ace.auth import RelayAuthRequest, create_auth_headers, parse_auth_headers, verify_auth_headers
from ace.discovery import adopt_decision, is_blocked_address
from ace.encryption import ACE_KEM_SALT
from ace.messages import decode_body
from ace.relay import _map_relay_response, normalize_relay_url

from .helpers import VECTORS, agent, peer_of

V = VECTORS["vectors"]


def test_version_and_sections():
    assert VECTORS["version"] == "3"
    assert {"envelopes", "bodies", "transitions", "replay", "signatures", "auth", "registrations",
            "registrationErrors", "urls", "base64", "peerBinding", "webhooks", "relayUrls",
            "blockedAddresses", "relayErrors", "directReceive"} <= set(V)
    counts = {
        k: len(V[k]["cases"])
        for k in ("webhooks", "relayUrls", "blockedAddresses", "relayErrors", "directReceive")
    }
    assert counts == {
        "webhooks": 21,
        "relayUrls": 43,
        "blockedAddresses": 91,
        "relayErrors": 41,
        "directReceive": 17,
    }


# --- identities, X-Wing, conversation, signData ---------------------------------------------------


@pytest.mark.parametrize("name", ["alice", "bob"])
def test_agents(name):
    a, ident = VECTORS["agents"][name], agent(name)
    assert base64.b64encode(ident.get_signing_public_key()).decode() == a["signingPublicKey"]
    assert base64.b64encode(ident.get_encryption_public_key()).decode() == a["encryptionPublicKey"]
    assert ident.get_ace_id() == a["aceId"] == compute_ace_id(ident.get_signing_public_key())
    assert ident.get_address() == a["address"]
    assert ident.export_private_key() == {
        k: a[k] for k in ("scheme", "signingPrivateKey", "encryptionPrivateKey")
    }


@pytest.mark.parametrize("v", VECTORS["xwing"], ids=["kat1", "kat2", "kat3"])
def test_xwing_kats(v):
    seed = bytes.fromhex(v["seed"])
    assert kem_public_key_from_seed(seed).hex() == v["publicKey"]
    assert _xwing.decapsulate(bytes.fromhex(v["ciphertext"]), seed).hex() == v["sharedSecret"]


def test_salt_conversation_and_sign_data():
    alice, bob = agent("alice"), agent("bob")
    assert ACE_KEM_SALT.hex() == V["aceKemSalt"]
    assert (
        compute_conversation_id(alice.get_encryption_public_key(), bob.get_encryption_public_key())
        == V["conversationId"]
    )
    sd = V["signData"]
    mp = sd["messagePayload"]
    payload = encode_payload(
        mp["type"],
        mp["to"],
        mp["conversationId"],
        mp["messageId"],
        mp["threadId"],
        base64.b64decode(mp["kemCiphertext"]),
        base64.b64decode(mp["ciphertext"]),
    )
    data = build_sign_data(sd["action"], sd["aceId"], sd["timestamp"], payload)
    assert data.hex() == sd["signDataHex"]
    assert base64.b64encode(alice.sign(data)).decode() == V["signature"]["signatureValue"]


def test_encrypted_message():
    alice, bob = agent("alice"), agent("bob")
    em = V["encryptedMessage"]
    ts = em["envelope"]["timestamp"]
    parsed = parse_message(
        decode_envelope(em["envelope"]),
        bob,
        peer_of(alice),
        threads=ThreadStateMachine(bob.get_ace_id()),
        replay=ReplayDetector(horizon=ts - 1),
        clock=lambda: ts,
    )
    assert parsed.body == em["expectedBody"]
    env = em["envelope"]
    seed = base64.b64decode(VECTORS["agents"]["bob"]["encryptionPrivateKey"])
    raw = decrypt_with_seed(
        base64.b64decode(env["encryption"]["kemCiphertext"]),
        base64.b64decode(env["encryption"]["payload"]),
        seed,
        env["conversationId"],
    )
    assert json.loads(raw) == em["expectedBody"]


# --- envelopes / bodies ---------------------------------------------------------------------------


@pytest.mark.parametrize("v", V["envelopes"], ids=lambda v: v["name"])
def test_envelopes(v):
    obj = json.loads(v["json"])
    if v["valid"]:
        assert envelope_fingerprint(decode_envelope(obj)) == v["fingerprint"]
    else:
        with pytest.raises(ACEError) as info:
            decode_envelope(obj)
        assert info.value.code == v["error"]


@pytest.mark.parametrize("v", V["bodies"], ids=lambda v: v["name"])
def test_bodies(v):
    raw = bytes.fromhex(v["bodyHex"]) if "bodyHex" in v else v["bodyJson"].encode("utf-8")
    if v["valid"]:
        decode_body(v["type"], raw)
    else:
        with pytest.raises(ACEError) as info:
            decode_body(v["type"], raw)
        assert info.value.code == "invalid_body"


# --- transitions ----------------------------------------------------------------------------------

T = V["transitions"]
ROLES = {"buyer": T["buyer"], "seller": T["seller"], "third": T["third"]}


def _mid(i: int) -> str:
    return f"00000000-0000-4000-8000-{i:012d}"


def _step(sm, i, type_, frm, to, body) -> str:
    e = ThreadEvent(
        T["conversationId"], T["threadId"], type_, _mid(i), 1741000000 + i, ROLES[frm], ROLES[to]
    )
    try:
        return sm.apply(e, body)
    except ACEError as exc:
        return "error:" + exc.code


def _synth(type_, ids):
    out = {}
    for k, v in T["bodyTemplates"][type_].items():
        if v == "$head":
            v = ids[-1] if ids else ""
        elif v == "$beforeHead":
            v = ids[-2] if len(ids) >= 2 else ""
        out[k] = v
    return out


def _other(role):
    return "seller" if role == "buyer" else "buyer"


@pytest.mark.parametrize("local", ["buyer", "seller"])
def test_transition_matrix(local):
    for state, row in T["matrix"].items():
        for type_, cell in row.items():
            for sender, expect in cell.items():
                sm = ThreadStateMachine(ROLES[local])
                ids = []
                for i, step in enumerate(T["paths"][state], start=1):
                    t, frm = step.split(":")
                    assert not _step(sm, i, t, frm, _other(frm), _synth(t, ids)).startswith("error")
                    ids.append(_mid(i))
                before = sm.export_state()
                got = _step(sm, len(ids) + 1, type_, sender, _other(sender), _synth(type_, ids))
                assert got == expect, (state, type_, sender)
                if got.startswith("error"):
                    assert sm.export_state() == before


@pytest.mark.parametrize("case", T["cases"], ids=lambda c: c["name"])
def test_transition_cases(case):
    sm = ThreadStateMachine(ROLES[case["local"]])
    for i, s in enumerate(case["steps"], start=1):
        assert _step(sm, i, s["type"], s["from"], s["to"], s["body"]) == s["expect"], i


# --- replay ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("v", V["replay"], ids=lambda v: v["name"])
def test_replay(v):
    if "initialStateJson" in v:
        det = ReplayDetector.from_state(json.loads(v["initialStateJson"]), capacity=v["capacity"])
    else:
        det = ReplayDetector(capacity=v["capacity"], horizon=v["horizon"])
    for op in v["ops"]:
        if op["op"] == "commit":
            got = det.commit(op["messageId"], op["sender"], op["timestamp"], op["floor"])
        else:
            got = det.accepts(op["messageId"], op["sender"], op["timestamp"])
        assert got == op["expect"], op
    assert canonical_state_bytes(det.export_state()).decode() == v["finalStateJson"]
    # clone and from_state round-trip preserve the canonical bytes
    again = ReplayDetector.from_state(json.loads(v["finalStateJson"]), capacity=v["capacity"])
    assert canonical_state_bytes(again.export_state()).decode() == v["finalStateJson"]
    assert canonical_state_bytes(det.clone().export_state()).decode() == v["finalStateJson"]


# --- signatures -----------------------------------------------------------------------------------


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_signatures(scheme):
    for v in V["signatures"][scheme]:
        try:
            sig = decode_signature(v["signature"], scheme, "invalid_signature")
            ok = verify_signature(
                bytes.fromhex(v["signDataHex"]), sig, scheme, from_base64(v["publicKey"])
            )
        except ACEError:
            ok = False
        assert ok == v["valid"], v["name"]


# --- auth -----------------------------------------------------------------------------------------


def _auth_request(r: dict) -> RelayAuthRequest:
    if r["action"] == "listen":
        return RelayAuthRequest.listen(r["since"])
    if r["action"] == "inbox":
        return RelayAuthRequest.inbox(r["since"], r["limit"])
    if r["action"] == "unregister":
        return RelayAuthRequest.unregister()
    if r["action"] == "webhook":
        return RelayAuthRequest.webhook(r["method"], r["url"], r["secret"])
    return RelayAuthRequest.intent(r["need"], r["tags"], r["maxPrice"], r["currency"], r["ttl"])


def test_auth_vector_count():
    assert len(V["auth"]) == 18
    assert sum(1 for v in V["auth"] if v["action"] == "webhook") == 6


@pytest.mark.parametrize(
    "v", V["auth"], ids=lambda v: f"{v['agent']}-{v['action']}-{v['payloadHex'][:12]}"
)
def test_auth(v):
    ident = agent(v["agent"])
    req = _auth_request(v["request"])
    assert req.payload().hex() == v["payloadHex"]
    assert (
        build_sign_data(v["action"], ident.get_ace_id(), v["timestamp"], req.payload()).hex()
        == v["signDataHex"]
    )
    if not v.get("verifyOnly"):
        assert create_auth_headers(ident, req, v["timestamp"]) == v["headers"]
    auth = parse_auth_headers(v["headers"])
    verify_auth_headers(
        auth,
        req,
        ace_id=ident.get_ace_id(),
        scheme=ident.get_signing_scheme(),
        signing_public_key=ident.get_signing_public_key(),
        clock=lambda: v["timestamp"],
    )


# --- registrations --------------------------------------------------------------------------------


@pytest.mark.parametrize("v", V["registrations"], ids=lambda v: f"{v['agent']}-{v['mode']}")
def test_registrations(v):
    result = verify_registration_request(v["request"], clock=lambda: v["now"])
    assert (
        result.request_digest
        == v["requestDigest"]
        == hashlib.sha256(bytes.fromhex(v["signDataHex"])).hexdigest()
    )
    assert result.peer.ace_id == v["request"]["aceId"]
    assert result.request == v["request"]


@pytest.mark.parametrize("v", V["registrationErrors"], ids=lambda v: v["name"])
def test_registration_errors(v):
    with pytest.raises(ACEError) as info:
        verify_registration_request(v["request"], clock=lambda: v["now"])
    assert info.value.code == v["error"]


# --- urls / base64 --------------------------------------------------------------------------------


def test_urls():
    for v in V["urls"]:
        assert is_https_url(v["url"]) == v["valid"], v["url"]


def test_base64():
    for v in V["base64"]:
        try:
            raw = from_base64(v["text"])
            assert v["valid"] and raw.hex() == v["hex"], v["text"]
        except ACEError as exc:
            assert not v["valid"] and exc.code == "invalid_argument", v["text"]


# --- peer binding ---------------------------------------------------------------------------------


@pytest.mark.parametrize("case", V["peerBinding"], ids=lambda c: c["name"])
def test_peer_binding(case):
    pin = None
    for step in case["sequence"]:
        try:
            if "record" in step:
                cand = verify_peer_record(step["record"])
            else:
                cand = verify_registration_file(
                    step["registrationFile"], pinned_at=step["pinnedAt"]
                )
            pin, got = adopt_decision(pin, cand, case["now"])
        except ACEError as exc:
            got = "error:" + exc.code
        assert got == step["expect"]
        if "pinRegisteredAt" in step:
            assert pin.registered_at == step["pinRegisteredAt"]
            assert (
                base64.b64encode(pin.encryption_public_key).decode()
                == step["pinEncryptionPublicKey"]
            )


# --- webhooks -------------------------------------------------------------------------------------


@pytest.mark.parametrize("v", V["webhooks"]["cases"], ids=lambda v: v["name"])
def test_webhooks(v):
    def verify():
        return verify_webhook_notification(
            secret=v["secret"],
            timestamp=v["timestamp"],
            signature=v["signature"],
            body=v["body"].encode("utf-8"),
            clock=lambda: v["now"],
        )

    if "result" in v:
        got = verify()
        assert {"aceId": got.ace_id, "streamId": got.stream_id} == v["result"]
    else:
        with pytest.raises(ACEError) as info:
            verify()
        assert info.value.code == v["error"]


# --- relay client rules ---------------------------------------------------------------------------


@pytest.mark.parametrize("v", V["relayUrls"]["cases"], ids=lambda v: repr(v["input"]))
def test_relay_urls(v):
    if "normalized" in v:
        assert normalize_relay_url(v["input"]) == v["normalized"]
    else:
        with pytest.raises(ACEError) as info:
            normalize_relay_url(v["input"])
        assert info.value.code == v["error"]


def test_blocked_addresses():
    for v in V["blockedAddresses"]["cases"]:
        assert is_blocked_address(v["address"]) == v["blocked"], v["address"]


@pytest.mark.parametrize("v", V["relayErrors"]["cases"], ids=lambda v: v["name"])
def test_relay_errors(v):
    retry_after = next((val for k, val in v["headers"].items() if k.lower() == "retry-after"), None)
    err = _map_relay_response(v["status"], v["body"].encode("utf-8"), retry_after)
    got = (err.code, err.category, err.relay_code, err.retry_after_seconds, err.status)
    assert got == (v["code"], v["category"], v["relayCode"], v["retryAfterSeconds"], v["status"])


# --- direct delivery ------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def direct_inbox():
    store = MemoryStore()
    inbox = Inbox.open(agent("alice"), store, PeerStore(store), lambda m: None)
    yield inbox
    inbox.close()


@pytest.mark.parametrize("v", V["directReceive"]["cases"], ids=lambda v: v["name"])
def test_direct_receive(v, direct_inbox):
    assert V["directReceive"]["maxDirectBodyBytes"] == MAX_DIRECT_BODY_BYTES
    raw = bytes.fromhex(v["bodyHex"]) if "bodyHex" in v else v["body"].encode("utf-8")
    if "padTo" in v:
        raw = raw.ljust(v["padTo"], b" ")
    reply = direct_inbox.receive_direct(raw)
    assert (reply.status, reply.body) == (v["status"], {"ok": False, "error": v["error"]})
