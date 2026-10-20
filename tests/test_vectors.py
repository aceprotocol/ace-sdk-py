"""The shared conformance vectors (ace-spec/test-vectors.json, copied to tests/fixtures).

Every section that applies to this SDK is verified here; check-sdk-artifacts.py keeps the copy
byte-identical.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ace import (
    COMMERCE,
    CORE,
    TEXT,
    ACEError,
    Inbox,
    Outbox,
    PeerStore,
    PrekeyVault,
    ProfileManifest,
    Profiles,
    RelayClient,
    ReplayDetector,
    SoftwareIdentity,
    _xwing,
    canonical_state_bytes,
    check_receipt_body,
    check_stranger_source,
    conversation_key,
    create_packet,
    decode_content,
    decode_packet,
    encode_payload,
    extend_kel,
    from_base64,
    is_usable,
    signing_message,
    verify_card_bundle,
    verify_delegation,
    verify_erc8004_registration,
    verify_kel,
    verify_permit,
    verify_published_agent,
    verify_signature,
)
from ace._encoding import (
    CAIP10_RE,
    CAIP19_RE,
    check_json_value,
    is_ace_id,
    is_handle,
    is_https_url,
    is_message_id,
    is_namespaced_id,
    is_sha256_hex,
    is_stream_id,
    is_thread_id,
    loads_json,
    wire_int,
)
from ace._net import is_blocked_address
from ace._relay_url import normalize_relay_url
from ace.auth import create_auth_headers
from ace.commerce import ThreadStore, commerce_rules, validate_commerce_ext
from ace.delegation import validate_erc8004
from ace.errors import _CODE_RE
from ace.kel import event_bytes, verify_operational_signature
from ace.packet import packet_header
from ace.prekeys import _entry, _State
from ace.relay import map_relay_response
from ace.rules import MessageEvent
from ace.store import MemoryStore
from tests.helpers import open_packet

V = json.loads((Path(__file__).parent / "fixtures" / "test-vectors.json").read_text("utf-8"))
NOW = V["now"]
AGENTS = V["agents"]


def kel_of(name: str) -> list:
    return AGENTS[name]["export"]["kel"]


def state_of(name: str, now: int = NOW):
    return verify_kel(kel_of(name), now)


def code_of(fn) -> str | None:
    try:
        fn()
    except ACEError as exc:
        return exc.code
    return None


def ids(cases, key="name"):
    return [c.get(key, str(i)) for i, c in enumerate(cases)]


def test_agents_load_from_their_exports():
    for name, a in AGENTS.items():
        ident = SoftwareIdentity.from_export(a["export"], now=NOW)
        assert ident.get_ace_id() == a["aceId"], name


# --- encoding -----------------------------------------------------------------------------


def test_base64():
    for c in V["encoding"]["base64"]:
        if c["valid"]:
            assert from_base64(c["text"]).hex() == c["hex"]
        else:
            assert code_of(lambda: from_base64(c["text"])) == "invalid_argument", c["text"]


@pytest.mark.parametrize(
    "c", V["encoding"]["canonicalJson"], ids=ids(V["encoding"]["canonicalJson"])
)
def test_canonical_json(c):
    def run():
        v = loads_json(c["input"])
        check_json_value(v, "invalid_argument")
        return canonical_state_bytes(v)

    if c.get("error"):
        with pytest.raises(Exception):
            run()
    else:
        assert run() == c["canonical"].encode("utf-8")


def test_wire_ints():
    for c in V["encoding"]["wireInts"]:
        assert wire_int(loads_json(c["json"])) == c["value"], c["json"]


PREDICATES = {
    "aceId": is_ace_id,
    "messageId": is_message_id,
    "hexDigest": is_sha256_hex,
    "namespacedId": is_namespaced_id,
    "threadId": is_thread_id,
    "handle": is_handle,
    "streamId": is_stream_id,
    "outcomeCode": lambda v: _CODE_RE.fullmatch(v) is not None,
    "caip10": lambda v: CAIP10_RE.fullmatch(v) is not None,
    "caip19": lambda v: CAIP19_RE.fullmatch(v) is not None,
}


def test_identifiers():
    assert set(V["encoding"]["identifiers"]) == set(PREDICATES)
    for kind, cases in V["encoding"]["identifiers"].items():
        for c in cases:
            assert bool(PREDICATES[kind](c["value"])) == c["valid"], (kind, c["value"])


def test_urls_relay_urls_blocked_addresses_and_pair_key():
    e = V["encoding"]
    for c in e["httpsUrls"]:
        assert is_https_url(c["url"]) == c["valid"], c["url"]
    for c in e["relayUrls"]:
        if "error" in c:
            assert code_of(lambda: normalize_relay_url(c["input"])) == c["error"], c["input"]
        else:
            assert normalize_relay_url(c["input"]) == c["normalized"]
    for c in e["blockedAddresses"]:
        assert is_blocked_address(c["address"]) == c["blocked"], c["address"]
    ck = e["conversationKey"]
    assert conversation_key(ck["a"], ck["b"]) == conversation_key(ck["b"], ck["a"]) == ck["key"]


# --- signing ------------------------------------------------------------------------------


def test_encode_payload_message_and_action_separation():
    s = V["signing"]
    for c in s["encodePayload"]:
        fields = [f["text"] if "text" in f else bytes.fromhex(f["hex"]) for f in c["fields"]]
        assert encode_payload(*fields).hex() == c["hex"]
    for c in s["message"]:
        m = signing_message(c["aceId"], c["timestamp"], c["seq"], bytes.fromhex(c["payloadHex"]))
        assert m.hex() == c["messageHex"]
    for a in s["actionSeparation"]:
        pk = state_of(a["signer"]).signing.public_key
        msg, sig = bytes.fromhex(a["messageHex"]), base64.b64decode(a["signature"])
        if "claims" in a:  # credential-shaped claims: M is over their canonical bytes
            st = state_of(a["signer"])
            c = a["claims"]
            m = signing_message(st.ace_id, c["issuedAt"], st.signing.seq, canonical_state_bytes(c))
            assert m == msg
        for action, ok in a["actions"].items():
            assert verify_signature(msg, action, sig, pk) == ok, action


# --- KEL ----------------------------------------------------------------------------------


def test_kel_valid():
    for c in V["kel"]["valid"]:
        st = verify_kel(kel_of(c["agent"])[: c.get("events")], c["now"])
        assert (st.ace_id, st.seq, st.last_hash, st.root_scheme, st.next) == (
            c["aceId"],
            c["seq"],
            c["lastHash"],
            c["rootScheme"],
            c["next"],
        )
        signing = (
            None
            if st.signing is None
            else {"seq": st.signing.seq, "notAfter": st.signing.not_after}
        )
        assert signing == c["signing"]
        assert is_usable(st, c["now"]) == c["usable"]


@pytest.mark.parametrize("c", V["kel"]["invalid"], ids=ids(V["kel"]["invalid"]))
def test_kel_invalid(c):
    assert code_of(lambda: verify_kel(c["kel"], c["now"])) == c["error"]


def test_kel_event_bytes_forks_and_operational_signatures():
    k = V["kel"]
    for c in k["eventBytes"]:
        assert event_bytes(c["event"]).hex() == c["hex"]
    for c in k["forks"]:
        pinned = None if c["pinned"] is None else verify_kel(c["pinned"], c["now"])
        if "error" in c:
            assert code_of(lambda: extend_kel(pinned, c["candidate"], c["now"])) == c["error"], c[
                "name"
            ]
        else:
            st, outcome = extend_kel(pinned, c["candidate"], c["now"])
            assert (outcome, st.seq) == (c["outcome"], c["seq"]), c["name"]
    for c in k["operational"]:
        st = state_of(c["signer"], c["now"])
        payload = bytes.fromhex(c["payloadHex"])
        got = code_of(
            lambda: verify_operational_signature(
                st, c["signature"], payload, c["action"], c["timestamp"], c["now"]
            )
        )
        assert got == c["error"], c["name"]


# --- X-Wing and packets -------------------------------------------------------------------


def test_xwing_draft_vectors():
    for c in V["xwing"]["cases"]:
        dk = _xwing.DecapsulationKey(bytes.fromhex(c["seed"]))
        assert dk.public_key.hex() == c["publicKey"]
        assert dk.decapsulate(bytes.fromhex(c["ciphertext"])).hex() == c["sharedSecret"]


def bob_vault(tmp_path) -> PrekeyVault:
    """A vault holding only the vector prekey seed, through the public 0600 file format."""
    seed = V["packet"]["deterministic"]["prekeySeed"]
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "prekeys.json"
    doc = {
        "version": 1,
        "current": {"seed": base64.b64encode(bytes.fromhex(seed)).decode(), "createdAt": 0},
        "retired": [],
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    return PrekeyVault(path)


def test_packet_deterministic(tmp_path):
    d = V["packet"]["deterministic"]
    kem, ss, nonce = (bytes.fromhex(d[k]) for k in ("kemCiphertext", "sharedSecret", "nonce"))
    alice, bob = AGENTS[d["sender"]]["aceId"], AGENTS[d["recipient"]]["aceId"]
    header = packet_header(alice, bob, d["messageId"], d["timestamp"], d["prekey"]["id"], kem)
    assert header.hex() == d["headerHex"]
    assert d["saltHex"] == ""  # 03: the HKDF salt is the empty string
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=header).derive(ss)
    assert key.hex() == d["keyHex"]
    plaintext = canonical_state_bytes(d["content"])
    assert plaintext.hex() == d["plaintextHex"]
    payload = nonce + AESGCM(key).encrypt(nonce, plaintext, header)
    assert payload.hex() == d["payloadHex"]
    assert (
        encode_payload(bob, d["messageId"], d["prekey"]["id"], kem, payload).hex()
        == d["signPayloadHex"]
    )
    seq = d["packet"]["signature"]["seq"]
    m = signing_message(alice, d["timestamp"], seq, bytes.fromhex(d["signPayloadHex"]))
    assert m.hex() == d["messageHex"]
    sig = base64.b64decode(d["packet"]["signature"]["value"])
    assert verify_signature(m, "packet", sig, state_of("alice").signing.public_key)
    sender = SoftwareIdentity.from_export(AGENTS["alice"]["export"], now=NOW)
    made = create_packet(
        sender,
        bob,
        d["prekey"],
        plaintext,
        timestamp=d["timestamp"],
        message_id=d["messageId"],
        _kem=(ss, kem),
        _nonce=nonce,
    )
    assert made["encryption"] == d["packet"]["encryption"]
    for pkt in (made, d["packet"]):
        msg = open_packet(
            decode_packet(pkt), state_of("alice"), bob_vault(tmp_path / str(id(pkt))), now=NOW
        )
        assert (msg.type, msg.thread_id, msg.body) == (
            d["content"]["type"],
            d["content"]["threadId"],
            d["content"]["body"],
        )


@pytest.mark.parametrize("c", V["packet"]["decode"], ids=ids(V["packet"]["decode"]))
def test_packet_decode(c):
    value = loads_json(c["json"]) if "json" in c else c["packet"]
    assert code_of(lambda: decode_packet(value)) == c["error"]


@pytest.mark.parametrize("c", V["packet"]["open"], ids=ids(V["packet"]["open"]))
def test_packet_open(c, tmp_path):
    me = AGENTS[c["recipient"]]["aceId"]

    def run():
        p = decode_packet(c["packet"])
        if p.to_id != me:
            raise ACEError("wrong_recipient", "")
        open_packet(p, state_of(c["sender"], c["now"]), bob_vault(tmp_path), now=c["now"])

    assert code_of(run) == c["error"]


@pytest.mark.parametrize("c", V["privateContent"]["cases"], ids=ids(V["privateContent"]["cases"]))
def test_private_content(c):
    raw = c["text"].encode("utf-8") if "text" in c else bytes.fromhex(c["hex"])
    assert code_of(lambda: decode_content(raw)) == c["error"]


# --- descriptor, delegation, permit, ERC-8004 ---------------------------------------------


@pytest.mark.parametrize("c", V["descriptor"]["valid"], ids=ids(V["descriptor"]["valid"]))
def test_descriptor_valid(c):
    assert (
        list(verify_published_agent(c["publishedAgent"], now=c["now"]).delegations)
        == c["delegations"]
    )


@pytest.mark.parametrize("c", V["descriptor"]["invalid"], ids=ids(V["descriptor"]["invalid"]))
def test_descriptor_invalid(c):
    assert code_of(lambda: verify_published_agent(c["publishedAgent"], now=c["now"])) == c["error"]


@pytest.mark.parametrize("c", V["descriptor"]["pinned"], ids=ids(V["descriptor"]["pinned"]))
def test_descriptor_against_the_pin(c):
    pinned = state_of(c["pinned"], c["now"])
    got = code_of(lambda: verify_published_agent(c["publishedAgent"], now=c["now"], pinned=pinned))
    assert got == c["error"]
    # A PeerStore holding the pin behaves the same (no prekey substitution by a superseded key).
    from ace import PeerStore

    peers = PeerStore(MemoryStore(), clock=lambda: c["now"])
    peers.pin(kel_of(c["pinned"]), c["now"])
    assert code_of(lambda: peers.adopt(c["publishedAgent"], c["now"])) == c["error"]
    if c["error"] is None:
        assert (
            peers.agent(AGENTS[c["pinned"]]["aceId"]).prekey.id
            == c["publishedAgent"]["descriptor"]["prekey"]["id"]
        )


@pytest.mark.parametrize("c", V["cardRecords"]["valid"], ids=ids(V["cardRecords"]["valid"]))
def test_card_record_valid(c):
    v = verify_card_bundle(c["bundle"], c["now"])
    got = {
        "aceId": v.ace_id,
        "home": v.home,
        "handle": v.handle,
        "pay": v.pay,
        "contact": v.contact,
        "listed": v.listed,
    }
    assert got == c["expect"]


@pytest.mark.parametrize("c", V["cardRecords"]["invalid"], ids=ids(V["cardRecords"]["invalid"]))
def test_card_record_invalid(c):
    assert code_of(lambda: verify_card_bundle(c["bundle"], c["now"])) == c["error"]


def test_delegation_permit_and_erc8004():
    for c in V["delegation"]["cases"]:

        def run():
            _, live = verify_delegation(c["entry"], c["subject"], now=c["now"])
            return "live" if live else "expired"

        if "result" in c:
            assert run() == c["result"], c["name"]
        else:
            assert code_of(run) == c["error"], c["name"]
    for c in V["delegation"]["pinned"]:

        def run_pinned():
            pin = state_of(c["pinned"], c["now"])
            _, live = verify_delegation(c["entry"], c["subject"], now=c["now"], pinned=pin)
            return "live" if live else "expired"

        if "result" in c:
            assert run_pinned() == c["result"], c["name"]
        else:
            assert code_of(run_pinned) == c["error"], c["name"]
    for c in V["delegation"]["descriptors"]:
        pins = {V["agents"][x]["aceId"]: state_of(x, c["now"]) for x in c["delegationPins"]}
        got = code_of(
            lambda: verify_published_agent(c["publishedAgent"], now=c["now"], delegation_pins=pins)
        )
        assert got == c["error"], c["name"]
        assert code_of(lambda: verify_published_agent(c["publishedAgent"], now=c["now"])) is None
    for c in V["permit"]["cases"]:
        got = code_of(
            lambda: verify_permit(
                c["permit"], state_of(c["issuer"], c["now"]), c["subject"], now=c["now"]
            )
        )
        assert got == c["error"], c["name"]
    for c in V["erc8004"]["shapes"]:
        assert (code_of(lambda: validate_erc8004(c["entry"])) is None) == c["valid"]
    for c in V["erc8004"]["registrations"]:
        assert verify_erc8004_registration(c["registration"], c["aceId"]) == c["result"]


@pytest.mark.parametrize("c", V["coreRules"]["receipts"], ids=ids(V["coreRules"]["receipts"]))
def test_core_receipt_rules(c):
    assert code_of(lambda: check_receipt_body(c["body"])) == c["error"]


@pytest.mark.parametrize(
    "c", V["coreRules"]["strangerSources"], ids=ids(V["coreRules"]["strangerSources"])
)
def test_stranger_source_bounds(c):
    assert code_of(lambda: check_stranger_source(c["source"])) == c["error"]


# --- manifests ----------------------------------------------------------------------------


def test_manifests():
    m = V["manifests"]
    bundled = {x.id: x for x in (CORE, TEXT, COMMERCE)}
    for o in m["official"]:
        pm = bundled[o["id"]]
        assert pm.digest == o["digest"]
        assert {t: s.digest for t, s in pm.messages.items()} == o["messages"]
    for c in m["thirdParty"]:
        if c["valid"]:
            pm = ProfileManifest(c["manifest"])
            assert (
                pm.digest == c["digest"]
                and {t: s.digest for t, s in pm.messages.items()} == c["messages"]
            )
        else:
            assert code_of(lambda: ProfileManifest(c["manifest"])) == "invalid_argument", c["name"]
    prof = Profiles([TEXT, COMMERCE])
    for c in m["bodies"]:
        assert (
            code_of(lambda: prof.validate(c["type"], c["schemaDigest"], c["body"])) == c["error"]
        ), c["name"]


# --- replay -------------------------------------------------------------------------------


@pytest.mark.parametrize("c", V["replay"]["cases"], ids=ids(V["replay"]["cases"]))
def test_replay(c):
    if "initialState" in c:
        det = ReplayDetector.from_state(c["initialState"], capacity=c["capacity"])
    else:
        det = ReplayDetector(capacity=c["capacity"], horizon=c["horizon"])
    for op in c["ops"]:
        m, s, ts = op["messageId"], op["sender"], op["timestamp"]
        if op["op"] == "commit":
            assert det.commit(m, s, ts, op["floor"]) == op["expect"], op
        else:
            got = (
                "duplicate" if det.seen(m, s) else "replay_horizon" if det.covered(s, ts) else "new"
            )
            assert got == op["expect"], op
    assert canonical_state_bytes(det.export_state()) == canonical_state_bytes(c["finalState"])


# --- commerce -----------------------------------------------------------------------------


@pytest.mark.parametrize("c", V["commerce"]["transitions"], ids=ids(V["commerce"]["transitions"]))
def test_commerce_transitions(c):
    parties = {role: AGENTS[name]["aceId"] for role, name in V["commerce"]["parties"].items()}
    local = parties[c["local"]]
    threads = ThreadStore(MemoryStore(), local)
    for st in c["steps"]:
        frm, to = parties[st["from"]], parties[st["to"]]
        e = MessageEvent(
            "send" if frm == local else "receive",
            st["messageId"],
            frm,
            to,
            st["timestamp"],
            st["type"],
            st.get("threadId"),
        )
        try:
            threads.decide(e, st["body"])
            got = threads.apply(e, st["body"])
        except ACEError as exc:
            got = exc.code
        assert got == st["expect"], st


@pytest.mark.parametrize("c", V["commerce"]["sender"], ids=ids(V["commerce"]["sender"]))
def test_commerce_sender(c):
    a, b = AGENTS["alice"]["aceId"], AGENTS["bob"]["aceId"]
    clock = {"t": V["now"]}
    store = MemoryStore()
    rules = commerce_rules(store, a)

    class _Id:
        def get_ace_id(self):
            return a

    ob = Outbox(_Id(), store, Profiles([TEXT, COMMERCE]), rules=[rules], clock=lambda: clock["t"])
    conv = conversation_key(a, b)
    for i, st in enumerate(c["steps"]):
        clock["t"] = V["now"] + i
        tid = st.get("threadId", "t1")
        got = "ok"
        try:
            if st["op"] == "send":
                ob.enqueue(b, st["type"], st["body"], thread_id=tid, message_id=st["messageId"])
            elif st["op"] == "receipt":
                ob.settle(st["messageId"], st["outcome"], st.get("code"), sender=b)
            elif st["op"] == "abandon":
                ob.abandon(st["messageId"])
            else:
                e = MessageEvent("receive", st["messageId"], b, a, clock["t"], st["type"], tid)
                if ob.busy(b, tid) is not None:
                    raise ACEError("thread_busy", "busy")
                rules.check(e, st["body"])
                rules.commit(e, st["body"])
        except ACEError as exc:
            got = exc.code
        snap = rules.threads.get(conv, "t1")
        assert got == st["expect"], st
        assert (None if snap is None else snap.state) == st["state"], st
        assert (ob.busy(b, "t1") is not None) == st["busy"], st


def test_commerce_ext():
    for c in V["commerce"]["ext"]:
        assert (code_of(lambda: validate_commerce_ext(c["value"])) is None) == c["valid"], c[
            "value"
        ]


# --- receive pipeline ---------------------------------------------------------------------


@pytest.mark.parametrize("c", V["pipeline"]["cases"], ids=ids(V["pipeline"]["cases"]))
def test_receive_pipeline(c):
    me = SoftwareIdentity.from_export(AGENTS[c["receiver"]]["export"], now=NOW)
    clock = {"t": NOW}
    store = MemoryStore()
    peers = PeerStore(store, clock=lambda: clock["t"])
    for name, agent in c["admitted"].items():
        peers.adopt(agent, NOW)
        peers.set_status(AGENTS[name]["aceId"], "admitted")
    vault = PrekeyVault()
    vault._state = _State(_entry(bytes.fromhex(V["packet"]["deterministic"]["prekeySeed"]), 0), [])
    inbox = Inbox.open(
        me,
        store,
        vault,
        peers,
        Profiles(),
        on_message=lambda m: None,
        contact=c["contact"],
        capacity=c["capacity"],
        clock=lambda: clock["t"],
    )
    names = {
        "delivered": "delivered",
        "duplicate": "duplicate",
        "dropped": "drop",
        "rejected": "reject",
    }
    for step in c["steps"]:
        clock["t"] = step["now"]
        out = inbox.receive(json.dumps(step["packet"]).encode())
        want = step["expect"]
        assert names[out.kind] == want["disposition"], (c["name"], step["now"])
        assert (None if out.error is None else out.error.code) == want["code"]
        assert (out.receipt is None) == (want["receipt"] is None)
    inbox.close()


# --- auth, registration, relay errors -------------------------------------------------------


def test_auth_headers_and_registration():
    a = V["auth"]
    for c in a["cases"]:
        st = state_of(c["agent"], c["timestamp"])
        assert (
            encode_payload(c["audience"], c["nonce"], bytes.fromhex(c["payloadHex"])).hex()
            == (c["authPayloadHex"])
        )
        m = signing_message(
            st.ace_id, c["timestamp"], st.signing.seq, bytes.fromhex(c["authPayloadHex"])
        )
        assert m.hex() == c["messageHex"]
        sig = from_base64(c["headers"]["X-ACE-Signature"])
        assert verify_signature(m, c["request"]["action"], sig, st.signing.public_key)
        # this SDK reproduces the headers' signed content (only the hedged signature differs)
        me = SoftwareIdentity.from_export(AGENTS[c["agent"]]["export"], now=NOW)
        mine = create_auth_headers(
            me,
            c["request"]["action"],
            bytes.fromhex(c["payloadHex"]),
            c["timestamp"],
            audience=c["audience"],
            nonce=c["nonce"],
        )
        assert {k: v for k, v in mine.items() if k != "X-ACE-Signature"} == {
            k: v for k, v in c["headers"].items() if k != "X-ACE-Signature"
        }
    r = a["registration"]
    st = state_of(r["agent"], r["now"])
    assert st.last_hash == r["lastHashHex"]
    assert encode_payload(r["lastHashHex"], r["audience"]).hex() == r["payloadHex"]
    m = signing_message(
        st.ace_id, r["request"]["timestamp"], st.signing.seq, bytes.fromhex(r["payloadHex"])
    )
    assert m.hex() == r["messageHex"] and hashlib.sha256(m).hexdigest() == r["requestDigest"]
    sig = from_base64(r["request"]["signature"]["value"])
    assert verify_signature(m, "register-request", sig, st.signing.public_key)


def test_wake_registration_bodies():
    w = V["auth"]["wake"]
    me = SoftwareIdentity.from_export(AGENTS["bob"]["export"], now=NOW)
    client = RelayClient("https://relay.example")
    sent = []
    client._call = lambda *a, **k: sent.append(k["body"])  # no network: validation only
    for b in w["valid"]:
        client.set_wake(me, b["gateway"], b["token"])
    assert sent == w["valid"]
    for c in w["invalid"]:
        b = c["body"]
        if set(b) != {"gateway", "token"}:
            continue  # a closed-object check: the typed call cannot build these
        with pytest.raises(ACEError) as info:
            client.set_wake(me, b["gateway"], b["token"])
        assert info.value.code == c["error"], c["name"]


@pytest.mark.parametrize("c", V["relayErrors"]["cases"], ids=ids(V["relayErrors"]["cases"]))
def test_relay_error_mapping(c):
    e = map_relay_response(c["status"], c["body"].encode(), c["headers"].get("Retry-After"))
    assert (e.code, e.category, e.relay_code, e.retry_after_seconds, e.status) == (
        c["code"],
        c["category"],
        c["relayCode"],
        c["retryAfterSeconds"],
        c["status"],
    )
