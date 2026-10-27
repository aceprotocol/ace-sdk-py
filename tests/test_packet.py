import copy
import hashlib
import json
import os
import stat

import pytest

from ace import (
    TEXT,
    PrekeyVault,
    SoftwareIdentity,
    create_packet,
    decode_content,
    decode_packet,
    encode_content,
    verify_kel,
)
from ace._encoding import canonical_state_bytes, conversation_key, to_base64
from ace._signing import encode_payload
from ace.limits import MAX_PACKET_BYTES, MAX_PLAINTEXT_BYTES, OFFLINE_WINDOW_SECONDS
from ace.packet import (
    PLAINTEXT_BUCKETS,
    decrypt_packet,
    packet_header,
    pad_plaintext,
    plaintext_bucket,
    unpad_plaintext,
)
from ace.prekeys import decode_prekey_public_key, prekey_public_key
from tests.helpers import NOW, PEER_PREKEY, open_packet, raises, retained

DIGEST = TEXT.messages["ace:text:1"].digest


def parties():
    a, b = SoftwareIdentity.generate(now=NOW), SoftwareIdentity.generate(now=NOW)
    vault = PrekeyVault()
    vault.current(NOW)
    return a, b, vault


def text(msg="hello", thread=None):
    return encode_content("ace:text:1", DIGEST, {"message": msg}, thread, prekey=PEER_PREKEY)


def state(identity):
    return verify_kel(identity.get_kel(), NOW + 1)


def test_round_trip_and_wire_shape():
    a, b, vault = parties()
    p = create_packet(a, b.get_ace_id(), vault.current(), text(thread="t1"), timestamp=NOW)
    assert set(p) == {"ace", "messageId", "from", "to", "timestamp", "encryption", "signature"}
    assert p["ace"] == "1" and set(p["encryption"]) == {"prekey", "kemCiphertext", "payload"}
    assert p["signature"]["scheme"] == "ml-dsa-65" and p["signature"]["seq"] == 1
    m = open_packet(p, state(a), vault, now=NOW + 5)
    assert (m.type, m.body, m.thread_id, m.schema_digest) == (
        "ace:text:1",
        {"message": "hello"},
        "t1",
        DIGEST,
    )
    assert m.conversation == conversation_key(b.get_ace_id(), a.get_ace_id())


def test_header_and_content_bytes():
    a, b, vault = parties()
    p = create_packet(a, b.get_ace_id(), vault.current(), text(), timestamp=NOW)
    pk = decode_packet(p)
    assert pk.header == encode_payload(
        "ace.v1.packet",
        a.get_ace_id(),
        b.get_ace_id(),
        p["messageId"],
        str(NOW),
        pk.prekey_id,
        pk.kem_ciphertext,
    )
    assert text() == canonical_state_bytes(
        {
            "type": "ace:text:1",
            "schemaDigest": DIGEST,
            "body": {"message": "hello"},
            "prekey": to_base64(PEER_PREKEY),
        }
    )
    with raises("invalid_body"):
        decode_content(
            b'{"type":"ace:text:1","schemaDigest":"'
            + DIGEST.encode()
            + b'","body":{},"threadId":null}'
        )


def test_deterministic_injection_hooks():
    a, b, vault = parties()
    pre = vault.current()
    kem = (bytes(32), bytes(1120))
    p1 = create_packet(
        a,
        b.get_ace_id(),
        pre,
        text(),
        timestamp=NOW,
        message_id="00000000-0000-4000-8000-000000000000",
        _kem=kem,
        _nonce=bytes(12),
    )
    p2 = create_packet(
        a,
        b.get_ace_id(),
        pre,
        text(),
        timestamp=NOW,
        message_id="00000000-0000-4000-8000-000000000000",
        _kem=kem,
        _nonce=bytes(12),
    )
    assert p1["encryption"] == p2["encryption"]


def test_resigned_by_another_identity_does_not_decrypt():
    a, b, vault = parties()
    mallory = SoftwareIdentity.generate(now=NOW)
    p = decode_packet(create_packet(a, b.get_ace_id(), vault.current(), text(), timestamp=NOW))
    # mallory keeps the ciphertext, swaps from and signs it herself: the signature verifies,
    # but the AEAD header binds from, so decryption fails
    from ace.identity import sign_operational
    from ace.packet import Packet, packet_sign_payload

    body = packet_sign_payload(p.to_id, p.message_id, p.prekey_id, p.kem_ciphertext, p.payload)
    forged = Packet(
        p.message_id,
        mallory.get_ace_id(),
        p.to_id,
        p.timestamp,
        p.prekey_id,
        p.kem_ciphertext,
        p.payload,
        sign_operational(mallory, NOW, body, "packet"),
    )
    with raises("decryption_failed"):
        open_packet(forged, state(mallory), vault, now=NOW)
    with raises("invalid_signature"):
        open_packet(p, state(mallory), vault, now=NOW)  # wrong sender state


def test_decoding_rules():
    a, b, vault = parties()
    p = create_packet(a, b.get_ace_id(), vault.current(), text(), timestamp=NOW)
    for mutate, code in [
        (lambda q: q.update(ace="2.0"), "unsupported_version"),
        (lambda q: q.update(extra=1), "invalid_packet"),
        (lambda q: q["encryption"].update(x=1), "invalid_packet"),
        (lambda q: q.update(to=q["from"]), "invalid_packet"),
        (lambda q: q.update(timestamp=-1), "invalid_packet"),
        (lambda q: q["signature"].update(scheme="ml-dsa-87"), "invalid_packet"),
        (lambda q: q["encryption"].update(kemCiphertext=to_base64(b"x" * 10)), "invalid_packet"),
        (lambda q: q.pop("ace"), "invalid_packet"),
    ]:
        q = copy.deepcopy(p)
        mutate(q)
        with raises(code):
            decode_packet(q)
    with raises("stale_timestamp"):
        open_packet(p, state(a), vault, now=NOW + OFFLINE_WINDOW_SECONDS + 1)
    with raises("stale_timestamp"):
        open_packet(p, state(a), vault, now=NOW - 301)
    with raises("invalid_argument"):
        create_packet(a, a.get_ace_id(), vault.current(), text(), timestamp=NOW)


def test_prekey_rotation_retention_and_unknown_prekey():
    a, b, vault = parties()
    old = vault.current()
    p = decode_packet(create_packet(a, b.get_ace_id(), old, text(), timestamp=NOW))
    new = vault.rotate(NOW + 100)
    assert new.id != old.id and new.id == hashlib.sha256(new.public_key).hexdigest()
    assert decrypt_packet(p, vault, NOW + 101) == text()  # retained after supersession
    vault.prune(NOW + 100 + OFFLINE_WINDOW_SECONDS - 1)
    assert old.id in retained(vault)
    # open refuses a seed whose retention ended even before prune ran, and prunes it (L3)
    with raises("unknown_prekey"):
        decrypt_packet(p, vault, NOW + 100 + OFFLINE_WINDOW_SECONDS)
    assert old.id not in retained(vault)
    for i in range(20):
        vault.rotate(NOW + 200 + i)
    assert len(retained(vault)) == 16


def test_file_vault_is_owner_only(tmp_path):
    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    first = v.current(NOW)
    v.rotate(NOW + 1)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = PrekeyVault(path)
    assert again.open(first.id, NOW + 2) is not None and again.current().id == v.current().id
    os.chmod(path, 0o644)
    with raises("storage_failed"):
        PrekeyVault(path)


def test_header_helper_matches():
    assert packet_header("a", "b", "m", 1, "p", b"k") == encode_payload(
        "ace.v1.packet", "a", "b", "m", "1", "p", b"k"
    )


def test_file_vaults_sharing_a_path_never_lose_a_key(tmp_path):
    path = tmp_path / "prekeys.json"
    send, receive = PrekeyVault(path), PrekeyVault(path)
    first = send.current(NOW)
    assert receive.current().id == first.id  # reloaded, not a second generated key
    k1 = send.rotate(NOW + 1)
    k2 = receive.rotate(NOW + 2)  # its cache is stale: it must not drop k1
    fresh = PrekeyVault(path)
    assert fresh.current().id == k2.id and send.current().id == k2.id
    for k in (first, k1, k2):
        assert fresh.open(k.id, NOW + 3) is not None
        assert send.open(k.id, NOW + 3) is not None


def test_file_vault_failed_write_leaves_no_key_in_memory(tmp_path, monkeypatch):
    import ace.prekeys

    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    real = ace.prekeys.write_file_atomic

    def fail(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(ace.prekeys, "write_file_atomic", fail)
    with raises("storage_failed"):
        v.current(NOW)
    monkeypatch.setattr(ace.prekeys, "write_file_atomic", real)
    first = v.current(NOW)
    assert PrekeyVault(path).current().id == first.id
    monkeypatch.setattr(ace.prekeys, "write_file_atomic", fail)
    with raises("storage_failed"):
        v.rotate(NOW + 1)
    assert v.current().id == first.id and retained(v) == []


def _body_at(n: int) -> dict:
    """A body whose deepest container is at depth ``n`` from the body (``n + 1`` in the content)."""
    v: list = []
    for _ in range(n - 1):
        v = [v]
    return {"x": v}


def test_sent_body_depth_counts_from_the_content_root():
    """02 § JSON values: receivers count depth from the private content, so senders do too."""
    encode_content("ace:text:1", DIGEST, _body_at(31), prekey=PEER_PREKEY)
    with raises("invalid_body") as info:
        encode_content("ace:text:1", DIGEST, _body_at(32), prekey=PEER_PREKEY)
    assert "depth" in info.value.message


# --- plaintext padding (03 § Encryption) -------------------------------------------------


@pytest.mark.parametrize(
    "n,b",
    [
        (0, 4096),
        (4092, 4096),
        (4093, 8192),
        (2**20 - 4, 2**20),
        (2**20 - 3, 1_179_652),
        (MAX_PLAINTEXT_BYTES, 1_179_652),
    ],
)
def test_plaintext_bucket(n, b):
    assert plaintext_bucket(n) == b


def test_plaintext_buckets_set():
    assert PLAINTEXT_BUCKETS == frozenset([4096 << i for i in range(9)] + [1_179_652])


def test_pad_unpad_roundtrip():
    c = b"x" * 5000
    p = pad_plaintext(c)
    assert len(p) == 8192 and p[:4] == (5000).to_bytes(4, "big") and unpad_plaintext(p) == c
    assert p[4 + 5000 :] == bytes(8192 - 5004)
    assert unpad_plaintext(pad_plaintext(b"")) == b""


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


@pytest.mark.parametrize(
    "bad",
    [
        _u32(5) + b"x" * 5 + bytes(4095 - 9),  # not a bucket length (4095)
        _u32(8200) + bytes(8188),  # 4 + n > len
        _u32(5000) + bytes(4092),  # prefix 5000 inside a 4096 buffer
        _u32(10) + b"x" * 10 + bytes(8192 - 14),  # 8192 buffer, n = 10 belongs to 4096
        _u32(5) + b"x" * 5 + bytes(100) + b"\x01" + bytes(4096 - 110),  # non-zero padding
        _u32(MAX_PLAINTEXT_BYTES + 1) + bytes(1_179_648),  # n > MAX_PLAINTEXT_BYTES
    ],
)
def test_unpad_rejects(bad):
    with raises("invalid_body"):
        unpad_plaintext(bad)


def test_decode_packet_requires_a_padded_bucket():
    a, b, vault = parties()
    p = create_packet(a, b.get_ace_id(), vault.current(), text(), timestamp=NOW)
    for size in (27, 4096 + 27):
        q = copy.deepcopy(p)
        q["encryption"]["payload"] = to_base64(bytes(size))
        with raises("invalid_packet"):
            decode_packet(q)
    q = copy.deepcopy(p)
    q["encryption"]["payload"] = to_base64(bytes(4096 + 28))
    assert len(decode_packet(q).payload) == 4096 + 28  # length check passes; signature is later
    with raises("invalid_signature"):
        open_packet(q, state(a), vault, now=NOW)


def test_packet_payload_is_padded_and_decrypts_to_content():
    a, b, vault = parties()
    p = decode_packet(create_packet(a, b.get_ace_id(), vault.current(), text(), timestamp=NOW))
    assert len(p.payload) == 4096 + 28
    assert decrypt_packet(p, vault, NOW) == text()


def test_largest_content_fits_a_packet():
    a, b, vault = parties()
    shell = canonical_state_bytes({"body": {"m": ""}, "schemaDigest": DIGEST, "type": "ace:text:1"})
    raw = canonical_state_bytes(
        {
            "body": {"m": "x" * (MAX_PLAINTEXT_BYTES - len(shell))},
            "schemaDigest": DIGEST,
            "type": "ace:text:1",
        }
    )
    assert len(raw) == MAX_PLAINTEXT_BYTES
    p = create_packet(a, b.get_ace_id(), vault.current(), raw, timestamp=NOW)
    assert len(canonical_state_bytes(p)) <= MAX_PACKET_BYTES
    assert decrypt_packet(decode_packet(p), vault, NOW) == raw


# --- private content carries the offered peer prekey (03 § Private content) -----------------


def test_encode_content_requires_prekey():
    with pytest.raises(TypeError):
        encode_content("ace:text:1", DIGEST, {"message": "hi"})  # type: ignore[call-arg]
    with raises("invalid_argument"):
        encode_content("ace:text:1", DIGEST, {}, prekey=bytes(1215))
    with raises("invalid_argument"):
        encode_content("ace:text:1", DIGEST, {}, prekey="not bytes")  # type: ignore[arg-type]


def test_content_prekey_round_trip():
    pk = prekey_public_key(bytes(32))
    raw = encode_content("ace:text:1", DIGEST, {"message": "hi"}, "t", prekey=pk)
    assert json.loads(raw)["prekey"] == to_base64(pk)
    c = decode_content(raw)
    assert c["prekey"] == pk and c["body"] == {"message": "hi"} and c["threadId"] == "t"


def test_decode_content_prekey_rules():
    base = {"type": "ace:text:1", "schemaDigest": DIGEST, "body": {}}
    for bad in (
        base,  # missing
        {**base, "prekey": "QQ=="},  # wrong length
        {**base, "prekey": 7},  # not a string
        {**base, "prekey": to_base64(PEER_PREKEY)[:-1] + "B"},  # non-canonical Base64
        {**base, "prekey": to_base64(b"\xff" * 1216)},  # 1216 bytes, not an X-Wing key
    ):
        with raises("invalid_body"):
            decode_content(canonical_state_bytes(bad))
    assert (
        decode_content(canonical_state_bytes({**base, "prekey": to_base64(PEER_PREKEY)}))["prekey"]
        == PEER_PREKEY
    )


def test_decode_prekey_public_key():
    assert decode_prekey_public_key(to_base64(PEER_PREKEY)) == PEER_PREKEY
    for bad in ("QQ==", None, to_base64(PEER_PREKEY) + "A", to_base64(b"\xff" * 1216)):
        with raises("invalid_body"):
            decode_prekey_public_key(bad)  # type: ignore[arg-type]
