from ace import SoftwareIdentity
from ace.signing import build_sign_data, encode_payload, verify_signature


def test_build_sign_data_deterministic():
    payload = encode_payload("rfq", "ace:sha256:bbb", "ccc", "msg-001", "thread-1", b"\x01\x02\x03")
    d1 = build_sign_data("message", "ace:sha256:aaa", 1741000000, payload)
    d2 = build_sign_data("message", "ace:sha256:aaa", 1741000000, payload)
    assert len(d1) == 32
    assert d1 == d2


def test_action_switching_prevention():
    payload = encode_payload("offer", "ace:sha256:bbb", "ccc", "id1", "thread-1", b"\x01\x02\x03")
    d1 = build_sign_data("message", "ace:sha256:aaa", 1741000000, payload)
    payload2 = encode_payload("text", "ace:sha256:bbb", "ccc", "id1", "", b"\x01\x02\x03")
    d2 = build_sign_data("message", "ace:sha256:aaa", 1741000000, payload2)
    assert d1 != d2


def test_different_actions_differ():
    d1 = build_sign_data("message", "ace:sha256:aaa", 1741000000)
    d2 = build_sign_data("listen", "ace:sha256:aaa", 1741000000, encode_payload("-"))
    assert d1 != d2


def test_ed25519_sign_verify():
    id_ = SoftwareIdentity.generate("ed25519")
    payload = encode_payload("rfq", "ace:sha256:recipient", "conv123", "msg-001", "thread-1", b"\x0a\x14\x1e")
    sign_data = build_sign_data("message", id_.get_ace_id(), 1741000000, payload)
    sig, scheme = id_.sign(sign_data)
    assert verify_signature(sign_data, sig, scheme, id_.get_signing_public_key())


def test_ed25519_reject_tampered():
    id_ = SoftwareIdentity.generate("ed25519")
    payload = encode_payload("rfq", "ace:sha256:recipient", "conv123", "msg-001", "thread-1", b"\x0a\x14\x1e")
    sign_data = build_sign_data("message", id_.get_ace_id(), 1741000000, payload)
    sig, scheme = id_.sign(sign_data)
    tampered = bytearray(sign_data)
    tampered[0] ^= 0xFF
    assert not verify_signature(bytes(tampered), sig, scheme, id_.get_signing_public_key())


def test_secp256k1_sign_verify():
    id_ = SoftwareIdentity.generate("secp256k1")
    payload = encode_payload("offer", "ace:sha256:recipient", "conv456", "msg-002", "thread-1", b"\x63")
    sign_data = build_sign_data("message", id_.get_ace_id(), 1741000000, payload)
    sig, scheme = id_.sign(sign_data)
    assert verify_signature(sign_data, sig, scheme, id_.get_signing_public_key())


def test_secp256k1_reject_tampered():
    id_ = SoftwareIdentity.generate("secp256k1")
    payload = encode_payload("offer", "ace:sha256:recipient", "conv456", "msg-002", "thread-1", b"\x63")
    sign_data = build_sign_data("message", id_.get_ace_id(), 1741000000, payload)
    sig, scheme = id_.sign(sign_data)
    tampered = bytearray(sign_data)
    tampered[0] ^= 0xFF
    assert not verify_signature(bytes(tampered), sig, scheme, id_.get_signing_public_key())


def test_encode_payload_deterministic():
    p1 = encode_payload("hello", b"\x01\x02")
    p2 = encode_payload("hello", b"\x01\x02")
    assert p1 == p2


def test_encode_payload_different_fields():
    p1 = encode_payload("a", "b")
    p2 = encode_payload("a", "c")
    assert p1 != p2


def test_listen_sign_data():
    d = build_sign_data("listen", "ace:sha256:aaa", 1741000000, encode_payload("-"))
    assert len(d) == 32


def test_register_sign_data():
    payload = encode_payload("epk", "spk")
    d = build_sign_data("register", "ace:sha256:aaa", 1741000000, payload)
    assert len(d) == 32


def test_intent_sign_data():
    payload = encode_payload("need-gpu")
    d = build_sign_data("intent", "ace:sha256:aaa", 1741000000, payload)
    assert len(d) == 32
