import hashlib

from ace._signing import signing_message, verify_signature
from ace.keys import SoftwareKey, generate_software_key, key_digest
from tests.helpers import raises

M = signing_message("ace:sha256:" + "11" * 32, 5, None, b"z")


def test_software_key_roundtrip_and_sign():
    k = SoftwareKey(bytes(32))
    assert len(k.public_key()) == 1952 and k.scheme == "ml-dsa-65"
    assert SoftwareKey(bytes(32)).public_key() == k.public_key()  # deterministic from seed
    sig = k.sign(M, "kel")
    assert len(sig) == 3309 and verify_signature(M, "kel", sig, k.public_key())
    assert not verify_signature(M, "dlg", sig, k.public_key())


def test_generate():
    k = generate_software_key()
    assert len(k.public_key()) == 1952 and len(k.seed) == 32 and k.scheme == "ml-dsa-65"
    assert generate_software_key().seed != generate_software_key().seed


def test_invalid_inputs():
    with raises("invalid_argument"):
        SoftwareKey(bytes(31))


def test_key_digest():
    pk = bytes(1952)
    assert key_digest("ml-dsa-65", pk) == hashlib.sha256(b"ml-dsa-65\x00" + pk).digest()


def test_sign_rejects_invalid_action_and_body():
    k = SoftwareKey(bytes(32))
    with raises("invalid_argument"):
        k.sign(M, None)
    with raises("invalid_argument"):
        k.sign(M, "x" * 256)
    with raises("invalid_argument"):
        k.sign("str", "kel")


def test_sign_accepts_max_length_action():
    k = SoftwareKey(bytes(32))
    sig = k.sign(M, "x" * 255)
    assert verify_signature(M, "x" * 255, sig, k.public_key())
