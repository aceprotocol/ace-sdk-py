from cryptography.hazmat.primitives.asymmetric import mldsa

from ace._signing import (
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    SIGNATURE_SIZE,
    encode_payload,
    is_signing_key,
    signing_message,
    verify_signature,
)
from tests.helpers import raises

SEED = bytes(range(32))
ID = "ace:sha256:" + "ab" * 32


def test_sizes():
    assert (SEED_SIZE, PUBLIC_KEY_SIZE, SIGNATURE_SIZE) == (32, 1952, 3309)


def test_signing_message_is_one_encode_payload():
    assert signing_message(ID, 1760140800, 3, b"xy") == encode_payload(
        "ace.v1", ID, "1760140800", "3", b"xy"
    )
    # a KEL event signature has an empty seqOrEmpty
    assert signing_message(ID, 0, None, b"") == encode_payload("ace.v1", ID, "0", "", b"")
    with raises("invalid_argument"):
        signing_message(ID, -1, 1, b"")
    with raises("invalid_argument"):
        signing_message(ID, 2**53, 1, b"")
    with raises("invalid_argument"):
        signing_message(ID, 1, True, b"")


def test_encode_payload():
    assert encode_payload() == b""
    assert encode_payload("a", b"\x00\x01") == b"\x00\x00\x00\x01a\x00\x00\x00\x02\x00\x01"


def test_verify_ml_dsa_65_with_context():
    sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(SEED)
    pk = sk.public_key().public_bytes_raw()
    m = signing_message(ID, 1, 1, b"p")
    sig = sk.sign(m, context=b"packet")
    assert verify_signature(m, "packet", sig, pk)
    assert not verify_signature(m, "kel", sig, pk)  # wrong context
    assert not verify_signature(m + b"x", "packet", sig, pk)
    assert not verify_signature(m, "packet", sig[:-1], pk)  # wrong size
    # malformed inputs return False, never raise
    assert not verify_signature(m, "packet", None, pk)
    assert not verify_signature(m, "packet", 5, pk)
    assert not verify_signature("str", "packet", sig, pk)
    assert not verify_signature(m, None, sig, pk)
    assert not verify_signature(m, "packet", sig, bytes(2592))


def test_public_key_validation():
    assert is_signing_key("ml-dsa-65", bytes(1952))
    assert not is_signing_key("ml-dsa-65", bytes(2592))
    assert not is_signing_key("ml-dsa-87", bytes(2592))
    assert not is_signing_key("ed25519", bytes(32))
    assert not is_signing_key("ml-dsa-65", "not bytes")
