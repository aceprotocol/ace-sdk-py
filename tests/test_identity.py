"""SoftwareIdentity, seed helpers and encryption errors."""

import os

import pytest

from ace import (
    SoftwareIdentity,
    compute_conversation_id,
    decrypt_with_seed,
    generate_kem_seed,
    kem_public_key_from_seed,
)
from ace._signing import verify_signature
from ace.encryption import encrypt

from .helpers import raises


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_export_round_trip_and_sign(scheme):
    ident = SoftwareIdentity.generate(scheme)
    exported = ident.export_private_key()
    assert set(exported) == {"scheme", "signingPrivateKey", "encryptionPrivateKey"}
    restored = SoftwareIdentity.from_export(exported)
    assert restored.get_ace_id() == ident.get_ace_id()
    assert restored.get_encryption_public_key() == ident.get_encryption_public_key()
    data = os.urandom(32)
    sig = ident.sign(data)
    assert isinstance(sig, bytes) and len(sig) == (64 if scheme == "ed25519" else 65)
    assert verify_signature(data, sig, scheme, ident.get_signing_public_key())


def test_invalid_constructor_inputs():
    with raises("invalid_argument"):
        SoftwareIdentity.generate("rsa")  # type: ignore[arg-type]
    with raises("invalid_key"):
        SoftwareIdentity("ed25519", b"\x01" * 31, b"\x02" * 32)
    with raises("invalid_key"):
        SoftwareIdentity("secp256k1", b"\x00" * 32, b"\x02" * 32)
    with raises("invalid_key"):
        SoftwareIdentity("ed25519", b"\x01" * 32, b"\x02" * 31)
    with raises("invalid_key"):
        SoftwareIdentity.from_export({"scheme": "ed25519", "signingPrivateKey": "QR==", "encryptionPrivateKey": ""})
    with raises("invalid_argument"):
        SoftwareIdentity.generate("ed25519").sign(b"short")


def test_registration_file_tier_and_validation():
    ident = SoftwareIdentity.generate("secp256k1")
    reg = ident.to_registration_file(name="Agent", endpoint="https://agent.example/ace", tier=1)
    assert reg.tier == 1 and reg.signing.signing_public_key is not None
    assert SoftwareIdentity.generate("ed25519").to_registration_file(name="A", endpoint="https://a.example").tier == 0
    with raises("invalid_registration"):
        ident.to_registration_file(name="Agent", endpoint="http://agent.example")
    with raises("invalid_registration"):
        ident.to_registration_file(name="", endpoint="https://agent.example")


def test_seed_helpers_and_decrypt_errors():
    seed = generate_kem_seed()
    pk = kem_public_key_from_seed(seed)
    me = SoftwareIdentity("ed25519", b"\x05" * 32, seed)
    assert me.get_encryption_public_key() == pk
    other = SoftwareIdentity.generate("ed25519").get_encryption_public_key()
    cid = compute_conversation_id(pk, other)
    kem, payload = encrypt(b"hello", pk, cid)
    assert decrypt_with_seed(kem, payload, seed, cid) == b"hello"
    assert me.decrypt(kem, payload, cid) == b"hello"
    with raises("decryption_failed"):
        decrypt_with_seed(kem, payload[:-1] + bytes([payload[-1] ^ 1]), seed, cid)
    with raises("decryption_failed"):
        decrypt_with_seed(kem[:-1], payload, seed, cid)
    with raises("decryption_failed"):
        decrypt_with_seed(kem, payload[:27], seed, cid)
    with raises("decryption_failed"):
        decrypt_with_seed(kem, payload, generate_kem_seed(), cid)
    with raises("invalid_key"):
        decrypt_with_seed(kem, payload, seed[:31], cid)
    with raises("invalid_argument"):
        decrypt_with_seed(kem, payload, seed, "x")
    with raises("invalid_key"):
        kem_public_key_from_seed(b"")
    with raises("invalid_key"):
        compute_conversation_id(pk, pk[:-1])
    with raises("limit_exceeded"):
        encrypt(b"x" * 65509, pk, cid)
