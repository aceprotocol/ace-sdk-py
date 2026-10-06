import hashlib
import re

import pytest

from ace import SoftwareIdentity, xwing
from ace.encryption import (
    MAX_PAYLOAD_SIZE,
    compute_conversation_id,
    decrypt,
    encrypt,
    get_ace_kem_salt,
)


def test_get_ace_kem_salt():
    salt = get_ace_kem_salt()
    assert len(salt) == 32
    assert salt == get_ace_kem_salt()  # Deterministic
    assert salt == hashlib.sha256(b"ace.protocol.kem.v1").digest()


def test_conversation_id_deterministic():
    a = SoftwareIdentity.generate("ed25519")
    b = SoftwareIdentity.generate("ed25519")
    id1 = compute_conversation_id(a.get_encryption_public_key(), b.get_encryption_public_key())
    id2 = compute_conversation_id(a.get_encryption_public_key(), b.get_encryption_public_key())
    assert id1 == id2


def test_conversation_id_symmetric():
    a = SoftwareIdentity.generate("ed25519")
    b = SoftwareIdentity.generate("ed25519")
    ab = compute_conversation_id(a.get_encryption_public_key(), b.get_encryption_public_key())
    ba = compute_conversation_id(b.get_encryption_public_key(), a.get_encryption_public_key())
    assert ab == ba


def test_conversation_id_hex():
    a = SoftwareIdentity.generate("ed25519")
    b = SoftwareIdentity.generate("ed25519")
    cid = compute_conversation_id(a.get_encryption_public_key(), b.get_encryption_public_key())
    assert re.match(r"^[a-f0-9]{64}$", cid)


def test_encrypt_decrypt_roundtrip():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    plaintext = b"Hello ACE!"
    kem_ct, payload = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)

    assert len(kem_ct) == xwing.CIPHERTEXT_SIZE == 1120
    assert len(payload) == len(plaintext) + 28

    decrypted = decrypt(kem_ct, payload, receiver.get_encryption_seed(), conv_id)
    assert decrypted == plaintext


def test_decrypt_wrong_key_fails():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    wrong = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    kem_ct, payload = encrypt(b"Secret", receiver.get_encryption_public_key(), conv_id)

    with pytest.raises(Exception):
        decrypt(kem_ct, payload, wrong.get_encryption_seed(), conv_id)


def test_decrypt_wrong_conv_id_fails():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    kem_ct, payload = encrypt(b"Secret", receiver.get_encryption_public_key(), conv_id)

    with pytest.raises(Exception):
        decrypt(kem_ct, payload, receiver.get_encryption_seed(), "wrong-conv-id")


def test_kem_ciphertexts_differ():
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = "a" * 64
    plaintext = b"Same message"
    ct1, pay1 = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    ct2, pay2 = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    assert ct1 != ct2
    assert pay1 != pay2


def test_encryption_public_key_is_1216_bytes():
    idn = SoftwareIdentity.generate("ed25519")
    assert len(idn.get_encryption_public_key()) == xwing.PUBLIC_KEY_SIZE == 1216


def test_maximum_plaintext_roundtrip():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    plaintext = b"\x5a" * (MAX_PAYLOAD_SIZE - 28)
    kem_ct, payload = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    assert len(payload) <= MAX_PAYLOAD_SIZE
    decrypted = decrypt(kem_ct, payload, receiver.get_encryption_seed(), conv_id)
    assert decrypted == plaintext


def test_plaintext_larger_than_maximum_rejected():
    receiver = SoftwareIdentity.generate("ed25519")
    with pytest.raises(ValueError, match="Plaintext too large"):
        encrypt(b"\x00" * (MAX_PAYLOAD_SIZE - 27), receiver.get_encryption_public_key(), "a" * 64)
