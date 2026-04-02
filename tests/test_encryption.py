import re
import pytest
from ace import SoftwareIdentity
from ace.encryption import compute_conversation_id, encrypt, decrypt, get_ace_dh_salt, MAX_PAYLOAD_SIZE


def test_get_ace_dh_salt():
    salt = get_ace_dh_salt()
    assert len(salt) == 32
    assert salt == get_ace_dh_salt()  # Deterministic


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
    eph_pub, payload = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)

    assert len(eph_pub) == 32
    assert len(payload) > len(plaintext)

    decrypted = decrypt(eph_pub, payload, receiver.get_encryption_private_key(), conv_id)
    assert decrypted == plaintext


def test_decrypt_wrong_key_fails():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    wrong = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    eph_pub, payload = encrypt(b"Secret", receiver.get_encryption_public_key(), conv_id)

    with pytest.raises(Exception):
        decrypt(eph_pub, payload, wrong.get_encryption_private_key(), conv_id)


def test_decrypt_wrong_conv_id_fails():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    eph_pub, payload = encrypt(b"Secret", receiver.get_encryption_public_key(), conv_id)

    with pytest.raises(Exception):
        decrypt(eph_pub, payload, receiver.get_encryption_private_key(), "wrong-conv-id")


def test_ephemeral_keys_differ():
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = "a" * 64
    plaintext = b"Same message"
    eph1, pay1 = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    eph2, pay2 = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    assert eph1 != eph2
    assert pay1 != pay2


def test_maximum_plaintext_roundtrip():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    plaintext = b"\x5a" * (MAX_PAYLOAD_SIZE - 28)
    eph_pub, payload = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    assert len(payload) <= MAX_PAYLOAD_SIZE
    decrypted = decrypt(eph_pub, payload, receiver.get_encryption_private_key(), conv_id)
    assert decrypted == plaintext


def test_plaintext_larger_than_maximum_rejected():
    receiver = SoftwareIdentity.generate("ed25519")
    with pytest.raises(ValueError, match="Plaintext too large"):
        encrypt(b"\x00" * (MAX_PAYLOAD_SIZE - 27), receiver.get_encryption_public_key(), "a" * 64)
