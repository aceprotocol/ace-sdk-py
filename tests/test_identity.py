import re
from ace import SoftwareIdentity


def test_ed25519_generate():
    id_ = SoftwareIdentity.generate("ed25519")
    assert id_.get_signing_scheme() == "ed25519"
    assert id_.get_tier() == 0
    assert len(id_.get_signing_public_key()) == 32
    assert len(id_.get_encryption_public_key()) == 32


def test_ed25519_ace_id():
    id_ = SoftwareIdentity.generate("ed25519")
    ace_id = id_.get_ace_id()
    assert re.match(r"^ace:sha256:[a-f0-9]{64}$", ace_id)
    assert id_.get_ace_id() == ace_id  # deterministic


def test_ed25519_address():
    id_ = SoftwareIdentity.generate("ed25519")
    addr = id_.get_address()
    assert len(addr) > 0
    assert not addr.startswith("0x")


def test_two_identities_differ():
    a = SoftwareIdentity.generate("ed25519")
    b = SoftwareIdentity.generate("ed25519")
    assert a.get_ace_id() != b.get_ace_id()


def test_ed25519_sign():
    id_ = SoftwareIdentity.generate("ed25519")
    sig, scheme = id_.sign(b"\x01\x02\x03\x04")
    assert scheme == "ed25519"
    assert len(sig) == 64


def test_ed25519_export_import():
    id_ = SoftwareIdentity.generate("ed25519")
    d = id_.to_dict(include_private_keys=True)
    restored = SoftwareIdentity.from_dict(d)
    assert restored.get_ace_id() == id_.get_ace_id()
    assert restored.get_address() == id_.get_address()


def test_ed25519_registration_file():
    id_ = SoftwareIdentity.generate("ed25519")
    reg = id_.to_registration_file(name="TestAgent", endpoint="https://test.example.com/ace")
    assert reg.ace == "1.0"
    assert reg.id == id_.get_ace_id()
    assert reg.name == "TestAgent"
    assert reg.tier == 0
    assert reg.signing.scheme == "ed25519"


def test_secp256k1_generate():
    id_ = SoftwareIdentity.generate("secp256k1")
    assert id_.get_signing_scheme() == "secp256k1"
    assert len(id_.get_signing_public_key()) == 33  # compressed
    assert len(id_.get_encryption_public_key()) == 32


def test_secp256k1_address():
    id_ = SoftwareIdentity.generate("secp256k1")
    addr = id_.get_address()
    assert re.match(r"^0x[a-fA-F0-9]{40}$", addr)


def test_secp256k1_sign():
    id_ = SoftwareIdentity.generate("secp256k1")
    sig, scheme = id_.sign(b"\x01\x02\x03\x04" + b"\x00" * 28)  # 32 bytes for digest
    assert scheme == "secp256k1"
    assert len(sig) == 65  # r(32) + s(32) + v(1)


def test_secp256k1_export_import():
    id_ = SoftwareIdentity.generate("secp256k1")
    d = id_.to_dict(include_private_keys=True)
    restored = SoftwareIdentity.from_dict(d)
    assert restored.get_ace_id() == id_.get_ace_id()
    assert restored.get_address() == id_.get_address()
    assert restored.get_signing_scheme() == "secp256k1"


def test_eip55_checksum_address():
    """EIP-55 addresses have mixed case."""
    id_ = SoftwareIdentity.generate("secp256k1")
    addr = id_.get_address()
    assert addr.startswith("0x")
    assert addr != addr.lower()  # should have uppercase chars (EIP-55)
    # Verify checksum is deterministic
    assert id_.get_address() == addr


def test_decrypt_payload():
    """SoftwareIdentity.decrypt_payload decrypts correctly."""
    from ace.encryption import compute_conversation_id, encrypt
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    conv_id = compute_conversation_id(
        sender.get_encryption_public_key(), receiver.get_encryption_public_key()
    )
    plaintext = b"test payload"
    eph_pub, payload = encrypt(plaintext, receiver.get_encryption_public_key(), conv_id)
    decrypted = receiver.decrypt_payload(eph_pub, payload, conv_id)
    assert decrypted == plaintext
