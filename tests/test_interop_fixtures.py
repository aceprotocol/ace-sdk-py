"""Cross-language interoperability tests using shared V1 test vectors.

These vectors are generated from deterministic seed keys and shared across
all SDKs (TypeScript, Python, Swift) to guarantee wire-format compatibility.
"""

import json
import pathlib
import base64

from ace.identity import SoftwareIdentity, compute_ace_id
from ace.encryption import compute_conversation_id, get_ace_dh_salt
from ace.signing import build_sign_data, encode_payload, verify_signature, decode_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


VECTORS_PATH = pathlib.Path(__file__).resolve().parent.parent.parent / "spec" / "test-vectors.json"


def _load_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


def _b64(s: str) -> bytes:
    return base64.b64decode(s)


def test_vectors_file_exists():
    assert VECTORS_PATH.exists(), f"Missing shared test vectors at {VECTORS_PATH}"


def test_ace_dh_salt():
    v = _load_vectors()
    assert get_ace_dh_salt().hex() == v["vectors"]["aceDhSalt"]


def test_alice_identity_derivation():
    v = _load_vectors()
    a = v["agents"]["alice"]
    alice = SoftwareIdentity(
        "ed25519",
        _b64(a["signingPrivateKey"]),
        X25519PrivateKey.from_private_bytes(_b64(a["encryptionPrivateKey"])),
    )
    assert alice.get_ace_id() == a["aceId"]
    assert alice.get_address() == a["address"]
    assert base64.b64encode(alice.get_signing_public_key()).decode() == a["signingPublicKey"]
    assert base64.b64encode(alice.get_encryption_public_key()).decode() == a["encryptionPublicKey"]


def test_bob_identity_derivation():
    v = _load_vectors()
    b = v["agents"]["bob"]
    bob = SoftwareIdentity(
        "secp256k1",
        _b64(b["signingPrivateKey"]),
        X25519PrivateKey.from_private_bytes(_b64(b["encryptionPrivateKey"])),
    )
    assert bob.get_ace_id() == b["aceId"]
    assert bob.get_address() == b["address"]
    assert base64.b64encode(bob.get_signing_public_key()).decode() == b["signingPublicKey"]
    assert base64.b64encode(bob.get_encryption_public_key()).decode() == b["encryptionPublicKey"]


def test_conversation_id():
    v = _load_vectors()
    alice_enc = _b64(v["agents"]["alice"]["encryptionPublicKey"])
    bob_enc = _b64(v["agents"]["bob"]["encryptionPublicKey"])
    assert compute_conversation_id(alice_enc, bob_enc) == v["vectors"]["conversationId"]
    # Symmetric: B↔A == A↔B
    assert compute_conversation_id(bob_enc, alice_enc) == v["vectors"]["conversationId"]


def test_sign_data():
    v = _load_vectors()
    sd = v["vectors"]["signData"]
    mp = sd["messagePayload"]

    message_payload = encode_payload(
        mp["type"],
        mp["to"],
        mp["conversationId"],
        mp["messageId"],
        mp["threadId"],
        _b64(mp["ciphertext"]),
    )
    sign_data = build_sign_data(sd["action"], sd["aceId"], sd["timestamp"], message_payload)
    assert sign_data.hex() == sd["signDataHex"]


def test_ed25519_signature_verification():
    v = _load_vectors()
    sig_v = v["vectors"]["signature"]
    alice = v["agents"]["alice"]

    sign_data = bytes.fromhex(sig_v["signDataHex"])
    sig_bytes = decode_signature(sig_v["signatureValue"], "ed25519")
    pub_key = _b64(alice["signingPublicKey"])

    assert verify_signature(sign_data, sig_bytes, "ed25519", pub_key)


def test_cross_sign_and_verify():
    """Alice (ed25519) signs, verify with her public key from fixture."""
    v = _load_vectors()
    a = v["agents"]["alice"]
    alice = SoftwareIdentity(
        "ed25519",
        _b64(a["signingPrivateKey"]),
        X25519PrivateKey.from_private_bytes(_b64(a["encryptionPrivateKey"])),
    )

    sd = v["vectors"]["signData"]
    sign_data = bytes.fromhex(sd["signDataHex"])
    sig, scheme = alice.sign(sign_data)
    assert scheme == "ed25519"

    # Verify matches fixture
    from ace.signing import encode_signature
    assert encode_signature(sig, "ed25519") == v["vectors"]["signature"]["signatureValue"]
