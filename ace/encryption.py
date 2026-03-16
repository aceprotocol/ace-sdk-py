"""ACE Protocol E2E encryption: X25519 ECDH + HKDF-SHA256 + AES-256-GCM."""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Pre-computed: SHA-256("ace.protocol.dh.v1")
_ace_dh_salt = hashlib.sha256(b"ace.protocol.dh.v1").digest()


def get_ace_dh_salt() -> bytes:
    """Return the ACE DH salt (SHA-256 of 'ace.protocol.dh.v1')."""
    return _ace_dh_salt

# AES-256-GCM: 12-byte nonce + 16-byte authentication tag
_NONCE_LEN = 12
_GCM_TAG_LEN = 16
_MIN_PAYLOAD_LEN = _NONCE_LEN + _GCM_TAG_LEN  # 28 bytes

# Maximum payload size to prevent OOM (10 MB)
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024
_MAX_PLAINTEXT_SIZE = MAX_PAYLOAD_SIZE - _MIN_PAYLOAD_LEN

_ZERO_KEY = b"\x00" * 32


def _derive_aes_key(shared_secret: bytes, conv_id_bytes: bytes) -> bytes:
    """Derive AES-256 key from shared secret via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_ace_dh_salt,
        info=conv_id_bytes,
    )
    return hkdf.derive(shared_secret)


def compute_conversation_id(pub_a: bytes, pub_b: bytes) -> str:
    """Compute deterministic conversation ID from two X25519 public keys.

    conversationId = hex(SHA-256(sort_bytes(pubA, pubB)))
    """
    if pub_a <= pub_b:
        first, second = pub_a, pub_b
    else:
        first, second = pub_b, pub_a
    combined = first + second
    return hashlib.sha256(combined).hexdigest()


def _validate_public_key(pub_key: bytes) -> None:
    """Validate X25519 public key: must be 32 bytes, non-zero."""
    if len(pub_key) != 32:
        raise ValueError(f"X25519 public key must be exactly 32 bytes, got {len(pub_key)}")
    if pub_key == _ZERO_KEY:
        raise ValueError("Refusing to use all-zeros X25519 public key (known weak key)")


def encrypt(
    plaintext: bytes,
    recipient_pub_key: bytes,
    conversation_id: str,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext for a recipient.

    Returns (ephemeral_pub_key, payload) where payload = nonce[12] || ciphertext || tag[16].
    """
    # 0. Validate inputs
    _validate_public_key(recipient_pub_key)
    if len(plaintext) > _MAX_PLAINTEXT_SIZE:
        raise ValueError(
            f"Plaintext too large ({len(plaintext)} bytes): maximum is {_MAX_PLAINTEXT_SIZE}"
        )

    # 1. Generate ephemeral X25519 key pair
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key().public_bytes_raw()

    # 2. ECDH shared secret
    recipient_key = X25519PublicKey.from_public_bytes(recipient_pub_key)
    shared_secret = ephemeral_priv.exchange(recipient_key)

    # 3. HKDF key derivation
    conv_id_bytes = conversation_id.encode("utf-8")
    aes_key = _derive_aes_key(shared_secret, conv_id_bytes)

    # 4. AES-256-GCM encryption
    nonce = os.urandom(_NONCE_LEN)
    aad = conv_id_bytes
    aesgcm = AESGCM(aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)

    # 5. Payload = nonce[12] || ciphertext || tag[16]
    payload = nonce + ciphertext_and_tag
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Encrypted payload too large ({len(payload)} bytes): maximum is {MAX_PAYLOAD_SIZE}"
        )

    # NOTE: `del` only removes the Python reference; the key material remains in
    # memory until garbage-collected.  True zeroization is not possible in pure
    # Python.  For production use, prefer Tier 1/2 identities (HSM / TEE).
    del ephemeral_priv, shared_secret, aes_key

    return ephemeral_pub, payload


def decrypt(
    ephemeral_pub_key: bytes,
    payload: bytes,
    recipient_priv_key: X25519PrivateKey,
    conversation_id: str,
) -> bytes:
    """Decrypt a message using own private key."""
    # 0. Validate inputs
    _validate_public_key(ephemeral_pub_key)
    if len(payload) < _MIN_PAYLOAD_LEN:
        raise ValueError(
            f"Payload too short ({len(payload)} bytes): "
            f"must contain at least {_NONCE_LEN}-byte nonce + {_GCM_TAG_LEN}-byte tag"
        )
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload too large ({len(payload)} bytes): maximum is {MAX_PAYLOAD_SIZE}"
        )

    # 1. ECDH shared secret
    ephemeral_key = X25519PublicKey.from_public_bytes(ephemeral_pub_key)
    shared_secret = recipient_priv_key.exchange(ephemeral_key)

    # 2. HKDF key derivation
    conv_id_bytes = conversation_id.encode("utf-8")
    aes_key = _derive_aes_key(shared_secret, conv_id_bytes)

    # 3. Parse payload: nonce[12] || ciphertext+tag
    nonce = payload[:_NONCE_LEN]
    ciphertext_and_tag = payload[_NONCE_LEN:]

    # 4. AES-256-GCM decryption
    aad = conv_id_bytes
    aesgcm = AESGCM(aes_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    finally:
        del shared_secret, aes_key
