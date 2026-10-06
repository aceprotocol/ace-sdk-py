"""ACE E2E encryption: X-Wing hybrid KEM + HKDF-SHA256 + AES-256-GCM.

    (ss, kem_ciphertext) = XWing.Encapsulate(recipient_public_key)
    aes_key = HKDF-SHA256(ikm = ss, salt = SHA-256("ace.protocol.kem.v1"), info = conversationId, L = 32)
    payload = nonce[12] || AES-256-GCM(aes_key, nonce, plaintext, aad = conversationId)

Byte lengths of keys, seeds and KEM ciphertexts are owned by :mod:`ace._xwing`.

No forward secrecy on the recipient side: compromise of a recipient's static seed
reveals every message encrypted to that key.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _xwing
from ._encoding import is_conversation_id
from .errors import ACEError
from .limits import KEM_SEED_SIZE, MAX_PAYLOAD_BYTES, MAX_PLAINTEXT_BYTES

ACE_KEM_SALT = hashlib.sha256(b"ace.protocol.kem.v1").digest()
_NONCE_LEN = 12
_TAG_LEN = 16
MIN_PAYLOAD_BYTES = _NONCE_LEN + _TAG_LEN


def _aes_key(shared_secret: bytes, conversation_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=ACE_KEM_SALT,
        info=conversation_id.encode("ascii"),
    ).derive(shared_secret)


def _check_key(value: object, size: int, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != size:
        raise ACEError("invalid_key", f"{what} must be {size} bytes")
    return bytes(value)


def compute_conversation_id(pub_a: bytes, pub_b: bytes) -> str:
    """hex(SHA-256(min(pubA, pubB) || max(pubA, pubB))) over two X-Wing public keys."""
    try:
        _xwing.check_public_key(pub_a)
        _xwing.check_public_key(pub_b)
    except ACEError as exc:
        raise ACEError("invalid_key", exc.message) from None
    a, b = bytes(pub_a), bytes(pub_b)
    return hashlib.sha256(a + b if a <= b else b + a).hexdigest()


def generate_kem_seed() -> bytes:
    """A fresh 32-byte X-Wing private seed."""
    return os.urandom(KEM_SEED_SIZE)


def kem_public_key_from_seed(seed: bytes) -> bytes:
    """The 1216-byte X-Wing public key of a 32-byte seed."""
    return _xwing.public_key_from_seed(_check_key(seed, KEM_SEED_SIZE, "X-Wing seed"))


def encrypt(plaintext: bytes, recipient_public_key: bytes, conversation_id: str) -> tuple[bytes, bytes]:
    """Internal: returns ``(kem_ciphertext, payload)``."""
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ACEError("limit_exceeded", f"plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes")
    try:
        shared_secret, kem_ciphertext = _xwing.encapsulate(recipient_public_key)
    except ACEError as exc:
        raise ACEError("invalid_key", exc.message) from None
    nonce = os.urandom(_NONCE_LEN)
    payload = nonce + AESGCM(_aes_key(shared_secret, conversation_id)).encrypt(
        nonce, bytes(plaintext), conversation_id.encode("ascii"),
    )
    return kem_ciphertext, payload


def decrypt_with_key(
    key: _xwing.DecapsulationKey, kem_ciphertext: bytes, payload: bytes, conversation_id: str,
) -> bytes:
    """Internal: decrypt with an expanded key. Every crypto failure is ``decryption_failed``."""
    if not is_conversation_id(conversation_id):
        raise ACEError("invalid_argument", "conversation_id must be 64 lowercase hex characters")
    if not isinstance(payload, (bytes, bytearray)) or not MIN_PAYLOAD_BYTES <= len(payload) <= MAX_PAYLOAD_BYTES:
        raise ACEError("decryption_failed", "payload length out of range")
    try:
        shared_secret = key.decapsulate(kem_ciphertext)
    except ACEError as exc:
        raise ACEError("decryption_failed", exc.message) from None
    payload = bytes(payload)
    try:
        return AESGCM(_aes_key(shared_secret, conversation_id)).decrypt(
            payload[:_NONCE_LEN], payload[_NONCE_LEN:], conversation_id.encode("ascii"),
        )
    except InvalidTag:
        raise ACEError("decryption_failed", "AEAD authentication failed") from None


def decrypt_with_seed(kem_ciphertext: bytes, payload: bytes, seed: bytes, conversation_id: str) -> bytes:
    """Decrypt with a borrowed 32-byte X-Wing seed (for custom identities).

    Crypto failures are ``ACEError(decryption_failed)``; a malformed seed is ``invalid_key``.
    """
    key = _xwing.DecapsulationKey(_check_key(seed, KEM_SEED_SIZE, "X-Wing seed"))
    return decrypt_with_key(key, kem_ciphertext, payload, conversation_id)
