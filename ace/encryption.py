"""ACE Protocol E2E encryption: X-Wing hybrid KEM + HKDF-SHA256 + AES-256-GCM.

Pipeline:
    (ss, kem_ciphertext) = XWing.Encapsulate(recipient_public_key)
    aes_key = HKDF-SHA256(ikm = ss, salt = ACE_KEM_SALT, info = UTF-8(conversationId), L = 32)
    payload = nonce[12] || AES-256-GCM(aes_key, nonce, plaintext, aad = UTF-8(conversationId))

The recipient's static key is an X-Wing public key (``xwing.PUBLIC_KEY_SIZE`` =
1216 bytes) whose private key is a 32-byte seed. Each message carries a fresh KEM
ciphertext (``xwing.CIPHERTEXT_SIZE`` = 1120 bytes). Byte-length validation of
those values lives in :mod:`ace.xwing`; this module only checks the AEAD payload.

Security note (no forward secrecy on the recipient side): compromise of a sender
reveals nothing about past messages, but compromise of a recipient's static seed
reveals every past and future message encrypted to that key.
"""

from __future__ import annotations

import hashlib
import os
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import xwing
from ._utils import from_base64

# ACE_KEM_SALT = SHA-256("ace.protocol.kem.v1")
_ace_kem_salt = hashlib.sha256(b"ace.protocol.kem.v1").digest()


def get_ace_kem_salt() -> bytes:
    """Return the ACE KEM salt (SHA-256 of 'ace.protocol.kem.v1')."""
    return _ace_kem_salt


# AES-256-GCM: 12-byte nonce + 16-byte authentication tag
_NONCE_LEN = 12
_GCM_TAG_LEN = 16
_MIN_PAYLOAD_LEN = _NONCE_LEN + _GCM_TAG_LEN  # 28 bytes

# Maximum payload size to prevent OOM (10 MB)
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024
_MAX_PLAINTEXT_SIZE = MAX_PAYLOAD_SIZE - _MIN_PAYLOAD_LEN


def _padded_base64_length(n_bytes: int) -> int:
    """Length of the padded Base64 encoding of ``n_bytes`` bytes."""
    return 4 * ((n_bytes + 2) // 3)


_MAX_PUBLIC_KEY_B64_LEN = _padded_base64_length(xwing.PUBLIC_KEY_SIZE)  # 1624
_MAX_CIPHERTEXT_B64_LEN = _padded_base64_length(xwing.CIPHERTEXT_SIZE)  # 1496


def _decode_fixed_size(
    b64: str, max_b64_len: int, check: Callable[[bytes], None], what: str
) -> bytes:
    if not isinstance(b64, str):
        raise ValueError(f"{what} must be a Base64 string")
    # Cheap pre-check: refuse to decode anything longer than the encoding of a
    # correctly sized value.
    if len(b64) > max_b64_len:
        raise ValueError(f"{what} Base64 is too long ({len(b64)} chars, max {max_b64_len})")
    raw = from_base64(b64)
    check(raw)
    return raw


def decode_kem_public_key(b64: str) -> bytes:
    """Decode a Base64 X-Wing public key and enforce its length (1216 bytes)."""
    return _decode_fixed_size(
        b64, _MAX_PUBLIC_KEY_B64_LEN, xwing.check_public_key, "X-Wing public key"
    )


def decode_kem_ciphertext(b64: str) -> bytes:
    """Decode a Base64 X-Wing KEM ciphertext and enforce its length (1120 bytes)."""
    return _decode_fixed_size(
        b64, _MAX_CIPHERTEXT_B64_LEN, xwing.check_ciphertext, "X-Wing ciphertext"
    )


def _derive_aes_key(shared_secret: bytes, conv_id_bytes: bytes) -> bytes:
    """Derive AES-256 key from the KEM shared secret via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_ace_kem_salt,
        info=conv_id_bytes,
    )
    return hkdf.derive(shared_secret)


def compute_conversation_id(pub_a: bytes, pub_b: bytes) -> str:
    """Compute deterministic conversation ID from two X-Wing public keys.

    conversationId = hex(SHA-256(sort_bytes(pubA, pubB)))
    """
    xwing.check_public_key(pub_a)
    xwing.check_public_key(pub_b)
    if pub_a <= pub_b:
        first, second = pub_a, pub_b
    else:
        first, second = pub_b, pub_a
    return hashlib.sha256(first + second).hexdigest()


def encrypt(
    plaintext: bytes,
    recipient_pub_key: bytes,
    conversation_id: str,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext for a recipient.

    Returns (kem_ciphertext, payload) where kem_ciphertext is the 1120-byte X-Wing
    ciphertext and payload = nonce[12] || ciphertext || tag[16].
    """
    # 0. Validate payload size (the public key length is checked by xwing.encapsulate)
    if len(plaintext) > _MAX_PLAINTEXT_SIZE:
        raise ValueError(
            f"Plaintext too large ({len(plaintext)} bytes): maximum is {_MAX_PLAINTEXT_SIZE}"
        )

    # 1. KEM encapsulation
    shared_secret, kem_ciphertext = xwing.encapsulate(recipient_pub_key)

    # 2. HKDF key derivation
    conv_id_bytes = conversation_id.encode("utf-8")
    aes_key = _derive_aes_key(shared_secret, conv_id_bytes)

    # 3. AES-256-GCM encryption
    nonce = os.urandom(_NONCE_LEN)
    aad = conv_id_bytes
    aesgcm = AESGCM(aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)

    # 4. Payload = nonce[12] || ciphertext || tag[16]
    payload = nonce + ciphertext_and_tag
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Encrypted payload too large ({len(payload)} bytes): maximum is {MAX_PAYLOAD_SIZE}"
        )

    # NOTE: `del` only removes the Python reference; the key material remains in
    # memory until garbage-collected.  True zeroization is not possible in pure
    # Python.  For production use, prefer Tier 1/2 identities (HSM / TEE).
    del shared_secret, aes_key

    return kem_ciphertext, payload


def decrypt(
    kem_ciphertext: bytes,
    payload: bytes,
    private_seed: bytes,
    conversation_id: str,
) -> bytes:
    """Decrypt a message using own X-Wing private seed (32 bytes).

    All length checks run before any decapsulation.
    """
    # 0. Validate payload size (kem_ciphertext / seed lengths are checked by
    #    xwing.decapsulate before any KEM work)
    if len(payload) < _MIN_PAYLOAD_LEN:
        raise ValueError(
            f"Payload too short ({len(payload)} bytes): "
            f"must contain at least {_NONCE_LEN}-byte nonce + {_GCM_TAG_LEN}-byte tag"
        )
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload too large ({len(payload)} bytes): maximum is {MAX_PAYLOAD_SIZE}"
        )

    # 1. KEM decapsulation (implicit rejection: a bad ciphertext yields an
    #    unrelated secret, caught by the GCM tag below)
    shared_secret = xwing.decapsulate(kem_ciphertext, private_seed)

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
