"""X-Wing hybrid KEM (draft-connolly-cfrg-xwing-kem-11). Internal module.

X-Wing = ML-KEM-768 + X25519, combined with SHA3-256 and a fixed label. It is the
general-purpose hybrid KEM standardised by the CFRG; the ML-KEM-768 component gives
post-quantum confidentiality, the X25519 component (classical elliptic-curve
Diffie-Hellman) keeps the construction at least as strong as today's ECDH even if a
flaw is found in ML-KEM.

Sizes (bytes):
    seed (private key)   32   expanded = SHAKE256(seed, 96)
                              (d, z) = expanded[0:64]  -> ML-KEM-768 KeyGen_internal
                              sk_X   = expanded[64:96] -> X25519 scalar
    public key         1216   pk_M[1184] || pk_X[32]
    ciphertext         1120   ct_M[1088] || ct_X[32]
    shared secret        32   SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)

The combiner binds ``pk_X`` and ``ct_X`` into the shared secret, so no X25519
small-order point checks are needed (draft-11 Section 7).

Backed by ``cryptography>=48`` (``MLKEM768PrivateKey.from_seed_bytes``) and
``hashlib`` (``shake_256``, ``sha3_256``).

This module is the single owner of the X-Wing byte-length checks:
:func:`check_public_key`, :func:`check_ciphertext` and :func:`check_seed`.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .errors import ACEError
from .limits import (
    KEM_CIPHERTEXT_SIZE as CIPHERTEXT_SIZE,
    KEM_PUBLIC_KEY_SIZE as PUBLIC_KEY_SIZE,
    KEM_SEED_SIZE as SEED_SIZE,
)

SHARED_SECRET_SIZE = 32

# XWingLabel = ASCII "\.//^\" (6 bytes), hex 5c2e2f2f5e5c.
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")

_MLKEM_PK_SIZE = 1184  # PUBLIC_KEY_SIZE - 32
_MLKEM_CT_SIZE = 1088  # CIPHERTEXT_SIZE - 32
_MLKEM_SEED_SIZE = 64  # d || z
_X_SIZE = 32
_EXPANDED_SIZE = _MLKEM_SEED_SIZE + _X_SIZE  # 96


def _check_length(value: bytes, expected: int, what: str) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise ACEError("invalid_argument", f"X-Wing {what} must be bytes, got {type(value).__name__}")
    if len(value) != expected:
        raise ACEError("invalid_argument", f"X-Wing {what} must be exactly {expected} bytes, got {len(value)}")


def check_public_key(public_key: bytes) -> None:
    """Raise ``ACEError(invalid_argument)`` unless ``public_key`` is exactly 1216 bytes."""
    _check_length(public_key, PUBLIC_KEY_SIZE, "public key")


def check_ciphertext(ciphertext: bytes) -> None:
    """Raise ``ACEError(invalid_argument)`` unless ``ciphertext`` is exactly 1120 bytes."""
    _check_length(ciphertext, CIPHERTEXT_SIZE, "ciphertext")


def check_seed(seed: bytes) -> None:
    """Raise ``ACEError(invalid_argument)`` unless ``seed`` is exactly 32 bytes."""
    _check_length(seed, SEED_SIZE, "seed")


def _combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


class DecapsulationKey:
    """An X-Wing private key expanded once from its 32-byte seed.

    expandDecapsulationKey (SHAKE256 + ML-KEM-768 keygen + X25519 base-point
    multiplication) runs in the constructor, so holders that decapsulate
    repeatedly pay for it once.
    """

    __slots__ = ("_sk_m", "_sk_x", "_pk_x", "public_key")

    def __init__(self, seed: bytes) -> None:
        check_seed(seed)
        expanded = hashlib.shake_256(bytes(seed)).digest(_EXPANDED_SIZE)
        self._sk_m = MLKEM768PrivateKey.from_seed_bytes(expanded[:_MLKEM_SEED_SIZE])
        self._sk_x = X25519PrivateKey.from_private_bytes(expanded[_MLKEM_SEED_SIZE:_EXPANDED_SIZE])
        self._pk_x = self._sk_x.public_key().public_bytes_raw()
        self.public_key: bytes = self._sk_m.public_key().public_bytes_raw() + self._pk_x

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate an X-Wing ciphertext; returns 32 bytes.

        ML-KEM-768 uses implicit rejection: a malformed or foreign ``ct_M`` yields a
        pseudorandom secret instead of an error, so callers must rely on the AEAD tag
        to detect a bad ciphertext.
        """
        check_ciphertext(ciphertext)
        ct_m = bytes(ciphertext[:_MLKEM_CT_SIZE])
        ct_x = bytes(ciphertext[_MLKEM_CT_SIZE:])
        ss_m = self._sk_m.decapsulate(ct_m)
        ss_x = self._sk_x.exchange(X25519PublicKey.from_public_bytes(ct_x))
        return _combiner(ss_m, ss_x, ct_x, self._pk_x)


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 1216-byte X-Wing public key from a 32-byte seed."""
    return DecapsulationKey(seed).public_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to an X-Wing public key.

    Returns ``(shared_secret, ciphertext)``: 32 bytes and 1120 bytes.
    """
    check_public_key(public_key)
    pk_m = bytes(public_key[:_MLKEM_PK_SIZE])
    pk_x = bytes(public_key[_MLKEM_PK_SIZE:])

    ek_x = X25519PrivateKey.generate()
    ct_x = ek_x.public_key().public_bytes_raw()
    ss_x = ek_x.exchange(X25519PublicKey.from_public_bytes(pk_x))

    # pyca returns (shared_secret[32], ciphertext[1088]).
    ss_m, ct_m = MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()

    ss = _combiner(ss_m, ss_x, ct_x, pk_x)
    return ss, ct_m + ct_x


def decapsulate(ciphertext: bytes, seed: bytes) -> bytes:
    """Decapsulate an X-Wing ciphertext with the 32-byte seed; returns 32 bytes.

    See :meth:`DecapsulationKey.decapsulate`; prefer holding a
    :class:`DecapsulationKey` when decapsulating repeatedly.
    """
    # Ciphertext length is checked before the (more expensive) key expansion.
    check_ciphertext(ciphertext)
    return DecapsulationKey(seed).decapsulate(ciphertext)
