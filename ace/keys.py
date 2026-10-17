"""Key providers: where a signing key lives and how it signs. Software provider only here."""

from __future__ import annotations

import hashlib
import os
from typing import Literal, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import mldsa

from ._signing import SCHEME, SEED_SIZE
from .errors import ACEError

#: The only scheme (02 § Signatures): roots and signing keys.
SigningScheme = Literal["ml-dsa-65"]


@runtime_checkable
class KeyProvider(Protocol):
    """A signing key. Hardware providers (Secure Enclave, Keystore, TPM) implement this."""

    scheme: SigningScheme

    def public_key(self) -> bytes: ...

    def sign(self, message: bytes, action: str) -> bytes: ...


def key_digest(scheme: str, public_key: bytes) -> bytes:
    """``SHA-256(scheme || 0x00 || publicKey)``: the pre-rotation commitment of a key."""
    return hashlib.sha256(scheme.encode("utf-8") + b"\x00" + bytes(public_key)).digest()


class SoftwareKey:
    """An ML-DSA-65 key expanded from a 32-byte seed, held in process memory."""

    scheme: SigningScheme = SCHEME

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_SIZE:
            raise ACEError("invalid_argument", f"seed must be {SEED_SIZE} bytes")
        self.seed = bytes(seed)
        self._key = mldsa.MLDSA65PrivateKey.from_seed_bytes(self.seed)
        self._public = self._key.public_key().public_bytes_raw()

    def public_key(self) -> bytes:
        return self._public

    def sign(self, message: bytes, action: str) -> bytes:
        """Hedged ML-DSA-65 over ``message`` (the full ``M``) with ctx = UTF-8(action)."""
        if not isinstance(message, (bytes, bytearray)):
            raise ACEError("invalid_argument", "message must be bytes")
        if not isinstance(action, str) or len(action.encode("utf-8")) > 255:
            raise ACEError("invalid_argument", "action must be a string of at most 255 UTF-8 bytes")
        return self._key.sign(bytes(message), context=action.encode("utf-8"))


def generate_software_key() -> SoftwareKey:
    return SoftwareKey(os.urandom(SEED_SIZE))
