"""SoftwareIdentity (Tier 0): keys held in process memory.

Python cannot zeroize memory; key bytes live until garbage-collected. Use a hardware
identity (Secure Enclave, TPM, HSM) for high-value deployments.
"""

from __future__ import annotations

import hashlib
import os

import base58
from coincurve import PrivateKey as SecpPrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import _xwing
from ._encoding import decode_b64, eip55, keccak256, to_base64
from .encryption import decrypt_with_key
from .errors import ACEError
from .limits import KEM_SEED_SIZE
from .types import (
    SIGNING_SCHEMES,
    SigningScheme,
    SoftwareIdentityExport,
)


def compute_ace_id(signing_public_key: bytes) -> str:
    """``ace:sha256:hex(SHA-256(signingPublicKey))``."""
    return "ace:sha256:" + hashlib.sha256(bytes(signing_public_key)).hexdigest()


def signing_address(scheme: str, signing_public_key: bytes) -> str:
    """ed25519: Base58 of the key. secp256k1: EIP-55 address of the compressed key."""
    if scheme == "ed25519":
        return base58.b58encode(bytes(signing_public_key)).decode("ascii")
    from coincurve import PublicKey

    uncompressed = PublicKey(bytes(signing_public_key)).format(compressed=False)
    return eip55(keccak256(uncompressed[1:])[-20:].hex())


class SoftwareIdentity:
    """Software ACE identity. Caches its expanded X-Wing key in memory (never persisted)."""

    def __init__(
        self, scheme: SigningScheme, signing_private_key: bytes, encryption_seed: bytes
    ) -> None:
        if scheme not in SIGNING_SCHEMES:
            raise ACEError("invalid_argument", f"unsupported signing scheme {str(scheme)[:32]!r}")
        if (
            not isinstance(signing_private_key, (bytes, bytearray))
            or len(signing_private_key) != 32
        ):
            raise ACEError("invalid_key", "signing private key must be 32 bytes")
        if (
            not isinstance(encryption_seed, (bytes, bytearray))
            or len(encryption_seed) != KEM_SEED_SIZE
        ):
            raise ACEError("invalid_key", f"encryption seed must be {KEM_SEED_SIZE} bytes")
        self._scheme: SigningScheme = scheme
        self._signing_private_key = bytes(signing_private_key)
        self._encryption_seed = bytes(encryption_seed)
        self._decapsulation_key = _xwing.DecapsulationKey(self._encryption_seed)
        if scheme == "ed25519":
            self._ed = Ed25519PrivateKey.from_private_bytes(self._signing_private_key)
            self._signing_public_key = self._ed.public_key().public_bytes_raw()
        else:
            try:
                self._secp = SecpPrivateKey(self._signing_private_key)
            except Exception:
                raise ACEError("invalid_key", "secp256k1 private key out of range") from None
            self._signing_public_key = self._secp.public_key.format(compressed=True)
        self._encryption_public_key = self._decapsulation_key.public_key
        self._ace_id = compute_ace_id(self._signing_public_key)

    @classmethod
    def generate(cls, scheme: SigningScheme) -> "SoftwareIdentity":
        if scheme == "ed25519":
            signing = Ed25519PrivateKey.generate().private_bytes_raw()
        elif scheme == "secp256k1":
            signing = SecpPrivateKey().secret
        else:
            raise ACEError("invalid_argument", f"unsupported signing scheme {str(scheme)[:32]!r}")
        return cls(scheme, signing, os.urandom(KEM_SEED_SIZE))

    # --- ACEIdentity ---

    def get_ace_id(self) -> str:
        return self._ace_id

    def get_signing_scheme(self) -> SigningScheme:
        return self._scheme

    def get_signing_public_key(self) -> bytes:
        return self._signing_public_key

    def get_encryption_public_key(self) -> bytes:
        return self._encryption_public_key

    def sign(self, data: bytes) -> bytes:
        """Sign a 32-byte signData digest. secp256k1 returns r||s||v (low-S, v in {0,1})."""
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ACEError("invalid_argument", "signData must be 32 bytes")
        if self._scheme == "ed25519":
            return self._ed.sign(bytes(data))
        return self._secp.sign_recoverable(bytes(data), hasher=None)

    def decrypt(self, kem_ciphertext: bytes, payload: bytes, conversation_id: str) -> bytes:
        return decrypt_with_key(self._decapsulation_key, kem_ciphertext, payload, conversation_id)

    # --- convenience ---

    def get_address(self) -> str:
        return signing_address(self._scheme, self._signing_public_key)

    def export_private_key(self) -> SoftwareIdentityExport:
        return {
            "scheme": self._scheme,
            "signingPrivateKey": to_base64(self._signing_private_key),
            "encryptionPrivateKey": to_base64(self._encryption_seed),
        }

    @classmethod
    def from_export(cls, data: SoftwareIdentityExport) -> "SoftwareIdentity":
        if not isinstance(data, dict):
            raise ACEError("invalid_argument", "export must be a dict")
        return cls(
            data.get("scheme"),  # type: ignore[arg-type]
            decode_b64(data.get("signingPrivateKey"), "invalid_key", "signingPrivateKey"),
            decode_b64(data.get("encryptionPrivateKey"), "invalid_key", "encryptionPrivateKey"),
        )
