"""ACE Protocol identity: SoftwareIdentity implementation.

Security note on key material lifetime:
    SoftwareIdentity (Tier 0) stores private keys as Python objects in memory.
    Python does not provide deterministic memory zeroization — key bytes persist
    until garbage-collected and may be swapped to disk.  For production
    deployments handling high-value transactions, use Tier 1 (secure enclave /
    TPM) or Tier 2 (HSM) identity providers.
"""

from __future__ import annotations

import hashlib
import warnings
from typing import Any

import base58
from coincurve import PrivateKey as SecpPrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .types import (
    SigningScheme, IdentityTier, HardwareBacking, RegistrationFile, SigningConfig,
)
from ._utils import to_base64, from_base64, secp_pubkey_to_address

_VALID_SCHEMES: frozenset[str] = frozenset({"ed25519", "secp256k1"})


def compute_ace_id(signing_public_key_bytes: bytes) -> str:
    """Compute ACE ID from signing public key bytes."""
    h = hashlib.sha256(signing_public_key_bytes).hexdigest()
    return f"ace:sha256:{h}"


class SoftwareIdentity:
    """Software-based ACE identity (Tier 0)."""

    def __init__(
        self,
        scheme: SigningScheme,
        signing_private_key: bytes,
        encryption_private_key: X25519PrivateKey,
    ) -> None:
        if scheme not in _VALID_SCHEMES:
            raise ValueError(f"Unsupported signing scheme: '{scheme}' (expected one of {sorted(_VALID_SCHEMES)})")

        self._scheme = scheme
        self._signing_private_key = signing_private_key
        self._encryption_private_key = encryption_private_key

        # Derive public keys and address
        if scheme == "ed25519":
            ed_priv = Ed25519PrivateKey.from_private_bytes(signing_private_key)
            self._signing_public_key = ed_priv.public_key().public_bytes_raw()
            self._ed_private_key = ed_priv
            self._address = base58.b58encode(self._signing_public_key).decode("ascii")
        else:
            sk = SecpPrivateKey(signing_private_key)
            self._signing_public_key = sk.public_key.format(compressed=True)
            self._secp_private_key = sk
            uncompressed = sk.public_key.format(compressed=False)
            self._address = secp_pubkey_to_address(uncompressed)

        self._encryption_public_key = encryption_private_key.public_key().public_bytes_raw()
        self._ace_id = compute_ace_id(self._signing_public_key)

    @classmethod
    def generate(cls, scheme: SigningScheme) -> "SoftwareIdentity":
        """Generate a new random identity."""
        if scheme not in _VALID_SCHEMES:
            raise ValueError(f"Unsupported signing scheme: '{scheme}' (expected one of {sorted(_VALID_SCHEMES)})")

        encryption_private_key = X25519PrivateKey.generate()
        enc_pub = encryption_private_key.public_key().public_bytes_raw()

        if scheme == "ed25519":
            ed_priv = Ed25519PrivateKey.generate()
            signing_pub = ed_priv.public_key().public_bytes_raw()
            obj = cls.__new__(cls)
            obj._scheme = scheme
            obj._signing_private_key = ed_priv.private_bytes_raw()
            obj._encryption_private_key = encryption_private_key
            obj._ed_private_key = ed_priv
            obj._signing_public_key = signing_pub
            obj._address = base58.b58encode(signing_pub).decode("ascii")
            obj._encryption_public_key = enc_pub
            obj._ace_id = compute_ace_id(signing_pub)
            return obj
        else:
            sk = SecpPrivateKey()
            return cls(scheme, sk.secret, encryption_private_key)

    def get_encryption_public_key(self) -> bytes:
        return self._encryption_public_key

    def get_signing_public_key(self) -> bytes:
        return self._signing_public_key

    def get_encryption_private_key(self) -> X25519PrivateKey:
        """Internal — used by encryption module."""
        return self._encryption_private_key

    def sign(self, data: bytes) -> tuple[bytes, SigningScheme]:
        """Sign data and return (signature, scheme). Data must be pre-hashed (32 bytes)."""
        if self._scheme == "ed25519":
            signature = self._ed_private_key.sign(data)
            return signature, "ed25519"
        else:
            # coincurve: sign_recoverable returns 65 bytes (r[32] + s[32] + v[1])
            sig = self._secp_private_key.sign_recoverable(data, hasher=None)
            # coincurve format: r(32) + s(32) + recovery_id(1)
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:64], "big")
            v = sig[64]

            # Low-S normalization per spec
            order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if s > order // 2:
                s = order - s
                v ^= 1  # flip recovery id

            r_bytes = r.to_bytes(32, "big")
            s_bytes = s.to_bytes(32, "big")
            return r_bytes + s_bytes + bytes([v]), "secp256k1"

    def get_address(self) -> str:
        return self._address

    def get_signing_scheme(self) -> SigningScheme:
        return self._scheme

    def get_tier(self) -> IdentityTier:
        return 0

    def get_ace_id(self) -> str:
        return self._ace_id

    def decrypt_payload(self, ephemeral_pub_key: bytes, payload: bytes, conversation_id: str) -> bytes:
        """Decrypt an encrypted payload using this identity's private key."""
        from .encryption import decrypt
        return decrypt(ephemeral_pub_key, payload, self._encryption_private_key, conversation_id)

    def to_dict(self, *, include_private_keys: bool = False) -> dict[str, Any]:
        """Export identity for persistence.

        Args:
            include_private_keys: Must be explicitly set to ``True`` to include
                private key material in the output.  This guard prevents
                accidental leakage via logging or serialization.
        """
        if not include_private_keys:
            raise ValueError(
                "to_dict() requires include_private_keys=True to export "
                "private key material.  This guard prevents accidental leakage."
            )
        return {
            "scheme": self._scheme,
            "signingPrivateKey": to_base64(self._signing_private_key),
            "encryptionPrivateKey": to_base64(
                self._encryption_private_key.private_bytes_raw()
            ),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SoftwareIdentity":
        """Restore identity from exported dict."""
        scheme = d["scheme"]
        signing_priv = from_base64(d["signingPrivateKey"])
        enc_priv_bytes = from_base64(d["encryptionPrivateKey"])
        enc_priv = X25519PrivateKey.from_private_bytes(enc_priv_bytes)
        return cls(scheme, signing_priv, enc_priv)

    def to_registration_file(
        self,
        name: str,
        endpoint: str,
        description: str | None = None,
        hardware_backing: HardwareBacking | None = None,
        capabilities: list | None = None,
        settlement: list[str] | None = None,
        chains: list | None = None,
    ) -> RegistrationFile:
        """Generate a registration file for this identity."""
        signing_config = SigningConfig(
            scheme=self._scheme,
            address=self.get_address(),
            encryption_public_key=to_base64(self._encryption_public_key),
            signing_public_key=(
                to_base64(self._signing_public_key)
                if self._scheme == "secp256k1"
                else None
            ),
        )

        return RegistrationFile(
            ace="1.0",
            id=self.get_ace_id(),
            name=name,
            endpoint=endpoint,
            tier=self.get_tier(),
            signing=signing_config,
            hardware_backing=hardware_backing,
            description=description,
            capabilities=capabilities,
            settlement=settlement,
            chains=chains,
        )
