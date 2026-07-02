"""ACE Protocol signing: ed25519 + secp256k1 sign/verify + signData construction."""

from __future__ import annotations

import hashlib
import hmac
import struct

from coincurve import PublicKey as SecpPublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .types import SigningScheme
from ._utils import to_base64, from_base64

# Maximum valid Unix timestamp: 2^53 - 1 (safe integer range)
_MAX_TIMESTAMP = (1 << 53) - 1

# Unified domain prefix for all sign-data contexts
_DOMAIN_PREFIX = b"ace.v1"

# secp256k1 curve order N and N/2 — used to enforce canonical low-S signatures.
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_HALF_ORDER = _SECP256K1_ORDER // 2


def _length_prefix(data: bytes) -> bytes:
    """4-byte big-endian length prefix."""
    return struct.pack(">I", len(data)) + data


def encode_payload(*fields: str | bytes) -> bytes:
    """Encode multiple fields into a single payload blob.

    Each field is length-prefixed: [len(4 BE)] || data.
    String fields are UTF-8 encoded before length-prefixing.
    """
    chunks: list[bytes] = []
    for f in fields:
        if isinstance(f, str):
            chunks.append(_length_prefix(f.encode("utf-8")))
        else:
            chunks.append(_length_prefix(f))
    return b"".join(chunks)


def build_sign_data(
    action: str,
    ace_id: str,
    timestamp: int,
    payload: bytes = b"",
) -> bytes:
    """Build the unified signData hash.

    Format: SHA-256("ace.v1" || len(action) || action || len(ace_id) || ace_id
                    || timestamp[8 BE] || len(payload) || payload)
    """
    if not isinstance(timestamp, int) or timestamp < 0 or timestamp > _MAX_TIMESTAMP:
        raise ValueError(f"Timestamp must be an integer in range [0, {_MAX_TIMESTAMP}], got {timestamp!r}")
    chunks: list[bytes] = [_DOMAIN_PREFIX]
    chunks.append(_length_prefix(action.encode("utf-8")))
    chunks.append(_length_prefix(ace_id.encode("utf-8")))
    chunks.append(struct.pack(">Q", timestamp))
    chunks.append(_length_prefix(payload))
    return hashlib.sha256(b"".join(chunks)).digest()


def verify_signature(
    sign_data: bytes,
    signature: bytes,
    scheme: SigningScheme,
    signing_public_key: bytes,
) -> bool:
    """Verify a signature against signData.

    For ed25519: direct verification with public key.
    For secp256k1: recover public key from signature and compare against expected key.
    """
    if scheme == "ed25519":
        try:
            pub_key = Ed25519PublicKey.from_public_bytes(signing_public_key)
            pub_key.verify(signature, sign_data)
            return True
        except (InvalidSignature, ValueError):
            return False
    elif scheme == "secp256k1":
        if len(signature) != 65:
            return False

        # Extract r, s, v from 65-byte signature
        compact = signature[:64]
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:64], "big")
        v = signature[64]

        # Reject out-of-range and non-canonical (high-S) signatures. ECDSA is
        # malleable: (r, s) and (r, n - s) recover the same key, so accepting
        # high-S lets an observer re-mint a valid signature with different bytes
        # and slip past signature-keyed replay protection. Requiring low-S makes
        # the signature bytes canonical (matches how all ACE SDKs sign).
        if v not in (0, 1):
            return False
        if r < 1 or r >= _SECP256K1_ORDER:
            return False
        if s < 1 or s > _SECP256K1_HALF_ORDER:
            return False

        # Recover public key using coincurve
        try:
            recoverable_sig = compact + bytes([v])
            recovered = SecpPublicKey.from_signature_and_message(
                recoverable_sig, sign_data, hasher=None
            )
            recovered_compressed = recovered.format(compressed=True)

            # Constant-time comparison to prevent timing side-channels
            return hmac.compare_digest(recovered_compressed, signing_public_key)
        except (ValueError, TypeError):
            return False
    else:
        raise ValueError(f"Unsupported signing scheme: '{scheme}'")


def encode_signature(signature: bytes, scheme: SigningScheme) -> str:
    """Encode a signature to its wire format."""
    if scheme == "ed25519":
        return to_base64(signature)
    else:
        return "0x" + signature.hex()


def decode_signature(encoded: str, scheme: SigningScheme) -> bytes:
    """Decode a signature from its wire format."""
    if scheme == "ed25519":
        sig = from_base64(encoded)
        if len(sig) != 64:
            raise ValueError(f"Invalid ed25519 signature length: expected 64 bytes, got {len(sig)}")
        return sig
    else:
        hex_str = encoded[2:] if encoded.startswith("0x") else encoded
        try:
            sig = bytes.fromhex(hex_str)
        except ValueError:
            raise ValueError("Invalid secp256k1 signature: not valid hex")
        if len(sig) != 65:
            raise ValueError(f"Invalid secp256k1 signature length: expected 65 bytes, got {len(sig)}")
        return sig
