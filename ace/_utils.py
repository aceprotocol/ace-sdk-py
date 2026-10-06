"""ACE Protocol shared utilities."""

from __future__ import annotations

import base64
import binascii
import re

from Crypto.Hash import keccak as keccak_mod

__all__ = ["keccak256", "to_base64", "from_base64", "secp_pubkey_to_address", "eip55_checksum", "CONTROL_CHAR_RE"]

CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')


def keccak256(data: bytes) -> bytes:
    k = keccak_mod.new(digest_bits=256)
    k.update(data)
    return k.digest()


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_base64(s: str, *, max_len: int | None = None, what: str = "Base64 value") -> bytes:
    """Strictly decode Base64.

    With ``max_len``, ``s`` must be a ``str`` and anything longer than the padded
    encoding of ``max_len`` bytes is refused before decoding (DoS guard).
    """
    if max_len is not None:
        if not isinstance(s, str):
            raise ValueError(f"{what} must be a Base64 string")
        max_encoded = 4 * ((max_len + 2) // 3)
        if len(s) > max_encoded:
            raise ValueError(f"{what} too large: {len(s)} Base64 chars exceeds max {max_encoded}")
    try:
        raw = base64.b64decode(s, validate=True)
    except binascii.Error as exc:
        raise ValueError("Invalid Base64 input") from exc
    if max_len is not None and len(raw) > max_len:
        raise ValueError(f"{what} too large: {len(raw)} bytes exceeds max {max_len}")
    return raw


def eip55_checksum(address: str) -> str:
    """Apply EIP-55 mixed-case checksum to an Ethereum address."""
    addr = address.lower().removeprefix("0x")
    addr_hash = keccak256(addr.encode("ascii")).hex()
    return "0x" + "".join(
        c.upper() if int(addr_hash[i], 16) >= 8 else c
        for i, c in enumerate(addr)
    )


def secp_pubkey_to_address(uncompressed_pubkey: bytes) -> str:
    """Derive EIP-55 checksummed Ethereum address from uncompressed secp256k1 public key.

    Args:
        uncompressed_pubkey: 65-byte uncompressed public key starting with 0x04.
    """
    if len(uncompressed_pubkey) != 65 or uncompressed_pubkey[0] != 0x04:
        raise ValueError("Expected 65-byte uncompressed public key with 0x04 prefix")
    h = keccak256(uncompressed_pubkey[1:])
    return eip55_checksum("0x" + h[-20:].hex())
