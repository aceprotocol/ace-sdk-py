"""signData construction and strict ed25519 / secp256k1 verification. Internal."""

from __future__ import annotations

import hashlib
import hmac
import struct

from coincurve import PublicKey as SecpPublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._encoding import MAX_SAFE_INTEGER
from .errors import ACEError

_DOMAIN_PREFIX = b"ace.v1"

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2
ED25519_L = 2**252 + 27742317777372353535851937790883648493

_SMALL_ORDER = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
))


def _prefix(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def encode_payload(*fields: str | bytes) -> bytes:
    """``len(4 BE) || bytes`` per field; strings are UTF-8."""
    return b"".join(_prefix(f.encode("utf-8") if isinstance(f, str) else bytes(f)) for f in fields)


def build_sign_data(action: str, ace_id: str, timestamp: int, payload: bytes = b"") -> bytes:
    """SHA-256("ace.v1" || lp(action) || lp(aceId) || ts[8 BE] || lp(payload))."""
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or not 0 <= timestamp <= MAX_SAFE_INTEGER:
        raise ACEError("invalid_argument", "timestamp must be an integer in [0, 2^53-1]")
    return hashlib.sha256(
        _DOMAIN_PREFIX + _prefix(action.encode("utf-8")) + _prefix(ace_id.encode("utf-8"))
        + struct.pack(">Q", timestamp) + _prefix(payload)
    ).digest()


def is_valid_signing_public_key(scheme: str, key: bytes) -> bool:
    """ed25519: 32 bytes. secp256k1: a 33-byte compressed point on the curve."""
    if not isinstance(key, (bytes, bytearray)):
        return False
    if scheme == "ed25519":
        return len(key) == 32
    if scheme == "secp256k1":
        if len(key) != 33 or key[0] not in (2, 3):
            return False
        try:
            SecpPublicKey(bytes(key))
        except Exception:
            return False
        return True
    return False


def _ed25519_point_ok(enc: bytes) -> bool:
    b = bytearray(enc)
    b[31] &= 0x7F
    if b[31] == 0x7F and all(x == 0xFF for x in b[1:31]) and b[0] >= 0xED:
        return False  # non-canonical y >= p
    return bytes(b) not in _SMALL_ORDER


def verify_ed25519(sign_data: bytes, sig: bytes, public_key: bytes) -> bool:
    if len(sig) != 64 or len(public_key) != 32:
        return False
    if int.from_bytes(sig[32:], "little") >= ED25519_L:
        return False
    if not _ed25519_point_ok(public_key) or not _ed25519_point_ok(sig[:32]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(sig), bytes(sign_data))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_secp256k1(sign_data: bytes, sig: bytes, public_key: bytes) -> bool:
    if len(sig) != 65 or len(sign_data) != 32 or not is_valid_signing_public_key("secp256k1", public_key):
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    if v not in (0, 1) or not 1 <= r < SECP256K1_N or not 1 <= s <= SECP256K1_HALF_N:
        return False
    try:
        recovered = SecpPublicKey.from_signature_and_message(bytes(sig), bytes(sign_data), hasher=None)
    except Exception:
        return False
    return hmac.compare_digest(recovered.format(compressed=True), bytes(public_key))


def verify_signature(sign_data: bytes, sig: bytes, scheme: str, public_key: bytes) -> bool:
    if scheme == "ed25519":
        return verify_ed25519(sign_data, sig, public_key)
    if scheme == "secp256k1":
        return verify_secp256k1(sign_data, sig, public_key)
    return False
