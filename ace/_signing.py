"""The signed message ``M`` and ML-DSA-65 verification (02 § Signatures). Internal."""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

from ._encoding import check_wire_int

DOMAIN = "ace.v1"
SCHEME = "ml-dsa-65"
SEED_SIZE = 32
PUBLIC_KEY_SIZE = 1952
SIGNATURE_SIZE = 3309


def encode_payload(*fields: str | bytes) -> bytes:
    """``len(4 BE) || bytes`` per field; strings are UTF-8."""
    out = []
    for f in fields:
        raw = f.encode("utf-8") if isinstance(f, str) else bytes(f)
        out.append(struct.pack(">I", len(raw)) + raw)
    return b"".join(out)


def signing_message(ace_id: str, timestamp: int, seq: int | None, payload: bytes) -> bytes:
    """``M = encodePayload("ace.v1", aceId, decimal(timestamp), seqOrEmpty, payload)``:
    ``seq`` is None for a KEL event signature, else the signing delegation's ``seq``."""
    check_wire_int(timestamp, "timestamp")
    return encode_payload(
        DOMAIN,
        ace_id,
        str(timestamp),
        "" if seq is None else str(check_wire_int(seq, "seq")),
        payload,
    )


def is_signing_key(scheme: object, key: object) -> bool:
    return scheme == SCHEME and isinstance(key, (bytes, bytearray)) and len(key) == PUBLIC_KEY_SIZE


def verify_signature(message: bytes, action: str, sig: bytes, public_key: bytes) -> bool:
    """ML-DSA-65 verify of ``message`` with ctx = UTF-8(action). Malformed input is ``False``."""
    if not (
        isinstance(message, (bytes, bytearray))
        and isinstance(action, str)
        and isinstance(sig, (bytes, bytearray))
        and len(sig) == SIGNATURE_SIZE
        and is_signing_key(SCHEME, public_key)
    ):
        return False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(sig), bytes(message), context=action.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
