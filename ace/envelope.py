"""Envelope decoding (04 "Envelope decoding"), signature check and fingerprint."""

from __future__ import annotations

import hashlib

from . import _xwing
from ._encoding import (
    canonical_json,
    decode_b64,
    decode_signature,
    is_ace_id,
    is_conversation_id,
    is_message_id,
    wire_int,
)
from ._signing import build_sign_data, encode_payload, verify_signature
from .errors import ACEError
from .limits import MAX_PAYLOAD_BYTES
from .types import (
    SIGNING_SCHEMES,
    ACEMessage,
    EncryptionEnvelope,
    SignatureEnvelope,
    SigningScheme,
)

_MIN_PAYLOAD_BYTES = 28


def _bad(msg: str) -> ACEError:
    return ACEError("invalid_envelope", msg)


def decode_kem_ciphertext(text: object) -> bytes:
    raw = decode_b64(text, "invalid_envelope", "encryption.kemCiphertext")
    try:
        _xwing.check_ciphertext(raw)
    except ACEError as exc:
        raise _bad(exc.message) from None
    return raw


def decode_payload(text: object) -> bytes:
    raw = decode_b64(text, "invalid_envelope", "encryption.payload", max_bytes=MAX_PAYLOAD_BYTES)
    if not _MIN_PAYLOAD_BYTES <= len(raw) <= MAX_PAYLOAD_BYTES:
        raise _bad(f"encryption.payload must be {_MIN_PAYLOAD_BYTES}..{MAX_PAYLOAD_BYTES} bytes")
    return raw


def decode_envelope(obj: object) -> ACEMessage:
    """Apply the 04 decoding rules exactly; ``invalid_envelope`` or ``unsupported_version``.

    Unknown fields at any level are ignored.
    """
    if not isinstance(obj, dict):
        raise _bad("envelope must be a JSON object")
    ace = obj.get("ace")
    if not isinstance(ace, str):
        raise _bad("ace must be a string")
    if ace != "2.0":
        raise ACEError("unsupported_version", f"unsupported ACE version {ace[:16]!r}")
    message_id = obj.get("messageId")
    if not is_message_id(message_id):
        raise _bad("messageId must be a lowercase UUIDv4")
    from_id, to_id = obj.get("from"), obj.get("to")
    if not is_ace_id(from_id) or not is_ace_id(to_id):
        raise _bad("from/to must be ACE IDs")
    conversation_id = obj.get("conversationId")
    if not is_conversation_id(conversation_id):
        raise _bad("conversationId must be 64 lowercase hex characters")
    if any(k in obj for k in ("type", "threadId", "body", "schemaDigest")):
        raise _bad("application fields must be encrypted")
    timestamp = wire_int(obj.get("timestamp"))
    if timestamp is None:
        raise _bad("timestamp must be an integer in [0, 2^53-1]")
    enc = obj.get("encryption")
    if not isinstance(enc, dict):
        raise _bad("encryption must be an object")
    kem_text, payload_text = enc.get("kemCiphertext"), enc.get("payload")
    decode_kem_ciphertext(kem_text)
    decode_payload(payload_text)
    sig = obj.get("signature")
    if not isinstance(sig, dict):
        raise _bad("signature must be an object")
    scheme = sig.get("scheme")
    if scheme not in SIGNING_SCHEMES:
        raise _bad("unsupported signature scheme")
    decode_signature(sig.get("value"), scheme, "invalid_envelope")
    return ACEMessage(
        ace=ace,
        message_id=message_id,  # type: ignore[arg-type]
        from_id=from_id,  # type: ignore[arg-type]
        to_id=to_id,  # type: ignore[arg-type]
        conversation_id=conversation_id,  # type: ignore[arg-type]
        timestamp=timestamp,
        encryption=EncryptionEnvelope(kem_ciphertext=kem_text, payload=payload_text),  # type: ignore[arg-type]
        signature=SignatureEnvelope(scheme=scheme, value=sig["value"]),  # type: ignore[arg-type]
    )


def revalidate(env: object) -> ACEMessage:
    """Re-run the decoding rules on an ``ACEMessage`` built by the caller."""
    if not isinstance(env, ACEMessage):
        raise ACEError("invalid_argument", "expected an ACEMessage (use decode_envelope)")
    return decode_envelope(env.to_dict())


def message_sign_data(env: ACEMessage) -> bytes:
    payload = encode_payload(
        env.to_id,
        env.conversation_id,
        env.message_id,
        decode_kem_ciphertext(env.encryption.kem_ciphertext),
        decode_payload(env.encryption.payload),
    )
    return build_sign_data("packet", env.from_id, env.timestamp, payload)


def verify_envelope_signature(
    env: ACEMessage, *, scheme: SigningScheme, signing_public_key: bytes
) -> None:
    """Signature-only check against a known signer.

    ``scheme_mismatch`` if the envelope scheme differs; ``invalid_signature`` otherwise.
    """
    env = revalidate(env)
    if env.signature.scheme != scheme:
        raise ACEError("scheme_mismatch", "envelope signature scheme differs from the signer's")
    sig = decode_signature(env.signature.value, scheme, "invalid_envelope")
    if not verify_signature(message_sign_data(env), sig, scheme, signing_public_key):
        raise ACEError("invalid_signature", "message signature does not verify")


def envelope_fingerprint(env: ACEMessage) -> str:
    """Lowercase hex SHA-256 of the RFC 8785 JSON of the 10 known envelope fields."""
    if not isinstance(env, ACEMessage):
        raise ACEError("invalid_argument", "expected an ACEMessage")
    return hashlib.sha256(canonical_json(env.to_dict()).encode("utf-8")).hexdigest()
