"""Relay request authentication headers (07 § Authentication). Relay-side verification is the
relay's job (the TypeScript SDK provides it)."""

from __future__ import annotations

import secrets

from ._encoding import check_wire_int, is_sha256_hex, to_base64
from ._relay_url import is_canonical_relay_url
from ._signing import encode_payload, signing_message
from .errors import ACEError
from .identity import ACEIdentity, check_usable

#: The header-authenticated actions (02 § Signing actions).
AUTH_ACTIONS = frozenset({"listen", "inbox", "inbox-ack", "block", "unregister"})


def create_auth_headers(
    identity: ACEIdentity,
    action: str,
    payload: bytes,
    timestamp: int,
    *,
    audience: str,
    nonce: str | None = None,
) -> dict[str, str]:
    """The six ``X-ACE-*`` headers for ``action`` with its ``actionPayload`` (02 § Signing
    actions): the signature is over ``M(aceId, timestamp, seq, encodePayload(audience, nonce,
    actionPayload))`` with ctx = action. ``nonce`` is fresh for every HTTP attempt."""
    if action not in AUTH_ACTIONS or not isinstance(payload, (bytes, bytearray)):
        raise ACEError("invalid_argument", "unknown auth action or payload")
    check_wire_int(timestamp, "timestamp")
    nonce = secrets.token_hex(32) if nonce is None else nonce
    # The audience is a relay's own configured URL: loopback HTTP is its development setup.
    if not is_canonical_relay_url(audience, allow_loopback=True):
        raise ACEError("invalid_argument", "audience must be a canonical relay URL")
    if not is_sha256_hex(nonce):
        raise ACEError("invalid_argument", "nonce must be 32 random bytes in lowercase hex")
    seq = check_usable(identity, timestamp).signing.seq  # type: ignore[union-attr]
    ace_id = identity.get_ace_id()
    message = signing_message(ace_id, timestamp, seq, encode_payload(audience, nonce, payload))
    return {
        "X-ACE-Audience": audience,
        "X-ACE-Nonce": nonce,
        "X-ACE-Id": ace_id,
        "X-ACE-Timestamp": str(timestamp),
        "X-ACE-Seq": str(seq),
        "X-ACE-Signature": to_base64(identity.sign(message, action)),
    }
