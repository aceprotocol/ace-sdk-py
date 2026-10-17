"""Shared rules for signed JSON documents (descriptor, permit, delegation credential). Internal."""

from __future__ import annotations

from ._encoding import canonical_state_bytes, wire_int
from .errors import ACEError
from .kel import KelState, verify_operational_signature
from .limits import TIMESTAMP_WINDOW_SECONDS


def bad(message: str) -> ACEError:
    return ACEError("invalid_authorization", message)


def claims(document: dict) -> dict:
    return {k: v for k, v in document.items() if k != "signature"}


def check_lifetime(document: dict, now: int, maximum: int, *, allow_expired: bool = False) -> None:
    """``issuedAt <= now+300``, ``issuedAt < expiresAt <= issuedAt+maximum`` and, unless
    ``allow_expired``, ``now < expiresAt``."""
    issued, expires = document.get("issuedAt"), document.get("expiresAt")
    if (
        wire_int(issued) is None
        or wire_int(expires) is None
        or issued > now + TIMESTAMP_WINDOW_SECONDS
        or not issued < expires <= issued + maximum
    ):
        raise bad("invalid document lifetime")
    if not allow_expired and expires <= now:
        raise bad("document expired")


def verify_claims(state: KelState, action: str, document: dict, now: int) -> None:
    """``signature`` over ``canonical(claims)`` at ``issuedAt`` as an operational signature of
    ``state`` (01); ``stale_peer_binding`` passes through, anything else is
    ``invalid_authorization``."""
    issued = wire_int(document["issuedAt"])
    assert issued is not None  # check_lifetime ran first
    try:
        verify_operational_signature(
            state,
            document.get("signature"),
            canonical_state_bytes(claims(document)),
            action,
            issued,
            now,
            "invalid_authorization",
        )
    except ACEError as exc:
        if exc.code == "stale_peer_binding":
            raise
        raise bad(f"{action}: {exc.message}") from None
