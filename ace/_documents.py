"""Shared rules for signed JSON documents (descriptor, card record, permit, delegation credential).
Internal."""

from __future__ import annotations

from ._encoding import canonical_state_bytes, wire_int
from .errors import ACEError
from .kel import (
    KelState,
    check_signature_shape,
    is_usable,
    reconcile_kel,
    verify_kel,
    verify_operational_signature,
)
from .limits import TIMESTAMP_WINDOW_SECONDS


def bad(message: str) -> ACEError:
    return ACEError("invalid_authorization", message)


def claims(document: dict) -> dict:
    return {k: v for k, v in document.items() if k != "signature"}


def check_size(value: object, limit: int, what: str) -> None:
    """``canonical(value)`` is at most ``limit`` bytes."""
    try:
        n = len(canonical_state_bytes(value))
    except (TypeError, ValueError):
        raise bad(f"{what} is not JSON") from None
    if n > limit:
        raise bad(f"{what} exceeds {limit} bytes")


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


def verify_signed(
    kel: object, document: dict, action: str, now: int, pinned: KelState | None
) -> KelState:
    """The signature's shape (``invalid_authorization``, before any KEL work, 04 §
    Verification), the KEL usable at ``now`` (``invalid_kel`` / ``invalid_signature``) naming
    ``document["aceId"]``, reconciled with ``pinned`` when given, ``issuedAt`` not before the
    ``dlg`` of the current signing key (``stale_peer_binding``), and ``document`` signed under it
    (``verify_claims``). Returns the state it verified under."""
    check_signature_shape(document.get("signature"), "invalid_authorization")
    state = verify_kel(kel, now)
    if not is_usable(state, now):
        raise ACEError("invalid_kel", "identity has no live signing delegation")
    if state.ace_id != document["aceId"]:
        raise bad("aceId does not match the kel")
    if pinned is not None:
        state, _ = reconcile_kel(pinned, state)
    # Issued before its signing delegation: signed under another branch that delegated the same
    # key at the same seq (a recovered fork), never under this log.
    s = state.signing
    if s is not None and document["issuedAt"] < wire_int(state.events[s.seq]["ts"]):  # type: ignore[operator]
        raise ACEError("stale_peer_binding", f"{action} issued before its signing delegation")
    verify_claims(state, action, document, now)
    return state
