"""The single ACE SDK exception type (06-security § SDK Error Codes)."""

from __future__ import annotations

from typing import Literal, get_args

ACEErrorCategory = Literal["permanent", "transient", "local"]

ACEErrorCode = Literal[
    # permanent
    "invalid_argument", "invalid_envelope", "unsupported_version", "wrong_recipient",
    "invalid_signature", "invalid_authorization", "scheme_mismatch", "stale_timestamp",
    "replay", "decryption_failed", "invalid_body", "transition_not_allowed", "wrong_role",
    "wrong_party", "bad_reference", "limit_exceeded", "invalid_key", "invalid_registration",
    "invalid_profile", "invalid_principal", "wrong_principal", "invalid_peer",
    "stale_peer_binding", "unknown_peer", "not_registered",
    "relay_rejected", "envelope_expired", "pending_send_conflict", "blocked_address",
    "direct_rejected", "delivery_rejected",
    # transient
    "relay_unavailable", "relay_protocol_error", "fetch_failed", "direct_unavailable",
    # local
    "storage_failed", "identity_unavailable", "handler_failed", "receiver_busy", "lock_busy",
]

_TRANSIENT = frozenset(
    {"relay_unavailable", "relay_protocol_error", "fetch_failed", "direct_unavailable"}
)
_LOCAL = frozenset(
    {"storage_failed", "identity_unavailable", "handler_failed", "receiver_busy", "lock_busy"}
)
_ALL_CODES = frozenset(get_args(ACEErrorCode))


def _category(code: str) -> ACEErrorCategory:
    if code in _TRANSIENT:
        return "transient"
    if code in _LOCAL:
        return "local"
    return "permanent"


class ACEError(Exception):
    """Every SDK-originated failure. ``category`` is a fixed function of ``code``."""

    def __init__(
        self,
        code: ACEErrorCode,
        message: str = "",
        *,
        status: int | None = None,
        relay_code: str | None = None,
        remote_code: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        if code not in _ALL_CODES:
            raise ValueError(f"unknown ACEError code: {code!r}")
        super().__init__(f"{code}: {message}" if message else code)
        self.code: ACEErrorCode = code
        self.message = message or code
        self.status = status
        self.relay_code = relay_code
        #: ``direct_rejected``: the receiver's ``error`` string (08-relay § Direct Delivery);
        #: ``delivery_rejected``: the Inbox code in the receiver's secure-delivery receipt (13).
        self.remote_code = remote_code
        self.retry_after_seconds = retry_after_seconds

    @property
    def category(self) -> ACEErrorCategory:
        return _category(self.code)

    @property
    def is_transient(self) -> bool:
        return self.category != "permanent"

    def __repr__(self) -> str:
        return f"ACEError({self.code!r}, {self.message!r})"
