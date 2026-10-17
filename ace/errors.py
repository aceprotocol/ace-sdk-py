"""The single ACE SDK exception type."""

from __future__ import annotations

import re
from typing import Literal

ACEErrorCategory = Literal["permanent", "transient", "local"]

ACEErrorCode = Literal[
    # permanent (06 § Error codes)
    "invalid_argument",
    "invalid_packet",
    "unsupported_version",
    "wrong_recipient",
    "invalid_signature",
    "invalid_authorization",
    "stale_timestamp",
    "stale_peer_binding",
    "decryption_failed",
    "unknown_prekey",
    "unsupported_schema",
    "invalid_body",
    "replay_horizon",
    "invalid_kel",
    "kel_conflict",
    "unknown_peer",
    "not_registered",
    "not_permitted",
    "relay_rejected",
    "blocked_address",
    "delivery_rejected",
    "expired",
    # profile-rule codes of the official commerce profile
    "transition_not_allowed",
    "wrong_role",
    "wrong_party",
    "bad_reference",
    "limit_exceeded",
    # transient
    "relay_unavailable",
    "relay_protocol_error",
    "fetch_failed",
    # local
    "storage_failed",
    "identity_unavailable",
    "lock_busy",
    "receiver_capacity",
    "thread_busy",
]

_TRANSIENT = frozenset({"relay_unavailable", "relay_protocol_error", "fetch_failed"})
_LOCAL = frozenset(
    {"storage_failed", "identity_unavailable", "lock_busy", "receiver_capacity", "thread_busy"}
)
#: Profile rules may raise further permanent codes matching the outcome-code grammar.
_CODE_RE = re.compile(r"[a-z0-9_]{1,64}")


def is_outcome_code(value: object) -> bool:
    """The outcome-code grammar ``[a-z0-9_]{1,64}``."""
    return isinstance(value, str) and _CODE_RE.fullmatch(value) is not None


class ACEError(Exception):
    """Every SDK-originated failure. ``category`` is a fixed function of ``code``."""

    def __init__(
        self,
        code: ACEErrorCode,
        message: str = "",
        *,
        status: int | None = None,
        relay_code: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        if not is_outcome_code(code):
            raise ValueError(f"invalid ACEError code: {code!r}")
        super().__init__(f"{code}: {message}" if message else code)
        self.code: ACEErrorCode = code
        self.message = message or code
        self.status = status
        self.relay_code = relay_code
        self.retry_after_seconds = retry_after_seconds

    @property
    def category(self) -> ACEErrorCategory:
        if self.code in _TRANSIENT:
            return "transient"
        if self.code in _LOCAL:
            return "local"
        return "permanent"

    @property
    def is_transient(self) -> bool:
        return self.category != "permanent"

    def __repr__(self) -> str:
        return f"ACEError({self.code!r}, {self.message!r})"
