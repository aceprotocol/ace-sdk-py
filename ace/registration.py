"""Relay registration (``POST /v1/register``): identity-only authorization over the KEL head."""

from __future__ import annotations

from ._encoding import resolve_now
from ._relay_url import normalize_relay_url
from ._signing import encode_payload
from .identity import ACEIdentity, sign_operational
from .kel import tail_time, verify_kel


def create_registration_request(
    identity: ACEIdentity, timestamp: int | None = None, *, audience: str
) -> dict:
    """``{aceId, kel, timestamp, audience, signature}`` signed with action ``register-request``
    over ``encodePayload(lastHashHex, audience)`` at ``max(timestamp, ts of the KEL's last
    event)``; ``audience`` is the canonical URL of the relay
    it is meant for (07 § Registration)."""
    kel = identity.get_kel()
    ts = tail_time(kel, resolve_now(timestamp, "timestamp"))
    aud = normalize_relay_url(audience)
    last_hash = verify_kel(kel, ts).last_hash
    return {
        "aceId": identity.get_ace_id(),
        "kel": kel,
        "timestamp": ts,
        "audience": aud,
        "signature": sign_operational(
            identity, ts, encode_payload(last_hash, aud), "register-request"
        ),
    }
