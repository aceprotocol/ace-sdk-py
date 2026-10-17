"""Delivery permits: the receiver (issuer) lets ``subject`` deliver to it and resolve its private
descriptor, for at most 30 days. A permit is communication permission only."""

from __future__ import annotations

import copy

from ._documents import bad, check_lifetime, verify_claims
from ._encoding import is_ace_id, resolve_now
from .identity import ACEIdentity, sign_claims
from .kel import KelState
from .limits import MAX_PERMIT_LIFETIME

_KEYS = {"issuer", "subject", "issuedAt", "expiresAt", "signature"}


def create_permit(
    identity: ACEIdentity,
    subject: str,
    *,
    now: int | None = None,
    lifetime: int = MAX_PERMIT_LIFETIME,
) -> dict:
    """A permit from ``identity`` to ``subject`` valid for ``lifetime`` seconds (<= 30 days)."""
    t = resolve_now(now)
    if not is_ace_id(subject) or subject == identity.get_ace_id():
        raise bad("invalid permit subject")
    if type(lifetime) is not int or not 0 < lifetime <= MAX_PERMIT_LIFETIME:
        raise bad("permit lifetime must be in (0, 2592000]")
    claims = {
        "issuer": identity.get_ace_id(),
        "subject": subject,
        "issuedAt": t,
        "expiresAt": t + lifetime,
    }
    return sign_claims(identity, "delivery-permit", claims)


def verify_permit(value: object, issuer: KelState, subject: str, *, now: int) -> dict:
    """A copy of ``value`` if it is a live permit from ``issuer`` (the issuer's current KEL
    state, usable at ``now``) to ``subject``; ``invalid_authorization`` or
    ``stale_peer_binding`` otherwise."""
    if (
        type(value) is not dict
        or set(value) != _KEYS
        or value["issuer"] != issuer.ace_id
        or value["subject"] != subject
        or not is_ace_id(subject)
        or subject == issuer.ace_id
    ):
        raise bad("invalid permit binding")
    check_lifetime(value, now, MAX_PERMIT_LIFETIME)
    verify_claims(issuer, "delivery-permit", value, now)
    return copy.deepcopy(value)
