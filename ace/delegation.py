"""Optional ``ace:delegation:1`` profile (profiles/delegation.md): credentials by which an issuer
declares that a subject acts on its behalf, the descriptor extension that publishes them and the
message that hands one over.

A credential grants no execution, payment or communication right; the issuer revokes it by not
renewing. Descriptor verification checks the extension's shape only: a client that needs to know
whether ``subject`` acts for ``issuer`` pins the issuer (``NetworkClient.verify_delegation``) and
verifies the credential under that pin (``verify_delegation_credential``).

Install with ``Profiles([TEXT, DELEGATION])``; a ``NetworkClient`` with it installed runs
``delegation_rules`` itself.
"""

from __future__ import annotations

import copy

from ._documents import bad, check_lifetime, verify_claims
from ._encoding import is_ace_id, resolve_now, wire_int
from .errors import ACEError
from .identity import ACEIdentity, sign_claims
from .kel import KelState, check_signature_shape, tail_time
from .peers import PeerStore
from .rules import MessageEvent

DELEGATION_PROFILE_ID = "ace:delegation:1"
#: The hand-over message type; also the action credentials are signed with (02 § Signing actions).
DELEGATION_TYPE = "ace:delegation:1"
MAX_DELEGATION_CREDENTIALS = 4
MAX_DELEGATION_CREDENTIAL_LIFETIME = 604_800

_KEYS = {"issuer", "subject", "issuedAt", "expiresAt", "signature"}


def create_delegation_credential(
    identity: ACEIdentity,
    subject: str,
    *,
    now: int | None = None,
    ttl: int | None = None,
) -> dict:
    """A credential from ``identity`` (the issuer) declaring that ``subject`` acts on its behalf,
    issued at ``max(now, ts of the issuer's last KEL event)`` for ``ttl`` seconds (default and
    maximum 7 days)."""
    t = resolve_now(now)
    if not is_ace_id(subject) or subject == identity.get_ace_id():
        raise ACEError("invalid_argument", "subject must be another ACE ID")
    lifetime = MAX_DELEGATION_CREDENTIAL_LIFETIME if ttl is None else ttl
    if type(lifetime) is not int or not 0 < lifetime <= MAX_DELEGATION_CREDENTIAL_LIFETIME:
        raise ACEError(
            "invalid_argument", f"ttl must be in (0, {MAX_DELEGATION_CREDENTIAL_LIFETIME}]"
        )
    issued = tail_time(identity.get_kel(), t)
    claims = {
        "issuer": identity.get_ace_id(),
        "subject": subject,
        "issuedAt": issued,
        "expiresAt": issued + lifetime,
    }
    return sign_claims(identity, DELEGATION_TYPE, claims)


def check_credential(value: object, now: int) -> dict:
    """Internal. The closed credential and its field grammar: ACE IDs with ``issuer != subject``,
    ``issuedAt <= now + 300``, ``issuedAt < expiresAt <= issuedAt + 7 days``, a delegated
    signature's shape. No expiry, no signature check. ``invalid_authorization``."""
    if (
        type(value) is not dict
        or set(value) != _KEYS
        or not is_ace_id(value["issuer"])
        or not is_ace_id(value["subject"])
        or value["issuer"] == value["subject"]
    ):
        raise bad("credential must be {issuer, subject, issuedAt, expiresAt, signature}")
    check_lifetime(value, now, MAX_DELEGATION_CREDENTIAL_LIFETIME, allow_expired=True)
    check_signature_shape(value["signature"], "invalid_authorization")
    return value


def validate_delegation_ext(value: object, subject: str, now: int) -> list[dict]:
    """Descriptor ``ext["ace:delegation:1"]``: the closed ``{credentials}`` with 1-4 credentials
    of distinct issuers, each naming ``subject`` (the descriptor's ``aceId``). Shape only: no
    expiry and no signature (``invalid_authorization``)."""
    if type(value) is not dict or set(value) != {"credentials"}:
        raise bad("delegation ext must be {credentials}")
    items = value["credentials"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_DELEGATION_CREDENTIALS:
        raise bad(f"delegation ext must hold 1-{MAX_DELEGATION_CREDENTIALS} credentials")
    for c in items:
        check_credential(c, now)
        if c["subject"] != subject:
            raise bad("a delegation credential must name the descriptor's aceId")
    if len({c["issuer"] for c in items}) != len(items):
        raise bad("delegation credential issuers must be distinct")
    return copy.deepcopy(items)


def verify_delegation_credential(value: object, issuer: KelState, now: int) -> dict:
    """A copy of ``value`` if it is a live credential of ``issuer`` (the issuer's pinned KEL
    state): its shape, ``now < expiresAt`` and an operational signature of ``issuer`` with action
    ``ace:delegation:1``. ``stale_peer_binding`` from the signature check passes through; any
    other failure is ``invalid_authorization``."""
    c = check_credential(value, now)
    if c["issuer"] != issuer.ace_id:
        raise bad("the credential names another issuer")
    if wire_int(c["expiresAt"]) <= now:  # type: ignore[operator]
        raise bad("credential expired")
    verify_claims(issuer, DELEGATION_TYPE, c, now)
    return copy.deepcopy(c)


class DelegationRules:
    """``ProfileRules`` for the ``ace:delegation:1`` message: the issuer hands a credential to its
    subject. ``check`` requires the credential to be the sender's, about the recipient and live
    (on receive also signed under the sender's pin); any failure is ``invalid_body``. ``commit``
    changes no state: the application stores the credential and publishes it in its ``ext``."""

    types = frozenset({DELEGATION_TYPE})

    def __init__(self, peers: PeerStore) -> None:
        self.peers = peers

    def check(self, event: MessageEvent, body: dict) -> None:
        now = self.peers._now()
        try:
            c = check_credential(body.get("credential"), now)
            if c["issuer"] != event.from_id or c["subject"] != event.to_id:
                raise bad("the credential must be from the sender about the recipient")
            if c["expiresAt"] <= now:
                raise bad("credential expired")
            if event.direction == "receive":
                pinned = self.peers.state(event.from_id)
                if pinned is None:
                    raise bad("the sender is not pinned")
                verify_delegation_credential(c, pinned, now)
        except ACEError as exc:
            if exc.code == "storage_failed":
                raise
            raise ACEError("invalid_body", f"delegation: {exc.message}") from None

    def commit(self, event: MessageEvent, body: dict) -> None:
        return None


def delegation_rules(peers: PeerStore) -> DelegationRules:
    """The ``ace:delegation:1`` message rule; ``peers`` supplies the sender's pin and the clock."""
    return DelegationRules(peers)
