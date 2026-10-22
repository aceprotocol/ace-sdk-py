"""The card record (04 § Card record): an agent's durable identity facts.

Its set-once handle, card, payment accounts, whether strangers may request contact and whether it
is listed, published as the closed CardBundle ``{kel, card}`` and signed with action
``card-record`` over ``canonicalStateBytes(claims)`` (claims: the record without ``signature``).
It has no expiry.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Literal, TypedDict
from urllib.parse import urlsplit

from ._documents import bad, check_size, verify_signed
from ._encoding import (
    check_json_value,
    is_ace_id,
    is_caip10_account,
    is_handle,
    resolve_now,
    wire_int,
)
from .descriptor import validate_card, validate_relay_route
from .identity import ACEIdentity, sign_claims
from .kel import KelState, tail_time
from .limits import (
    MAX_CARD_RECORD_BYTES,
    MAX_PAY_ACCOUNTS,
    MAX_PUBLISHED_AGENT_BYTES,
    TIMESTAMP_WINDOW_SECONDS,
)

#: Whether strangers' contact requests are processed (05 § Flow). No card record is ``closed``.
Contact = Literal["open", "closed"]

_REQUIRED = {"aceId", "issuedAt", "home", "card", "contact", "listed", "signature"}
_OPTIONAL = {"handle", "pay"}


class _CardRecordOptional(TypedDict, total=False):
    handle: str
    pay: list[str]


class CardRecord(_CardRecordOptional):
    """The signed record (a plain dict on the wire)."""

    aceId: str
    issuedAt: int
    home: str
    card: dict
    contact: Contact
    listed: bool
    signature: dict


class CardBundle(TypedDict):
    """The publication unit ``{kel, card}``."""

    kel: list
    card: CardRecord


@dataclass(frozen=True)
class VerifiedCard:
    """A verified CardBundle (``record`` is ``bundle["card"]``). ``kel_live``: whether the KEL it
    verified under was confirmed by a live descriptor or an existing pin
    (``NetworkClient.lookup_card``); False when only the bundle's own KEL vouches for it, as from
    ``verify_card_bundle`` alone or a lookup of an identity with no live descriptor (04 § Card
    record)."""

    ace_id: str
    state: KelState
    bundle: dict = field(hash=False)
    kel_live: bool = False

    @property
    def record(self) -> dict:
        return self.bundle["card"]

    @property
    def home(self) -> str:
        return self.record["home"]

    @property
    def handle(self) -> str | None:
        return self.record.get("handle")

    @property
    def card(self) -> dict:
        return copy.deepcopy(self.record["card"])

    @property
    def pay(self) -> list[str] | None:
        pay = self.record.get("pay")
        return None if pay is None else list(pay)

    @property
    def contact(self) -> Contact:
        return self.record["contact"]

    @property
    def listed(self) -> bool:
        return self.record["listed"]

    @property
    def issued_at(self) -> int:
        return self.record["issuedAt"]


def verify_card_bundle(
    value: object,
    now: int | None = None,
    *,
    allow_loopback_relays: bool = False,
    pinned: KelState | None = None,
) -> VerifiedCard:
    """Verify a CardBundle at ``now``, in order (04 § Card record): shape, both size bounds and
    field rules (``invalid_authorization``); the KEL usable at ``now`` (``invalid_kel`` /
    ``invalid_signature``) naming ``aceId`` (``invalid_authorization``); the signature as an
    operational signature of the KEL, reconciled with ``pinned`` when given
    (``stale_peer_binding`` / ``invalid_authorization``). No expiry check."""
    t = resolve_now(now)
    if type(value) is not dict or set(value) != {"kel", "card"}:
        raise bad("card bundle must be {kel, card}")
    check_json_value(value, "invalid_authorization")  # bounds the depth before anything recurses
    check_size(value, MAX_PUBLISHED_AGENT_BYTES, "card bundle")
    r = value["card"]
    if (
        type(r) is not dict
        or not _REQUIRED <= set(r) <= _REQUIRED | _OPTIONAL
        or not is_ace_id(r["aceId"])
    ):
        raise bad("invalid card record shape")
    check_size(r, MAX_CARD_RECORD_BYTES, "card record")
    issued = wire_int(r["issuedAt"])
    if issued is None or issued > t + TIMESTAMP_WINDOW_SECONDS:
        raise bad("invalid card record issuedAt")
    validate_relay_route(r["home"], allow_loopback=allow_loopback_relays)
    if "handle" in r:
        if not is_handle(r["handle"]):
            raise bad("handle must match [a-z][a-z0-9]*(-[a-z0-9]+)*, 3-32 characters")
        if urlsplit(r["home"]).path:
            raise bad("a handle needs a home without a path (it resolves at https://host)")
    validate_card(r["card"])
    if "pay" in r:
        pay = r["pay"]
        if (
            not isinstance(pay, list)
            or not 1 <= len(pay) <= MAX_PAY_ACCOUNTS
            or not all(is_caip10_account(a) for a in pay)
            or len(set(pay)) != len(pay)
        ):
            raise bad(f"pay must hold 1-{MAX_PAY_ACCOUNTS} distinct CAIP-10 accounts")
    if r["contact"] not in ("open", "closed"):
        raise bad("contact must be open or closed")
    if type(r["listed"]) is not bool:
        raise bad("listed must be a boolean")
    state = verify_signed(value["kel"], r, "card-record", t, pinned)
    return VerifiedCard(r["aceId"], state, copy.deepcopy(value))


def create_card_record(
    identity: ACEIdentity,
    *,
    home: str,
    handle: str | None = None,
    card: dict | None = None,
    pay: list[str] | None = None,
    contact: Contact,
    listed: bool,
    now: int | None = None,
    allow_loopback_relays: bool = False,
) -> dict:
    """Create and sign this identity's CardBundle (verified before it is returned), issued at
    ``max(now, ts of the KEL's last event)``: never before its signing delegation."""
    t = resolve_now(now)
    kel = identity.get_kel()
    claims: dict = {
        "aceId": identity.get_ace_id(),
        "issuedAt": tail_time(kel, t),
        "home": home,
        "card": copy.deepcopy(card or {}),
        "contact": contact,
        "listed": listed,
    }
    if handle is not None:
        claims["handle"] = handle
    if pay is not None:
        claims["pay"] = list(pay)
    bundle = {"kel": kel, "card": sign_claims(identity, "card-record", claims)}
    verify_card_bundle(bundle, t, allow_loopback_relays=allow_loopback_relays)
    return bundle
