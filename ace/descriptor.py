"""Signed descriptors: ``PublishedAgent = {kel, descriptor}`` (self-declared, at most
``MAX_DESCRIPTOR_LIFETIME``; 24 hours by default). Handle, card, payment accounts and contact
live in the card record (``card_record``).

The descriptor is signed with action ``agent-descriptor``, ``aceId``, ``issuedAt`` and payload
``canonicalStateBytes(claims)``. Expired delegation entries are
dropped; any other invalid field invalidates the whole descriptor (``invalid_authorization``).
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field

from ._documents import bad, check_lifetime, check_size, verify_signed
from ._encoding import (
    CONTROL_CHAR_RE,
    canonical_state_bytes,
    check_json_value,
    decode_fixed_b64,
    is_ace_id,
    is_https_url,
    is_namespaced_id,
    is_sha256_hex,
    resolve_now,
)
from ._relay_url import is_canonical_relay_url
from .delegation import validate_erc8004, verify_delegation
from .errors import ACEError
from .identity import ACEIdentity, sign_claims
from .kel import KelState
from .limits import (
    DEFAULT_DESCRIPTOR_LIFETIME,
    KEM_PUBLIC_KEY_SIZE,
    MAX_DESCRIPTOR_DELEGATIONS,
    MAX_DESCRIPTOR_ERC8004,
    MAX_DESCRIPTOR_LIFETIME,
    MAX_DESCRIPTOR_PROFILES,
    MAX_DESCRIPTOR_RELAYS,
    MAX_EXT_BYTES,
    MAX_PUBLISHED_AGENT_BYTES,
    MAX_STRANGER_DELEGATIONS,
    MAX_STRANGER_KEL_EVENTS,
)
from .prekeys import Prekey, prekey_id

_REQUIRED = {
    "aceId",
    "issuedAt",
    "expiresAt",
    "relays",
    "prekey",
    "profiles",
    "signature",
}
_OPTIONAL = {"ext", "delegations", "erc8004"}
_TAG_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


@dataclass(frozen=True)
class VerifiedAgent:
    """A verified PublishedAgent. ``delegations`` lists the issuers of the live credentials."""

    ace_id: str
    state: KelState
    source: dict = field(hash=False)
    prekey: Prekey
    delegations: tuple[str, ...] = ()

    @property
    def descriptor(self) -> dict:
        return self.source["descriptor"]

    @property
    def relays(self) -> list[str]:
        return list(self.descriptor["relays"])

    @property
    def profiles(self) -> list[dict]:
        return copy.deepcopy(self.descriptor["profiles"])

    @property
    def issued_at(self) -> int:
        return self.descriptor["issuedAt"]

    @property
    def expires_at(self) -> int:
        return self.descriptor["expiresAt"]

    @property
    def ext(self) -> dict:
        return copy.deepcopy(self.descriptor.get("ext", {}))


def validate_relay_route(value: object, *, allow_loopback: bool = False) -> str:
    """A canonical HTTPS relay URL; HTTP to a loopback host only when ``allow_loopback`` (explicit
    local development; production verifiers reject it, 02 § Relay URLs)."""
    if not is_canonical_relay_url(value, allow_loopback=allow_loopback):
        raise bad("relay route must be a canonical HTTPS relay URL")
    return value  # type: ignore[return-value]


def validate_card(card: object) -> dict:
    """A card record's closed ``card``: ``{name?, description?, image?, tags?}`` (tag ``hosted``:
    keys held by a host)."""
    if type(card) is not dict or not set(card) <= {"name", "description", "image", "tags"}:
        raise bad("card permits only name, description, image and tags")

    def text(key: str, lo: int, hi: int) -> None:
        v = card[key]
        if not isinstance(v, str) or not lo <= len(v) <= hi or CONTROL_CHAR_RE.search(v):
            raise bad(f"card.{key} must be {lo}-{hi} characters without control characters")

    if "name" in card:
        text("name", 1, 64)
    if "description" in card:
        text("description", 0, 256)
    if "image" in card and not is_https_url(card["image"]):
        raise bad("card.image must be an ACE HTTPS URL")
    if "tags" in card:
        tags = card["tags"]
        if (
            not isinstance(tags, list)
            or len(tags) > 10
            or not all(
                isinstance(t, str) and 1 <= len(t) <= 32 and set(t) <= _TAG_CHARS for t in tags
            )
            or len(set(tags)) != len(tags)
        ):
            raise bad("card.tags must be at most 10 distinct [a-z0-9-]{1,32}")
    return copy.deepcopy(card)


def _check_profiles(profiles: object) -> list[dict]:
    if (
        not isinstance(profiles, list)
        or len(profiles) > MAX_DESCRIPTOR_PROFILES
        or not all(
            type(p) is dict
            and set(p) == {"id", "digest"}
            and is_namespaced_id(p["id"])
            and is_sha256_hex(p["digest"])
            for p in profiles
        )
        or len({p["id"] for p in profiles}) != len(profiles)
        or any(p["id"] == "ace:core:1" for p in profiles)
    ):
        raise bad("invalid profiles")
    return profiles


#: Official profiles' descriptor ``ext`` validators; an official profile without one takes no ext.
def _official_ext() -> dict:
    from .commerce import PROFILE_ID, validate_commerce_ext

    return {PROFILE_ID: validate_commerce_ext}


def _check_ext(ext: object, profile_ids: set[str]) -> None:
    """Keys are announced profile ids, values objects, canonical size <= 4096; an official
    profile's value must match its schema (and only official profiles that define one)."""
    if type(ext) is not dict or not ext or not set(ext) <= profile_ids:
        raise bad("ext keys must be announced profile ids")
    if not all(type(v) is dict for v in ext.values()):
        raise bad("ext values must be objects")
    try:
        size = len(canonical_state_bytes(ext))
    except (TypeError, ValueError):
        raise bad("ext is not JSON") from None
    if size > MAX_EXT_BYTES:
        raise bad(f"ext exceeds {MAX_EXT_BYTES} canonical bytes")
    official = _official_ext()
    for key, value in ext.items():
        if key in official:
            official[key](value)
        elif key.startswith("ace:"):
            raise bad(f"profile {key} defines no ext")


def _check_prekey(prekey: object) -> Prekey:
    if type(prekey) is not dict or set(prekey) != {"id", "publicKey"}:
        raise bad("prekey must be {id, publicKey}")
    try:
        pk = decode_fixed_b64(
            prekey["publicKey"], KEM_PUBLIC_KEY_SIZE, "invalid_authorization", "prekey"
        )
    except ACEError as exc:
        raise bad(exc.message) from None
    if prekey["id"] != prekey_id(pk):
        raise bad("prekey.id must be the SHA-256 of the public key")
    return Prekey(prekey["id"], pk)


def check_stranger_source(value: object) -> None:
    """The bounds on a stranger's contact ``source`` (05 § Receiver admission), checked before
    any signature: its KEL and each delegation entry's KEL hold at most
    ``MAX_STRANGER_KEL_EVENTS`` events and it carries at most ``MAX_STRANGER_DELEGATIONS``
    delegation entries. ``not_permitted`` otherwise (the request is dropped)."""

    def short(kel: object) -> bool:
        return isinstance(kel, list) and len(kel) <= MAX_STRANGER_KEL_EVENTS

    d = value.get("descriptor") if isinstance(value, dict) else None
    if not isinstance(value, dict) or not isinstance(d, dict) or not short(value.get("kel")):
        raise ACEError("not_permitted", "stranger source exceeds the KEL bound")
    dl = d.get("delegations", [])
    if not isinstance(dl, list) or len(dl) > MAX_STRANGER_DELEGATIONS:
        raise ACEError("not_permitted", "stranger source carries too many delegations")
    if not all(isinstance(e, dict) and short(e.get("kel")) for e in dl):
        raise ACEError("not_permitted", "stranger delegation exceeds the KEL bound")


def verify_published_agent(
    value: object,
    *,
    now: int | None = None,
    allow_loopback_relays: bool = False,
    pinned: KelState | None = None,
    delegation_pins: Mapping[str, KelState] | None = None,
) -> VerifiedAgent:
    """Verify a ``{kel, descriptor}`` at ``now``; ``invalid_authorization`` (or the KEL's own
    ``invalid_kel`` / ``invalid_signature`` codes).

    With ``pinned`` (the verifier's pin for this identity) the carried KEL is first reconciled
    with the pin under the fork rules and the signature must verify under the resulting, newest
    state: a descriptor carrying an older prefix of the pinned log and signed by a delegation
    the pin has superseded is ``stale_peer_binding``; a fork is ``kel_conflict``.

    ``delegation_pins`` maps delegation issuers to the verifier's pins for them; each entry's
    issuer KEL is reconciled with its pin the same way (a failure is ``invalid_authorization``)."""
    t = resolve_now(now)
    if type(value) is not dict or set(value) != {"kel", "descriptor"}:
        raise bad("published agent must be {kel, descriptor}")
    check_json_value(value, "invalid_authorization")  # depth counts from the agent's root
    check_size(value, MAX_PUBLISHED_AGENT_BYTES, "published agent")
    d = value["descriptor"]
    if (
        type(d) is not dict
        or not _REQUIRED <= set(d) <= _REQUIRED | _OPTIONAL
        or not is_ace_id(d["aceId"])
    ):
        raise bad("invalid descriptor")
    routes = d["relays"]
    if (
        not isinstance(routes, list)
        or not 1 <= len(routes) <= MAX_DESCRIPTOR_RELAYS
        or len(set(map(str, routes))) != len(routes)
    ):
        raise bad("invalid relays")
    for route in routes:
        validate_relay_route(route, allow_loopback=allow_loopback_relays)
    prekey = _check_prekey(d["prekey"])
    profiles = _check_profiles(d["profiles"])
    if "ext" in d:
        _check_ext(d["ext"], {p["id"] for p in profiles})
    if "erc8004" in d:
        e = d["erc8004"]
        if not isinstance(e, list) or not 1 <= len(e) <= MAX_DESCRIPTOR_ERC8004:
            raise bad("erc8004 must hold 1-4 entries")
        for entry in e:
            validate_erc8004(entry)
        if len({(x["agentRegistry"], x["agentId"]) for x in e}) != len(e):
            raise bad("duplicate erc8004 entry")
    check_lifetime(d, t, MAX_DESCRIPTOR_LIFETIME)
    state = verify_signed(value["kel"], d, "agent-descriptor", t, pinned)
    live: list[str] = []
    if "delegations" in d:
        dl = d["delegations"]
        if not isinstance(dl, list) or not 1 <= len(dl) <= MAX_DESCRIPTOR_DELEGATIONS:
            raise bad("delegations must hold 1-4 entries")
        issuers = [
            e.get("credential", {}).get("issuer")
            if type(e) is dict and type(e.get("credential")) is dict
            else None
            for e in dl
        ]
        if len(set(map(str, issuers))) != len(issuers):
            raise bad("delegation issuers must be distinct")
        for entry, who in zip(dl, issuers):
            pin = delegation_pins.get(who) if delegation_pins and isinstance(who, str) else None
            issuer, ok = verify_delegation(entry, d["aceId"], now=t, pinned=pin)
            if ok:
                live.append(issuer.ace_id)
    return VerifiedAgent(d["aceId"], state, copy.deepcopy(value), prekey, tuple(live))


def create_published_agent(
    identity: ACEIdentity,
    *,
    relays: list[str],
    prekey: Prekey,
    profiles: list[dict] | None = None,
    ext: dict | None = None,
    delegations: list[dict] | None = None,
    erc8004: list[dict] | None = None,
    now: int | None = None,
    lifetime: int = DEFAULT_DESCRIPTOR_LIFETIME,
    allow_loopback_relays: bool = False,
) -> dict:
    """Build and sign a PublishedAgent (verified before it is returned)."""
    t = resolve_now(now)
    if type(lifetime) is not int or not 0 < lifetime <= MAX_DESCRIPTOR_LIFETIME:
        raise ACEError("invalid_argument", f"lifetime must be in (0, {MAX_DESCRIPTOR_LIFETIME}]")
    if not isinstance(prekey, Prekey):
        raise ACEError("invalid_argument", "prekey must be a Prekey")
    claims: dict = {
        "aceId": identity.get_ace_id(),
        "issuedAt": t,
        "expiresAt": t + lifetime,
        "relays": list(relays),
        "prekey": prekey.to_dict(),
        "profiles": copy.deepcopy(profiles or []),
    }
    if ext:
        claims["ext"] = copy.deepcopy(ext)
    if delegations:
        claims["delegations"] = copy.deepcopy(delegations)
    if erc8004:
        claims["erc8004"] = copy.deepcopy(erc8004)
    source = {
        "kel": identity.get_kel(),
        "descriptor": sign_claims(identity, "agent-descriptor", claims),
    }
    verify_published_agent(source, now=t, allow_loopback_relays=allow_loopback_relays)
    return source
