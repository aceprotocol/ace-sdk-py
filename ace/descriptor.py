"""Signed descriptors: ``PublishedAgent = {kel, descriptor}`` (self-declared, at most
``MAX_DESCRIPTOR_LIFETIME``; 24 hours by default). Handle, card, payment accounts and contact
live in the card record (``card_record``).

The descriptor is signed with action ``agent-descriptor``, ``aceId``, ``issuedAt`` and payload
``canonicalStateBytes(claims)``. Any invalid field invalidates the whole descriptor
(``invalid_authorization``).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from ._documents import bad, check_lifetime, check_size, verify_signed
from ._encoding import (
    CONTROL_CHAR_RE,
    check_json_value,
    decode_fixed_b64,
    is_ace_id,
    is_https_url,
    is_namespaced_id,
    is_sha256_hex,
    resolve_now,
)
from ._relay_url import is_canonical_relay_url
from .errors import ACEError
from .identity import ACEIdentity, sign_claims
from .kel import KelState, tail_time
from .limits import (
    DEFAULT_DESCRIPTOR_LIFETIME,
    KEM_PUBLIC_KEY_SIZE,
    MAX_DESCRIPTOR_LIFETIME,
    MAX_DESCRIPTOR_PROFILES,
    MAX_DESCRIPTOR_RELAYS,
    MAX_EXT_BYTES,
    MAX_PUBLISHED_AGENT_BYTES,
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
_OPTIONAL = {"ext"}
_TAG_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


@dataclass(frozen=True)
class VerifiedAgent:
    """A verified PublishedAgent."""

    ace_id: str
    state: KelState
    source: dict = field(hash=False)
    prekey: Prekey

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
    """A card record's closed ``card``: ``{description?, image?, tags?}`` (tag ``hosted``: keys
    held by a host)."""
    if type(card) is not dict or not set(card) <= {"description", "image", "tags"}:
        raise bad("card permits only description, image and tags")

    def text(key: str, lo: int, hi: int) -> None:
        v = card[key]
        if not isinstance(v, str) or not lo <= len(v) <= hi or CONTROL_CHAR_RE.search(v):
            raise bad(f"card.{key} must be {lo}-{hi} characters without control characters")

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


#: Official profiles' descriptor ``ext`` validators, called with ``(value, aceId, now)``; an
#: official profile without one takes no ext.
def _official_ext() -> dict:
    from .commerce import PROFILE_ID, validate_commerce_ext
    from .delegation import DELEGATION_PROFILE_ID, validate_delegation_ext

    return {
        PROFILE_ID: lambda value, ace_id, now: validate_commerce_ext(value),
        DELEGATION_PROFILE_ID: validate_delegation_ext,
    }


def _check_ext(ext: object, profile_ids: set[str], ace_id: str, now: int) -> None:
    """Keys are announced profile ids, values objects, canonical size <= ``MAX_EXT_BYTES``; an
    official profile's value must match its schema (and only official profiles that define
    one)."""
    if type(ext) is not dict or not ext or not set(ext) <= profile_ids:
        raise bad("ext keys must be announced profile ids")
    if not all(type(v) is dict for v in ext.values()):
        raise bad("ext values must be objects")
    check_size(ext, MAX_EXT_BYTES, "ext")
    official = _official_ext()
    for key, value in ext.items():
        if key in official:
            official[key](value, ace_id, now)
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
    """The bound on a stranger's contact ``source`` (05 § Receiver admission), checked before
    any signature: its ``kel`` holds at most ``MAX_STRANGER_KEL_EVENTS`` events.
    ``not_permitted`` otherwise (the request is dropped)."""
    kel = value.get("kel") if isinstance(value, dict) else None
    if not isinstance(kel, list) or len(kel) > MAX_STRANGER_KEL_EVENTS:
        raise ACEError("not_permitted", "stranger source exceeds the KEL bound")


def verify_published_agent(
    value: object,
    *,
    now: int | None = None,
    allow_loopback_relays: bool = False,
    pinned: KelState | None = None,
) -> VerifiedAgent:
    """Verify a ``{kel, descriptor}`` at ``now``; ``invalid_authorization`` (or the KEL's own
    ``invalid_kel`` / ``invalid_signature`` codes).

    With ``pinned`` (the verifier's pin for this identity) the carried KEL is first reconciled
    with the pin under the fork rules and the signature must verify under the resulting, newest
    state: a descriptor carrying an older prefix of the pinned log and signed by a delegation
    the pin has superseded is ``stale_peer_binding``; a fork is ``kel_conflict``."""
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
        _check_ext(d["ext"], {p["id"] for p in profiles}, d["aceId"], t)
    check_lifetime(d, t, MAX_DESCRIPTOR_LIFETIME)
    state = verify_signed(value["kel"], d, "agent-descriptor", t, pinned)
    return VerifiedAgent(d["aceId"], state, copy.deepcopy(value), prekey)


def create_published_agent(
    identity: ACEIdentity,
    *,
    relays: list[str],
    prekey: Prekey,
    profiles: list[dict] | None = None,
    ext: dict | None = None,
    now: int | None = None,
    lifetime: int = DEFAULT_DESCRIPTOR_LIFETIME,
    allow_loopback_relays: bool = False,
) -> dict:
    """Build and sign a PublishedAgent (verified before it is returned), issued at
    ``max(now, ts of the KEL's last event)``: never before its signing delegation."""
    t = resolve_now(now)
    if type(lifetime) is not int or not 0 < lifetime <= MAX_DESCRIPTOR_LIFETIME:
        raise ACEError("invalid_argument", f"lifetime must be in (0, {MAX_DESCRIPTOR_LIFETIME}]")
    if not isinstance(prekey, Prekey):
        raise ACEError("invalid_argument", "prekey must be a Prekey")
    kel = identity.get_kel()
    issued = tail_time(kel, t)
    claims: dict = {
        "aceId": identity.get_ace_id(),
        "issuedAt": issued,
        "expiresAt": issued + lifetime,
        "relays": list(relays),
        "prekey": prekey.to_dict(),
        "profiles": copy.deepcopy(profiles or []),
    }
    if ext:
        claims["ext"] = copy.deepcopy(ext)
    source = {"kel": kel, "descriptor": sign_claims(identity, "agent-descriptor", claims)}
    verify_published_agent(source, now=t, allow_loopback_relays=allow_loopback_relays)
    return source
