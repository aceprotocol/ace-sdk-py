"""NetworkClient: publish, discover, look up, connect / accept / reject / block, send, pull.

It wires the core pieces together over relays: our descriptor (with prekey rotation) and card
record (handle, card, pay, contact, listed; 04 § Card record), the
PeerStore admission table, the Outbox (send + retry), the Inbox (receipts, permit renewal) and
relay clients for foreign relays (SSRF-safe ``RelayClient``). Remote content (contacts,
descriptors, messages) never changes local admission: only ``connect``, ``accept``, ``reject``,
``block``, ``unblock``, ``create_invitation`` or a matching local ``accept_profiles`` rule do.
"""

from __future__ import annotations

import copy
import functools
import re
import threading
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from ._documents import claims
from ._encoding import (
    HANDLE_RE,
    canonical_state_bytes,
    is_ace_id,
    is_message_id,
    sha256_hex,
    unix_now,
    wire_int,
)
from .card_record import Contact, VerifiedCard, create_card_record, verify_card_bundle
from .descriptor import VerifiedAgent, create_published_agent, verify_published_agent
from .errors import ACEError
from .identity import ACEIdentity
from .inbox import Inbox, ReceiveOutcome, Reply
from .invitation import verify_invitation
from .kel import KelState, event_bytes
from .limits import (
    CONTACT_REQUEST_TTL_SECONDS,
    DEFAULT_PAGE_LIMIT,
    MAX_INBOX_PAGE,
    MAX_PENDING_CONTACT_REQUESTS,
    PREKEY_ROTATION_SECONDS,
)
from .outbox import Attempt, Outbox, OutboxEntry
from .packet import PrivateMessage, create_packet, encode_content
from .peers import PeerStore
from .permit import create_permit, verify_permit
from .prekeys import PrekeyVault
from .profiles import CONTACT_TYPE, CORE, Profiles
from .relay import RelayClient, RelayEntry
from .rules import ProfileRules
from .store import ACEStore, load_record, write_record

_SELF_KEY = "network/self.json"
_HANDLE_RE = re.compile("@(" + HANDLE_RE.pattern + r")@([a-z0-9.-]+(?::[0-9]+)?)")


def _incoming_key(ace_id: str) -> str:
    return f"network/incoming/{sha256_hex(ace_id)}.json"


def _block_key(ace_id: str) -> str:
    return f"network/blocks/{sha256_hex(ace_id)}.json"


def _handle_pin_key(ace_id: str) -> str:
    """A peer's card pin: the newest verified record's ``issuedAt`` and claims digest (no
    rollback), and the ``{home, handle}`` it holds (set once per home)."""
    return f"network/handles/{sha256_hex(ace_id)}.json"


def _handle_owner_key(home: str, handle: str) -> str:
    """The reverse handle pin: the ACE ID ``@handle@home`` first resolved to. A binding is
    permanent, so a later other one is misbehavior."""
    return f"network/handle-owners/{sha256_hex(f'{home} {handle}')}.json"


def _kel_provenance_key(ace_id: str) -> str:
    """How a peer's KEL pin was confirmed: ``liveConfirmed`` False when a card lookup pinned the
    bundle's own KEL because the identity had no live descriptor, until a live descriptor confirms
    it. No record: pinned through a descriptor."""
    return f"network/kel-provenance/{sha256_hex(ace_id)}.json"


def _valid_card_pin(p: dict) -> bool:
    return (
        wire_int(p.get("issuedAt")) is not None
        and isinstance(p.get("digest"), str)
        and isinstance(p.get("home"), str)
        and (p.get("handle") is None or isinstance(p["handle"], str))
    )


def _valid_owner_pin(p: dict) -> bool:
    return all(isinstance(p.get(k), str) for k in ("aceId", "home", "handle"))


def _valid_provenance(p: dict) -> bool:
    return isinstance(p.get("aceId"), str) and isinstance(p.get("liveConfirmed"), bool)


def _load_pin(store: ACEStore, key: str, valid: Callable[[dict], bool]) -> dict | None:
    """A stored pin, None when absent; one that is not a record or lacks a required member is
    ``storage_failed``, never no pin."""
    pin = load_record(store, key)
    if pin is not None and not valid(pin):
        raise ACEError("storage_failed", f"{key} is invalid")
    return pin


def _first_served(urls: list[str], get: Callable[[str], Any]) -> Any:
    """``get`` at the first of ``urls`` that serves it. ``unknown_peer`` only when every route
    answered it; otherwise the first other failure (a transient one included), so an unreachable
    route never reads as "not there"."""
    unknown = ACEError("unknown_peer", "no route to the peer")
    other: ACEError | None = None
    for url in urls:
        try:
            return get(url)
        except ACEError as exc:
            if exc.code == "unknown_peer":
                unknown = exc
            elif other is None:
                other = exc
    raise other or unknown


def _blocked_peer() -> ACEError:
    return ACEError("not_permitted", "the peer is blocked; unblock it first")


@dataclass(frozen=True)
class ContactRequest:
    """A held incoming contact request (05 § Flow step 2)."""

    from_id: str
    message_id: str
    profile: str
    note: str
    source: dict
    permit: dict
    received_at: int


class NetworkClient:
    """Create with ``NetworkClient.open(...)``; ``__init__`` only assigns and does no I/O."""

    def __init__(
        self,
        identity: ACEIdentity,
        store: ACEStore,
        relay: RelayClient,
        vault: PrekeyVault,
        *,
        profiles: Profiles | None = None,
        rules: list[ProfileRules] | tuple[ProfileRules, ...] = (),
        handle: str | None = None,
        card: dict | None = None,
        pay: list[str] | None = None,
        contact: Contact = "closed",
        listed: bool = False,
        ext: dict | None = None,
        delegations: list[dict] | None = None,
        erc8004: list[dict] | None = None,
        accept_profiles: tuple[str, ...] | list[str] = (),
        relay_factory: Callable[[str], RelayClient] | None = None,
        on_message: Callable[[PrivateMessage], None] | None = None,
        on_receipt: Callable[[str, dict, Any], None] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.identity, self.store, self.relay, self.vault = identity, store, relay, vault
        self.profiles = profiles or Profiles()
        if any(self.profiles.get(p) is None for p in accept_profiles):
            raise ACEError("invalid_argument", "accept_profiles must name installed profiles")
        self.accept_profiles = tuple(accept_profiles)
        # the card record: handle is set once per home (it can never change or be dropped there)
        self.handle, self.card, self.pay = handle, card or {}, pay
        self.contact, self.listed, self.ext = contact, listed, ext
        self.delegations, self.erc8004 = delegations, erc8004
        # foreign relays come from untrusted descriptors: same loopback policy as the home relay
        self._factory = relay_factory or (
            lambda url: RelayClient(url, allow_loopback=relay.allow_loopback, clock=clock)
        )
        self._clock = clock
        self._user_on_message = on_message
        self._rules = rules
        self._user_on_receipt = on_receipt
        self.peers = PeerStore(store, clock=clock, allow_loopback_relays=relay.allow_loopback)
        self.outbox = Outbox(
            identity, store, self.profiles, rules=rules, resolve_peer=self._known, clock=clock
        )
        self.inbox: Inbox | None = None

    @classmethod
    def open(
        cls,
        identity: ACEIdentity,
        store: ACEStore,
        relay: RelayClient,
        vault: PrekeyVault,
        *,
        receive: bool = True,
        **options: Any,
    ) -> "NetworkClient":
        """A client over ``relay`` (the home relay). With ``receive`` (the default) it opens the
        Inbox, taking the store's exclusive ``receive`` lock. ``receive=False`` gives a send-only
        client that can run beside a receiving process on the same store; ``pull``/``follow``
        are then unavailable. The identity is registered on demand by ``publish``."""
        c = cls(identity, store, relay, vault, **options)
        if receive:
            c.inbox = Inbox.open(
                identity,
                store,
                vault,
                c.peers,
                c.profiles,
                on_message=c._on_message,
                on_receipt=c._user_on_receipt,
                rules=c._rules,
                outbox=c.outbox,
                contact=c._own_contact,
                refresh=lambda ace_id: c.agent(ace_id, refresh=True),
                resolve=lambda ace_id: c.agent(ace_id),
                clock=c._clock,
            )
        return c

    def close(self) -> None:
        if self.inbox is not None:
            self.inbox.close()

    def _now(self) -> int:
        return unix_now(self._clock)

    def _own_contact(self) -> str:
        """05 § Receiver admission: strangers only while configured ``open`` and the published
        card record says ``open`` (no record is ``closed``)."""
        if self.contact != "open":
            return "closed"
        rec = load_record(self.store, _SELF_KEY)
        card = None if rec is None else rec.get("card")
        return "open" if card is not None and card["card"]["contact"] == "open" else "closed"

    def _relay_for(self, url: str) -> RelayClient:
        return self.relay if url == self.relay.base_url else self._factory(url)

    # --- our descriptor ---------------------------------------------------------------

    def publish(self, *, force: bool = False) -> dict:
        """Publish our card record, then our PublishedAgent (rotating the prekey every 24 h). The
        card record goes first because it is the post a relay refuses (handle rules); a refused
        card leaves the published descriptor unchanged. The card record is re-signed when its
        settings change or after a new ``dlg`` (its digest covers the KEL's last event), else
        reused (re-posted with ``force``). An unchanged descriptor with more than an hour left is
        reused, and posted again only with ``force``. When the home relay holds no registration
        or an older KEL, the current KEL is registered first. Returns the PublishedAgent."""
        now = self._now()
        self.vault.prune(now)
        prekey = self.vault.current(now)
        created = self.vault.current_created_at
        if created is not None and now - created >= PREKEY_ROTATION_SECONDS:
            prekey = self.vault.rotate(now)
        with self.store.lock("network-self"):
            old = load_record(self.store, _SELF_KEY)
            kel = self.identity.get_kel()
            params = {
                "home": self.relay.base_url,
                "card": self.card,
                "contact": self.contact,
                "listed": self.listed,
                **({"handle": self.handle} if self.handle is not None else {}),
                **({"pay": self.pay} if self.pay is not None else {}),
            }
            digest = sha256_hex(
                canonical_state_bytes(
                    {"params": params, "lastHash": sha256_hex(event_bytes(kel[-1]))}
                )
            )
            card = None if old is None else old.get("card")
            card_state = None if old is None else old.get("cardParams")
            if card is not None and card_state == digest:
                if force:
                    self._post_card(card)
            else:
                issued = now if card is None else max(now, card["card"]["issuedAt"] + 1)
                card = create_card_record(
                    self.identity,
                    **params,
                    now=issued,
                    allow_loopback_relays=self.peers.allow_loopback_relays,
                )
                self._post_card(card)
                card_state = digest
                # Without a self record yet, the card is saved with the first descriptor below.
                if old is not None:
                    old = {**old, "card": card, "cardParams": card_state}
                    write_record(self.store, _SELF_KEY, old)
            rec = self._publish_descriptor(old, prekey, now, force)
            if rec is not old:
                write_record(self.store, _SELF_KEY, {**rec, "card": card, "cardParams": card_state})
            return copy.deepcopy(rec["source"])

    def _publish_descriptor(self, old: dict | None, prekey, now: int, force: bool) -> dict:
        """The self record holding the current descriptor: ``old`` itself when its descriptor is
        reused, else a new record (the descriptor already posted)."""
        wanted = {
            "relays": [self.relay.base_url],
            "prekey": prekey.to_dict(),
            "profiles": self.profiles.entries(),
            **({"ext": self.ext} if self.ext else {}),
            **({"delegations": self.delegations} if self.delegations else {}),
            **({"erc8004": self.erc8004} if self.erc8004 else {}),
        }
        if old is not None:
            src = old["source"]
            d = src["descriptor"]
            same = (
                src["kel"] == self.identity.get_kel()
                and all(d.get(k) == v for k, v in wanted.items())
                and all(k in wanted for k in ("ext", "delegations", "erc8004") if k in d)
            )
            if same and d["expiresAt"] > now + 3600:
                if force:
                    self._post_descriptor(src)
                return old
        issued = now if old is None else max(now, old["source"]["descriptor"]["issuedAt"] + 1)
        source = create_published_agent(
            self.identity,
            relays=[self.relay.base_url],
            prekey=prekey,
            profiles=self.profiles.entries(),
            ext=self.ext,
            delegations=self.delegations,
            erc8004=self.erc8004,
            now=issued,
            allow_loopback_relays=self.peers.allow_loopback_relays,
        )
        self._post_descriptor(source)
        return {**(old or {}), "source": source}

    def _post_descriptor(self, source: dict) -> None:
        """Post to the home relay, registering on demand (``_registered``)."""
        self._registered(lambda: self.relay.publish(source))

    def _post_card(self, bundle: dict) -> None:
        """Post our card record to the home relay, registering on demand like the descriptor."""
        self._registered(lambda: self.relay.publish_card(bundle))

    def _registered(self, post: Callable[[], None]) -> None:
        """Run ``post``; when the home relay lacks our registration (``not_registered``) or holds
        an older KEL (``kel_conflict``), register the current KEL and post once more."""
        try:
            post()
        except ACEError as exc:
            if exc.code != "not_registered" and exc.relay_code != "kel_conflict":
                raise
            self.relay.register(self.identity)
            post()

    # --- discovery --------------------------------------------------------------------

    def discover(
        self,
        *,
        profile: str | None = None,
        cursor: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> tuple[list[VerifiedAgent], str | None]:
        """The public directory of our relay: identities whose card record is listed (verified,
        not pinned)."""
        return self.relay.directory(profile=profile, cursor=cursor, limit=limit)

    def import_agent(self, source: dict | VerifiedAgent) -> VerifiedAgent:
        """Verify and pin a PublishedAgent (e.g. shared out of band). Does not admit it."""
        return self.peers.adopt(source, self._now())

    def lookup(self, target: str) -> VerifiedAgent:
        """An ACE ID (``agent(target)``) or ``@name@relay-host`` (through its card record, checked
        against the handle pin): the verified, pinned descriptor of that identity, fetched from
        the relay that holds the handle."""
        return self._resolve_target(target)[0]

    def lookup_with_card(self, target: str) -> tuple[VerifiedAgent, VerifiedCard | None]:
        """``lookup`` plus the peer's verified card record (None: it has none, ``unknown_peer`` at
        every route). By handle, the card record the handle resolved through; by ACE ID,
        ``lookup_card``."""
        agent, card = self._resolve_target(target)
        return agent, (card if card is not None else self._card_or_none(agent.ace_id))

    def _resolve_target(self, target: str) -> tuple[VerifiedAgent, VerifiedCard | None]:
        """``lookup``, with the card record verified on the way when ``target`` is a handle."""
        if is_ace_id(target):
            return self.agent(target), None
        card, relay, handle = self._card_by_handle(target)
        provenance = _load_pin(self.store, _kel_provenance_key(card.ace_id), _valid_provenance)
        # The descriptor first: it pins or advances the KEL, so the card verifies under the
        # current KEL.
        agent = self._fetch(card.ace_id, [relay.base_url])
        self._confirm_live(card.ace_id, provenance)
        return agent, self._check_card(card.bundle, (relay.base_url, handle))

    def lookup_card(self, target: str) -> VerifiedCard:
        """The verified card record of ``target`` (an ACE ID or ``@name@relay-host``). A handle
        resolves only to a record whose ``home`` is the queried relay and whose ``handle`` is the
        queried one (``unknown_peer``). A handle is set once per home: after a record with a
        handle was seen for an identity, a record of it naming the same home with another or no
        handle is ``invalid_authorization``; a record naming a new home re-pins. A handle's first
        resolution pins its ACE ID; a later resolution to another one is
        ``invalid_authorization``. Without a KEL pin for the identity, its descriptor is looked
        up first and its KEL pinned, so the card is verified under the current KEL, never one a
        relay chose. When every route answers ``unknown_peer`` (no live descriptor: offline past
        its lifetime), the card is verified under the bundle's own KEL instead, that KEL is
        pinned as a descriptor's would be, and the result has ``kel_live`` False (04 § Card
        record). That pin is recorded as not confirmed live: later lookups look the descriptor up
        again and report False until one confirms it."""
        if is_ace_id(target):
            fetch_card = functools.cache(lambda: self._fetch_card(target))
            kel_live = self._card_kel(target, lambda: self.agent(target), fetch_card)
            return self._check_card(fetch_card().bundle, kel_live=kel_live)
        card, relay, handle = self._card_by_handle(target)
        kel_live = self._card_kel(
            card.ace_id, lambda: self._fetch(card.ace_id, [relay.base_url]), lambda: card
        )
        return self._check_card(card.bundle, (relay.base_url, handle), kel_live=kel_live)

    def _card_kel(
        self,
        ace_id: str,
        fetch: Callable[[], VerifiedAgent],
        card: Callable[[], VerifiedCard],
    ) -> bool:
        """The KEL a card lookup verifies under, and whether a live descriptor confirmed it. A
        pin confirmed live is used as is. Otherwise the descriptor is looked up through ``fetch``
        (pinning or reconciling the KEL): on success the pin is recorded as confirmed live. When
        every route answers ``unknown_peer``, an unconfirmed pin stays unconfirmed, and without a
        pin the card's own bundle (``card``) pins the KEL (``_pin_bundle_kel``). Every other
        failure propagates."""
        pinned = self.peers.state(ace_id)
        provenance = _load_pin(self.store, _kel_provenance_key(ace_id), _valid_provenance)
        if pinned is not None and (provenance is None or provenance["liveConfirmed"]):
            return True
        try:
            fetch()
        except ACEError as exc:
            if exc.code != "unknown_peer":
                raise
            if pinned is None:
                self._pin_bundle_kel(card())
            return False
        self._confirm_live(ace_id, provenance)
        return True

    def _mark_unconfirmed(self, ace_id: str) -> None:
        """Record ``ace_id``'s KEL pin as not confirmed live (pinned without a live descriptor);
        called under the ``peers`` lock, with the pin."""
        write_record(
            self.store, _kel_provenance_key(ace_id), {"aceId": ace_id, "liveConfirmed": False}
        )

    def _confirm_live(self, ace_id: str, provenance: dict | None) -> None:
        """After a live descriptor was reconciled with ``ace_id``'s pin: a pin recorded (in
        ``provenance``, read before the descriptor lookup) as not confirmed live is now
        confirmed."""
        if provenance is not None and not provenance["liveConfirmed"]:
            with self.store.lock("peers"):
                write_record(
                    self.store,
                    _kel_provenance_key(ace_id),
                    {"aceId": ace_id, "liveConfirmed": True},
                )

    def _pin_bundle_kel(self, card: VerifiedCard) -> None:
        """Pin the KEL of ``card`` (already verified for the looked-up identity; no live
        descriptor), recorded as not confirmed live with the pin, atomically (under the ``peers``
        lock). ``peers.pin`` reconciles it with any pin written since; ``_check_card`` then
        re-verifies the record under the pin."""

        def record(pinned: KelState, _outcome: str) -> None:
            # As for a descriptor: another path advanced the pin past the card's KEL state.
            if pinned.last_hash != card.state.last_hash:
                raise ACEError("stale_peer_binding", "the pin advanced past the card record")
            self._mark_unconfirmed(card.ace_id)

        self.peers.pin(list(card.state.events), self._now(), then=record)

    def _check_card(
        self, bundle: dict, resolved: tuple[str, str] | None = None, *, kel_live: bool = True
    ) -> VerifiedCard:
        """Verify a fetched card record against the identity's KEL pin and its card pin (written
        on first sight, persisted in the store): no rollback first (an older ``issuedAt``, or an
        equal one with other claims, is ``stale_descriptor``), then the set-once handle per home
        (a record naming the pinned home must carry the pinned handle; a new home re-pins). A
        record ``resolved`` from ``(home, handle)`` must name the ACE ID that handle first
        resolved to (``invalid_authorization``)."""
        ace_id = bundle["card"]["aceId"]
        v = verify_card_bundle(
            bundle,
            self._now(),
            allow_loopback_relays=self.peers.allow_loopback_relays,
            pinned=self.peers.state(ace_id),
        )
        digest = sha256_hex(canonical_state_bytes(claims(v.record)))
        with self.store.lock("network-handles"):
            if resolved is None:
                self._advance_card_pin(v, digest)
            else:
                owner_key = _handle_owner_key(*resolved)
                owner = _load_pin(self.store, owner_key, _valid_owner_pin)
                if owner is not None and owner["aceId"] != ace_id:
                    raise ACEError(
                        "invalid_authorization",
                        "the handle resolved to another identity than before",
                    )
                self._advance_card_pin(v, digest)
                if owner is None:
                    home, handle = resolved
                    write_record(
                        self.store, owner_key, {"home": home, "handle": handle, "aceId": ace_id}
                    )
        return replace(v, kel_live=kel_live)

    def _advance_card_pin(self, v: VerifiedCard, digest: str) -> None:
        """The card pin checks and update of ``_check_card``, under the ``network-handles``
        lock."""
        key = _handle_pin_key(v.ace_id)
        pin = _load_pin(self.store, key, _valid_card_pin)
        if pin is not None:
            if v.issued_at < pin["issuedAt"]:
                raise ACEError("stale_descriptor", "an older card record than one already verified")
            if v.issued_at == pin["issuedAt"]:
                if digest != pin["digest"]:
                    raise ACEError("stale_descriptor", "another card record with the same issuedAt")
                return
        pinned_handle = None if pin is None else pin.get("handle")
        if pinned_handle is not None and pin["home"] == v.home and pinned_handle != v.handle:
            raise ACEError(
                "invalid_authorization",
                "the card record does not carry the handle this identity set",
            )
        # The handle pin is unchanged (same home: equal by the check above, so taking the
        # record's is the same), set on first claim, or re-pinned by a handle at a new home; a
        # record without a handle at another home keeps the earlier home's handle pin.
        keep = pinned_handle is not None and v.handle is None
        if keep:
            held = {"home": pin["home"], "handle": pinned_handle}
        else:
            held = {"home": v.home, **({"handle": v.handle} if v.handle is not None else {})}
        write_record(self.store, key, {**held, "issuedAt": v.issued_at, "digest": digest})

    def _card_by_handle(self, target: object) -> tuple[VerifiedCard, RelayClient, str]:
        m = _HANDLE_RE.fullmatch(target) if isinstance(target, str) else None
        if m is None:
            raise ACEError("invalid_argument", "use an ACE ID or @name@relay-host")
        home = urlsplit(self.relay.base_url)
        url = self.relay.base_url if m[2] == home.netloc else "https://" + m[2]
        relay = self._relay_for(url)
        return relay.handle(m[1]), relay, m[1]

    def _fetch_card(self, ace_id: str) -> VerifiedCard:
        """The peer's card record from the first route that serves it: its cached descriptor's
        relays, then our relay."""
        cached = self.peers.cached(ace_id)
        urls = [] if cached is None else cached.relays
        if self.relay.base_url not in urls:
            urls.append(self.relay.base_url)
        return _first_served(urls, lambda url: self._relay_for(url).card(ace_id))

    def agent(self, ace_id: str, *, refresh: bool = False) -> VerifiedAgent:
        """The peer's current descriptor: the pinned one while unexpired and bound to our
        current pins (unless ``refresh``), else fetched from its relays (``GET
        /v1/descriptor``) and pinned. A failed refresh raises: a stale descriptor is never
        used."""
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "invalid ACE ID")
        current, cached, bound = self.peers.lookup_state(ace_id, self._now())
        if current is not None and not refresh:
            return current
        # A descriptor no longer bound to our current pins (the subject's KEL or a delegation
        # issuer's moved on) may name relays chosen by a superseded, possibly compromised key:
        # our relay is asked too, as when nothing is cached.
        urls = [self.relay.base_url] if cached is None else cached.relays
        if cached is not None and not bound and self.relay.base_url not in urls:
            urls.append(self.relay.base_url)
        return self._fetch(ace_id, urls)

    def _fetch(self, ace_id: str, urls: list[str]) -> VerifiedAgent:
        """Fetch and pin the peer's descriptor from the first of ``urls`` that serves it."""
        return _first_served(
            urls, lambda url: self.peers.adopt(self._relay_for(url).descriptor(ace_id), self._now())
        )

    def _target(self, target: str | dict | VerifiedAgent) -> VerifiedAgent:
        if isinstance(target, (VerifiedAgent, dict)):
            return self.import_agent(target)
        return self.lookup(target)

    # --- invitations (05 § Invitations) ---------------------------------------------

    def create_invitation(
        self, peer: str | dict | VerifiedAgent, *, profile: str | None = None
    ) -> dict:
        """Invite one peer (ACE ID, ``@handle@host``, or its PublishedAgent shared out of band)
        to contact us: import it, record it ``admitted`` (an explicit local decision; clears a
        block) and return ``{agent, permit}``: our PublishedAgent and a permit issued to the
        peer, which reaches us even while our contact is ``closed``. Share it privately: the
        permit is a bearer credential."""
        if profile is not None and self.profiles.get(profile) is None:
            raise ACEError("invalid_argument", f"{profile} is not installed")
        agent = self._target(peer)
        if agent.ace_id == self.identity.get_ace_id():
            raise ACEError("invalid_argument", "cannot invite this identity")
        permit = create_permit(self.identity, agent.ace_id, now=self._now())
        self._decide(agent.ace_id, "admitted", profile)
        invitation = {"agent": self.publish(), "permit": permit}
        self.peers.note_issued(agent.ace_id, permit)
        return invitation

    def import_invitation(self, value: object) -> VerifiedAgent:
        """Import an invitation ``{agent, permit}`` addressed to us: verify and pin the agent and
        hold its permit (so ``connect`` reaches a ``closed`` inviter). Never admits the inviter."""
        agent, permit = verify_invitation(
            value,
            self.identity.get_ace_id(),
            now=self._now(),
            allow_loopback_relays=self.peers.allow_loopback_relays,
        )
        pinned = self.import_agent(agent)
        self._hold_permit(pinned.ace_id, permit)
        return pinned

    # --- sending ----------------------------------------------------------------------

    def _their_permit(self, ace_id: str) -> dict | None:
        return self.peers.presentable_permit(ace_id, self.identity.get_ace_id(), self._now())

    def _hold_permit(self, issuer: str, permit: object, when=None) -> None:
        self.peers.hold_permit(issuer, permit, self.identity.get_ace_id(), self._now(), when=when)

    def _post(self, packet: dict, agent: VerifiedAgent, permit: dict | None = None) -> None:
        """Post to the peer's relays in order until one queues it, with ``permit`` (default the
        newest one the peer issued us). A permanent refusal ends the attempt (only a transient
        failure or ``unknown_peer`` moves on to the next relay)."""
        if permit is None:
            permit = self._their_permit(agent.ace_id)
        error: ACEError | None = None
        for url in agent.relays:
            try:
                self._relay_for(url).send(packet, permit)
                return
            except ACEError as exc:
                if not exc.is_transient and exc.code != "unknown_peer":
                    raise
                error = exc
        raise error or ACEError("unknown_peer", "no relay route")

    def _attempt(self, packet: dict, agent: VerifiedAgent) -> None:
        """The Outbox transport: every attempt carries the newest permit the peer issued us that
        is valid under its current pin, else ``not_permitted`` (retried on the schedule while a
        renewal or refresh arrives); never the stranger path (06 § Outbox step 3)."""
        permit = self._their_permit(agent.ace_id)
        if permit is None:
            raise ACEError("not_permitted", "no valid permit from this peer")
        self._post(packet, agent, permit)

    def _send_contact(self, agent: VerifiedAgent, body: dict, permit: dict | None = None) -> str:
        """A contact packet: one attempt, never queued. A permit it carries counts as issued
        only once the packet was sent (a failed send leaves the peer due for a fresh one)."""
        plaintext = encode_content(CONTACT_TYPE, CORE.messages[CONTACT_TYPE].digest, body)
        packet = create_packet(
            self.identity, agent.ace_id, agent.prekey, plaintext, timestamp=self._now()
        )
        self._post(packet, agent, permit)
        if "permit" in body:
            self.peers.note_issued(agent.ace_id, body["permit"])
        return packet["messageId"]

    def _contact(self, kind: str, profile: str, note: str = "", to: str | None = None) -> dict:
        """A contact body carrying our descriptor and, for ``to``, a fresh permit."""
        body = {"kind": kind, "profile": profile, "note": note, "source": self.publish()}
        if to is not None:
            body["permit"] = create_permit(self.identity, to, now=self._now())
        return body

    def send(self, to: str, type_: str, body: dict, *, thread_id: str | None = None) -> str:
        """Queue a message and attempt it now; returns the messageId. The peer must have issued us
        a permit valid under its current pin (06 § Outbox), else ``not_permitted`` and nothing is
        stored. Delivery is confirmed only by the receipt (``outbox.get(id).status``,
        ``on_receipt``)."""
        if self._their_permit(to) is None:
            raise ACEError("not_permitted", "no valid permit from this peer")
        mid = self.outbox.enqueue(to, type_, body, thread_id=thread_id)
        self.outbox.deliver(mid, self._attempt, self._resolve)
        return mid

    def flush(self) -> list[Attempt]:
        """Attempt every due Outbox entry."""
        return self.outbox.flush(self._attempt, self._resolve)

    def attempt(self, message_id: str) -> OutboxEntry | None:
        """One attempt of ``message_id`` now, due or not (TS ``outbox.attempt``): ``None`` for an
        unknown message, a final entry as is, a pending one after the attempt."""
        if not is_message_id(message_id) or self.outbox.get(message_id) is None:
            return None
        self.outbox.deliver(message_id, self._attempt, self._resolve, force=True)
        return self.outbox.get(message_id)

    def _known(self, ace_id: str) -> None:
        """A cached descriptor (even expired or stale: attempts refresh it) suffices; otherwise
        one must resolve now."""
        if self.peers.cached(ace_id) is None:
            self.agent(ace_id)

    def _resolve(self, ace_id: str, refresh: bool = False) -> VerifiedAgent:
        return self.agent(ace_id, refresh=refresh)

    # --- admission --------------------------------------------------------------------

    def _decide(
        self,
        ace_id: str,
        status: str | None,
        profile: str | None = None,
        *,
        lift: bool = False,
        keep_block: bool = False,
    ) -> None:
        """Apply a local admission decision. Setting a block, or lifting one, allocates the next
        relay revision in the same step under the ``network-blocks`` lock and persists it as
        ``unsynced`` until the home relay registers it (``maintain`` re-sends exactly it); a
        block also discards the peer's held request in that step. With ``lift`` the decision
        applies only while the peer is still blocked; with ``keep_block`` (accept) a blocked
        peer is ``not_permitted``. The local state is the enforcement point."""
        key = _block_key(ace_id)
        with self.store.lock("network-blocks"):
            was_blocked = self.peers.is_blocked(ace_id)
            if lift and not was_blocked:
                return
            if keep_block and was_blocked:
                raise _blocked_peer()
            self.peers.set_status(ace_id, status, profile)
            blocked = status == "blocked"
            if blocked:
                self.store.delete(_incoming_key(ace_id))
            if not blocked and not was_blocked:
                return
            rec = load_record(self.store, key)
            revision = 0 if rec is None else rec["revision"] + 1
            write_record(
                self.store,
                key,
                {"peer": ace_id, "blocked": blocked, "revision": revision, "unsynced": revision},
            )
        self._sync_block(ace_id, blocked, revision)

    def _sync_block(self, ace_id: str, blocked: bool, revision: int) -> None:
        """Register a block decision at the home relay with its allocated ``revision``.
        Confirmed, or refused ``stale_revision`` (the relay holds a later decision), it is
        settled; any other failure leaves it for ``maintain``."""
        try:
            self.relay.set_block(self.identity, ace_id, blocked, revision)
        except ACEError as exc:
            if exc.relay_code != "stale_revision":
                return
        key = _block_key(ace_id)
        with self.store.lock("network-blocks"):
            cur = load_record(self.store, key)
            if cur is not None and cur["unsynced"] == revision:
                write_record(self.store, key, {**cur, "unsynced": None})

    def _resync_blocks(self) -> None:
        for key in self.store.list("network/blocks/"):
            rec = load_record(self.store, key)
            if rec is not None and rec["unsynced"] is not None:
                self._sync_block(rec["peer"], rec["blocked"], rec["unsynced"])

    def connect(self, target: str | dict | VerifiedAgent, *, profile: str, note: str = "") -> str:
        """Send a contact request for ``profile``; the peer becomes ``pending`` (a local decision).
        Without a permit it issued us, the target's card record must be ``contact: open`` (no
        record is ``closed``; 05 § Flow); our own ``contact`` does not matter. A blocked peer is
        ``not_permitted``: only ``unblock`` (or an invitation) lifts a block (05 § Blocks)."""
        if isinstance(target, (VerifiedAgent, dict)):
            agent, card = self.import_agent(target), None
        else:
            agent, card = self._resolve_target(target)
        installed = self.profiles.get(profile)
        if installed is None or installed.descriptor() not in agent.profiles:
            raise ACEError("invalid_argument", "no common profile with an equal digest")
        if self.peers.is_blocked(agent.ace_id):
            raise _blocked_peer()
        if self._their_permit(agent.ace_id) is None:
            card = card if card is not None else self._card_or_none(agent.ace_id)
            if card is None or card.contact != "open":
                raise ACEError(
                    "not_permitted",
                    "the peer takes contact requests only from peers it issued a permit",
                )
        if self.peers.status(agent.ace_id) != "admitted":
            self.peers.set_status(agent.ace_id, "pending", profile)
        return self._send_contact(agent, self._contact("request", profile, note, agent.ace_id))

    def _card_or_none(self, ace_id: str) -> VerifiedCard | None:
        """The peer's verified card record; None when it has none (``unknown_peer``: closed,
        unlisted)."""
        try:
            return self.lookup_card(ace_id)
        except ACEError as exc:
            if exc.code == "unknown_peer":
                return None
            raise

    def _held_requests(self) -> list[tuple[str, dict]]:
        """Unexpired held requests ``(key, record)``, oldest first; expired ones are deleted."""
        now, out = self._now(), []
        for key in self.store.list("network/incoming/"):
            d = load_record(self.store, key)
            if d is None:
                continue
            if now >= d["receivedAt"] + CONTACT_REQUEST_TTL_SECONDS:
                self.store.delete(key)
                continue
            out.append((key, d))
        out.sort(key=lambda kd: (kd[1]["receivedAt"], kd[0]))
        return out

    @staticmethod
    def _request_of(d: dict) -> ContactRequest:
        m = d["message"]
        b = m["body"]
        return ContactRequest(
            m["from"],
            m["messageId"],
            b["profile"],
            b["note"],
            b["source"],
            b["permit"],
            d["receivedAt"],
        )

    def requests(self) -> list[ContactRequest]:
        """Pending incoming contact requests, oldest first: at most
        ``MAX_PENDING_CONTACT_REQUESTS``, one per sender, each expiring
        ``CONTACT_REQUEST_TTL_SECONDS`` after receipt (05 § Flow). Never admitted automatically
        except by a local ``accept_profiles`` rule or an existing admission."""
        return [self._request_of(d) for _, d in self._held_requests()]

    def _request(self, ace_id: str) -> ContactRequest:
        key = _incoming_key(ace_id)
        d = next((d for k, d in self._held_requests() if k == key), None)
        if d is None:
            raise ACEError("invalid_argument", "no pending contact request from this peer")
        return self._request_of(d)

    def accept(self, ace_id: str) -> None:
        """Explicitly accept a pending request: pin, keep its permit, admit, reply ``accepted``.
        A blocked peer is ``not_permitted``, also when blocked meanwhile: accept never clears a
        block (05 § Blocks)."""
        req = self._request(ace_id)
        if self.peers.is_blocked(ace_id):
            raise _blocked_peer()
        if req.source["descriptor"]["expiresAt"] > self._now():
            agent = self.import_agent(req.source)
        else:
            agent = self._refresh_source(ace_id, req.source)
        self._decide(ace_id, "admitted", req.profile, keep_block=True)
        self._hold_permit(agent.ace_id, req.permit)
        self._send_contact(agent, self._contact("accepted", req.profile, to=ace_id))
        self.store.delete(_incoming_key(ace_id))

    def _refresh_source(self, ace_id: str, source: dict) -> VerifiedAgent:
        """A held request (24 h) can outlive its source descriptor: pin the source's KEL (05 § Flow
        step 3) and refresh the descriptor, from the source's routes while the source is bound
        to the pin, else by a normal lookup. A KEL pinned (or advanced) from the source alone is
        not confirmed live, as a card bundle's own KEL is not, until the refreshed descriptor
        confirms it (04 § Card record)."""

        def record(state: KelState, outcome: str) -> None:
            if outcome != "unchanged":
                self._mark_unconfirmed(state.ace_id)

        # A pin failure (a fork: kel_conflict) fails the accept, never passed over by a lookup.
        state, _ = self.peers.pin(source["kel"], self._now(), then=record)
        relays = list(source["descriptor"]["relays"])
        # bound: the source's kel ends at the pin (the pin did not move past it)
        bound = state.ace_id == ace_id and state.last_hash == sha256_hex(
            event_bytes(source["kel"][-1])
        )
        provenance = _load_pin(self.store, _kel_provenance_key(ace_id), _valid_provenance)
        agent = self._fetch(ace_id, relays) if bound else self.agent(ace_id, refresh=True)
        self._confirm_live(ace_id, provenance)
        return agent

    def reject(self, ace_id: str, note: str = "") -> None:
        """Decline a pending request (a ``rejected`` reply, best effort)."""
        req = self._request(ace_id)
        self.store.delete(_incoming_key(ace_id))
        try:
            now = self._now()
            agent = verify_published_agent(
                req.source, now=now, allow_loopback_relays=self.peers.allow_loopback_relays
            )
            permit = verify_permit(req.permit, agent.state, self.identity.get_ace_id(), now=now)
            self._send_contact(agent, self._contact("rejected", req.profile, note), permit)
        except ACEError:
            pass

    def block(self, ace_id: str) -> None:
        """Block locally (in force at once, surviving restart), drop its held request and register
        the block at the home relay; a relay failure is retried by ``maintain``."""
        self._decide(ace_id, "blocked")

    def unblock(self, ace_id: str) -> None:
        """Remove a block (the explicit admission action, 05 § Blocks); the peer becomes a
        stranger again until contact is re-established."""
        self._decide(ace_id, None, lift=True)

    def set_wake(self, gateway: str, token: str) -> None:
        """Ask the home relay to wake ``gateway`` with ``token`` when entries are queued for us
        (07 § Wake hints). A hint only: delivery still comes from ``pull`` / ``follow``."""
        self.relay.set_wake(self.identity, gateway, token)

    def clear_wake(self) -> None:
        """Remove the home relay's wake registration."""
        self.relay.clear_wake(self.identity)

    # --- receiving --------------------------------------------------------------------

    def _on_message(self, m: PrivateMessage) -> None:
        if m.type == CONTACT_TYPE:
            self._on_contact(m)
        if self._user_on_message is not None:
            self._user_on_message(m)

    def _on_contact(self, m: PrivateMessage) -> None:
        kind, sender = m.body["kind"], m.from_id
        if kind == "request":
            # 05 § Flow: one slot per sender (replaced), TTL, and the oldest evicted when full.
            key = _incoming_key(sender)
            with self.store.lock("network-incoming"):
                held = [k for k, _ in self._held_requests() if k != key]
                while len(held) >= MAX_PENDING_CONTACT_REQUESTS:
                    self.store.delete(held.pop(0))
                write_record(self.store, key, {"message": m.to_dict(), "receivedAt": self._now()})
            return
        status, rec = self.peers.status(sender), self.peers.get(sender)
        refresh = status == "admitted" and kind == "accepted"
        if not refresh and (status != "pending" or rec is None or rec.profile != m.body["profile"]):
            return  # replies count only for our own unexpired pending request
        if kind != "accepted":
            self.peers.set_status(sender, None)
            return
        agent = self.import_agent(m.body["source"])
        expected = "admitted" if refresh else "pending"
        self._hold_permit(
            agent.ace_id, m.body["permit"], when=lambda r: r is not None and r.status == expected
        )
        if not refresh:  # a permit refresh (05 § Delivery permits) changes only the permit
            self.peers.set_status(sender, "admitted", m.body["profile"])

    def _auto_accept(self) -> None:
        for r in self.requests():
            # a matching local rule, or a peer we already admitted (e.g. invited)
            if r.profile in self.accept_profiles or self.peers.status(r.from_id) == "admitted":
                try:
                    self.accept(r.from_id)
                except ACEError:
                    continue

    def _reply(self, reply: Reply) -> None:
        self._post(reply.packet, self.agent(reply.to))
        if reply.permit is not None:
            self.peers.note_issued(reply.to, reply.permit)

    def _inbox(self) -> Inbox:
        if self.inbox is None:
            raise ACEError("invalid_argument", "this client was opened without the receive role")
        return self.inbox

    def _consume(self, inbox: Inbox, entry: RelayEntry) -> tuple[ReceiveOutcome, bool]:
        """Process one entry and send its receipt; whether it reached a final disposition."""
        out = inbox.receive(entry.packet)
        if out.receipt is not None:
            try:
                self._reply(out.receipt)
            except ACEError as exc:
                if exc.is_transient:
                    return out, False  # 06 step 11: retried on the next fetch
        return out, out.ack

    def pull(self, *, limit: int = MAX_INBOX_PAGE) -> list[ReceiveOutcome]:
        """Fetch one inbox page: process entries in stream order, send each receipt, then ack
        once through the last entry with a final disposition. Stops at the first entry without
        one (it stays on the relay)."""
        inbox = self._inbox()
        outcomes: list[ReceiveOutcome] = []
        page = self.relay.inbox(self.identity, limit=limit)
        through = None
        try:
            for entry in page.entries:
                out, final = self._consume(inbox, entry)
                outcomes.append(out)
                if not final:
                    break
                through = entry.stream_id
        finally:
            if through is not None:
                self.relay.ack(self.identity, through)
        self._auto_accept()
        return outcomes

    def follow(self, *, stop: threading.Event | None = None) -> Iterator[ReceiveOutcome]:
        """Follow the home relay's listen stream: each entry is processed, its receipt sent and
        the entry acknowledged before its outcome is yielded. Ends at an entry without a final
        disposition (pull again later), when ``stop`` is set, or with ``relay_unavailable``."""
        inbox = self._inbox()
        for entry in self.relay.listen(self.identity, stop=stop):
            out, final = self._consume(inbox, entry)
            if not final:
                yield out
                return
            self.relay.ack(self.identity, entry.stream_id)
            self._auto_accept()
            yield out

    def _refresh_permits(self) -> list[str]:
        """After a signing-key change, re-send a contact request carrying a fresh permit to every
        admitted peer whose newest permit from us predates the current delegation (05 § Delivery
        permits); the peer accepts it automatically. Best effort per peer: a failed send is
        retried at the next upkeep. Returns the peers sent to."""
        seq, sent = self.identity.get_signing_seq(), []
        for rec in self.peers.list():
            issued = rec.issued_permit
            if self.peers.status(rec.ace_id) != "admitted" or (
                issued is not None and issued["seq"] == seq
            ):
                continue
            try:
                agent = self.agent(rec.ace_id)
                # a profile both sides still list: the recorded one, else the first shared one
                shared = [p["id"] for p in agent.profiles if self.profiles.supports(p)]
                if not shared:
                    continue
                profile = rec.profile if rec.profile in shared else shared[0]
                self._send_contact(agent, self._contact("request", profile, to=rec.ace_id))
                sent.append(rec.ace_id)
            except ACEError:
                continue
        return sent

    def maintain(self) -> None:
        """Periodic upkeep: publish (renewing descriptor and prekey, registering when needed),
        push fresh permits after a signing-key change, re-register blocks whose relay call
        failed, retry due Outbox entries and prune settled ones. Every step runs even when an
        earlier one fails (an unreachable home relay must not stop Outbox retries to peers'
        relays); the first failure is raised at the end."""
        failure: Exception | None = None
        for step in (
            self.publish,
            self._refresh_permits,
            self._resync_blocks,
            self.flush,
            self.outbox.prune,
        ):
            try:
                step()
            except Exception as exc:
                failure = failure or exc
        if failure is not None:
            raise failure
