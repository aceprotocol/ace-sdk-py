"""PeerStore: per-peer pinned KEL, cached descriptor, the admission table (``pending``,
``admitted``, ``blocked``; absent = stranger) and the permits exchanged with that peer.
One record per peer (lock ``peers``)."""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass
from typing import Any, Callable

from ._encoding import canonical_state_bytes, is_ace_id, sha256_hex, unix_now, wire_int
from .descriptor import VerifiedAgent, verify_published_agent
from .errors import ACEError
from .kel import KelState, is_usable, reconcile_kel, tail_time, verify_kel
from .limits import OFFLINE_WINDOW_SECONDS
from .permit import verify_permit
from .store import ACEStore, load_record, write_record

_CACHE = 256


def _key(ace_id: str) -> str:
    return f"peers/{sha256_hex(ace_id)}.json"


@dataclass(frozen=True)
class PeerRecord:
    ace_id: str
    kel: list | None
    agent: dict | None
    status: str | None  # None (stranger), "pending", "admitted", "blocked"
    held_permit: dict | None
    issued_permit: dict | None  # {expiresAt, seq} of the newest permit we sent the peer
    profile: str | None
    updated_at: int | None = None  # when ``status`` was last set (a pending entry's TTL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "aceId": self.ace_id,
            "kel": self.kel,
            "agent": self.agent,
            "status": self.status,
            "heldPermit": self.held_permit,
            "issuedPermit": self.issued_permit,
            "profile": self.profile,
            "updatedAt": self.updated_at,
        }


def _record(d: dict, key: str) -> PeerRecord:
    try:
        r = PeerRecord(
            d["aceId"],
            d["kel"],
            d["agent"],
            d["status"],
            d["heldPermit"],
            d["issuedPermit"],
            d["profile"],
            d["updatedAt"],
        )
        if (
            not is_ace_id(r.ace_id)
            or key != _key(r.ace_id)
            or r.status not in (None, "pending", "admitted", "blocked")
            or (r.kel is not None and not isinstance(r.kel, list))
            or (r.agent is not None and not isinstance(r.agent, dict))
            or (r.profile is not None and not isinstance(r.profile, str))
            or (r.updated_at is not None and wire_int(r.updated_at) is None)
            or (
                r.held_permit is not None
                and (
                    not isinstance(r.held_permit, dict)
                    or r.held_permit.get("issuer") != r.ace_id
                    or wire_int(r.held_permit.get("issuedAt")) is None
                    or wire_int(r.held_permit.get("expiresAt")) is None
                )
            )
            or (
                r.issued_permit is not None
                and (
                    not isinstance(r.issued_permit, dict)
                    or wire_int(r.issued_permit.get("expiresAt")) is None
                    or wire_int(r.issued_permit.get("seq")) is None
                )
            )
        ):
            raise ValueError("fields")
    except (KeyError, TypeError, ValueError) as exc:
        raise ACEError("storage_failed", f"{key}: invalid peer record ({exc})") from None
    return r


class PeerStore:
    """Local knowledge about peers. Nothing here performs network I/O."""

    def __init__(
        self,
        store: ACEStore,
        *,
        clock: Callable[[], int] | None = None,
        allow_loopback_relays: bool = False,
    ) -> None:
        self._store = store
        self.allow_loopback_relays = allow_loopback_relays
        self._clock = clock
        self._states: dict[bytes, KelState] = {}

    def _now(self) -> int:
        return unix_now(self._clock)

    # --- records ---

    def get(self, ace_id: str) -> PeerRecord | None:
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "ace_id must be an ACE ID")
        d = load_record(self._store, _key(ace_id))
        return None if d is None else _record(d, _key(ace_id))

    def _update(self, ace_id: str, **changes: Any) -> PeerRecord:
        """Caller holds the ``peers`` lock."""
        old = self.get(ace_id) or PeerRecord(ace_id, None, None, None, None, None, None)
        new = dataclasses.replace(old, **changes)
        write_record(self._store, _key(ace_id), new.to_dict())
        return new

    def list(self) -> list[PeerRecord]:
        out = []
        for key in self._store.list("peers/"):
            d = load_record(self._store, key)
            if d is not None:
                out.append(_record(d, key))
        return out

    # --- KEL pins ---

    def state(self, ace_id: str) -> KelState | None:
        """The pinned log state (verified at the time of its last event)."""
        rec = self.get(ace_id)
        if rec is None or rec.kel is None:
            return None
        state = self._verify(rec.kel)
        if state.ace_id != ace_id:
            raise ACEError("storage_failed", "pinned kel names another identity")
        return state

    def _verify(self, kel: list) -> KelState:
        raw = canonical_state_bytes(kel)
        cached = self._states.get(raw)
        if cached is None:
            try:
                cached = verify_kel(kel, tail_time(kel, 0))
            except ACEError as exc:
                raise ACEError("storage_failed", f"pinned kel is invalid: {exc.message}") from None
            if len(self._states) >= _CACHE:
                self._states.clear()
            self._states[raw] = cached
        return cached

    def pin(
        self,
        kel: list,
        now: int | None = None,
        *,
        then: Callable[[KelState], None] | None = None,
    ) -> tuple[KelState, str]:
        """Adopt or extend the pinned log (fork rules); ``kel_conflict`` on a fork. ``then`` runs
        with the resulting pin still under the ``peers`` lock, so state derived from it is written
        atomically with it (raising there leaves the pin as it was)."""
        t = self._now() if now is None else now
        with self._store.lock("peers"):
            cand = verify_kel(kel, t)
            pinned = self.state(cand.ace_id)
            state, outcome = reconcile_kel(pinned, cand)
            if then is not None:
                then(state)
            if outcome != "unchanged":
                self._update(state.ace_id, kel=list(state.events))
            return state, outcome

    # --- descriptors ---

    def delegation_pins(self, source: object) -> dict[str, KelState]:
        """Our pins for the delegation issuers a PublishedAgent names (01 § Pinning)."""
        pins: dict[str, KelState] = {}
        d = source.get("descriptor") if isinstance(source, dict) else None
        entries = d.get("delegations") if isinstance(d, dict) else None
        for e in entries if isinstance(entries, list) else []:
            c = e.get("credential") if isinstance(e, dict) else None
            who = c.get("issuer") if isinstance(c, dict) else None
            if isinstance(who, str) and is_ace_id(who) and who not in pins:
                st = self.state(who)
                if st is not None:
                    pins[who] = st
        return pins

    def adopt(self, agent: VerifiedAgent | dict, now: int | None = None) -> VerifiedAgent:
        """Pin the agent's KEL (fork rules) and its descriptor. The descriptor must verify under the
        KEL state that ends up pinned (a descriptor carrying an older prefix of the pin and signed
        by a superseded delegation is ``stale_peer_binding``). It replaces the pinned one only
        when its ``issuedAt`` is newer (or equal with identical claims); an older one is ignored
        and the pinned agent returned, unless the subject's KEL state moved on since the cached one
        was verified: then it is replaced unconditionally (a descriptor signed by a superseded key
        can never outlive the key change). Unsigned metadata is never merged."""
        t = self._now() if now is None else now
        source = agent.source if isinstance(agent, VerifiedAgent) else agent
        with self._store.lock("peers"):
            ace_id = (
                source["descriptor"]["aceId"]
                if isinstance(source, dict)
                and isinstance(source.get("descriptor"), dict)
                and is_ace_id(source["descriptor"].get("aceId"))
                else None
            )
            rec = None if ace_id is None else self.get(ace_id)
            pinned = None if rec is None or rec.kel is None else self._verify(rec.kel)
            verified = verify_published_agent(
                source,
                now=t,
                allow_loopback_relays=self.allow_loopback_relays,
                pinned=pinned,
                delegation_pins=self.delegation_pins(source),
            )
            state = verified.state
            kel = list(state.events)
            old = None if rec is None else rec.agent
            if (
                old is not None
                and self._verify(old["kel"]).last_hash == state.last_hash
                and (
                    old["descriptor"]["issuedAt"] > verified.issued_at
                    or (
                        old["descriptor"]["issuedAt"] == verified.issued_at
                        and old["descriptor"] != verified.descriptor
                    )
                )
            ):
                self._update(verified.ace_id, kel=kel)
                kept = self.current(verified.ace_id, t)
                if kept is None:
                    # An older revision never stands in for the newer cached one,
                    # and a stale one is never returned.
                    raise ACEError(
                        "stale_peer_binding",
                        "an older descriptor revision cannot replace the cached one",
                    )
                return kept
            stored = {"kel": kel, "descriptor": copy.deepcopy(verified.descriptor)}
            self._update(verified.ace_id, kel=kel, agent=stored)
        return VerifiedAgent(verified.ace_id, state, stored, verified.prekey, verified.delegations)

    def _cached(self, agent: dict, pins: dict[str, KelState] | None = None) -> VerifiedAgent:
        return verify_published_agent(
            agent,
            now=tail_time(agent["kel"], agent["descriptor"]["issuedAt"]),
            allow_loopback_relays=self.allow_loopback_relays,
            delegation_pins=pins,
        )

    def cached(self, ace_id: str) -> VerifiedAgent | None:
        """The cached descriptor as stored, even expired or stale: use only its ``relays``
        (where to refresh it); ``agent`` is the descriptor to encrypt to or expose."""
        rec = self.get(ace_id)
        if rec is None or rec.agent is None:
            return None
        try:
            return self._cached(rec.agent)
        except (ACEError, KeyError, TypeError) as exc:
            raise ACEError("storage_failed", f"cached descriptor is invalid: {exc}") from None

    def binding(self, ace_id: str) -> tuple[VerifiedAgent | None, bool]:
        """``cached(ace_id)`` and whether it was verified under our current pin of the
        subject's KEL (its relays may then be trusted with the subject's permit)."""
        cached = self.cached(ace_id)
        pin = None if cached is None else self.state(ace_id)
        return cached, cached is not None and pin is not None and (
            cached.state.last_hash == pin.last_hash
        )

    def agent(self, ace_id: str) -> VerifiedAgent | None:
        """The cached descriptor while it is bound to our current pins (possibly expired: use
        ``current`` to encrypt to it): verified under the subject's pinned KEL state and still
        verifying against our current pins for its delegation issuers. None when absent or stale
        (a pin moved on since it was verified): refresh it, never use the stale one. Delegations
        expired at the store clock are dropped."""
        return self._bound_agent(*self.binding(ace_id))

    def _bound_agent(self, cached: VerifiedAgent | None, bound: bool) -> VerifiedAgent | None:
        if cached is None or not bound:
            return None
        pins = self.delegation_pins(cached.source)
        if pins:
            try:
                cached = self._cached(cached.source, pins)
            except ACEError:
                return None  # a delegation issuer's key changed since the entry was verified
        # an entry that has expired since is dropped (04 § Delegations), never reported
        now = self._now()
        expires = {
            e["credential"]["issuer"]: e["credential"]["expiresAt"]
            for e in cached.descriptor.get("delegations") or []
        }
        live = tuple(i for i in cached.delegations if expires[i] > now)
        return (
            cached if live == cached.delegations else dataclasses.replace(cached, delegations=live)
        )

    def current(self, ace_id: str, now: int | None = None) -> VerifiedAgent | None:
        """``agent(ace_id)`` while usable at ``now``: the descriptor to encrypt to."""
        return self.lookup_state(ace_id, now)[0]

    def lookup_state(
        self, ace_id: str, now: int | None = None
    ) -> tuple[VerifiedAgent | None, VerifiedAgent | None, bool]:
        """``(current, cached, bound)`` from one read: the descriptor to encrypt to (04 § Caching:
        bound to our current pins, unexpired, and the subject usable at ``now``, 01 § Verifier
        rules 5: never send to an unusable identity), else None; plus ``binding(ace_id)`` for a
        refresh."""
        t = self._now() if now is None else now
        cached, bound = self.binding(ace_id)
        agent = self._bound_agent(cached, bound)
        # a bound descriptor's state is the pin, so the subject's usability is read off it
        usable = agent is not None and agent.expires_at > t and is_usable(agent.state, t)
        return (agent if usable else None), cached, bound

    # --- admission ---

    def status(self, ace_id: str) -> str | None:
        """The admission state. A ``pending`` entry expires ``OFFLINE_WINDOW_SECONDS`` (the
        relay's retention of the request) after its request was sent: the peer is a stranger
        again (05 § Flow step 4)."""
        rec = self.get(ace_id)
        if rec is not None and self._lapsed(rec):
            with self._store.lock("peers"):
                cur = self.get(ace_id)
                if cur is not None and self._lapsed(cur):  # deleted: a stranger again
                    self._update(ace_id, status=None, profile=None)
            rec = self.get(ace_id)
        return None if rec is None else rec.status

    def _lapsed(self, rec: PeerRecord) -> bool:
        return rec.status == "pending" and (
            self._now() >= (rec.updated_at or 0) + OFFLINE_WINDOW_SECONDS
        )

    def is_admitted(self, ace_id: str) -> bool:
        """``pending`` or ``admitted``: the sender continues through the receive pipeline."""
        return self.status(ace_id) in ("pending", "admitted")

    def is_blocked(self, ace_id: str) -> bool:
        return self.status(ace_id) == "blocked"

    def set_status(self, ace_id: str, status: str | None, profile: str | None = None) -> None:
        """Local decision only (connect, accept, reject, block); never driven by remote content."""
        if status not in (None, "pending", "admitted", "blocked"):
            raise ACEError("invalid_argument", "invalid admission status")
        with self._store.lock("peers"):
            self._update(ace_id, status=status, profile=profile, updated_at=self._now())

    # --- permits ---

    def hold_permit(
        self,
        issuer: str,
        permit: object,
        subject: str,
        now: int,
        *,
        when: Callable[[PeerRecord | None], bool] | None = None,
    ) -> dict:
        """Verify ``permit`` from ``issuer`` to ``subject`` under our current pin of the issuer
        (``invalid_authorization`` otherwise) and keep it (``save_permit``)."""
        state = self.state(issuer)
        if state is None:
            raise ACEError("invalid_authorization", "permit issuer is not pinned")
        held = verify_permit(permit, state, subject, now=now)
        self.save_permit(held, state, subject, now, when=when)
        return held

    def presentable_permit(self, ace_id: str, subject: str, now: int) -> dict | None:
        """The newest permit ``ace_id`` issued ``subject`` that still verifies under our current
        pin of ``ace_id`` (never one signed by a superseded key)."""
        permit, state = self.permit_from(ace_id, now), self.state(ace_id)
        if permit is None or state is None:
            return None
        try:
            return verify_permit(permit, state, subject, now=now)
        except ACEError:
            return None

    def save_permit(
        self,
        permit: dict,
        state: KelState | None = None,
        subject: str | None = None,
        now: int | None = None,
        *,
        when: Callable[[PeerRecord | None], bool] | None = None,
    ) -> None:
        """Keep a permit issued to us by ``permit.issuer``, verified under ``state`` (our current
        pin of the issuer): the one slot per issuer, written by every path (accept, ``accepted``,
        receipt renewal, invitation, import). The held permit is kept instead only while it is
        newer (``issuedAt``) and, given ``state``, still verifies under that pin, so a permit from
        a superseded key never shadows a valid one. ``when`` makes it conditional on the issuer's
        record; both are checked under the ``peers`` lock."""
        with self._store.lock("peers"):
            rec = self.get(permit["issuer"])
            if when is not None and not when(rec):
                return
            old = None if rec is None else rec.held_permit
            if old is not None and old["issuedAt"] > permit["issuedAt"]:
                if state is None or subject is None:
                    return
                try:
                    verify_permit(old, state, subject, now=self._now() if now is None else now)
                    return
                except ACEError:
                    pass
            self._update(permit["issuer"], held_permit=copy.deepcopy(permit))

    def permit_from(self, ace_id: str, now: int | None = None) -> dict | None:
        """The newest permit ``ace_id`` issued to us, if still unexpired."""
        rec = self.get(ace_id)
        p = None if rec is None else rec.held_permit
        t = self._now() if now is None else now
        return copy.deepcopy(p) if p is not None and p["expiresAt"] > t else None

    def note_issued(self, subject: str, permit: dict) -> None:
        """Record ``permit`` as the newest one the peer holds from us, once the packet carrying
        it was sent (a failed send leaves the peer due for a fresh one)."""
        issued = {"expiresAt": permit["expiresAt"], "seq": permit["signature"]["seq"]}
        with self._store.lock("peers"):
            self._update(subject, issued_permit=issued)

    def issued(self, subject: str) -> dict | None:
        rec = self.get(subject)
        return None if rec is None else rec.issued_permit
