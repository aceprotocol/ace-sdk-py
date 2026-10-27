"""Outbox (contract § 6): persist the private content, then re-encrypt and re-sign per attempt.

The first attempt encrypts to the peer prekey held for the recipient (04 § Peer prekeys) while it
is usable, else, like every later attempt, to its *current* published prekey, with a fresh
timestamp and the same ``messageId``; every packet offers our peer prekey for the recipient. A
relay ``{ok: true}`` is not delivery: an entry stays ``pending`` until a
receipt settles it (``delivered`` / ``rejected``) or ``OFFLINE_WINDOW_SECONDS`` pass after the
first attempt (``expired``: we stopped retrying, the outcome is unknown; the recipient may still
have processed it, and a late receipt still settles the entry). Backoff: 60 s, doubling, at most
3600 s. An in-flight marker keeps concurrent ``deliver`` calls for one message from sending twice.

Profile rules (08 § Profile rules): ``check`` runs at enqueue, ``commit`` only when the
``delivered`` receipt arrives. While a rule-governed entry is pending for ``(to, threadId)``,
enqueueing another rule-governed message on that thread fails ``thread_busy``; a ``rejected``
receipt, expiry or abandonment releases the thread without any state change (a late
``delivered`` receipt for an expired entry still commits).

Every attempt after the first refreshes the recipient's descriptor (it may have lost its prekeys
with its state) and, through the ``admission`` hook given at construction, may add ``admission``
to that attempt's content (05 § Admission recovery); it is never stored in the entry.

Settled entries are kept until ``prune`` (``get(id).status`` reports the outcome), so retries
scan a pending index (``outbox-pending/``), not the whole history. The index is a superset of
the pending entries: a marker is written before its entry and removed after the entry leaves
``pending``; a stale marker is skipped and removed.
"""

from __future__ import annotations

import copy
import dataclasses
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Literal

from ._encoding import (
    check_json_value,
    is_ace_id,
    is_message_id,
    is_thread_id,
    sha256_hex,
    unix_now,
    wire_int,
)
from .errors import ACEError
from .identity import ACEIdentity
from .limits import (
    KEM_PUBLIC_KEY_SIZE,
    OFFLINE_WINDOW_SECONDS,
    OUTBOX_FIRST_BACKOFF_SECONDS,
    OUTBOX_MAX_BACKOFF_SECONDS,
)
from .packet import create_packet, encode_content
from .prekeys import PrekeyVault
from .profiles import CONTACT_TYPE, RECEIPT_TYPE, Profiles
from .rules import MessageEvent, ProfileRules, check_rules, governed, run_check, run_commit
from .store import ACEStore, load_record, write_record

#: An in-flight marker older than this is considered abandoned (crashed sender).
IN_FLIGHT_TIMEOUT_SECONDS = 120

Status = Literal["pending", "delivered", "rejected", "expired"]
#: ``transport(packet, recipient_agent)`` sends one packet, called with ``admission=`` (the
#: ``Admission`` the packet carries) when there is one; ``resolve(ace_id, refresh)`` returns the
#: recipient's current ``VerifiedAgent`` (refreshing an expired descriptor, or always when
#: ``refresh``).
Transport = Callable[..., None]
Resolver = Callable[[str, bool], Any]


@dataclass(frozen=True)
class Admission:
    """What a retry adds to its content (05 § Admission recovery): ``content`` is
    ``{proof, permit, source}``. The transport presents ``proof`` to the relay and, when
    ``fresh``, records the reply permit as issued once the packet was sent."""

    content: dict
    fresh: bool = False


#: ``admission(to, now)``: the ``Admission`` for a retry to ``to``, or None to send without.
AdmissionHook = Callable[[str, int], "Admission | None"]


def backoff(attempts: int) -> int:
    """Delay after ``attempts`` attempts: 60, 120, 240 ... capped at 3600 seconds."""
    return min(OUTBOX_FIRST_BACKOFF_SECONDS * 2 ** max(0, attempts - 1), OUTBOX_MAX_BACKOFF_SECONDS)


def _key(message_id: str) -> str:
    return f"outbox/{sha256_hex(message_id)}.json"


def _pending_key(message_id: str) -> str:
    return f"outbox-pending/{sha256_hex(message_id)}.json"


def _thread_key(to: str, thread_id: str) -> str:
    """The thread lock of a rule-governed pending entry: ``{messageId}``."""
    return f"outbox-threads/{sha256_hex(to, thread_id)}.json"


@dataclass(frozen=True)
class OutboxEntry:
    message_id: str
    to: str
    content: dict
    created_at: int
    status: Status
    attempts: int
    next_attempt_at: int
    first_attempt_at: int | None
    in_flight_at: int | None
    code: str | None
    prekey: str | None = None  # prekey id used by the last attempt
    refresh: bool = False  # a rejected:unknown_prekey asked for a descriptor refresh
    expired_at: int | None = None  # when the entry became ``expired``
    settled_at: int | None = None  # when a receipt made it ``delivered`` or ``rejected``

    def to_dict(self) -> dict[str, Any]:
        return {
            "messageId": self.message_id,
            "to": self.to,
            "content": self.content,
            "createdAt": self.created_at,
            "status": self.status,
            "attempts": self.attempts,
            "nextAttemptAt": self.next_attempt_at,
            "firstAttemptAt": self.first_attempt_at,
            "inFlightAt": self.in_flight_at,
            "code": self.code,
            "prekey": self.prekey,
            "refresh": self.refresh,
            "expiredAt": self.expired_at,
            "settledAt": self.settled_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "OutboxEntry":
        try:
            e = OutboxEntry(
                d["messageId"],
                d["to"],
                d["content"],
                d["createdAt"],
                d["status"],
                d["attempts"],
                d["nextAttemptAt"],
                d["firstAttemptAt"],
                d["inFlightAt"],
                d["code"],
                d["prekey"],
                d["refresh"],
                d["expiredAt"],
                d["settledAt"],
            )
        except (KeyError, TypeError) as exc:
            raise ACEError("storage_failed", f"invalid outbox record: {exc}") from None
        ints_ok = all(
            wire_int(v) is not None for v in (e.created_at, e.attempts, e.next_attempt_at)
        ) and all(
            v is None or wire_int(v) is not None
            for v in (e.first_attempt_at, e.in_flight_at, e.expired_at, e.settled_at)
        )
        if (
            not is_message_id(e.message_id)
            or not is_ace_id(e.to)
            or not isinstance(e.content, dict)
            or not {"type", "schemaDigest", "body"} <= set(e.content)
            or not ints_ok
            or type(e.refresh) is not bool
            or (e.prekey is not None and not isinstance(e.prekey, str))
            or e.status not in ("pending", "delivered", "rejected", "expired")
        ):
            raise ACEError("storage_failed", "invalid outbox record")
        return e

    def replace(self, **changes: Any) -> "OutboxEntry":
        return dataclasses.replace(self, **changes)

    def overdue(self, now: int) -> bool:
        """First attempted ``OFFLINE_WINDOW_SECONDS`` or more ago: it expires unsent."""
        return self.first_attempt_at is not None and (
            now - self.first_attempt_at >= OFFLINE_WINDOW_SECONDS
        )


@dataclass(frozen=True)
class Attempt:
    """The result of one ``deliver`` call: ``sent`` (wait for the receipt), ``skipped`` (not due,
    settled or in flight elsewhere) or ``failed`` (``error``; retried after backoff)."""

    message_id: str
    result: Literal["sent", "skipped", "failed"]
    status: Status
    error: ACEError | None = None


class Outbox:
    def __init__(
        self,
        identity: ACEIdentity,
        store: ACEStore,
        profiles: Profiles,
        *,
        vault: PrekeyVault,
        rules: list[ProfileRules] | tuple[ProfileRules, ...] = (),
        resolve_peer: Callable[[str], Any] | None = None,
        admission: AdmissionHook | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        """``resolve_peer(to)`` ensures a descriptor for ``to`` is held or resolvable; ``enqueue``
        calls it before storing anything (permanent failure: ``unknown_peer``; transient:
        re-raised). ``admission(to, now)``: what an attempt after the first adds to its content
        (05 § Admission recovery). ``vault``: the peer prekeys every packet offers and the ones
        held for first attempts (04 § Peer prekeys)."""
        if not isinstance(profiles, Profiles):
            raise ACEError("invalid_argument", "profiles must be a Profiles")
        if not isinstance(vault, PrekeyVault):
            raise ACEError("invalid_argument", "vault must be a PrekeyVault")
        self._vault = vault
        self._identity = identity
        self._store = store
        self._profiles = profiles
        self._rules = check_rules(list(rules))
        self._resolve_peer = resolve_peer
        self._admission = admission
        self._clock = clock

    def _now(self) -> int:
        return unix_now(self._clock)

    def _load(self, message_id: str) -> OutboxEntry | None:
        d = load_record(self._store, _key(message_id))
        return None if d is None else OutboxEntry.from_dict(d)

    def _save(self, e: OutboxEntry) -> None:
        write_record(self._store, _key(e.message_id), e.to_dict())
        if e.status != "pending":
            self._store.delete(_pending_key(e.message_id))
            self._release(e)

    def _expire(self, e: OutboxEntry) -> None:
        self._save(
            e.replace(status="expired", code="expired", in_flight_at=None, expired_at=self._now())
        )

    def _thread(self, e: OutboxEntry) -> str | None:
        """The thread id when the entry is rule-governed and threaded, else None."""
        tid = e.content.get("threadId")
        return tid if tid is not None and governed(self._rules, e.content["type"]) else None

    def _release(self, e: OutboxEntry) -> None:
        tid = self._thread(e)
        if tid is None:
            return
        key = _thread_key(e.to, tid)
        d = load_record(self._store, key)
        if d is not None and d.get("messageId") == e.message_id:
            self._store.delete(key)

    def busy(self, peer: str, thread_id: str) -> str | None:
        """The messageId of the rule-governed message in flight to ``peer`` on ``thread_id``, or
        None. While set, enqueueing another rule-governed message on the thread fails
        ``thread_busy`` and the Inbox rejects the peer's rule-governed messages on it."""
        key = _thread_key(peer, thread_id)
        d = load_record(self._store, key)
        if d is None:
            return None
        mid = d.get("messageId") if isinstance(d, dict) else None
        if not is_message_id(mid):
            raise ACEError("storage_failed", f"{key} is not a valid thread lock")
        e = self._load(mid)
        ok = (
            e is not None
            and e.status == "pending"
            and e.to == peer
            and e.content.get("threadId") == thread_id
        )
        return mid if ok else None

    # --- API ---

    def enqueue(
        self,
        to: str,
        type_: str,
        body: dict,
        *,
        thread_id: str | None = None,
        message_id: str | None = None,
    ) -> str:
        """Validate (installed schema, a resolvable descriptor for ``to``, a free thread, profile
        rules ``check``), persist and return the ``messageId``. The rules' ``commit`` runs on the
        ``delivered`` receipt. Receipts and contact requests are never queued."""
        if not is_ace_id(to) or to == self._identity.get_ace_id():
            raise ACEError("invalid_argument", "to must be another ACE ID")
        if type_ in (RECEIPT_TYPE, CONTACT_TYPE):
            raise ACEError("invalid_argument", "receipts and contact requests are not queued")
        if thread_id is not None and not is_thread_id(thread_id):
            raise ACEError(
                "invalid_argument", "thread_id must be 1..256 characters without controls"
            )
        mid = str(uuid.uuid4()) if message_id is None else message_id
        if not is_message_id(mid):
            raise ACEError("invalid_argument", "message_id must be a lowercase UUIDv4")
        if type(body) is not dict:
            raise ACEError("invalid_body", "body must be a JSON object")
        check_json_value({"body": body})  # depth counted from the content root, as receivers do
        body = copy.deepcopy(body)
        digest = self._profiles.message_digest(type_)
        self._profiles.validate(type_, digest, body)
        content: dict = {"type": type_, "schemaDigest": digest, "body": body}
        if thread_id is not None:
            content["threadId"] = thread_id
        # size check before anything is stored; every packet carries a prekey of this length
        encode_content(type_, digest, body, thread_id, prekey=bytes(KEM_PUBLIC_KEY_SIZE))
        now = self._now()
        event = MessageEvent("send", mid, self._identity.get_ace_id(), to, now, type_, thread_id)
        if self._resolve_peer is not None:
            try:
                self._resolve_peer(to)
            except ACEError as exc:
                if exc.is_transient:
                    raise
                raise ACEError(
                    "unknown_peer", "no descriptor can be resolved for the recipient"
                ) from exc
        entry = OutboxEntry(mid, to, content, now, "pending", 0, now, None, None, None)
        with self._store.lock("outbox"):
            if self._load(mid) is not None:
                raise ACEError("invalid_argument", "message_id is already queued")
            tid = self._thread(entry)
            if tid is not None and self.busy(to, tid) is not None:
                raise ACEError("thread_busy", "a message on this thread is awaiting its receipt")
            run_check(self._rules, event, body)
            if tid is not None:  # lock first: a lock without its entry reads as free
                write_record(self._store, _thread_key(to, tid), {"messageId": mid})
            write_record(self._store, _pending_key(mid), {"messageId": mid})  # index first
            self._save(entry)
        return mid

    def get(self, message_id: str) -> OutboxEntry | None:
        return self._load(message_id)

    def _scan(self) -> list[OutboxEntry]:
        records = (load_record(self._store, k) for k in self._store.list("outbox/"))
        return [OutboxEntry.from_dict(d) for d in records if d is not None]

    def _pending(self) -> list[OutboxEntry]:
        """The pending entries, via the index (stale markers are removed)."""
        out = []
        for key in self._store.list("outbox-pending/"):
            d = load_record(self._store, key)
            mid = d.get("messageId") if isinstance(d, dict) else None
            if not is_message_id(mid) or key != _pending_key(mid):
                raise ACEError("storage_failed", f"{key} is not a valid pending marker")
            e = self._load(mid)
            if e is not None and e.status == "pending":
                out.append(e)
            else:
                with self._store.lock("outbox"):
                    cur = self._load(mid)
                    if cur is None or cur.status != "pending":
                        self._store.delete(key)
        return out

    def entries(self, status: Status | None = None) -> list[OutboxEntry]:
        out = (
            self._pending()
            if status == "pending"
            else [e for e in self._scan() if status is None or e.status == status]
        )
        return sorted(out, key=lambda e: (e.created_at, e.message_id))

    def settle(
        self,
        message_id: str,
        outcome: str,
        code: str | None = None,
        *,
        sender: str | None = None,
        prekey: str | None = None,
    ) -> OutboxEntry | None:
        """Apply a receipt from ``sender``; returns the entry it matched (None for none).
        ``rejected:unknown_prekey`` is not final: when it names the held peer prekey the next
        attempt drops it; otherwise the next attempt refreshes the descriptor, and only if the
        published prekey is unchanged is it final. It counts only when its ``prekey`` is the
        prekey of the latest attempt, and only once (a
        late or replayed receipt is ignored, 06 § Outbox). An ``expired`` entry's outcome is
        unknown, so its receipt still settles it (except ``unknown_prekey``: nothing retries)."""
        with self._store.lock("outbox"):
            e = self._load(message_id) if is_message_id(message_id) else None
            if (
                e is None
                or e.status not in ("pending", "expired")
                or (sender is not None and sender != e.to)
            ):
                return None
            if outcome != "delivered" and code == "unknown_prekey":
                if e.status == "expired" or prekey is None or prekey != e.prekey or e.refresh:
                    return e  # another attempt's receipt, or already applied
                e = e.replace(refresh=True, next_attempt_at=self._now(), code=code)
                self._save(e)
                return e
            if outcome == "delivered":
                # Commit the send-side rules now (idempotent per messageId). A storage failure
                # leaves the entry pending so the receipt is processed again; a permanent rule
                # failure cannot undo the delivery and is not retried.
                c = e.content
                event = MessageEvent(
                    "send",
                    e.message_id,
                    self._identity.get_ace_id(),
                    e.to,
                    e.created_at,
                    c["type"],
                    c.get("threadId"),
                )
                try:
                    run_commit(self._rules, event, copy.deepcopy(c["body"]))
                except ACEError as exc:
                    if exc.is_transient:
                        raise
                e = e.replace(
                    status="delivered", code=None, in_flight_at=None, settled_at=self._now()
                )
                self._save(e)
                return e
            e = e.replace(status="rejected", code=code, in_flight_at=None, settled_at=self._now())
            self._save(e)
            return e

    def abandon(self, message_id: str) -> None:
        """Stop attempting a pending entry locally (``expired``: outcome unknown, a late receipt
        still settles it)."""
        with self._store.lock("outbox"):
            e = self._load(message_id) if is_message_id(message_id) else None
            if e is not None and e.status == "pending":
                self._expire(e)

    def deliver(
        self,
        message_id: str,
        transport: Transport,
        resolve: Resolver,
        *,
        force: bool = False,
    ) -> Attempt:
        """One attempt now (when due, or ``force``): resolve the recipient, encrypt (the first
        attempt to the peer prekey held for it, else to its current published prekey, offering
        ours), sign with a fresh timestamp and hand the packet to ``transport``. A
        ``rejected:unknown_prekey`` naming the held key drops it. An attempt after the first
        refreshes the descriptor and adds the ``admission`` hook's result to the
        content, unless that would exceed ``MAX_PLAINTEXT_BYTES`` (05 § Admission recovery)."""
        now = self._now()
        with self._store.lock("outbox"):
            e = self._load(message_id)
            if e is None:
                raise ACEError("invalid_argument", "no such outbox entry")
            if e.status != "pending":
                return Attempt(message_id, "skipped", e.status)
            if e.overdue(now):
                self._expire(e)
                return Attempt(message_id, "skipped", "expired")
            if e.in_flight_at is not None and now - e.in_flight_at < IN_FLIGHT_TIMEOUT_SECONDS:
                return Attempt(message_id, "skipped", "pending")
            if not force and now < e.next_attempt_at:
                return Attempt(message_id, "skipped", "pending")
            first_attempt_at = e.first_attempt_at
            e = e.replace(in_flight_at=now, first_attempt_at=first_attempt_at or now)
            self._save(e)
        error: ACEError | None = None
        used = e.prekey
        retry = e.attempts > 0
        peer_rejected = False
        extra: Admission | None = None
        try:
            # 06 § Outbox step 1: a retry refreshes any cached descriptor; if that fails, a cached
            # one still unexpired and bound to the pins is used. A refresh after an
            # `unknown_prekey` naming our published prekey never falls back.
            if not retry:
                agent = resolve(e.to, False)
            else:
                try:
                    agent = resolve(e.to, True)
                except ACEError:
                    agent = resolve(e.to, False)
                    if e.refresh and not self._held_is(e.to, agent, e.prekey, now):
                        raise
            # 04 § Peer prekeys: the key held for `to` while bound to its current pin. A
            # rejection naming it drops it (the retry then goes to the published prekey).
            held = self._vault.held(e.to, agent.state.last_hash, now)
            peer_rejected = e.refresh and held is not None and held.id == e.prekey
            if peer_rejected:
                self._vault.drop_held(e.to)
            elif e.refresh and agent.prekey.id == e.prekey:
                with self._store.lock("outbox"):
                    cur = self._load(message_id)
                    if cur is None:
                        raise ACEError("storage_failed", "outbox entry vanished during an attempt")
                    # A receipt may have settled the entry while the refresh was in flight: a
                    # settled outcome is final, so only a still-pending refresh is rejected.
                    if cur.status == "pending" and cur.refresh:
                        cur = cur.replace(
                            status="rejected", code="unknown_prekey", settled_at=self._now()
                        )
                    self._save(cur.replace(in_flight_at=None))
                return Attempt(message_id, "skipped", cur.status)
            # 06 § Outbox step 2: the first attempt to the held peer prekey, else (and every
            # later attempt) to the published one; every packet offers our peer prekey for `to`.
            prekey = agent.prekey if retry or held is None else held
            used = prekey.id
            c = e.content
            args = (c["type"], c["schemaDigest"], c["body"], c.get("threadId"))
            offered = self._vault.offer(e.to, now).public_key
            extra = self._admission(e.to, now) if retry and self._admission is not None else None
            try:
                plaintext = encode_content(
                    *args, prekey=offered, admission=None if extra is None else extra.content
                )
            except ACEError as exc:
                if extra is None or exc.code != "limit_exceeded":
                    raise
                extra = None  # too large with it: sent without
                plaintext = encode_content(*args, prekey=offered)
            packet = create_packet(
                self._identity,
                e.to,
                prekey,
                plaintext,
                timestamp=now,
                message_id=e.message_id,
            )
            if extra is None:
                transport(packet, agent)
            else:
                transport(packet, agent, admission=extra)
        except ACEError as exc:
            error = exc
        except Exception as exc:  # a host transport bug is retried like an outage
            error = ACEError("relay_unavailable", f"transport failed: {type(exc).__name__}: {exc}")
        except BaseException:
            # An interrupt (the host stopping) is not an attempt: release the lease, leave the
            # entry as it was
            with self._store.lock("outbox"):
                cur = self._load(message_id)
                if cur is not None:
                    self._save(cur.replace(in_flight_at=None, first_attempt_at=first_attempt_at))
            raise
        with self._store.lock("outbox"):
            cur = self._load(message_id)
            if cur is None:
                raise ACEError("storage_failed", "outbox entry vanished during an attempt")
            attempts = cur.attempts + 1
            if cur.status != "pending":
                cur = cur.replace(in_flight_at=None)
            elif cur.refresh and not e.refresh:
                # A rejected:unknown_prekey receipt arrived while this attempt was in flight:
                # keep its prekey, code and immediate retry instead of overwriting them.
                cur = cur.replace(attempts=attempts, in_flight_at=None)
            else:
                cur = cur.replace(
                    attempts=attempts,
                    next_attempt_at=now
                    + min(
                        max(backoff(attempts), (error.retry_after_seconds or 0) if error else 0),
                        OUTBOX_MAX_BACKOFF_SECONDS,
                    ),
                    in_flight_at=None,
                    code=None if error is None else error.code,
                    prekey=used if error is None else cur.prekey,
                    # a rejection of the held key is settled once it is dropped
                    refresh=cur.refresh and error is not None and not peer_rejected,
                )
            self._save(cur)
        if error is not None:
            return Attempt(message_id, "failed", cur.status, error)
        return Attempt(message_id, "sent", cur.status)

    def _held_is(self, to: str, agent: Any, prekey: str | None, now: int) -> bool:
        """Whether ``prekey`` is the peer prekey held for ``to`` under ``agent``'s pin."""
        held = self._vault.held(to, agent.state.last_hash, now)
        return held is not None and held.id == prekey

    def flush(self, transport: Transport, resolve: Resolver) -> list[Attempt]:
        """``deliver`` every pending entry that is due."""
        now = self._now()
        return [
            self.deliver(e.message_id, transport, resolve)
            for e in self.entries("pending")
            if now >= e.next_attempt_at or e.overdue(now)
        ]

    def prune(self) -> int:
        """Delete settled (``delivered``, ``rejected``) and ``expired`` entries once
        ``OFFLINE_WINDOW_SECONDS`` have passed since they settled or expired (06 § Outbox), so
        ``get``/``entries`` keep reporting an outcome for that long. Returns the number deleted."""
        now, n = self._now(), 0
        with self._store.lock("outbox"):
            for e in self._scan():
                done_at = e.settled_at if e.status in ("delivered", "rejected") else e.expired_at
                if e.status != "pending" and now - (done_at or 0) >= OFFLINE_WINDOW_SECONDS:
                    self._store.delete(_key(e.message_id))
                    self._store.delete(_pending_key(e.message_id))
                    n += 1
        return n
