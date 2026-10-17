"""Optional ``ace:commerce:1`` profile: thread state machine, settlement shapes, descriptor ext.

Install with ``Profiles([TEXT, COMMERCE])`` and pass ``commerce_rules(store, ace_id)`` to the
Inbox and Outbox. A received commerce message never authorizes a payment: paying is the
application's decision.

States: ``idle -> requested -> offered -> accepted | rejected``, ``accepted -> invoiced -> paid
-> delivered -> confirmed`` (``accepted`` may also go straight to ``paid`` or ``delivered``).
The first message's sender is the buyer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._encoding import CAIP19_RE, canonical_state_bytes, is_ace_id, is_https_url, sha256_hex
from .errors import ACEError
from .rules import MessageEvent
from .store import ACEStore, load_record, write_record

PROFILE_ID = "ace:commerce:1"
RFQ, OFFER, ACCEPT, REJECT, INVOICE, PAYMENT, DELIVER, CONFIRM = (
    f"ace:commerce:{n}:1"
    for n in ("rfq", "offer", "accept", "reject", "invoice", "payment", "deliver", "confirm")
)
COMMERCE_TYPES = frozenset({RFQ, OFFER, ACCEPT, REJECT, INVOICE, PAYMENT, DELIVER, CONFIRM})

# (state, type) -> (next state, sender role)
TRANSITIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("idle", RFQ): ("requested", "buyer"),
    ("requested", OFFER): ("offered", "seller"),
    ("requested", REJECT): ("rejected", "seller"),
    ("offered", OFFER): ("offered", "seller"),
    ("offered", ACCEPT): ("accepted", "buyer"),
    ("offered", REJECT): ("rejected", "buyer"),
    ("accepted", INVOICE): ("invoiced", "seller"),
    ("accepted", PAYMENT): ("paid", "buyer"),
    ("accepted", DELIVER): ("delivered", "seller"),
    ("invoiced", PAYMENT): ("paid", "buyer"),
    ("paid", DELIVER): ("delivered", "seller"),
    ("delivered", CONFIRM): ("confirmed", "buyer"),
}
TERMINAL_STATES = frozenset({"rejected", "confirmed"})
# type -> (body field, history position it must reference)
_REFERENCES = {
    ACCEPT: ("offerId", -1),
    INVOICE: ("offerId", -2),
    PAYMENT: ("referenceId", -1),
    CONFIRM: ("deliverId", -1),
}
MAX_HISTORY_PER_THREAD = 1000
MAX_OPEN_THREADS_PER_PEER = 1000  # non-terminal threads per peer


def _bad(msg: str) -> ACEError:
    return ACEError("invalid_body", msg)


def _nonempty(v: object) -> bool:
    return isinstance(v, str) and len(v) > 0


def validate_settlement(type_: str, body: dict) -> None:
    """Rule-level body constraints (``invalid_body``): exact settlement shapes for ``invoice`` /
    ``payment`` and the ``deliver`` content rule."""
    if type_ == INVOICE:
        s = body["settlement"]
        if s.get("method") == "stablecoin":
            if (
                not {"method", "asset", "recipient"}
                <= set(s)
                <= {"method", "asset", "recipient", "memo"}
            ):
                raise _bad("stablecoin settlement is {method, asset, recipient, memo?}")
            if CAIP19_RE.fullmatch(s["asset"]) is None or not _nonempty(s["recipient"]):
                raise _bad("stablecoin settlement needs a CAIP-19 asset and a non-empty recipient")
        elif set(s) != {"method", "url"} or not is_https_url(s["url"]):
            raise _bad("stripe-link settlement is {method, url: <ACE HTTPS URL>}")
    elif type_ == PAYMENT:
        s = body["settlement"]
        want = "txHash" if s["method"] == "stablecoin" else "paymentId"
        if set(s["proof"]) != {want} or not _nonempty(s["proof"][want]):
            raise _bad(f"{s['method']} payment proof must be {{{want}}}, non-empty")
    elif type_ == DELIVER:
        need = "content" if body["type"] == "inline" else "uri"
        if not isinstance(body.get(need), str):
            raise _bad(f"deliver ({body['type']}) requires {need}")


def validate_commerce_ext(value: object) -> dict:
    """Descriptor ``ext["ace:commerce:1"]``: closed ``{settlement}`` with 1-10 distinct entries,
    each ``{method: "stablecoin", asset: CAIP-19}`` or ``{method: "stripe-link"}``."""
    if not isinstance(value, dict) or set(value) != {"settlement"}:
        raise ACEError("invalid_authorization", "commerce ext must be {settlement}")
    items = value["settlement"]
    if not isinstance(items, list) or not 1 <= len(items) <= 10:
        raise ACEError("invalid_authorization", "commerce ext settlement must hold 1-10 entries")
    for it in items:
        stable = (
            isinstance(it, dict)
            and set(it) == {"method", "asset"}
            and it["method"] == "stablecoin"
            and isinstance(it["asset"], str)
            and CAIP19_RE.fullmatch(it["asset"]) is not None
        )
        if not stable and it != {"method": "stripe-link"}:
            raise ACEError("invalid_authorization", "invalid commerce settlement entry")
    if len({canonical_state_bytes(it) for it in items}) != len(items):
        raise ACEError("invalid_authorization", "commerce settlement entries must be distinct")
    return value


@dataclass(frozen=True)
class ThreadSnapshot:
    conversation: str
    thread_id: str
    peer: str
    state: str
    history: tuple[dict, ...]

    @property
    def buyer(self) -> str:
        return self.history[0]["from"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation": self.conversation,
            "threadId": self.thread_id,
            "peer": self.peer,
            "state": self.state,
            "history": list(self.history),
        }


def _thread_key(conversation: str, thread_id: str) -> str:
    return f"commerce/threads/{sha256_hex(conversation, thread_id)}.json"


def _open_prefix(peer: str) -> str:
    return f"commerce/open/{sha256_hex(peer)}/"


def _open_key(peer: str, conversation: str, thread_id: str) -> str:
    return f"{_open_prefix(peer)}{sha256_hex(conversation, thread_id)}.json"


class ThreadStore:
    """Commerce threads keyed by (local pair key, threadId); lock ``commerce``.

    Open (non-terminal) threads also carry a marker under ``commerce/open/<peer>/``, so the
    per-peer limit costs one listing rather than a read of every thread. The markers are a
    superset: written before a new thread, removed after it ends."""

    def __init__(self, store: ACEStore, local_ace_id: str) -> None:
        if not is_ace_id(local_ace_id):
            raise ACEError("invalid_argument", "local_ace_id must be an ACE ID")
        self._store = store
        self.local = local_ace_id

    def _mark(self, peer: str, conversation: str, thread_id: str) -> None:
        write_record(
            self._store,
            _open_key(peer, conversation, thread_id),
            {"conversation": conversation, "threadId": thread_id},
        )

    @staticmethod
    def _snapshot(d: dict) -> ThreadSnapshot:
        return ThreadSnapshot(
            d["conversation"], d["threadId"], d["peer"], d["state"], tuple(d["history"])
        )

    def get(self, conversation: str, thread_id: str) -> ThreadSnapshot | None:
        d = load_record(self._store, _thread_key(conversation, thread_id))
        return None if d is None else self._snapshot(d)

    def list(self) -> list[ThreadSnapshot]:
        records = (load_record(self._store, k) for k in self._store.list("commerce/threads/"))
        return [self._snapshot(d) for d in records if d is not None]

    def _open_with(self, peer: str) -> int:
        keys = self._store.list(_open_prefix(peer))
        if len(keys) < MAX_OPEN_THREADS_PER_PEER:
            return len(keys)  # an upper bound below the limit is enough
        count = 0  # at the limit: stale markers (a crash mid-apply) must not count
        for key in keys:
            d = load_record(self._store, key)
            t = None if d is None else self.get(d["conversation"], d["threadId"])
            if t is not None and t.peer == peer and t.state not in TERMINAL_STATES:
                count += 1
        return count

    def decide(self, e: MessageEvent, body: dict) -> tuple[str, ThreadSnapshot | None]:
        """Check order: threadId (and rule-level body shapes), parties, transition, role,
        reference, bounds."""
        if e.thread_id is None:
            raise _bad("commerce messages require a threadId")
        validate_settlement(e.type, body)
        if self.local not in (e.from_id, e.to_id) or e.from_id == e.to_id:
            raise ACEError("wrong_party", "the local identity is not exactly one party")
        t = self.get(e.conversation, e.thread_id)
        peer = e.to_id if e.from_id == self.local else e.from_id
        if t is not None and t.peer != peer:
            raise ACEError("wrong_party", "message is not between the thread's two parties")
        state = "idle" if t is None else t.state
        rule = None if state in TERMINAL_STATES else TRANSITIONS.get((state, e.type))
        if rule is None:
            raise ACEError("transition_not_allowed", f"{e.type} is not allowed in state {state}")
        next_state, role = rule
        if t is not None and ("buyer" if e.from_id == t.buyer else "seller") != role:
            raise ACEError("wrong_role", f"{e.type} in state {state} must come from the {role}")
        if e.type in _REFERENCES:
            field, pos = _REFERENCES[e.type]
            assert t is not None
            if body.get(field) != t.history[pos]["messageId"]:
                raise ACEError(
                    "bad_reference", f"{e.type}.{field} does not reference the required message"
                )
        if t is None:
            if self._open_with(peer) >= MAX_OPEN_THREADS_PER_PEER:
                raise ACEError("limit_exceeded", "too many open threads with this peer")
        elif len(t.history) >= MAX_HISTORY_PER_THREAD:
            raise ACEError("limit_exceeded", "thread history limit reached")
        return next_state, t

    def apply(self, e: MessageEvent, body: dict) -> str:
        """Idempotent per ``message_id``; returns the resulting state."""
        with self._store.lock("commerce"):
            t = self.get(e.conversation, e.thread_id or "")
            if t is not None and any(h["messageId"] == e.message_id for h in t.history):
                return t.state
            next_state, t = self.decide(e, body)
            entry = {
                "type": e.type,
                "messageId": e.message_id,
                "timestamp": e.timestamp,
                "from": e.from_id,
            }
            peer = e.to_id if e.from_id == self.local else e.from_id
            history = (t.history if t else ()) + (entry,)
            snap = ThreadSnapshot(e.conversation, e.thread_id, peer, next_state, history)  # type: ignore[arg-type]
            done = next_state in TERMINAL_STATES
            if t is None and not done:
                self._mark(peer, snap.conversation, snap.thread_id)  # marker first
            write_record(
                self._store, _thread_key(snap.conversation, snap.thread_id), snap.to_dict()
            )
            if done:
                self._store.delete(_open_key(peer, snap.conversation, snap.thread_id))
            return next_state


class CommerceRules:
    """``ProfileRules`` for ``ace:commerce:1`` backed by a ``ThreadStore``."""

    types = COMMERCE_TYPES

    def __init__(self, threads: ThreadStore) -> None:
        self.threads = threads

    def check(self, event: MessageEvent, body: dict) -> None:
        self.threads.decide(event, body)

    def commit(self, event: MessageEvent, body: dict) -> None:
        self.threads.apply(event, body)


def commerce_rules(store: ACEStore, local_ace_id: str) -> CommerceRules:
    """The commerce state machine as a profile rule, persisted in ``store``."""
    return CommerceRules(ThreadStore(store, local_ace_id))
