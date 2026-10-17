"""Profile rule hooks: application state (e.g. commerce threads) without core branches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, Sequence, runtime_checkable

from ._encoding import conversation_key
from .errors import ACEError


@dataclass(frozen=True)
class MessageEvent:
    """One message seen by a rule. ``direction`` is ``send`` (Outbox, before encryption) or
    ``receive`` (Inbox, after schema checks)."""

    direction: Literal["send", "receive"]
    message_id: str
    from_id: str
    to_id: str
    timestamp: int
    type: str
    thread_id: str | None

    @property
    def conversation(self) -> str:
        return conversation_key(self.from_id, self.to_id)


@runtime_checkable
class ProfileRules(Protocol):
    """``check`` raises an ``ACEError`` to refuse a message (never mutates); ``commit`` records
    it inside the persistence step (on receive with the delivery record; on send when the peer's
    ``delivered`` receipt arrives, never at enqueue). ``commit`` MUST be idempotent per
    ``(direction, from_id, message_id)``: crash recovery, a re-sent duplicate and a repeated
    receipt all run it again (06 § Crash recovery). On receive a permanent ``ACEError`` from
    ``commit`` aborts the delivery (``rejected:<code>``); any other failure is retried."""

    types: frozenset[str]

    def check(self, event: MessageEvent, body: dict) -> None: ...

    def commit(self, event: MessageEvent, body: dict) -> None: ...


def check_rules(rules: object) -> tuple[ProfileRules, ...]:
    if rules is None:
        return ()
    if not isinstance(rules, (list, tuple)) or not all(isinstance(r, ProfileRules) for r in rules):
        raise ACEError("invalid_argument", "rules must be a sequence of ProfileRules")
    return tuple(rules)


def governed(rules: Sequence[ProfileRules], type_: str) -> bool:
    """True when some rule governs ``type_``."""
    return any(type_ in r.types for r in rules)


def run_check(rules: Sequence[ProfileRules], event: MessageEvent, body: dict) -> None:
    for r in rules:
        if event.type in r.types:
            r.check(event, body)


def run_commit(rules: Sequence[ProfileRules], event: MessageEvent, body: dict) -> None:
    for r in rules:
        if event.type in r.types:
            r.commit(event, body)
