"""Helpers for Inbox / Outbox tests."""

from __future__ import annotations

from ace import ACEError, Inbox, MemoryStore, Outbox, PeerStore, SoftwareIdentity
from ace.registration import create_registration_file


class Clock:
    def __init__(self, t: int = 1_800_000_000) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t


class Host:
    """An idempotent host effect store keyed by (from, messageId), plus a raw call log."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.effects: dict[tuple[str, str], object] = {}
        self.fail = False

    def __call__(self, m) -> None:
        if self.fail:
            raise RuntimeError("host down")
        self.calls.append((m.from_id, m.message_id))
        self.effects.setdefault((m.from_id, m.message_id), m)


class CountingStore:
    """Wraps a store; ``fail_at`` makes the Nth write raise storage_failed (not applied)."""

    def __init__(self, inner, fail_at: int | None = None) -> None:
        self.inner = inner
        self.fail_at = fail_at
        self.writes: list[str] = []

    def read(self, key):
        return self.inner.read(key)

    def write(self, key, value):
        self.writes.append(key)
        if self.fail_at is not None and len(self.writes) == self.fail_at:
            raise ACEError("storage_failed", f"injected failure on write {self.fail_at} ({key})")
        self.inner.write(key, value)

    def delete(self, key):
        self.inner.delete(key)

    def list(self, prefix):
        return self.inner.list(prefix)

    def lock(self, name, timeout=10.0):
        return self.inner.lock(name, timeout)


def clone_memory(store: MemoryStore) -> MemoryStore:
    other = MemoryStore()
    other._data = dict(store._data)
    return other


class Agent:
    def __init__(self, name: str, scheme: str, clock: Clock, store=None, relay=None) -> None:
        self.name = name
        self.identity = SoftwareIdentity.generate(scheme)
        self.id = self.identity.get_ace_id()
        self.clock = clock
        self.store = store if store is not None else MemoryStore()
        self.peers = PeerStore(self.store, relay=relay, clock=clock)
        self.outbox = Outbox.open(self.identity, self.store, clock=clock, commerce=True)
        self.host = Host()
        self.inbox: Inbox | None = None

    def open(self, store=None, **kw) -> Inbox:
        self.inbox = Inbox.open(
            self.identity,
            store or self.store,
            PeerStore(store or self.store, relay=self.peers._relay, clock=self.clock),
            self.host,
            clock=self.clock,
            commerce=True,
            **kw,
        )
        return self.inbox

    def registration(self):
        return create_registration_file(
            self.identity, name=self.name, endpoint=f"https://{self.name}.example/ace", timestamp=0
        )

    def pin(self, other: "Agent"):
        return self.peers.pin_registration_file(other.registration())
