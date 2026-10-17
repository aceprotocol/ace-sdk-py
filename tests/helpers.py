"""Shared test helpers."""

from __future__ import annotations

import json
from contextlib import contextmanager
from decimal import Decimal
from fractions import Fraction

import pytest

from ace import (
    ACEError,
    MemoryStore,
    PeerStore,
    PrekeyVault,
    SoftwareIdentity,
    create_published_agent,
)

NOW = 1760140800
# injected clocks that are not non-negative integer Unix seconds within 2^53-1
BAD_CLOCK_VALUES = (
    float("nan"),
    float("inf"),
    float("-inf"),
    -1,
    -0.5,
    True,
    False,
    "1",
    None,
    1 << 53,
    Fraction(10**400),
    Fraction(10**400 + 1, 3),
    Fraction(-1, 2),
    Decimal("NaN"),
    Decimal("1"),
)


@contextmanager
def raises(code: str):
    with pytest.raises(ACEError) as info:
        yield info
    assert info.value.code == code, f"expected {code}, got {info.value.code}: {info.value.message}"


class Clock:
    """A settable test clock."""

    def __init__(self, now: int = NOW) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


class Party:
    """An identity with its store, prekey vault and peer store (no network)."""

    def __init__(self, clock: Clock, relay: str = "https://relay.example", **descriptor) -> None:
        self.clock = clock
        self.identity = SoftwareIdentity.generate(now=clock.now - 10)
        self.id = self.identity.get_ace_id()
        self.store = MemoryStore()
        self.vault = PrekeyVault()
        self.vault.current(clock.now - 10)
        self.peers = PeerStore(self.store, clock=clock)
        self.relay = relay
        self.descriptor = descriptor

    def source(self, **overrides) -> dict:
        kw = {
            "relays": [self.relay],
            "prekey": self.vault.current(),
            "profiles": [],
            "now": self.clock.now,
            **self.descriptor,
        }
        kw.update(overrides)
        return create_published_agent(self.identity, **kw)


def wire(packet: dict) -> bytes:
    return json.dumps(packet, separators=(",", ":")).encode()


def open_packet(packet, sender, vault, *, now: int):
    """Decode, verify (06 steps 4-5), decrypt and decode a packet (schema checks are the
    caller's). A test helper: the Inbox runs the full pipeline."""
    from ace import PrivateMessage, decode_content, decode_packet, decrypt_packet, verify_packet
    from ace.packet import check_window

    p = decode_packet(packet) if isinstance(packet, dict) else packet
    verify_packet(p, sender, now)
    check_window(p, now)
    return PrivateMessage.of(p, decode_content(decrypt_packet(p, vault, now)))


def retained(vault) -> list[str]:
    """The superseded prekey IDs a vault still holds (white-box)."""
    return [r.prekey.id for r in vault._state.retired]
