"""PrekeyVault: the endpoint's X-Wing prekey seeds (current + retained superseded ones), the
peer prekeys it offers each peer, and the peer prekey each peer offered it (04 § Peer prekeys).

A superseded seed is kept for ``OFFLINE_WINDOW_SECONDS`` after the moment it was superseded
(at most ``MAX_RETAINED_PREKEYS``), then deleted: that retention is the forward-secrecy window.
Per peer, the vault keeps at most an *offered* and an *in-use* seed (each deleted
``OFFLINE_WINDOW_SECONDS`` after it was last offered) and one *held* public key the peer offered
(bound to the pin state it was authenticated under). Seeds are secrets at the level of identity
seeds: the file backend writes a 0600 file atomically and refuses a file that is a symlink,
accessible to group/others or not ours.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Callable, Iterator, NamedTuple

from . import _xwing
from ._encoding import (
    check_wire_int,
    decode_fixed_b64,
    is_ace_id,
    is_sha256_hex,
    sha256_hex,
    to_base64,
    unix_now,
    wire_int,
)
from .errors import ACEError
from .limits import (
    KEM_PUBLIC_KEY_SIZE,
    KEM_SEED_SIZE,
    MAX_RETAINED_PREKEYS,
    OFFLINE_WINDOW_SECONDS,
)
from .store import flock_file, write_file_atomic

_LOCK_SECONDS = 10.0
_VERSION = 2
_MAX_FILE_BYTES = 64 << 20  # peer state grows with the number of peers


class Prekey(NamedTuple):
    """A public prekey as published in a descriptor."""

    id: str
    public_key: bytes

    def to_dict(self) -> dict:
        return {"id": self.id, "publicKey": to_base64(self.public_key)}


def prekey_id(public_key: bytes) -> str:
    """Lowercase hex SHA-256 of the 1216-byte X-Wing public key."""
    return sha256_hex(bytes(public_key))


def prekey_public_key(seed: bytes) -> bytes:
    """The 1216-byte X-Wing public key of a 32-byte prekey seed."""
    return _xwing.DecapsulationKey(seed).public_key


def decode_prekey_public_key(b64: object) -> bytes:
    """A content ``prekey`` member: canonical Base64 of an X-Wing public key, else
    ``invalid_body``. Checked here, at decode, so a key that cannot be encapsulated to is
    never held."""
    public = decode_fixed_b64(b64, KEM_PUBLIC_KEY_SIZE, "invalid_body", "prekey")
    _check_xwing_public_key(public, "invalid_body", "prekey")
    return public


def _check_xwing_public_key(public: bytes, code: str, what: str) -> None:
    try:
        _xwing.check_public_key(public)
    except ACEError:
        raise ACEError(code, f"{what} is not an X-Wing public key") from None


@dataclass
class _Entry:
    seed: bytes
    at: int  # createdAt for the current prekey, supersededAt for a retired one
    key: _xwing.DecapsulationKey
    prekey: Prekey


def _entry(seed: bytes, at: int) -> _Entry:
    key = _xwing.DecapsulationKey(seed)
    return _Entry(seed, at, key, Prekey(prekey_id(key.public_key), key.public_key))


class _Held(NamedTuple):
    """A peer's offered public key as held by us: the ``timestamp`` of the packet that carried it
    and the ``pin`` (last pinned KEL event digest) it was authenticated under."""

    prekey: Prekey
    timestamp: int
    pin: str


class _Peer(NamedTuple):
    offered: _Entry | None = None  # ``at`` = offeredAt
    in_use: _Entry | None = None  # ``at`` = offeredAt
    held: _Held | None = None


class _State(NamedTuple):
    current: _Entry | None
    retired: list[_Entry]
    peers: dict[str, _Peer]

    def with_peer(self, peer: str, p: _Peer) -> _State:
        """A copy with ``peer``'s state set to ``p`` (removed when ``p`` is empty)."""
        peers = dict(self.peers)
        if p == _Peer():
            peers.pop(peer, None)
        else:
            peers[peer] = p
        return self._replace(peers=peers)


def _seed_live(e: _Entry | None, now: int) -> bool:
    return e is not None and now < e.at + OFFLINE_WINDOW_SECONDS


class PrekeyVault:
    """``current()``, ``rotate(now)``, ``open(prekey_id, now, sender=)``, ``prune(now)``, and per
    peer ``offer``, ``used``, ``hold``, ``held``, ``drop_held`` (04 § Peer prekeys).

    ``PrekeyVault()`` keeps seeds in memory; ``PrekeyVault(path)`` persists them in a 0600 file
    that several processes may share (e.g. a send and a receive process): every operation holds
    the ``<path>.lock`` flock, reloads the file, writes the new state and only then adopts it.
    """

    def __init__(
        self, path: str | os.PathLike[str] | None = None, *, clock: Callable[[], int] | None = None
    ) -> None:
        self._path = None if path is None else os.path.abspath(os.fspath(path))
        self._clock = clock
        self._mutex = threading.Lock()
        self._state = _State(None, [], {})
        self._entries: dict[bytes, _Entry] = {}  # by seed: X-Wing key derivation once per seed
        with self._locked():
            pass

    # --- persistence ---

    @contextmanager
    def _locked(self) -> Iterator[_State]:
        """Hold the vault exclusively and yield the state as currently persisted."""
        with self._mutex:
            if self._path is None:
                yield self._state
                return
            fd = flock_file(self._path + ".lock", "prekeys", time.monotonic() + _LOCK_SECONDS)
            try:
                self._adopt(self._load())
                yield self._state
            finally:
                os.close(fd)

    def _load(self) -> _State:
        assert self._path is not None
        try:
            fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return _State(None, [], {})
        except OSError as exc:
            raise ACEError("storage_failed", f"cannot open prekey file: {exc}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.geteuid():
                raise ACEError("storage_failed", "prekey file must be our regular 0600 file")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                raw = fh.read(_MAX_FILE_BYTES + 1)
        finally:
            os.close(fd)
        try:
            if len(raw) > _MAX_FILE_BYTES:
                raise ValueError("too large")
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict) or data.get("version") != _VERSION:
                raise ValueError("version")
            if set(data) != {"version", "current", "retained", "peers"}:
                raise ValueError("members")
            cur, peers = data["current"], data["peers"]
            if not isinstance(peers, dict):
                raise ValueError("peers")
            return _State(
                None if cur is None else self._parse(cur, "createdAt"),
                [self._parse(r, "supersededAt") for r in data["retained"]],
                {_peer_key(k): self._parse_peer(v) for k, v in peers.items()},
            )
        except (ValueError, KeyError, TypeError, ACEError) as exc:
            raise ACEError("storage_failed", f"prekey file is invalid: {exc}") from None

    def _parse_peer(self, d: object) -> _Peer:
        if not isinstance(d, dict) or set(d) != {"offered", "inUse", "held"}:
            raise ValueError("peer")
        h = d["held"]
        held = None
        if h is not None:
            if (
                not isinstance(h, dict)
                or set(h) != {"publicKey", "timestamp", "pin"}
                or wire_int(h["timestamp"]) is None
                or not is_sha256_hex(h["pin"])
            ):
                raise ValueError("held")
            public = decode_fixed_b64(
                h["publicKey"], KEM_PUBLIC_KEY_SIZE, "storage_failed", "publicKey"
            )
            _check_xwing_public_key(public, "storage_failed", "held.publicKey")
            held = _Held(Prekey(prekey_id(public), public), h["timestamp"], h["pin"])
        return _Peer(
            None if d["offered"] is None else self._parse(d["offered"], "offeredAt"),
            None if d["inUse"] is None else self._parse(d["inUse"], "offeredAt"),
            held,
        )

    def _parse(self, d: object, at_key: str) -> _Entry:
        if not isinstance(d, dict) or set(d) != {"seed", at_key} or wire_int(d[at_key]) is None:
            raise ValueError("entry")
        seed = decode_fixed_b64(d["seed"], KEM_SEED_SIZE, "storage_failed", "seed")
        known = self._entries.get(seed)
        return _entry(seed, d[at_key]) if known is None else replace(known, at=d[at_key])

    def _commit(self, state: _State) -> None:
        """Persist ``state``, then adopt it: a failed write leaves the vault as it was."""
        if self._path is not None:
            data = {
                "version": _VERSION,
                "current": _dump(state.current, "createdAt"),
                "retained": [_dump(r, "supersededAt") for r in state.retired],
                "peers": {
                    k: {
                        "offered": _dump(p.offered, "offeredAt"),
                        "inUse": _dump(p.in_use, "offeredAt"),
                        "held": None
                        if p.held is None
                        else {
                            "publicKey": to_base64(p.held.prekey.public_key),
                            "timestamp": p.held.timestamp,
                            "pin": p.held.pin,
                        },
                    }
                    for k, p in state.peers.items()
                },
            }
            try:
                write_file_atomic(
                    self._path,
                    json.dumps(data, separators=(",", ":"), sort_keys=True).encode(),
                    f".{os.path.basename(self._path)}.{os.urandom(8).hex()}",
                )
            except OSError as exc:
                raise ACEError("storage_failed", f"cannot write prekey file: {exc}") from None
        self._adopt(state)

    def _adopt(self, state: _State) -> None:
        self._state = state
        seeds = [state.current, *state.retired]
        for p in state.peers.values():
            seeds += [p.offered, p.in_use]
        self._entries = {e.seed: e for e in seeds if e is not None}

    def _time(self, now: object) -> int:
        """``now`` as a wire integer (``invalid_argument``), or the clock when it is ``None``."""
        return unix_now(self._clock) if now is None else check_wire_int(now, "now")

    # --- API ---

    @property
    def current_created_at(self) -> int | None:
        with self._locked() as s:
            return None if s.current is None else s.current.at

    def current(self, now: int | None = None) -> Prekey:
        """The current prekey; the first call generates one (dated ``now``)."""
        at = self._time(now)
        with self._locked() as s:
            if s.current is None:
                self._commit(s._replace(current=_entry(os.urandom(KEM_SEED_SIZE), at)))
            assert self._state.current is not None
            return self._state.current.prekey

    def rotate(self, now: int) -> Prekey:
        """Generate a new current prekey; the old one is retained until ``now + OFFLINE``."""
        now = check_wire_int(now, "now")
        with self._locked() as s:
            retired = s.retired + ([replace(s.current, at=now)] if s.current else [])
            fresh = _entry(os.urandom(KEM_SEED_SIZE), now)
            self._commit(s._replace(current=fresh, retired=_live(retired, now)))
            return fresh.prekey

    def open(
        self, prekey_id: str, now: int | None = None, *, sender: str | None = None
    ) -> _xwing.DecapsulationKey:
        """The decapsulation key for ``prekey_id``, or ``unknown_prekey``: the published current
        or a retained prekey, else (only when ``sender`` is given) the peer prekey offered to
        ``sender`` or in use by it, while its window lasts. A retired prekey whose retention has
        ended is refused even before it is deleted; expired retired seeds, and an expired peer
        seed ``prekey_id`` names, are deleted here opportunistically (04 § Prekey, § Peer
        prekeys)."""
        if not is_sha256_hex(prekey_id):
            raise ACEError("unknown_prekey", "prekey id must be 64 lowercase hex")
        t = self._time(now)
        with self._locked() as s:
            live = _live(s.retired, t)
            if len(live) != len(s.retired):
                try:
                    self._commit(s._replace(retired=live))
                except ACEError:
                    pass  # best effort: the expired seed is refused below either way
            for e in ([s.current] if s.current else []) + live:
                if e.prekey.id == prekey_id:
                    return e.key
            p = s.peers.get(sender) if sender is not None else None
            seeds = [e for e in (p.offered, p.in_use) if e is not None] if p is not None else []
            for e in seeds:
                if e.prekey.id == prekey_id:
                    if _seed_live(e, t):
                        return e.key
                    assert sender is not None and p is not None
                    try:  # its window ended: delete it (best effort, refused below either way)
                        self._commit(self._state.with_peer(sender, _pruned(p, t)))
                    except ACEError:
                        pass
                    break
        raise ACEError("unknown_prekey", "unknown or deleted prekey")

    def prune(self, now: int) -> None:
        """Delete retired seeds superseded ``OFFLINE_WINDOW_SECONDS`` or more ago, and peer seeds
        and held keys whose window ended; a peer left with nothing is removed."""
        now = check_wire_int(now, "now")
        with self._locked() as s:
            peers = {k: q for k, p in s.peers.items() if (q := _pruned(p, now)) != _Peer()}
            pruned = s._replace(retired=_live(s.retired, now), peers=peers)
            if pruned != s:
                self._commit(pruned)

    # --- peer prekeys (04 § Peer prekeys) ---

    def offer(self, peer: str, now: int) -> Prekey:
        """The prekey offered to ``peer`` in a packet sent at ``now``: the current offered key
        while its window lasts (its window restarts at ``now``), else a fresh one."""
        _check_peer(peer)
        now = check_wire_int(now, "now")
        with self._locked() as s:
            p = s.peers.get(peer, _Peer())
            if p.offered is not None and _seed_live(p.offered, now):
                offered = replace(p.offered, at=now)
            else:
                offered = _entry(os.urandom(KEM_SEED_SIZE), now)
            if offered != p.offered:
                self._commit(s.with_peer(peer, p._replace(offered=offered)))
            return offered.prekey

    def used(self, peer: str, prekey_id: str, now: int) -> None:
        """A packet from ``peer`` opened under ``prekey_id``: when that is the offered key it
        becomes the in-use key (the previous in-use seed is deleted) and the next ``offer``
        generates a new one. Any other ID changes nothing."""
        _check_peer(peer)
        check_wire_int(now, "now")
        with self._locked() as s:
            p = s.peers.get(peer)
            if p is not None and p.offered is not None and p.offered.prekey.id == prekey_id:
                self._commit(s.with_peer(peer, p._replace(offered=None, in_use=p.offered)))

    def hold(self, peer: str, prekey: Prekey, timestamp: int, pin: str) -> None:
        """Record the prekey ``peer`` offered in a packet dated ``timestamp`` and authenticated
        under pin state ``pin``, unless the held key came from a packet at least as new."""
        _check_peer(peer)
        timestamp = check_wire_int(timestamp, "timestamp")
        if not is_sha256_hex(pin):
            raise ACEError("invalid_argument", "pin must be 64 lowercase hex")
        if (
            not isinstance(prekey, Prekey)
            or not isinstance(prekey.public_key, bytes)
            or len(prekey.public_key) != KEM_PUBLIC_KEY_SIZE
            or prekey_id(prekey.public_key) != prekey.id
        ):
            raise ACEError("invalid_argument", "prekey must be a 1216-byte key and its ID")
        with self._locked() as s:
            p = s.peers.get(peer, _Peer())
            if p.held is None or timestamp > p.held.timestamp:
                self._commit(s.with_peer(peer, p._replace(held=_Held(prekey, timestamp, pin))))

    def held(self, peer: str, pin: str, now: int) -> Prekey | None:
        """The key held for ``peer`` while ``pin`` is the pin state it is bound to and its window
        lasts; otherwise it is deleted and the answer is ``None``."""
        _check_peer(peer)
        now = check_wire_int(now, "now")
        with self._locked() as s:
            p = s.peers.get(peer)
            if p is None or p.held is None:
                return None
            if p.held.pin == pin and _held_live(p.held, now):
                return p.held.prekey
            self._commit(s.with_peer(peer, p._replace(held=None)))
            return None

    def drop_held(self, peer: str) -> None:
        """Delete the key held for ``peer`` (a block, or ``rejected:unknown_prekey`` naming it)."""
        _check_peer(peer)
        with self._locked() as s:
            p = s.peers.get(peer)
            if p is not None and p.held is not None:
                self._commit(s.with_peer(peer, p._replace(held=None)))


def _check_peer(peer: object) -> None:
    if not is_ace_id(peer):
        raise ACEError("invalid_argument", "peer must be an ACE ID")


def _peer_key(peer: object) -> str:
    if not is_ace_id(peer):
        raise ValueError("peer key")
    return peer  # type: ignore[return-value]


def _pruned(p: _Peer, now: int) -> _Peer:
    """``p`` without the seeds and held key whose window ended at ``now``."""
    return _Peer(
        p.offered if _seed_live(p.offered, now) else None,
        p.in_use if _seed_live(p.in_use, now) else None,
        p.held if p.held is not None and _held_live(p.held, now) else None,
    )


def _held_live(h: _Held, now: int) -> bool:
    return now < h.timestamp + OFFLINE_WINDOW_SECONDS


def _dump(e: _Entry | None, at_key: str) -> dict | None:
    return None if e is None else {"seed": to_base64(e.seed), at_key: e.at}


def _live(retired: list[_Entry], now: int) -> list[_Entry]:
    """The retired entries still within retention, newest ``MAX_RETAINED_PREKEYS``."""
    keep = [r for r in retired if now < r.at + OFFLINE_WINDOW_SECONDS]
    return sorted(keep, key=lambda r: r.at)[-MAX_RETAINED_PREKEYS:]
