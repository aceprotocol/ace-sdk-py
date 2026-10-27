"""PrekeyVault: the receiver's X-Wing prekey seeds (current + retained superseded ones).

A superseded seed is kept for ``OFFLINE_WINDOW_SECONDS`` after the moment it was superseded
(at most ``MAX_RETAINED_PREKEYS``), then deleted: that retention is the forward-secrecy window.
Seeds are secrets at the level of identity seeds: the file backend writes a 0600 file
atomically and refuses a file that is a symlink, accessible to group/others or not ours.
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
    """A content ``prekey`` member: canonical Base64 of 1216 bytes, else ``invalid_body``."""
    return decode_fixed_b64(b64, KEM_PUBLIC_KEY_SIZE, "invalid_body", "prekey")


@dataclass
class _Entry:
    seed: bytes
    at: int  # createdAt for the current prekey, supersededAt for a retired one
    key: _xwing.DecapsulationKey
    prekey: Prekey


def _entry(seed: bytes, at: int) -> _Entry:
    key = _xwing.DecapsulationKey(seed)
    return _Entry(seed, at, key, Prekey(prekey_id(key.public_key), key.public_key))


class _State(NamedTuple):
    current: _Entry | None
    retired: list[_Entry]


class PrekeyVault:
    """``current()``, ``rotate(now)``, ``open(prekey_id)``, ``prune(now)``.

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
        self._state = _State(None, [])
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
            return _State(None, [])
        except OSError as exc:
            raise ACEError("storage_failed", f"cannot open prekey file: {exc}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.geteuid():
                raise ACEError("storage_failed", "prekey file must be our regular 0600 file")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                raw = fh.read(1 << 20)
        finally:
            os.close(fd)
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict) or data.get("version") != 1:
                raise ValueError("version")
            cur = data["current"]
            return _State(
                None if cur is None else self._parse(cur, "createdAt"),
                [self._parse(r, "supersededAt") for r in data["retired"]],
            )
        except (ValueError, KeyError, TypeError, ACEError) as exc:
            raise ACEError("storage_failed", f"prekey file is invalid: {exc}") from None

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
                "version": 1,
                "current": None
                if state.current is None
                else {"seed": to_base64(state.current.seed), "createdAt": state.current.at},
                "retired": [
                    {"seed": to_base64(r.seed), "supersededAt": r.at} for r in state.retired
                ],
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
        self._entries = {
            e.seed: e for e in ([state.current] if state.current else []) + state.retired
        }

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
                self._commit(_State(_entry(os.urandom(KEM_SEED_SIZE), at), s.retired))
            assert self._state.current is not None
            return self._state.current.prekey

    def rotate(self, now: int) -> Prekey:
        """Generate a new current prekey; the old one is retained until ``now + OFFLINE``."""
        now = check_wire_int(now, "now")
        with self._locked() as s:
            retired = s.retired + ([replace(s.current, at=now)] if s.current else [])
            fresh = _entry(os.urandom(KEM_SEED_SIZE), now)
            self._commit(_State(fresh, _live(retired, now)))
            return fresh.prekey

    def open(self, prekey_id: str, now: int | None = None) -> _xwing.DecapsulationKey:
        """The decapsulation key for ``prekey_id``, or ``unknown_prekey``. A retired prekey whose
        retention has ended is refused even before it is deleted; expired seeds are pruned here
        opportunistically (04 § Prekey)."""
        if not is_sha256_hex(prekey_id):
            raise ACEError("unknown_prekey", "prekey id must be 64 lowercase hex")
        t = self._time(now)
        with self._locked() as s:
            live = _live(s.retired, t)
            if len(live) != len(s.retired):
                try:
                    self._commit(_State(s.current, live))
                except ACEError:
                    pass  # best effort: the expired seed is refused below either way
            for e in ([s.current] if s.current else []) + live:
                if e.prekey.id == prekey_id:
                    return e.key
        raise ACEError("unknown_prekey", "unknown or deleted prekey")

    def prune(self, now: int) -> None:
        """Delete retired seeds superseded ``OFFLINE_WINDOW_SECONDS`` or more ago."""
        now = check_wire_int(now, "now")
        with self._locked() as s:
            live = _live(s.retired, now)
            if len(live) != len(s.retired):
                self._commit(_State(s.current, live))


def _live(retired: list[_Entry], now: int) -> list[_Entry]:
    """The retired entries still within retention, newest ``MAX_RETAINED_PREKEYS``."""
    keep = [r for r in retired if now < r.at + OFFLINE_WINDOW_SECONDS]
    return sorted(keep, key=lambda r: r.at)[-MAX_RETAINED_PREKEYS:]
