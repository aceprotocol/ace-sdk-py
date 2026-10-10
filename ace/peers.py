"""Persistent peer bindings with the 02 rollback barrier (lock ``peers``)."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any, Callable, NamedTuple, TypeVar

from ._encoding import is_ace_id, to_base64, unix_now, wire_int
from .discovery import (
    AdoptOutcome,
    VerifiedPeer,
    _make_peer,
    adopt_decision,
    verify_peer_record,
    verify_registration_file,
)
from .errors import ACEError
from .principal import same_principal_claims, validate_principal_record
from .store import ACEStore, parse_record, write_record
from .threads import sha256_hex
from .types import PrincipalRecord, RegistrationFile

if TYPE_CHECKING:
    from .relay import RelayClient

DEFAULT_PEER_TTL_SECONDS = 86400
_VERIFIED_CACHE_SIZE = 256

_T = TypeVar("_T")


def _remember(cache: dict[tuple[str, bytes], _T], key: tuple[str, bytes], value: _T) -> _T:
    if len(cache) >= _VERIFIED_CACHE_SIZE:
        cache.clear()
    cache[key] = value
    return value


class PeerAdoption(NamedTuple):
    peer: VerifiedPeer
    outcome: AdoptOutcome


def _peer_key(ace_id: str) -> str:
    return f"peers/{sha256_hex(ace_id)}.json"


def _peer_to_record(peer: VerifiedPeer, fetched_at: int) -> dict[str, Any]:
    return {
        "aceId": peer.ace_id,
        "encryptionPublicKey": to_base64(peer.encryption_public_key),
        "fetchedAt": fetched_at,
        "profile": peer.profile.to_dict() if peer.profile is not None else None,
        "registeredAt": peer.registered_at,
        "registrationSignature": peer.registration_signature,
        "scheme": peer.scheme,
        "signingPublicKey": to_base64(peer.signing_public_key),
        "source": peer.source,
    }


def _peer_from_record(d: dict, key: str) -> tuple[VerifiedPeer, int]:
    """Re-verify a stored binding; any failure is ``storage_failed``."""
    try:
        source, fetched_at = d.get("source"), wire_int(d.get("fetchedAt"))
        if fetched_at is None:
            raise ACEError("invalid_peer", "fetchedAt must be an integer")
        if source not in ("relay", "registration"):
            raise ACEError("invalid_peer", "unknown source")
        record = {
            k: d.get(k)
            for k in (
                "aceId",
                "scheme",
                "encryptionPublicKey",
                "signingPublicKey",
                "registrationSignature",
                "registeredAt",
                "profile",
            )
        }
        verified = verify_peer_record(record, clock=lambda: fetched_at)
        peer = _make_peer(
            ace_id=verified.ace_id,
            scheme=verified.scheme,
            signing_public_key=verified.signing_public_key,
            encryption_public_key=verified.encryption_public_key,
            registered_at=verified.registered_at,
            registration_signature=verified.registration_signature,
            source=source,
            profile=verified.profile,
        )
    except ACEError as exc:
        raise ACEError("storage_failed", f"{key}: {exc.message}") from None
    if key != _peer_key(peer.ace_id):
        raise ACEError("storage_failed", f"{key} does not match its aceId")
    return peer, fetched_at


class PeerStore:
    """Pinned peer bindings, refreshed from a relay.

    - ``get`` returns the pin regardless of age.
    - ``resolve`` returns a pin younger than ``max_age_seconds`` (default ``ttl_seconds``),
      otherwise looks the peer up on the relay and adopts it; when the relay is unavailable,
      does not know the peer or offers a stale binding, the existing pin is returned
      (unless ``max_age_seconds == 0``).
    - ``adopt`` enforces the rollback barrier: a different encryption key replaces the pin
      only with a relay-signed binding and a strictly newer ``registered_at``.

    ``VerifiedPeer.profile`` is relay metadata (self-asserted by the peer, unverified by
    the relay); only the keys are verified.
    """

    def __init__(
        self,
        store: ACEStore,
        *,
        relay: "RelayClient | None" = None,
        ttl_seconds: int = DEFAULT_PEER_TTL_SECONDS,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if type(ttl_seconds) is not int or ttl_seconds < 0:
            raise ACEError("invalid_argument", "ttl_seconds must be a non-negative integer")
        self._store = store
        self._relay = relay
        self._ttl = ttl_seconds
        self._clock = clock
        # Stored records are re-verified on every read; verification is a pure function of the
        # exact bytes, so its result is cached per (key, bytes) and a changed row re-verifies.
        self._verified_pins: dict[tuple[str, bytes], tuple[VerifiedPeer, int]] = {}
        self._verified_horizons: dict[tuple[str, bytes], PrincipalRecord] = {}

    def _now(self) -> int:
        return unix_now(self._clock)

    @staticmethod
    def _check_id(ace_id: object) -> str:
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "ace_id must be an ACE ID")
        return ace_id  # type: ignore[return-value]

    def _load(
        self, ace_id: str, *, enforce_horizon: bool = True
    ) -> tuple[VerifiedPeer, int] | None:
        key = _peer_key(ace_id)
        raw = self._store.read(key)
        if raw is None:
            return None
        cached = self._verified_pins.get((key, bytes(raw)))
        if cached is None:
            cached = _remember(
                self._verified_pins,
                (key, bytes(raw)),
                _peer_from_record(parse_record(raw, key), key),
            )
        result = (copy.deepcopy(cached[0]), cached[1])  # profile is mutable: never share it
        if enforce_horizon:
            try:
                self._check_principal_horizon(result[0], persist=False)
            except ACEError as exc:
                raise ACEError("storage_failed", f"{key}: {exc.message}") from None
        return result

    def get(self, ace_id: str) -> VerifiedPeer | None:
        rec = self._load(self._check_id(ace_id))
        return rec[0] if rec else None

    def adopt(self, peer: VerifiedPeer) -> PeerAdoption:
        if not isinstance(peer, VerifiedPeer):
            raise ACEError("invalid_argument", "peer must be a VerifiedPeer")
        with self._store.lock("peers"):
            now = self._now()
            rec = self._load(peer.ace_id, enforce_horizon=False)
            pin = rec[0] if rec else None
            result, outcome = adopt_decision(pin, peer, now)
            self._check_principal_horizon(result)
            if result is not pin:
                write_record(self._store, _peer_key(peer.ace_id), _peer_to_record(result, now))
            return PeerAdoption(result, outcome)

    def _check_principal_horizon(self, peer: VerifiedPeer, *, persist: bool = True) -> None:
        next_ = peer.principal
        if next_ is None:
            return
        domain = "\0".join(
            [peer.ace_id, next_.account, next_.signer.scheme, next_.signer.public_key]
        )
        key = f"principal-horizons/{sha256_hex(domain)}.json"
        raw = self._store.read(key)
        # the key binds aceId, account and signer, so the bytes alone decide validity
        high = None if raw is None else self._verified_horizons.get((key, bytes(raw)))
        if raw is not None and high is None:
            try:
                d = parse_record(raw, key)
                if d.get("aceId") != peer.ace_id:
                    raise ValueError("wrong identity")
                high = PrincipalRecord.from_dict(d["principal"])
                if high.account != next_.account or high.signer != next_.signer:
                    raise ValueError("wrong authority")
                validate_principal_record(high, peer.signing_public_key, now=high.issued_at)
            except (ACEError, ValueError, KeyError, TypeError):
                raise ACEError("storage_failed", f"{key}: invalid principal horizon") from None
            _remember(self._verified_horizons, (key, bytes(raw)), high)
        if high is not None and (
            next_.issued_at < high.issued_at
            or (next_.issued_at == high.issued_at and not same_principal_claims(next_, high))
        ):
            raise ACEError(
                "invalid_principal", "principal rolls back or conflicts with the durable horizon"
            )
        if persist and (high is None or next_.issued_at > high.issued_at):
            write_record(self._store, key, {"aceId": peer.ace_id, "principal": next_.to_dict()})

    def pin_registration_file(self, reg: RegistrationFile | dict) -> VerifiedPeer:
        peer = verify_registration_file(reg, clock=self._clock)
        return self.adopt(peer).peer

    def remove(self, ace_id: str) -> None:
        key = _peer_key(self._check_id(ace_id))
        with self._store.lock("peers"):
            self._store.delete(key)

    def _refresh(self, ace_id: str) -> VerifiedPeer | None:
        """Look the peer up on the relay now and adopt it (rollback barrier); None without a
        relay. Errors propagate."""
        if self._relay is None:
            return None
        return self.adopt(self._relay.lookup_peer(self._check_id(ace_id))).peer

    def resolve(self, ace_id: str, *, max_age_seconds: int | None = None) -> VerifiedPeer:
        self._check_id(ace_id)
        max_age = self._ttl if max_age_seconds is None else max_age_seconds
        if type(max_age) is not int or max_age < 0:
            raise ACEError("invalid_argument", "max_age_seconds must be a non-negative integer")
        rec = self._load(ace_id)
        if rec is not None and self._now() - rec[1] <= max_age:
            return rec[0]
        if self._relay is None:
            if rec is not None:
                return rec[0]
            raise ACEError("unknown_peer", "peer is not pinned and no relay is configured")
        fallback = rec is not None and max_age > 0
        try:
            candidate = self._relay.lookup_peer(ace_id)
        except ACEError as exc:
            if (exc.is_transient or exc.code == "unknown_peer") and fallback:
                return rec[0]  # type: ignore[index]
            raise
        try:
            return self.adopt(candidate).peer
        except ACEError as exc:
            if exc.code == "stale_peer_binding" and fallback:
                return rec[0]  # type: ignore[index]
            raise
