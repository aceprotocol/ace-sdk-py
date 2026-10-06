"""Persistent peer bindings with the 02 rollback barrier (lock ``peers``)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable, NamedTuple

from ._encoding import is_ace_id, to_base64, wire_int
from .discovery import (
    AdoptOutcome,
    VerifiedPeer,
    _make_peer,
    adopt_decision,
    decode_encryption_key,
    decode_signing_key,
    validate_profile,
    verify_peer_record,
    verify_registration_file,
)
from .errors import ACEError
from .identity import compute_ace_id
from .store import ACEStore, dump_record, load_record
from .threads import sha256_hex
from .types import SIGNING_SCHEMES, RegistrationFile

if TYPE_CHECKING:
    from .relay import RelayClient

DEFAULT_PEER_TTL_SECONDS = 86400


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
        "version": 1,
    }


def _peer_from_record(d: dict, key: str) -> tuple[VerifiedPeer, int]:
    """Re-verify a stored binding; any failure is ``storage_failed``."""
    try:
        source, fetched_at = d.get("source"), wire_int(d.get("fetchedAt"))
        if fetched_at is None:
            raise ACEError("invalid_peer", "fetchedAt must be an integer")
        if source == "relay":
            record = {k: d.get(k) for k in (
                "aceId", "scheme", "encryptionPublicKey", "signingPublicKey", "registrationSignature",
                "registeredAt", "profile")}
            peer = verify_peer_record(record)
        elif source == "registration":
            ace_id, scheme = d.get("aceId"), d.get("scheme")
            if not is_ace_id(ace_id) or scheme not in SIGNING_SCHEMES:
                raise ACEError("invalid_peer", "aceId / scheme")
            signing_key = decode_signing_key(scheme, d.get("signingPublicKey"), "invalid_peer")
            if compute_ace_id(signing_key) != ace_id:
                raise ACEError("invalid_peer", "aceId does not match the signing key")
            enc_key = decode_encryption_key(d.get("encryptionPublicKey"), "invalid_peer")
            registered_at = wire_int(d.get("registeredAt"))
            if registered_at is None or d.get("registrationSignature") is not None:
                raise ACEError("invalid_peer", "registeredAt / registrationSignature")
            profile = None if d.get("profile") is None else validate_profile(d["profile"])
            peer = _make_peer(
                ace_id=ace_id, scheme=scheme, signing_public_key=signing_key, encryption_public_key=enc_key,
                registered_at=registered_at, registration_signature=None, source="registration", profile=profile,
            )
        else:
            raise ACEError("invalid_peer", "unknown source")
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

    def _now(self) -> int:
        return int(self._clock()) if self._clock is not None else int(time.time())

    @staticmethod
    def _check_id(ace_id: object) -> str:
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "ace_id must be an ACE ID")
        return ace_id  # type: ignore[return-value]

    def _load(self, ace_id: str) -> tuple[VerifiedPeer, int] | None:
        key = _peer_key(ace_id)
        d = load_record(self._store, key)
        return None if d is None else _peer_from_record(d, key)

    def get(self, ace_id: str) -> VerifiedPeer | None:
        rec = self._load(self._check_id(ace_id))
        return rec[0] if rec else None

    def adopt(self, peer: VerifiedPeer) -> PeerAdoption:
        if not isinstance(peer, VerifiedPeer):
            raise ACEError("invalid_argument", "peer must be a VerifiedPeer")
        with self._store.lock("peers"):
            now = self._now()
            rec = self._load(peer.ace_id)
            pin = rec[0] if rec else None
            result, outcome = adopt_decision(pin, peer, now)
            if result is not pin:
                self._store.write(_peer_key(peer.ace_id), dump_record(_peer_to_record(result, now)))
            return PeerAdoption(result, outcome)

    def pin_registration_file(self, reg: RegistrationFile | dict, *, pinned_at: int | None = None) -> VerifiedPeer:
        peer = verify_registration_file(reg, pinned_at=pinned_at, clock=self._clock)
        return self.adopt(peer).peer

    def remove(self, ace_id: str) -> None:
        key = _peer_key(self._check_id(ace_id))
        with self._store.lock("peers"):
            self._store.delete(key)

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
            if (exc.category == "transient" or exc.code == "unknown_peer") and fallback:
                return rec[0]  # type: ignore[index]
            raise
        try:
            return self.adopt(candidate).peer
        except ACEError as exc:
            if exc.code == "stale_peer_binding" and fallback:
                return rec[0]  # type: ignore[index]
            raise
