"""Identities: ``ACEIdentity`` and ``SoftwareIdentity`` (root, next root, signing key)."""

from __future__ import annotations

import copy
import sys
from collections.abc import Sequence
from typing import Any, Dict, List, Protocol, TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:  # pragma: no cover
    from typing_extensions import NotRequired

from ._encoding import (
    canonical_state_bytes,
    check_wire_int,
    decode_b64,
    from_base64,
    resolve_now,
    to_base64,
)
from ._signing import SCHEME, signing_message
from .errors import ACEError
from .kel import (
    KelState,
    create_inception,
    create_rotation,
    create_signing_delegation,
    is_usable,
    tail_time,
    verify_kel,
)
from .keys import SoftwareKey, generate_software_key, key_digest


class ACEIdentity(Protocol):
    """What the SDK needs from an identity (software, Secure Enclave, HSM, ...)."""

    def get_ace_id(self) -> str: ...
    def get_signing_public_key(self) -> bytes: ...
    def get_signing_seq(self) -> int:
        """Seq of the ``dlg`` event that delegated the signing key."""
        ...

    def get_kel(self) -> List[Dict[str, Any]]: ...
    def sign(self, message: bytes, action: str) -> bytes:
        """Sign the full message ``M`` with the signing key, ctx = UTF-8(action)."""
        ...


class SoftwareIdentityExport(TypedDict):
    """All Base64 except ``kel``."""

    rootSeed: str
    nextRootSeed: NotRequired[str]
    signingSeed: str
    kel: List[Dict[str, Any]]


def check_usable(identity: ACEIdentity, now: int) -> KelState:
    """The identity's verified log state, or ``identity_unavailable`` when it must not sign now.

    The log is verified at ``max(now, ts of its last event)``; the signing delegation must be
    live and must be the identity's own key and ``seq``."""
    check_wire_int(now, "now")
    try:
        kel = identity.get_kel()
        t = tail_time(kel, now)
        state = verify_kel(kel, t)
        pk = bytes(identity.get_signing_public_key())
        seq = identity.get_signing_seq()
    except ACEError as exc:
        raise ACEError(
            "identity_unavailable", f"identity kel does not verify: {exc.message}"
        ) from None
    except Exception as exc:
        raise ACEError(
            "identity_unavailable", f"identity unavailable: {type(exc).__name__}"
        ) from None
    s = state.signing
    if not is_usable(state, t):
        raise ACEError("identity_unavailable", "signing delegation missing or expired")
    if s is None or s.public_key != pk or type(seq) is not int or s.seq != seq:
        raise ACEError("identity_unavailable", "identity signing key or seq does not match its kel")
    return state


def sign_operational(identity: ACEIdentity, signed_at: int, payload: bytes, action: str) -> dict:
    """``{scheme, seq, value}`` over ``M(aceId, signed_at, seq, payload)``, after
    ``check_usable``."""
    state = check_usable(identity, signed_at)
    seq = state.signing.seq  # type: ignore[union-attr]
    message = signing_message(identity.get_ace_id(), signed_at, seq, payload)
    return {"scheme": SCHEME, "seq": seq, "value": to_base64(identity.sign(message, action))}


def sign_claims(identity: ACEIdentity, action: str, claims: dict) -> dict:
    """``claims`` plus ``signature`` over ``canonicalStateBytes(claims)`` at ``issuedAt``."""
    payload = canonical_state_bytes(claims)
    return {**claims, "signature": sign_operational(identity, claims["issuedAt"], payload, action)}


def _check_next_digest(digest: object) -> bytes | None:
    if digest is not None and (not isinstance(digest, (bytes, bytearray)) or len(digest) != 32):
        raise ACEError("invalid_argument", "next_root_digest must be 32 bytes")
    return None if digest is None else bytes(digest)


def _new_next_root(
    next_root_digest: bytes | None, current: SoftwareKey, events: Sequence[dict]
) -> tuple[SoftwareKey | None, bytes]:
    """The next root to commit and its digest; it must differ from every current or past root."""
    if next_root_digest is not None:
        nxt, digest = None, bytes(next_root_digest)
    else:
        nxt = generate_software_key()
        digest = key_digest(nxt.scheme, nxt.public_key())
    roots = {key_digest(current.scheme, current.public_key())}
    for ev in events:
        if ev["t"] in ("icp", "rot"):
            roots.add(key_digest(ev["root"]["scheme"], from_base64(ev["root"]["publicKey"])))
    if digest in roots:
        raise ACEError(
            "invalid_argument", "the next root must differ from every current or past root"
        )
    return nxt, digest


def _check_committed(key: SoftwareKey, state: KelState) -> None:
    if key_digest(key.scheme, key.public_key()).hex() != state.next:
        raise ACEError("invalid_argument", "next_root does not match the committed next root")


class SoftwareIdentity:
    """Root, optional next root and signing key in memory, plus the KEL."""

    def __init__(
        self,
        root: SoftwareKey,
        next_root: SoftwareKey | None,
        signing: SoftwareKey,
        kel: list[dict],
        now: int,
    ) -> None:
        state = verify_kel(kel, now)
        if state.root_public_key != root.public_key():
            raise ACEError("invalid_argument", "root seed does not match the kel")
        if next_root is not None:
            _check_committed(next_root, state)
        if state.signing is None:
            raise ACEError("invalid_kel", "kel has no signing delegation")
        if state.signing.public_key != signing.public_key():
            raise ACEError("invalid_argument", "signing seed does not match the kel")
        self._root, self._next_root, self._signing = root, next_root, signing
        self._kel, self._state = copy.deepcopy(kel), state

    @classmethod
    def generate(
        cls, next_root_digest: bytes | None = None, now: int | None = None
    ) -> "SoftwareIdentity":
        next_root_digest = _check_next_digest(next_root_digest)
        ts = resolve_now(now)
        root, signing = generate_software_key(), generate_software_key()
        next_root, digest = _new_next_root(next_root_digest, root, ())
        icp = create_inception(root, digest, ts)
        dlg = create_signing_delegation(verify_kel([icp], ts), root, signing.public_key(), ts)
        return cls(root, next_root, signing, [icp, dlg], ts)

    @classmethod
    def from_export(cls, data: object, now: int | None = None) -> "SoftwareIdentity":
        if not isinstance(data, dict) or not set(data) <= {
            "rootSeed",
            "nextRootSeed",
            "signingSeed",
            "kel",
        }:
            raise ACEError(
                "invalid_argument", "export must be {rootSeed, nextRootSeed?, signingSeed, kel}"
            )
        kel = data.get("kel")
        if not isinstance(kel, list) or not kel:
            raise ACEError("invalid_kel", "export.kel must be a non-empty array")
        ts = tail_time(kel, resolve_now(now))

        def key(name: str) -> SoftwareKey:
            return SoftwareKey(decode_b64(data.get(name), "invalid_argument", name))

        nxt = key("nextRootSeed") if "nextRootSeed" in data else None
        return cls(key("rootSeed"), nxt, key("signingSeed"), kel, ts)

    @classmethod
    def recover(
        cls,
        kel: list[dict],
        next_root: SoftwareKey,
        now: int | None = None,
        next_root_digest: bytes | None = None,
    ) -> "SoftwareIdentity":
        """Fork the log at the start of the current root epoch, append ``rot`` signed by the
        committed ``next_root`` and a fresh signing delegation."""
        if not isinstance(next_root, SoftwareKey):
            raise ACEError("invalid_argument", "next_root must be a SoftwareKey")
        next_root_digest = _check_next_digest(next_root_digest)
        now_ts = resolve_now(now)
        state = verify_kel(kel, now_ts)
        start = max(i for i, e in enumerate(state.events) if e["t"] in ("icp", "rot"))
        events = copy.deepcopy(list(state.events[: start + 1]))
        ts = tail_time(events, now_ts)
        state = verify_kel(events, ts)
        _check_committed(next_root, state)
        new_next, digest = _new_next_root(next_root_digest, next_root, events)
        signing = generate_software_key()
        events.append(create_rotation(state, next_root, digest, ts))
        events.append(
            create_signing_delegation(verify_kel(events, ts), next_root, signing.public_key(), ts)
        )
        return cls(next_root, new_next, signing, events, ts)

    def export_private_key(self) -> SoftwareIdentityExport:
        out: SoftwareIdentityExport = {
            "rootSeed": to_base64(self._root.seed),
            "signingSeed": to_base64(self._signing.seed),
            "kel": copy.deepcopy(self._kel),
        }
        if self._next_root is not None:
            out["nextRootSeed"] = to_base64(self._next_root.seed)
        return out

    # --- ACEIdentity ---
    def get_ace_id(self) -> str:
        return self._state.ace_id

    def get_signing_public_key(self) -> bytes:
        return self._signing.public_key()

    def get_signing_seq(self) -> int:
        return self._state.signing.seq  # type: ignore[union-attr]

    def get_kel(self) -> list[dict]:
        return copy.deepcopy(self._kel)

    def sign(self, message: bytes, action: str) -> bytes:
        return self._signing.sign(message, action)

    # --- key management ---
    def _append(self, ev: dict, now: int) -> None:
        self._state = verify_kel([*self._kel, ev], now)
        self._kel.append(ev)

    def rotate(
        self,
        now: int | None = None,
        next_root_digest: bytes | None = None,
        next_root: SoftwareKey | None = None,
    ) -> None:
        """Reveal the committed next root and commit a new one; re-delegates the signing key."""
        if next_root is not None:
            if self._next_root is not None:
                raise ACEError("invalid_argument", "the next root key is held by this identity")
            if not isinstance(next_root, SoftwareKey):
                raise ACEError("invalid_argument", "next_root must be a SoftwareKey")
            _check_committed(next_root, self._state)
            revealed = next_root
        elif self._next_root is None:
            raise ACEError("invalid_argument", "the next root key is not held by this identity")
        else:
            revealed = self._next_root
        next_root_digest = _check_next_digest(next_root_digest)
        ts = resolve_now(now)
        new_next, digest = _new_next_root(next_root_digest, revealed, self._state.events)
        self._append(create_rotation(self._state, revealed, digest, ts), ts)
        self._root, self._next_root = revealed, new_next
        self._append(
            create_signing_delegation(self._state, self._root, self._signing.public_key(), ts), ts
        )

    def delegate(self, now: int | None = None, not_after: int | None = None) -> None:
        """Delegate a fresh signing key (``dlg``), optionally with ``notAfter``."""
        ts = resolve_now(now)
        key = generate_software_key()
        self._append(
            create_signing_delegation(self._state, self._root, key.public_key(), ts, not_after), ts
        )
        self._signing = key
