"""Key event log: inception, rotation, signing delegation. ACE ID = SHA-256 of the icp bytes."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field, replace

from ._encoding import (
    canonical_state_bytes,
    decode_b64,
    decode_fixed_b64,
    is_sha256_hex,
    sha256_hex,
    to_base64,
    wire_int,
)
from ._signing import (
    SCHEME,
    SIGNATURE_SIZE,
    encode_payload,
    is_signing_key,
    signing_message,
    verify_signature,
)
from .errors import ACEError, ACEErrorCode
from .keys import KeyProvider, key_digest
from .limits import MAX_KEL_EVENTS, MAX_SIGNING_KEY_LIFETIME, TIMESTAMP_WINDOW_SECONDS

_KEYS = {
    "icp": {"t", "seq", "ts", "root", "next", "sig"},
    "rot": {"t", "seq", "ts", "prev", "root", "next", "sig"},
    "dlg": {"t", "seq", "ts", "prev", "key", "sig"},
}


@dataclass(frozen=True)
class DelegatedKey:
    scheme: str
    public_key: bytes
    seq: int
    not_after: int | None


@dataclass(frozen=True)
class KelState:
    ace_id: str
    seq: int
    last_hash: str
    root_scheme: str
    root_public_key: bytes
    next: str
    signing: DelegatedKey | None
    events: tuple[dict, ...] = field(hash=False)
    event_hashes: tuple[str, ...] = field(hash=False, repr=False)


def _bad(msg: str) -> ACEError:
    return ACEError("invalid_kel", msg)


def _key_bytes(obj: object, what: str) -> tuple[str, bytes]:
    if not isinstance(obj, dict) or set(obj) != {"scheme", "publicKey"}:
        raise _bad(f"{what} must be {{scheme, publicKey}}")
    scheme = obj["scheme"]
    if not isinstance(scheme, str):
        raise _bad(f"{what}.scheme must be a string")
    return scheme, decode_b64(obj["publicKey"], "invalid_kel", f"{what}.publicKey")


def event_bytes(event: dict) -> bytes:
    """Canonical bytes (signatures excluded). Raises invalid_kel on shape errors."""
    t = event.get("t") if isinstance(event, dict) else None
    if not isinstance(t, str) or t not in _KEYS:
        raise _bad("event must be icp, rot or dlg")
    allowed = _KEYS[t] | ({"notAfter"} if t == "dlg" else set())
    required = _KEYS[t] - {"sig"}
    if not set(event) <= allowed or not required <= set(event):
        raise _bad(f"{t} has unknown or missing members")
    seq, ts = wire_int(event["seq"]), wire_int(event["ts"])
    if seq is None or ts is None:
        raise _bad("seq and ts must be wire integers")
    if t == "icp":
        scheme, pk = _key_bytes(event["root"], "root")
        if not is_sha256_hex(event["next"]):
            raise _bad("next must be 64 lowercase hex")
        return encode_payload("icp", str(seq), str(ts), scheme, pk, bytes.fromhex(event["next"]))
    if not is_sha256_hex(event["prev"]):
        raise _bad("prev must be 64 lowercase hex")
    if t == "rot":
        scheme, pk = _key_bytes(event["root"], "root")
        if not is_sha256_hex(event["next"]):
            raise _bad("next must be 64 lowercase hex")
        return encode_payload(
            "rot",
            str(seq),
            str(ts),
            event["prev"],
            scheme,
            pk,
            bytes.fromhex(event["next"]),
        )
    scheme, pk = _key_bytes(event["key"], "key")
    if "notAfter" in event:
        n = wire_int(event["notAfter"])
        if n is None:
            raise _bad("notAfter must be a wire integer")
        na = str(n)
    else:
        na = ""
    return encode_payload("dlg", str(seq), str(ts), event["prev"], scheme, pk, na)


def compute_ace_id(inception_bytes: bytes) -> str:
    return "ace:sha256:" + sha256_hex(inception_bytes)


def _sig(provider: KeyProvider, ace_id: str, ts: int, eb: bytes) -> dict:
    sig = provider.sign(signing_message(ace_id, ts, None, eb), "kel")
    return {"scheme": provider.scheme, "value": to_base64(sig)}


def _check_sig(
    sig: object, ace_id: str, ts: int, eb: bytes, scheme: str, pk: bytes, who: str
) -> None:
    if not isinstance(sig, dict) or set(sig) != {"scheme", "value"} or sig["scheme"] != scheme:
        raise _bad(f"{who} signature must be {{scheme, value}} for {scheme}")
    raw = decode_b64(sig["value"], "invalid_signature", f"{who} signature")
    if not verify_signature(signing_message(ace_id, ts, None, eb), "kel", raw, pk):
        raise ACEError("invalid_signature", f"{who} signature does not verify")


def create_inception(root: KeyProvider, next_digest: bytes, ts: int) -> dict:
    ev = {
        "t": "icp",
        "seq": 0,
        "ts": ts,
        "root": {"scheme": root.scheme, "publicKey": to_base64(root.public_key())},
        "next": bytes(next_digest).hex(),
    }
    eb = event_bytes(ev)
    ev["sig"] = _sig(root, compute_ace_id(eb), ts, eb)
    return ev


def create_rotation(state: KelState, new_root: KeyProvider, next_digest: bytes, ts: int) -> dict:
    """``rot`` revealing the committed ``new_root``, signed by it alone (pre-rotation)."""
    if key_digest(new_root.scheme, new_root.public_key()).hex() != state.next:
        raise _bad("new root does not match the committed next digest")
    ev = {
        "t": "rot",
        "seq": state.seq + 1,
        "ts": ts,
        "prev": state.last_hash,
        "root": {"scheme": new_root.scheme, "publicKey": to_base64(new_root.public_key())},
        "next": bytes(next_digest).hex(),
    }
    eb = event_bytes(ev)
    ev["sig"] = _sig(new_root, state.ace_id, ts, eb)
    return ev


def create_signing_delegation(
    state: KelState,
    root: KeyProvider,
    signing_public_key: bytes,
    ts: int,
    not_after: int | None = None,
) -> dict:
    """``dlg`` delegating a signing key, signed by the current root."""
    if not_after is not None and not (ts < not_after <= ts + MAX_SIGNING_KEY_LIFETIME):
        raise _bad(f"notAfter must be in (ts, ts + {MAX_SIGNING_KEY_LIFETIME}]")
    ev: dict = {
        "t": "dlg",
        "seq": state.seq + 1,
        "ts": ts,
        "prev": state.last_hash,
        "key": {"scheme": SCHEME, "publicKey": to_base64(bytes(signing_public_key))},
    }
    if not_after is not None:
        ev["notAfter"] = not_after
    eb = event_bytes(ev)
    ev["sig"] = _sig(root, state.ace_id, ts, eb)
    return ev


_VERIFIED_CACHE_SIZE = 256
_VERIFIED_CACHE_BYTES = 16 * 1024 * 1024  # canonical event bytes held, all entries together
_verified: dict[str, tuple[KelState, int, int]] = {}  # key -> (state, last ts, bytes)
_verified_bytes = 0
_verified_lock = threading.Lock()


def _prefix_keys(events: object) -> tuple[list[str], int] | None:
    """Chained content keys and the log's canonical size: ``keys[i]`` hashes ``keys[i-1]`` and
    the canonical JSON of event ``i`` (its ``sig`` included), so it names the exact prefix
    ``events[:i+1]``. None for a value that is not a bounded JSON array."""
    if not isinstance(events, list) or not 0 < len(events) <= MAX_KEL_EVENTS:
        return None
    keys: list[str] = []
    size = 0
    try:
        for ev in events:
            eb = canonical_state_bytes(ev)
            size += len(eb)
            keys.append(sha256_hex(keys[-1] if keys else "", eb))
    except (TypeError, ValueError, ACEError, RecursionError):
        return None
    return keys, size


def _cache_put(key: str, state: KelState, last_ts: int, size: int) -> None:
    """Keep a verified state, oldest entries evicted first to stay within
    ``_VERIFIED_CACHE_SIZE`` entries and ``_VERIFIED_CACHE_BYTES``; a larger log is not kept."""
    global _verified_bytes
    if size > _VERIFIED_CACHE_BYTES:
        return
    with _verified_lock:
        old = _verified.pop(key, None)
        if old is not None:
            _verified_bytes -= old[2]
        while _verified and (
            len(_verified) >= _VERIFIED_CACHE_SIZE or _verified_bytes + size > _VERIFIED_CACHE_BYTES
        ):
            _verified_bytes -= _verified.pop(next(iter(_verified)))[2]
        _verified[key] = (replace(state, events=copy.deepcopy(state.events)), last_ts, size)
        _verified_bytes += size


def verify_kel(events: list, now: int) -> KelState:
    """Verify a KEL at ``now`` (01 § Verifier rules).

    Successful verifications are cached by their prefix key (05 § Receiver admission):
    verification is a pure function of the log and ``now``, and only the future bound
    ``ts <= now + TIMESTAMP_WINDOW_SECONDS`` depends on ``now``, so a hit re-checks that bound
    alone and costs no signature verification. A log extending a cached one (a pin plus new
    events) re-checks the whole structure but verifies only the new events' signatures. Only a
    log usable at ``now`` is cached, within a byte budget (a stranger's junk logs cannot crowd
    out the pins)."""
    prefix = _prefix_keys(events)
    keys, size = (None, 0) if prefix is None else prefix
    key = None if keys is None else keys[-1]
    resume = None
    if keys is not None:
        with _verified_lock:
            hit = _verified.get(key)
            if hit is None or hit[1] > now + TIMESTAMP_WINDOW_SECONDS:
                hit = None
                resume = next(
                    (_verified[k][0] for k in reversed(keys[:-1]) if k in _verified), None
                )
        if hit is not None:
            st = hit[0]
            return replace(st, events=copy.deepcopy(st.events))
    state = _verify_kel(events, now, resume)
    if key is not None and is_usable(state, now):
        _cache_put(key, state, wire_int(state.events[-1]["ts"]) or 0, size)
    return state


def _verify_kel(events: list, now: int, resume: KelState | None = None) -> KelState:
    """``resume``: a verified state of a prefix of ``events`` (same content, signatures
    included); its signatures are not checked again."""
    if not isinstance(events, list) or not events:
        raise _bad("kel must be a non-empty array")
    if len(events) > MAX_KEL_EVENTS:
        raise _bad(f"kel exceeds {MAX_KEL_EVENTS} events")
    if not isinstance(events[0], dict) or events[0].get("t") != "icp":
        raise _bad("kel must start with icp")
    eb0 = event_bytes(events[0])
    ace_id = compute_ace_id(eb0)
    root_scheme, root_pk = _key_bytes(events[0]["root"], "root")
    # Rule 1: the whole log's structure before any signature.
    prev_ts, prev_hash, checked = -1, None, []
    for i, ev in enumerate(events):
        eb = event_bytes(ev)
        if not _KEYS[ev["t"]] <= set(ev):
            raise _bad(f"event {i}: missing signature")
        sig = ev["sig"]
        if (
            not isinstance(sig, dict)
            or set(sig) != {"scheme", "value"}
            or not isinstance(sig["scheme"], str)
        ):
            raise _bad(f"event {i}: sig must be {{scheme, value}}")
        decode_b64(sig["value"], "invalid_kel", f"event {i} sig.value")
        seq, ts = wire_int(ev["seq"]), wire_int(ev["ts"])
        if seq != i or ts < prev_ts or ts > now + TIMESTAMP_WINDOW_SECONDS:
            raise _bad(f"event {i}: bad seq or ts")
        if i > 0 and ev["t"] == "icp":
            raise _bad(f"event {i}: icp only at seq 0")
        if i > 0 and ev["prev"] != prev_hash:
            raise _bad(f"event {i}: prev does not match")
        prev_ts, prev_hash = ts, sha256_hex(eb)
        checked.append((eb, ts, prev_hash))
    if not is_signing_key(root_scheme, root_pk):
        raise _bad("root key invalid")
    if resume is not None:
        state, copies = resume, [copy.deepcopy(e) for e in resume.events]
    else:
        state = KelState(
            ace_id, 0, checked[0][2], root_scheme, root_pk, events[0]["next"], None, (), ()
        )
        copies = []
    for i in range(len(copies), len(events)):
        ev = events[i]
        eb, ts, h = checked[i]
        signing = state.signing
        if ev["t"] == "icp":
            _check_sig(ev["sig"], ace_id, ts, eb, root_scheme, root_pk, "icp")
            new_root = (root_scheme, root_pk, ev["next"])
        elif ev["t"] == "rot":
            scheme, pk = _key_bytes(ev["root"], "root")
            if not is_signing_key(scheme, pk):
                raise _bad(f"event {i}: root key invalid")
            if key_digest(scheme, pk).hex() != state.next:
                raise _bad(f"event {i}: revealed root does not match commitment")
            _check_sig(ev["sig"], ace_id, ts, eb, scheme, pk, "rot")
            new_root, signing = (scheme, pk, ev["next"]), None
        else:
            _check_sig(ev["sig"], ace_id, ts, eb, state.root_scheme, state.root_public_key, "dlg")
            scheme, pk = _key_bytes(ev["key"], "key")
            na = wire_int(ev["notAfter"]) if "notAfter" in ev else None
            if na is not None and not (ts < na <= ts + MAX_SIGNING_KEY_LIFETIME):
                raise _bad(f"event {i}: notAfter out of range")
            if not is_signing_key(scheme, pk):
                raise _bad(f"event {i}: signing key must be ml-dsa-65")
            signing = DelegatedKey(scheme, pk, i, na)
            new_root = (state.root_scheme, state.root_public_key, state.next)
        copies.append(copy.deepcopy(ev))
        state = KelState(ace_id, i, h, *new_root, signing, (), ())
    return replace(state, events=tuple(copies), event_hashes=tuple(c[2] for c in checked))


def tail_time(kel: object, now: int) -> int:
    """``max(now, ts of the log's last event)``: a held log is verified at its own tail."""
    tail = kel[-1] if isinstance(kel, list) and kel else None
    last = wire_int(tail.get("ts")) if isinstance(tail, dict) else None
    return now if last is None else max(now, last)


def is_usable(state: KelState, now: int) -> bool:
    """A signing key is delegated and ``now < notAfter`` (if any)."""
    s = state.signing
    return s is not None and (s.not_after is None or now < s.not_after)


def extend_kel(pinned: KelState | None, events: list, now: int) -> tuple[KelState, str]:
    """Adopt, extend, recover (rule 6) or keep a pin; ``kel_conflict`` on any other fork."""
    return reconcile_kel(pinned, verify_kel(events, now))


def reconcile_kel(pinned: KelState | None, cand: KelState) -> tuple[KelState, str]:
    """``extend_kel`` for an already verified candidate."""
    if pinned is None:
        return cand, "adopted"
    if cand.ace_id != pinned.ace_id:
        raise ACEError("kel_conflict", "candidate names a different identity")
    ph, ch = pinned.event_hashes, cand.event_hashes
    for k, (a, b) in enumerate(zip(ph, ch)):
        if a != b:
            if cand.events[k]["t"] == "rot" and all(e["t"] != "rot" for e in pinned.events[k:]):
                return cand, "recovered"
            raise ACEError("kel_conflict", f"conflicting event at seq {k}")
    if len(ch) > len(ph):
        return cand, "extended"
    return pinned, "unchanged"


def check_signature_shape(signature: object, code: ACEErrorCode) -> bytes:
    """An operational signature's shape: ``{scheme: ml-dsa-65, seq, value}``, ``seq`` a wire
    integer and ``value`` canonical Base64 of a signature's length; its raw bytes, or ``code``."""
    if (
        not isinstance(signature, dict)
        or set(signature) != {"scheme", "seq", "value"}
        or signature["scheme"] != SCHEME
        or wire_int(signature["seq"]) is None
    ):
        raise ACEError(code, "signature must be {scheme: ml-dsa-65, seq, value}")
    return decode_fixed_b64(signature["value"], SIGNATURE_SIZE, code, "signature")


def verify_operational_signature(
    state: KelState,
    signature: object,
    payload: bytes,
    action: str,
    signed_at: int,
    now: int,
    code: ACEErrorCode = "invalid_signature",
) -> None:
    """01 § Operational signatures, in order, for a ``{scheme, seq, value}`` signature over
    ``M(state.ace_id, signed_at, seq, payload)``: 1. the shape (``check_signature_shape``,
    ``code``); 2. ``seq`` names the current signing delegation; 3. signed while live
    (``signed_at < notAfter``); 4. the signature verifies (``code``); 5. the signer is usable at
    ``now``. Failures of 2, 3 and 5 are ``stale_peer_binding``."""
    raw = check_signature_shape(signature, code)
    seq, signing = wire_int(signature["seq"]), state.signing  # type: ignore[index]
    if signing is None or seq != signing.seq:
        raise ACEError("stale_peer_binding", "seq is not the current signing delegation")
    if signing.not_after is not None and signed_at >= signing.not_after:
        raise ACEError("stale_peer_binding", "signed at or after the delegation's notAfter")
    message = signing_message(state.ace_id, signed_at, signing.seq, payload)
    if not verify_signature(message, action, raw, signing.public_key):
        raise ACEError(code, f"{action} signature does not verify")
    if not is_usable(state, now):
        raise ACEError("stale_peer_binding", "the signer is not usable now")
