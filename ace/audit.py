"""Optional salted commitments and RFC 9162 proofs. No publication or execution effects."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, replace

from ._encoding import (
    decode_signature,
    encode_signature,
    is_ace_id,
    is_message_id,
    is_sha256_hex,
    wire_int,
)
from ._signing import build_sign_data, encode_payload, verify_signature
from .discovery import VerifiedPeer
from .errors import ACEError
from .types import ACEIdentity, SignatureEnvelope, is_signing_scheme


def _bad():
    return ACEError("invalid_argument", "invalid audit input")


def _hash(*parts: bytes) -> str:
    return hashlib.sha256(b"".join(parts)).hexdigest()


_EMPTY = _hash(b"")


def _node(a: str, b: str) -> str:
    return _hash(b"\x01", bytes.fromhex(a), bytes.fromhex(b))


def _leaf(c: str) -> str:
    return _hash(b"\x00", bytes.fromhex(c))


def _size(n) -> bool:
    return type(n) is int and wire_int(n) is not None


def _proof(p) -> bool:
    return isinstance(p, (list, tuple)) and len(p) <= 54 and all(is_sha256_hex(x) for x in p)


def _split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def audit_commitment(statement: bytes, salt: bytes) -> str:
    """Keep the 32-byte random salt private until intentional disclosure."""
    if not isinstance(statement, bytes) or not isinstance(salt, bytes) or len(salt) != 32:
        raise _bad()
    return _hash(b"ace.audit.commitment.v1\0", salt, statement)


def create_audit_opening(statement: bytes) -> tuple[bytes, str]:
    salt = secrets.token_bytes(32)
    return salt, audit_commitment(statement, salt)


class AuditTree:
    """Reference builder. Inputs are commitments, never plaintext or salts."""

    def __init__(self, commitments=()):
        if (
            not isinstance(commitments, (list, tuple))
            or len(commitments) > 65536
            or not all(is_sha256_hex(x) for x in commitments)
        ):
            raise _bad()
        self._leaves = tuple(_leaf(x) for x in commitments)
        # A power-of-two subtree is the same in every prefix tree: hash it once (<= 2n entries).
        self._perfect: dict[tuple[int, int], str] = {}

    @property
    def size(self) -> int:
        return len(self._leaves)

    def _root(self, start, count):
        if count == 0:
            return _EMPTY
        if count == 1:
            return self._leaves[start]
        perfect = count & (count - 1) == 0
        if perfect and (start, count) in self._perfect:
            return self._perfect[(start, count)]
        k = _split(count)
        root = _node(self._root(start, k), self._root(start + k, count - k))
        if perfect:
            self._perfect[(start, count)] = root
        return root

    def root(self, count=None) -> str:
        count = self.size if count is None else count
        if not _size(count) or count > self.size:
            raise _bad()
        return self._root(0, count)

    def inclusion(self, index: int, count=None) -> list[str]:
        count = self.size if count is None else count
        if not _size(index) or not _size(count) or index >= count or count > self.size:
            raise _bad()

        def walk(i, start, n):
            if n == 1:
                return []
            k = _split(n)
            if i < k:
                return walk(i, start, k) + [self._root(start + k, n - k)]
            return walk(i - k, start + k, n - k) + [self._root(start, k)]

        return walk(index, 0, count)

    def consistency(self, first: int, second=None) -> list[str]:
        second = self.size if second is None else second
        if not _size(first) or not _size(second) or first > second or second > self.size:
            raise _bad()
        if first == 0 or first == second:
            return []

        def walk(m, start, n, complete):
            if m == n:
                return [] if complete else [self._root(start, n)]
            k = _split(n)
            if m <= k:
                return walk(m, start, k, complete) + [self._root(start + k, n - k)]
            return walk(m - k, start + k, n - k, False) + [self._root(start, k)]

        return walk(first, 0, second, True)


def verify_audit_inclusion(commitment: str, index: int, count: int, root: str, proof) -> bool:
    if (
        not is_sha256_hex(commitment)
        or not is_sha256_hex(root)
        or not _size(index)
        or not _size(count)
        or index >= count
        or not _proof(proof)
    ):
        return False
    at = 0

    def walk(i, n):
        nonlocal at
        if n == 1:
            return _leaf(commitment)
        k = _split(n)
        child = walk(i, k) if i < k else walk(i - k, n - k)
        sibling = proof[at]
        at += 1
        return _node(child, sibling) if i < k else _node(sibling, child)

    try:
        return walk(index, count) == root and at == len(proof)
    except (IndexError, ValueError):
        return False


def verify_audit_consistency(
    first: int, second: int, first_root: str, second_root: str, proof
) -> bool:
    if (
        not _size(first)
        or not _size(second)
        or first > second
        or not is_sha256_hex(first_root)
        or not is_sha256_hex(second_root)
        or not _proof(proof)
    ):
        return False
    if first == second:
        return (
            len(proof) == 0 and first_root == second_root and (first != 0 or first_root == _EMPTY)
        )
    if first == 0:
        return first_root == _EMPTY and len(proof) == 0
    at = 0

    def take():
        nonlocal at
        h = proof[at]
        at += 1
        return h

    def walk(m, n, complete):
        if m == n:
            h = first_root if complete else take()
            return h, h
        k = _split(n)
        if m <= k:
            old, new = walk(m, k, complete)
            return old, _node(new, take())
        old, new = walk(m - k, n - k, False)
        left = take()
        return _node(left, old), _node(left, new)

    try:
        old, new = walk(first, second, True)
        return old == first_root and new == second_root and at == len(proof)
    except (IndexError, ValueError):
        return False


@dataclass(frozen=True)
class AuditCheckpoint:
    log_id: str
    size: int
    root: str
    timestamp: int
    signer: str
    signature: SignatureEnvelope

    def to_dict(self) -> dict:
        return {
            "logId": self.log_id,
            "size": self.size,
            "root": self.root,
            "timestamp": self.timestamp,
            "signer": self.signer,
            "signature": {"scheme": self.signature.scheme, "value": self.signature.value},
        }

    @classmethod
    def from_dict(cls, value: dict) -> AuditCheckpoint:
        try:
            if set(value) != {"logId", "size", "root", "timestamp", "signer", "signature"} or set(
                value["signature"]
            ) != {"scheme", "value"}:
                raise _bad()
            if (
                not is_message_id(value["logId"])
                or wire_int(value["size"]) is None
                or not is_sha256_hex(value["root"])
                or wire_int(value["timestamp"]) is None
                or not is_ace_id(value["signer"])
                or not is_signing_scheme(value["signature"]["scheme"])
                or not isinstance(value["signature"]["value"], str)
            ):
                raise _bad()
            return cls(
                value["logId"],
                wire_int(value["size"]),
                value["root"],
                wire_int(value["timestamp"]),
                value["signer"],
                SignatureEnvelope(**value["signature"]),
            )
        except (TypeError, KeyError):
            raise _bad() from None


def _checkpoint_data(log_id, size_, root, timestamp, signer):
    if (
        not is_message_id(log_id)
        or not _size(size_)
        or not is_sha256_hex(root)
        or not _size(timestamp)
        or (size_ == 0 and root != _EMPTY)
    ):
        raise _bad()
    return build_sign_data(
        "audit", signer, timestamp, encode_payload(log_id, str(size_), bytes.fromhex(root))
    )


def create_audit_checkpoint(
    tree: AuditTree, log_id: str, signer: ACEIdentity, timestamp: int
) -> AuditCheckpoint:
    root = tree.root()
    value = encode_signature(
        signer.sign(_checkpoint_data(log_id, tree.size, root, timestamp, signer.get_ace_id())),
        signer.get_signing_scheme(),
    )
    return AuditCheckpoint(
        log_id,
        tree.size,
        root,
        timestamp,
        signer.get_ace_id(),
        SignatureEnvelope(signer.get_signing_scheme(), value),
    )


def verify_audit_checkpoint(
    c: AuditCheckpoint, operator: VerifiedPeer, previous: AuditCheckpoint | None = None, proof=()
) -> None:
    """The operator must be locally trusted. Retain accepted checkpoints durably."""

    def valid(v):
        return (
            v.signer == operator.ace_id
            and v.signature.scheme == operator.scheme
            and verify_signature(
                _checkpoint_data(v.log_id, v.size, v.root, v.timestamp, v.signer),
                decode_signature(v.signature.value, operator.scheme, "invalid_signature"),
                operator.scheme,
                operator.signing_public_key,
            )
        )

    try:
        if (
            not isinstance(operator, VerifiedPeer)
            or not valid(c)
            or (
                previous
                and (
                    not valid(previous)
                    or c.log_id != previous.log_id
                    or c.timestamp < previous.timestamp
                    or not verify_audit_consistency(
                        previous.size, c.size, previous.root, c.root, proof
                    )
                )
            )
        ):
            raise _bad()
        if previous is None and len(proof) != 0:
            raise _bad()
    except (ACEError, TypeError, ValueError, AttributeError):
        raise ACEError("invalid_signature", "invalid or inconsistent audit checkpoint") from None


def audit_checkpoint_digest(c: AuditCheckpoint) -> str:
    """Digest of checkpoint claims, independent of signature randomness/encoding."""
    return _checkpoint_data(c.log_id, c.size, c.root, c.timestamp, c.signer).hex()


@dataclass(frozen=True)
class AuditWitnessReceipt:
    log_id: str
    operator: str
    checkpoint_digest: str
    timestamp: int
    witness: str
    signature: SignatureEnvelope

    def to_dict(self) -> dict:
        return {
            "logId": self.log_id,
            "operator": self.operator,
            "checkpointDigest": self.checkpoint_digest,
            "timestamp": self.timestamp,
            "witness": self.witness,
            "signature": {"scheme": self.signature.scheme, "value": self.signature.value},
        }

    @classmethod
    def from_dict(cls, value: dict) -> AuditWitnessReceipt:
        try:
            if (
                set(value)
                != {"logId", "operator", "checkpointDigest", "timestamp", "witness", "signature"}
                or set(value["signature"]) != {"scheme", "value"}
                or wire_int(value["timestamp"]) is None
                or not is_signing_scheme(value["signature"]["scheme"])
                or not isinstance(value["signature"]["value"], str)
            ):
                raise _bad()
            r = cls(
                value["logId"],
                value["operator"],
                value["checkpointDigest"],
                wire_int(value["timestamp"]),
                value["witness"],
                SignatureEnvelope(**value["signature"]),
            )
            _witness_data(r)
            return r
        except (TypeError, KeyError):
            raise _bad() from None


def _witness_data(r: AuditWitnessReceipt) -> bytes:
    if (
        not is_message_id(r.log_id)
        or not is_ace_id(r.operator)
        or not is_ace_id(r.witness)
        or r.operator == r.witness
        or not is_sha256_hex(r.checkpoint_digest)
        or not _size(r.timestamp)
    ):
        raise _bad()
    return build_sign_data(
        "audit-witness",
        r.witness,
        r.timestamp,
        encode_payload(r.log_id, r.operator, bytes.fromhex(r.checkpoint_digest)),
    )


def create_audit_witness_receipt(
    c: AuditCheckpoint, operator: VerifiedPeer, witness: ACEIdentity, timestamp: int
) -> AuditWitnessReceipt:
    """A witness service MUST persist its accepted checkpoint before releasing the signature."""
    verify_audit_checkpoint(c, operator)
    if not _size(timestamp) or timestamp < c.timestamp:
        raise _bad()
    r = AuditWitnessReceipt(
        c.log_id,
        c.signer,
        audit_checkpoint_digest(c),
        timestamp,
        witness.get_ace_id(),
        SignatureEnvelope(witness.get_signing_scheme(), ""),
    )
    value = encode_signature(witness.sign(_witness_data(r)), r.signature.scheme)
    return replace(r, signature=SignatureEnvelope(r.signature.scheme, value))


def verify_audit_witness_receipt(
    r: AuditWitnessReceipt, c: AuditCheckpoint, operator: VerifiedPeer, witness: VerifiedPeer
) -> None:
    try:
        verify_audit_checkpoint(c, operator)
        _check_receipt(r, c, audit_checkpoint_digest(c), witness)
    except (ACEError, TypeError, ValueError, AttributeError):
        raise ACEError("invalid_signature", "invalid audit witness receipt") from None


def _check_receipt(
    r: AuditWitnessReceipt, c: AuditCheckpoint, digest: str, witness: VerifiedPeer
) -> None:
    """Receipt checks against an already verified checkpoint ``c`` whose digest is ``digest``."""
    if (
        not isinstance(witness, VerifiedPeer)
        or r.log_id != c.log_id
        or r.operator != c.signer
        or r.checkpoint_digest != digest
        or r.timestamp < c.timestamp
        or r.witness != witness.ace_id
        or r.signature.scheme != witness.scheme
        or not verify_signature(
            _witness_data(r),
            decode_signature(r.signature.value, witness.scheme, "invalid_signature"),
            witness.scheme,
            witness.signing_public_key,
        )
    ):
        raise _bad()


@dataclass(frozen=True)
class AuditWitnessPolicy:
    witnesses: tuple[VerifiedPeer, ...]
    threshold: int
    max_faulty: int
    max_age_seconds: int
    max_future_skew_seconds: int


def verify_audit_witness_quorum(
    c: AuditCheckpoint, receipts, operator: VerifiedPeer, policy: AuditWitnessPolicy, now: int
) -> None:
    """Locally trusted independent witnesses; 2*threshold > N+max_faulty, threshold <= N-f."""
    try:
        verify_audit_checkpoint(c, operator)
        ws, q, f = policy.witnesses, policy.threshold, policy.max_faulty
        age, skew = policy.max_age_seconds, policy.max_future_skew_seconds
        if (
            not isinstance(ws, (list, tuple))
            or not 1 <= len(ws) <= 32
            or not all(isinstance(w, VerifiedPeer) for w in ws)
            or len({w.ace_id for w in ws}) != len(ws)
            or any(w.ace_id == operator.ace_id for w in ws)
            or not _size(q)
            or not _size(f)
            or q > len(ws) - f
            or 2 * q <= len(ws) + f
            or not _size(age)
            or not _size(skew)
            or not _size(now)
            or not isinstance(receipts, (list, tuple))
            or len(receipts) > len(ws)
            or c.timestamp - now > skew
            or now - c.timestamp > age
        ):
            raise _bad()
        digest = audit_checkpoint_digest(c)
        by_id = {w.ace_id: w for w in ws}
        seen = set()
        for r in receipts:
            w = by_id.get(r.witness)
            if (
                w is None
                or r.witness in seen
                or r.timestamp - now > skew
                or now - r.timestamp > age
            ):
                raise _bad()
            _check_receipt(r, c, digest, w)
            seen.add(r.witness)
        if len(seen) < q:
            raise _bad()
    except (ACEError, TypeError, ValueError, AttributeError):
        raise ACEError(
            "invalid_signature", "audit witness quorum or freshness policy not satisfied"
        ) from None
