"""Principal binding (09-principal): records, the ``principal`` signing context,
same-account rules and the ``requests/`` ledger."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Callable

from ._encoding import (
    CONTROL_CHAR_RE,
    MAX_SAFE_INTEGER,
    check_wire_int,
    decode_b64,
    decode_signature,
    encode_signature,
    is_ace_id,
    is_conversation_id,
    is_message_id,
    to_base64,
    unix_now,
    wire_int,
)
from ._signing import build_sign_data, encode_payload, is_valid_signing_public_key, verify_signature
from .errors import ACEError
from .identity import compute_ace_id, signing_address
from .limits import PRINCIPAL_MAX_LIFETIME_SECONDS, TIMESTAMP_WINDOW_SECONDS
from .store import load_record, write_record
from .threads import sha256_hex
from .types import SIGNING_SCHEMES, ACEIdentity, PrincipalKey, PrincipalRecord, is_principal_type

if TYPE_CHECKING:
    from .store import ACEStore
    from .types import ACEMessage, ParsedMessage

#: 09 § Principal Record: ``controller`` approves, ``delegate`` acts; canonical order.
PRINCIPAL_ROLES: tuple[str, ...] = ("controller", "delegate")
_CAIP10_RE = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}")
_ALLOWED_ROLES = {("controller",), ("delegate",), ("controller", "delegate")}

#: ``open_request_to(conversation_id, request_id, now)``: the ACE ID the receiver sent that
#: ``request`` to, if it was sent in that conversation, no ``decision`` for it was accepted and
#: it is not expired at ``now``; otherwise None.
OpenRequestTo = Callable[[str, str, int], "str | None"]
_WRONG_DECIDER = "decision from a different controller than the request was sent to"
_EIP155_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def is_caip10(value: object) -> bool:
    return isinstance(value, str) and _CAIP10_RE.fullmatch(value) is not None


def same_principal_claims(a: PrincipalRecord, b: PrincipalRecord) -> bool:
    """Compare authenticated statements, not randomized signature bytes."""
    return replace(a, signature="") == replace(b, signature="")


def parse_principal_record(value: object) -> PrincipalRecord:
    """Strict wire parse of a principal record (09 rule 1) without rules 2-10;
    shape errors are ``invalid_principal``. See :func:`validate_principal_record`."""
    return PrincipalRecord.from_dict(value)


def _bad(msg: str) -> ACEError:
    return ACEError("invalid_principal", msg)


@dataclass(frozen=True)
class PrincipalSigner:
    """The key that signs a principal record: ``sign(digest32) -> signature bytes``
    (ed25519: 64 bytes; secp256k1: r||s||v, low-S). Any key source works (PRF, SE, HSM)."""

    scheme: str
    public_key: bytes
    sign: Callable[[bytes], bytes]

    @classmethod
    def from_identity(cls, identity: ACEIdentity) -> "PrincipalSigner":
        key = bytes(identity.get_signing_public_key())
        return cls(identity.get_signing_scheme(), key, identity.sign)


def principal_payload(record: PrincipalRecord, subject_signing_public_key: bytes) -> bytes:
    """``encodePayload(account, join(roles), signer.scheme, signer.publicKey, subjectKeyB64,
    scopeOrEmpty, decimal(expiresAtOr0))`` (09 § Signing Context)."""
    return encode_payload(
        record.account,
        ",".join(record.roles),
        record.signer.scheme,
        record.signer.public_key,
        to_base64(bytes(subject_signing_public_key)),
        record.scope if record.scope is not None else "",
        str(record.expires_at if record.expires_at is not None else 0),
    )


def principal_sign_data(record: PrincipalRecord, subject_signing_public_key: bytes) -> bytes:
    """The 32-byte digest the signer signs (no validation)."""
    return build_sign_data(
        "principal",
        compute_ace_id(bytes(subject_signing_public_key)),
        record.issued_at,
        principal_payload(record, subject_signing_public_key),
    )


def _check_fields(r: PrincipalRecord, now: int) -> bytes:
    """09 § Validation rules 2-7 on a parsed record; returns the decoded signer key."""
    if not is_caip10(r.account):  # 2
        raise _bad("principal.account must be a CAIP-10 account")
    if r.roles not in _ALLOWED_ROLES:  # 3
        raise _bad(
            'principal.roles must be ["controller"], ["delegate"] or ["controller","delegate"]'
        )
    if r.signer.scheme not in SIGNING_SCHEMES:  # 4
        raise _bad("principal.signer.scheme is unsupported")
    signer_key = decode_b64(
        r.signer.public_key, "invalid_principal", "principal.signer.publicKey", max_bytes=64
    )
    if not is_valid_signing_public_key(r.signer.scheme, signer_key):
        raise _bad("principal.signer.publicKey is not a valid key for its scheme")
    if r.issued_at > now + TIMESTAMP_WINDOW_SECONDS:  # 5
        raise _bad("principal.issuedAt is in the future")
    if not r.issued_at < r.expires_at <= r.issued_at + PRINCIPAL_MAX_LIFETIME_SECONDS:  # 6
        raise _bad("principal.expiresAt must be after issuedAt and at most 366 days later")
    if r.scope is not None and (
        not 1 <= len(r.scope) <= 256 or CONTROL_CHAR_RE.search(r.scope)
    ):  # 7
        raise _bad("principal.scope must be 1-256 characters without control characters")
    return signer_key


def validate_principal_record(
    record: PrincipalRecord | dict,
    subject_signing_public_key: bytes,
    now: int,
    *,
    allow_expired: bool = False,
) -> PrincipalRecord:
    """09 § Validation, rules 1-10 in order; every failure is ``invalid_principal``.
    ``allow_expired`` skips only rule 10 (expiry), so a caller can tell an expired-only record
    from an invalid one (R-P40).
    ``subject_signing_public_key`` is the key the caller has verified, never the record's."""
    r = PrincipalRecord.from_dict(record)  # 1
    signer_key = _check_fields(r, now)  # 2-7
    sig = decode_signature(r.signature, r.signer.scheme, "invalid_principal")  # 8
    subject = bytes(subject_signing_public_key)
    if not verify_signature(principal_sign_data(r, subject), sig, r.signer.scheme, signer_key):  # 9
        raise _bad("principal.signature does not verify for this subject")
    if r.expires_at <= now and not allow_expired:  # 10
        raise _bad("principal record has expired")
    return r


def create_principal_record(
    signer: PrincipalSigner,
    *,
    subject_signing_public_key: bytes,
    account: str,
    roles: list[str] | tuple[str, ...],
    expires_at: int,
    scope: str | None = None,
    issued_at: int | None = None,
) -> PrincipalRecord:
    """Sign a principal record for a subject key. Roles are canonicalized (deduplicated,
    ``controller`` first); the result is validated at ``issued_at`` (``invalid_principal``
    for invalid inputs). ``expires_at`` is required (09 § Principal Record)."""
    if not isinstance(roles, (list, tuple)) or any(r not in PRINCIPAL_ROLES for r in roles):
        raise ACEError("invalid_argument", "roles must contain only 'controller' and 'delegate'")
    ts = unix_now(None) if issued_at is None else issued_at
    draft = PrincipalRecord(
        account=account,
        roles=tuple(r for r in PRINCIPAL_ROLES if r in roles),
        signer=PrincipalKey(signer.scheme, to_base64(bytes(signer.public_key))),
        issued_at=ts,
        signature="",
        expires_at=expires_at,
        scope=scope,
    )
    # Rules 1-7 before asking the (possibly hardware) signer to sign.
    _check_fields(PrincipalRecord.from_dict(draft), ts)
    digest = principal_sign_data(draft, subject_signing_public_key)
    record = replace(draft, signature=encode_signature(bytes(signer.sign(digest)), signer.scheme))
    return validate_principal_record(record, subject_signing_public_key, ts)


@dataclass(frozen=True)
class PrincipalContext:
    """Step-7 inputs from the receiver: its own principal ``account``; the keys accepted as
    authorities of that account (``self_signer``, the signer of the receiver's own record, and
    host-provided ``trusted_signers``, e.g. read from chain); the ledger lookup
    ``open_request_to`` (see :data:`OpenRequestTo`). The Inbox refreshes a sender whose pinned
    principal fails 09 steps 2-5 before parsing, so the context carries no refresh hook."""

    account: str
    open_request_to: OpenRequestTo | None = None
    self_signer: PrincipalKey | None = None
    trusted_signers: frozenset[PrincipalKey] = frozenset()


def _is_account_authority(
    p: PrincipalRecord,
    self_signer: PrincipalKey | None,
    trusted_signers: frozenset[PrincipalKey],
) -> bool:
    """09 step 4: ``p.signer`` is an authority of ``p.account`` when it is the receiver's own
    attesting key, a host-trusted key, or (``eip155``) the secp256k1 key whose address is the
    account address. ``p`` has passed ``validate_principal_record``."""
    if p.signer == self_signer or p.signer in trusted_signers:
        return True
    namespace, _, address = p.account.split(":", 2)
    if namespace != "eip155" or p.signer.scheme != "secp256k1":
        return False
    if _EIP155_ADDRESS_RE.fullmatch(address) is None:
        return False
    key = decode_b64(p.signer.public_key, "invalid_principal", "principal.signer.publicKey")
    derived = signing_address("secp256k1", key)
    return derived.lower() == address.lower()


def check_principal_rules(
    type_: str,
    body: dict,
    *,
    conversation_id: str,
    sender_principal: PrincipalRecord | dict | None,
    sender_signing_public_key: bytes,
    self_account: str | None,
    open_request_to: OpenRequestTo | None,
    now: int,
    self_signer: PrincipalKey | None = None,
    trusted_signers: frozenset[PrincipalKey] = frozenset(),
) -> None:
    """09 § Same-Account Rules, steps 1-7 in order (first failure wins). Pure: no side
    effects, so a caller may refresh the sender's peer binding and call it again (R-P20).
    ``body`` has already passed ``validate_body``."""
    if not is_principal_type(type_):
        raise ACEError("invalid_argument", "not a principal message type")
    if self_account is None:  # 1
        raise ACEError("wrong_principal", "the receiver has no principal")
    if sender_principal is None:  # 2
        raise ACEError("wrong_principal", "the sender has no principal")
    try:  # 3
        p = validate_principal_record(sender_principal, sender_signing_public_key, now)
    except ACEError as exc:
        if exc.code != "invalid_principal":
            raise
        raise ACEError(
            "wrong_principal", f"the sender's principal is invalid: {exc.message}"
        ) from None
    if not _is_account_authority(p, self_signer, trusted_signers):  # 4
        raise ACEError("wrong_principal", "signer is not an authority of the account")
    if p.account != self_account:  # 5
        raise ACEError("wrong_principal", "the sender belongs to another account")
    if p.scope is not None:
        raise ACEError("wrong_principal", "unsupported principal scope")
    if type_ == "decision":
        if "controller" not in p.roles:  # 6
            raise ACEError("wrong_principal", "only a controller may send a decision")
        recipient = (
            None
            if open_request_to is None
            else open_request_to(conversation_id, body["requestId"], now)
        )
        if recipient is None:  # 7 (unknown, decided or expired request)
            raise ACEError(
                "bad_reference", "decision.requestId names no open request in this conversation"
            )
        if recipient != compute_ace_id(bytes(sender_signing_public_key)):  # 7 (decider)
            raise ACEError("wrong_principal", _WRONG_DECIDER)


def sender_principal_usable(
    sender_principal: PrincipalRecord | dict | None,
    sender_signing_public_key: bytes,
    ctx: PrincipalContext,
    now: int,
) -> bool:
    """True when the pinned sender principal passes 09 steps 2-5 for ``ctx`` (present, valid,
    signed by an authority of the account, same account). False means a peer refresh may
    help (R-P20)."""
    if sender_principal is None:
        return False
    try:
        p = validate_principal_record(sender_principal, sender_signing_public_key, now)
    except ACEError as exc:
        if exc.code != "invalid_principal":
            raise
        return False
    return (
        p.scope is None
        and _is_account_authority(p, ctx.self_signer, ctx.trusted_signers)
        and p.account == ctx.account
    )


# --- requests/ ledger (09 § Persistence, 06 Appendix A) ------------------------------


def request_key(conversation_id: str, message_id: str) -> str:
    return f"requests/{sha256_hex(conversation_id, message_id)}.json"


def _valid_decision(dec: object) -> bool:
    return dec is None or (
        isinstance(dec, dict)
        and is_message_id(dec.get("messageId"))
        and dec.get("outcome") in ("approve", "deny")
        and wire_int(dec.get("timestamp")) is not None
    )


def load_request_record(store: "ACEStore", conversation_id: str, message_id: str) -> dict | None:
    """The ledger entry of a sent ``request``, or None; a malformed entry is ``storage_failed``."""
    key = request_key(conversation_id, message_id)
    d = load_record(store, key)
    if d is None:
        return None
    if (
        d.get("conversationId") != conversation_id
        or d.get("messageId") != message_id
        or not is_ace_id(d.get("to"))
        or wire_int(d.get("sentAt")) is None
        or not (d.get("expiresAt") is None or wire_int(d.get("expiresAt")) is not None)
        or not _valid_decision(d.get("decision"))
    ):
        raise ACEError("storage_failed", f"{key}: invalid request record")
    return d


def open_request_to(
    store: "ACEStore", conversation_id: str, message_id: str, now: int
) -> str | None:
    """The ``to`` of a sent, undecided, unexpired request (expired when ``timestamp + ttl <
    now``), else None (09 § Same-Account Rules step 7). Bind ``store`` to get
    :data:`OpenRequestTo`."""
    rec = load_request_record(store, conversation_id, message_id)
    if rec is None or rec["decision"] is not None:
        return None
    expires_at = rec.get("expiresAt")
    return rec["to"] if expires_at is None or now <= expires_at else None


def record_request(
    store: "ACEStore", message: "ACEMessage", sent_at: int, ttl: int | None = None
) -> None:
    """Write the ledger entry of a delivered ``request`` (idempotent); ``ttl`` is the body's
    ``ttl``. Caller holds lock ``requests``."""
    if not is_conversation_id(message.conversation_id):
        raise ACEError("invalid_argument", "invalid conversationId")
    if not is_message_id(message.message_id):
        raise ACEError("invalid_argument", "invalid messageId")
    check_wire_int(sent_at, "sentAt")
    expires_at = None
    if ttl is not None:
        expires_at = min(message.timestamp + check_wire_int(ttl, "ttl"), MAX_SAFE_INTEGER)
    if load_request_record(store, message.conversation_id, message.message_id) is not None:
        return
    write_record(
        store,
        request_key(message.conversation_id, message.message_id),
        {
            "conversationId": message.conversation_id,
            "decision": None,
            "expiresAt": expires_at,
            "messageId": message.message_id,
            "sentAt": sent_at,
            "to": message.to_id,
        },
    )


def fill_decision(store: "ACEStore", m: "ParsedMessage") -> None:
    """Mark the request of an accepted ``decision`` decided. Replaying the recorded decision
    (same ``messageId``) is a no-op and an unknown request is a no-op; a second, different
    decision is ``bad_reference`` (a request has at most one accepted decision); a decision
    from anyone but the request's ``to`` is ``wrong_principal`` (09 step 7). The record is
    unchanged on failure. Caller holds lock ``requests``."""
    request_id = m.body["requestId"]
    rec = load_request_record(store, m.conversation_id, request_id)
    if rec is None:
        return
    if rec["decision"] is not None:
        if rec["decision"]["messageId"] == m.message_id:
            return
        raise ACEError("bad_reference", "the request already has an accepted decision")
    if m.from_id != rec["to"]:
        raise ACEError("wrong_principal", _WRONG_DECIDER)
    out: dict[str, Any] = {k: v for k, v in rec.items() if k != "version"}
    out["decision"] = {
        "messageId": m.message_id,
        "outcome": m.body["outcome"],
        "timestamp": m.timestamp,
    }
    write_record(store, request_key(m.conversation_id, request_id), out)
