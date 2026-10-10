"""Message construction and the receive pipeline (06-security)."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Callable

from ._encoding import (
    check_json_value,
    check_wire_int,
    decode_signature,
    dumps_body,
    encode_signature,
    is_conversation_id,
    is_message_id,
    is_sha256_hex,
    is_thread_id,
    loads_body,
    to_base64,
    unix_now,
    wire_int,
)
from ._signing import verify_signature
from .discovery import VerifiedPeer
from .encryption import compute_conversation_id, encrypt
from .envelope import decode_kem_ciphertext, decode_payload, message_sign_data, revalidate
from .errors import ACEError
from .limits import MAX_PLAINTEXT_BYTES, TIMESTAMP_WINDOW_SECONDS
from .principal import PrincipalContext, check_principal_rules
from .replay import ReplayDetector
from .state_machine import ThreadEvent, ThreadStateMachine
from .types import (
    ACEIdentity,
    ACEMessage,
    EncryptionEnvelope,
    MessageType,
    ParsedMessage,
    SignatureEnvelope,
    is_economic_type,
    is_message_type,
    is_principal_type,
)

# --- body schema ------------------------------------------------------------------

_STR, _OPT_STR, _OPT_OBJ, _OBJ, _OPT_TTL = "str", "opt_str", "opt_obj", "obj", "opt_ttl"

_SCHEMAS: dict[str, tuple[tuple[str, str], ...]] = {
    "rfq": (("need", _STR), ("maxPrice", _OPT_STR), ("currency", _OPT_STR), ("ttl", _OPT_TTL)),
    "offer": (("price", _STR), ("currency", _STR), ("terms", _OPT_STR), ("ttl", _OPT_TTL)),
    "accept": (("offerId", _STR),),
    "reject": (("reason", _OPT_STR),),
    "invoice": (
        ("offerId", _STR),
        ("amount", _STR),
        ("currency", _STR),
        ("settlementMethod", _STR),
        ("settlementDetails", _OPT_OBJ),
    ),
    "receipt": (
        ("referenceId", _STR),
        ("amount", _STR),
        ("currency", _STR),
        ("settlementMethod", _STR),
        ("proof", _OBJ),
    ),
    "deliver": (
        ("type", _STR),
        ("content", _OPT_STR),
        ("contentType", _OPT_STR),
        ("uri", _OPT_STR),
        ("metadata", _OPT_OBJ),
    ),
    "confirm": (("deliverId", _STR), ("message", _OPT_STR)),
    "info": (("message", _STR),),
    "text": (("message", _STR),),
    "request": (
        ("action", _STR),
        ("summary", _STR),
        ("ref", _OPT_OBJ),
        ("amount", _OPT_STR),
        ("currency", _OPT_STR),
        ("details", _OPT_OBJ),
        ("ttl", _OPT_TTL),
    ),
    "decision": (
        ("requestId", _STR),
        ("outcome", _STR),
        ("reason", _OPT_STR),
        ("result", _OPT_OBJ),
    ),
    "report": (
        ("action", _STR),
        ("summary", _STR),
        ("outcome", _STR),
        ("ref", _OPT_OBJ),
        ("requestId", _OPT_STR),
        ("proof", _OPT_OBJ),
    ),
}

_OUTCOMES: dict[str, tuple[str, ...]] = {
    "decision": ("approve", "deny"),
    "report": ("ok", "failed", "skipped"),
}


def _check_ref(type_: str, ref: dict) -> None:
    if not is_conversation_id(ref.get("conversationId")):
        raise ACEError("invalid_body", f"{type_}.ref.conversationId must be 64 lowercase hex")
    if not is_message_id(ref.get("messageId")):
        raise ACEError("invalid_body", f"{type_}.ref.messageId must be a lowercase UUID v4")
    thread_id = ref.get("threadId")
    if thread_id is not None and not is_thread_id(thread_id):
        raise ACEError("invalid_body", f"{type_}.ref.threadId must be a valid thread ID")


def validate_body(type_: MessageType, body: dict) -> None:
    """Validate a body against its type's schema; failures are ``invalid_body``.

    Optional fields set to null are absent; unknown fields are ignored.
    """
    if not is_message_type(type_):
        raise ACEError("invalid_argument", "unknown message type")
    if type(body) is not dict:
        raise ACEError("invalid_body", "body must be a JSON object")
    for name, kind in _SCHEMAS.get(type_, ()):
        v = body.get(name)
        if v is None:
            if kind in (_STR, _OBJ):
                raise ACEError("invalid_body", f"{type_}.{name} is required")
            continue
        ok = (
            isinstance(v, str)
            if kind in (_STR, _OPT_STR)
            else type(v) is dict
            if kind in (_OBJ, _OPT_OBJ)
            else wire_int(v) is not None
        )
        if not ok:
            raise ACEError("invalid_body", f"{type_}.{name} has the wrong type")
    if type_ == "deliver":
        kind = body["type"]
        required = "content" if kind == "inline" else "uri" if kind == "reference" else None
        if required is None:
            raise ACEError("invalid_body", "deliver.type must be 'inline' or 'reference'")
        if not isinstance(body.get(required), str):
            raise ACEError("invalid_body", f"deliver ({kind}) requires {required}")
    if type_ in _OUTCOMES and body["outcome"] not in _OUTCOMES[type_]:
        raise ACEError("invalid_body", f"{type_}.outcome must be one of {list(_OUTCOMES[type_])}")
    if type_ in ("request", "report") and body.get("ref") is not None:
        _check_ref(type_, body["ref"])


def decode_body(type_: MessageType, raw: bytes) -> dict:
    """Internal: decrypted bytes -> validated body (``invalid_body``)."""
    body = loads_body(raw)
    validate_body(type_, body)
    return body


# --- installed schemas --------------------------------------------------------------

#: A deterministic validator installed with ``Inbox.open(schemas=...)`` /
#: ``Outbox.open(schemas=...)``, keyed by ``schemaDigest``. It receives
#: ``{"type", "schemaDigest", "threadId", "body"}`` and returns None when the body is valid.
#: Raising an ``ACEError`` with a permanent code rejects the message with that code; any other
#: exception rejects it as ``invalid_body``. The Inbox quarantines, ``Outbox.stage`` raises.
SchemaValidator = Callable[[dict[str, Any]], None]


def check_schemas(schemas: object) -> dict[str, SchemaValidator]:
    """Validate an ``Inbox.open`` / ``Outbox.open`` ``schemas`` option (``invalid_argument``)."""
    if schemas is None:
        return {}
    if not isinstance(schemas, dict) or not all(
        is_sha256_hex(digest) and callable(validator) for digest, validator in schemas.items()
    ):
        raise ACEError("invalid_argument", "schemas must map 64-hex schemaDigest keys to callables")
    return dict(schemas)


def run_schema_validator(
    schemas: dict[str, SchemaValidator],
    type_: str,
    schema_digest: str,
    thread_id: str | None,
    body: dict,
) -> None:
    """Run the validator installed for ``schema_digest``, if any (see ``SchemaValidator``)."""
    validator = schemas.get(schema_digest)
    if validator is None:
        return
    copy = json.loads(dumps_body(body))  # a JSON round-trip copy: the validator cannot mutate
    try:
        validator(
            {"type": type_, "schemaDigest": schema_digest, "threadId": thread_id, "body": copy}
        )
    except ACEError as exc:
        if exc.category == "permanent":
            raise
        raise ACEError("invalid_body", f"schema validator failed: {exc.code}") from exc
    except Exception as exc:
        raise ACEError(
            "invalid_body", f"schema validator rejected the body: {type(exc).__name__}: {exc}"
        ) from exc


# --- helpers ----------------------------------------------------------------------


def _event(env: ParsedMessage) -> ThreadEvent:
    return ThreadEvent(
        env.conversation_id,
        env.thread_id,
        env.type,
        env.message_id,
        env.timestamp,
        env.from_id,
        env.to_id,
    )


# --- create -----------------------------------------------------------------------


_SCHEMA_KIND_NAMES = {
    "str": "str",
    "opt_str": "optStr",
    "obj": "obj",
    "opt_obj": "optObj",
    "opt_ttl": "optTtl",
}


def _schema_digest(type_: str, fields: tuple[tuple[str, str], ...]) -> str:
    descriptor = {
        "type": type_,
        "fields": [[name, _SCHEMA_KIND_NAMES[kind]] for name, kind in fields],
        "outcomes": list(_OUTCOMES.get(type_, ())),
        "version": 1,
    }
    return hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


_KNOWN_SCHEMA_DIGESTS = {t: _schema_digest(t, fields) for t, fields in _SCHEMAS.items()}


def known_schema_digest(type_: str) -> str | None:
    return _KNOWN_SCHEMA_DIGESTS.get(type_)


def private_content(
    type_: str, body: dict, thread_id: str | None, schema_digest: str | None
) -> dict:
    expected = known_schema_digest(type_)
    digest = schema_digest if schema_digest is not None else expected
    if not is_sha256_hex(digest) or (expected is not None and digest != expected):
        raise ACEError("invalid_body", "a matching immutable schemaDigest is required")
    content = {
        "type": type_,
        "body": body,
        "schemaDigest": digest,
        **({} if thread_id is None else {"threadId": thread_id}),
    }
    check_json_value(content)
    return content


def decode_private_content(raw: bytes) -> dict:
    content = loads_body(raw)
    if not set(content) <= {"type", "body", "schemaDigest", "threadId"}:
        raise ACEError("invalid_body", "unknown private content field")
    if (
        not is_message_type(content.get("type"))
        or type(content.get("body")) is not dict
        or not isinstance(content.get("schemaDigest"), str)
    ):
        raise ACEError("invalid_body", "invalid private content")
    if "threadId" in content and not is_thread_id(content["threadId"]):
        raise ACEError("invalid_body", "invalid private threadId")
    result = private_content(
        content["type"], content["body"], content.get("threadId"), content["schemaDigest"]
    )
    validate_body(result["type"], result["body"])
    return result


def create_message(
    sender: ACEIdentity,
    recipient: VerifiedPeer,
    type_: MessageType,
    body: dict,
    threads: ThreadStateMachine | None = None,
    *,
    thread_id: str | None = None,
    timestamp: int | None = None,
    schema_digest: str | None = None,
) -> ACEMessage:
    """Encrypt, sign and record an outbound message."""
    if not isinstance(recipient, VerifiedPeer):
        raise ACEError("invalid_argument", "recipient must be a VerifiedPeer")
    if threads is not None and not isinstance(threads, ThreadStateMachine):
        raise ACEError("invalid_argument", "threads must be a ThreadStateMachine")
    # 1. type, threadId, local identity
    if not is_message_type(type_):
        raise ACEError("invalid_argument", "unknown message type")
    if thread_id is not None and not is_thread_id(thread_id):
        raise ACEError(
            "invalid_argument", "thread_id must be 1..256 code points without control characters"
        )
    if threads is not None and thread_id is None and is_economic_type(type_):
        raise ACEError("invalid_argument", "economic messages require thread_id")
    from_id = sender.get_ace_id()
    if threads is not None and threads.local_ace_id != from_id:
        raise ACEError("invalid_argument", "threads.local_ace_id must be the sender")
    ts = unix_now(None) if timestamp is None else timestamp
    check_wire_int(ts, "timestamp")
    # 2. JSON values, then schema
    if type(body) is not dict:
        raise ACEError("invalid_body", "body must be a JSON object")
    check_json_value(body)
    validate_body(type_, body)
    # 3. conversation
    conversation_id = compute_conversation_id(
        sender.get_encryption_public_key(), recipient.encryption_public_key
    )
    message_id = str(uuid.uuid4())
    event = ThreadEvent(
        conversation_id, thread_id, type_, message_id, ts, from_id, recipient.ace_id
    )
    # 4. state machine pre-check
    if threads is not None:
        threads.check(event, body)
    # 5. serialize
    plaintext = dumps_body(private_content(type_, body, thread_id, schema_digest))
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ACEError("limit_exceeded", f"body exceeds {MAX_PLAINTEXT_BYTES} bytes")
    # 6. encrypt
    kem_ciphertext, payload = encrypt(plaintext, recipient.encryption_public_key, conversation_id)
    scheme = sender.get_signing_scheme()
    env = ACEMessage(
        ace="2.0",
        message_id=message_id,
        from_id=from_id,
        to_id=recipient.ace_id,
        conversation_id=conversation_id,
        timestamp=ts,
        encryption=EncryptionEnvelope(to_base64(kem_ciphertext), to_base64(payload)),
        signature=SignatureEnvelope(scheme, ""),
    )
    # 7. sign
    env.signature.value = encode_signature(sender.sign(message_sign_data(env)), scheme)
    # 8. commit
    if threads is not None:
        threads.apply(event, body)
    return env


# --- parse ------------------------------------------------------------------------


def parse_message(
    env: ACEMessage,
    receiver: ACEIdentity,
    sender: VerifiedPeer,
    *,
    threads: ThreadStateMachine | None = None,
    replay: ReplayDetector,
    floor: int | None = None,
    clock: Callable[[], int] | None = None,
    principal: PrincipalContext | None = None,
) -> ParsedMessage:
    """Verify, decrypt and validate an inbound message. The first failure wins:

    decode -> wrong_recipient -> from (invalid_envelope) -> scheme_mismatch ->
    conversationId (invalid_envelope) -> floor/timestamp (stale_timestamp) -> replay ->
    invalid_signature -> replay commit -> decrypt -> invalid_body -> state machine /
    principal rules.

    ``principal`` (the receiver's :class:`PrincipalContext`) installs the account policy:
    principal types (``request``, ``decision``, ``report``) then pass 09 § Same-Account
    Rules or fail with ``wrong_principal``. Without it they are plain data, never verified
    authority (06 step 7); receiving a message never authorizes execution.
    """
    if principal is not None and not isinstance(principal, PrincipalContext):
        raise ACEError("invalid_argument", "principal must be a PrincipalContext")
    if not isinstance(sender, VerifiedPeer):
        raise ACEError("invalid_argument", "sender must be a VerifiedPeer")
    if (threads is not None and not isinstance(threads, ThreadStateMachine)) or not isinstance(
        replay, ReplayDetector
    ):
        raise ACEError("invalid_argument", "threads and replay are required")
    return parse_with_gate(
        env,
        receiver,
        sender,
        threads=threads,
        replay=replay,
        floor=floor,
        clock=clock,
        principal=principal,
    )


def parse_with_gate(
    env: ACEMessage,
    receiver: ACEIdentity,
    sender: VerifiedPeer,
    *,
    threads: ThreadStateMachine | None,
    replay: Any,
    floor: int | None,
    clock: Callable[[], int] | None,
    principal: PrincipalContext | None,
) -> ParsedMessage:
    """Internal: ``parse_message`` on validated arguments. ``replay`` is any object with the
    seen store's ``accepts`` (step 7) and ``commit`` (step 9); the Inbox commits later."""
    receiver_id = receiver.get_ace_id()
    if threads is not None and threads.local_ace_id != receiver_id:
        raise ACEError("invalid_argument", "threads.local_ace_id must be the receiver")
    # 1
    env = revalidate(env)
    # 2-5
    if env.to_id != receiver_id:
        raise ACEError("wrong_recipient", "message is not addressed to this identity")
    if env.from_id != sender.ace_id:
        raise ACEError("invalid_envelope", "from does not match the sender")
    if env.signature.scheme != sender.scheme:
        raise ACEError("scheme_mismatch", "signature scheme differs from the sender's scheme")
    if env.conversation_id != compute_conversation_id(
        sender.encryption_public_key, receiver.get_encryption_public_key()
    ):
        raise ACEError("invalid_envelope", "conversationId does not match the verified keys")
    # 6
    now = unix_now(clock)
    if floor is None:
        floor = max(0, now - TIMESTAMP_WINDOW_SECONDS)
    elif isinstance(floor, bool) or not isinstance(floor, int) or not 0 <= floor <= now:
        raise ACEError("invalid_argument", "floor must be an integer in [0, now]")
    if not floor <= env.timestamp <= now + TIMESTAMP_WINDOW_SECONDS:
        raise ACEError("stale_timestamp", "timestamp is outside the acceptance window")
    # 7
    if not replay.accepts(env.message_id, env.from_id, env.timestamp):
        raise ACEError("replay", "message already seen or below the replay horizon")
    # 8
    sig = decode_signature(env.signature.value, env.signature.scheme, "invalid_envelope")
    if not verify_signature(message_sign_data(env), sig, sender.scheme, sender.signing_public_key):
        raise ACEError("invalid_signature", "message signature does not verify")
    # 9
    if not replay.commit(env.message_id, env.from_id, env.timestamp, floor):
        raise ACEError("replay", "message already seen or below the replay horizon")
    # 10
    try:
        plaintext = receiver.decrypt(
            decode_kem_ciphertext(env.encryption.kem_ciphertext),
            decode_payload(env.encryption.payload),
            env.conversation_id,
        )
    except ACEError:
        raise
    except Exception as exc:
        raise ACEError(
            "identity_unavailable", f"identity decrypt failed: {type(exc).__name__}"
        ) from exc
    content = decode_private_content(plaintext)
    parsed = ParsedMessage(
        message_id=env.message_id,
        from_id=env.from_id,
        to_id=env.to_id,
        conversation_id=env.conversation_id,
        timestamp=env.timestamp,
        type=content["type"],
        thread_id=content.get("threadId"),
        body=content["body"],
        schema_digest=content["schemaDigest"],
    )
    apply_receive_rules(parsed, sender, threads=threads, principal=principal, now=now)
    return parsed


def apply_receive_rules(
    parsed: ParsedMessage,
    sender: VerifiedPeer,
    *,
    threads: ThreadStateMachine | None,
    principal: PrincipalContext | None,
    now: int,
) -> None:
    """06 step 7 on a decrypted message: the thread state machine (economic types, when
    ``threads`` is given) and the principal rules (principal types, when ``principal`` is
    given). ``parse_message`` runs it last; the Inbox runs it under its own locks."""
    if threads is not None and is_economic_type(parsed.type):
        threads.apply(_event(parsed), parsed.body)
    if principal is not None and is_principal_type(parsed.type):
        _check_principal(parsed, sender, principal, now)


def _check_principal(
    env: ParsedMessage,
    sender: VerifiedPeer,
    ctx: PrincipalContext,
    now: int,
) -> None:
    """06 step 7 for principal types (09 § Same-Account Rules)."""
    check_principal_rules(
        env.type,
        env.body,
        conversation_id=env.conversation_id,
        sender_principal=sender.principal,
        sender_signing_public_key=sender.signing_public_key,
        self_account=ctx.account,
        open_request_to=ctx.open_request_to,
        now=now,
        self_signer=ctx.self_signer,
        trusted_signers=ctx.trusted_signers,
    )
