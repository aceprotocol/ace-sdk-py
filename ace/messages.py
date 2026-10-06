"""Message construction and the receive pipeline (06-security)."""

from __future__ import annotations

import uuid
from typing import Callable

from ._encoding import (
    check_json_value,
    check_wire_int,
    decode_signature,
    dumps_body,
    encode_signature,
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
)

# --- body schema ------------------------------------------------------------------

_STR, _OPT_STR, _OPT_OBJ, _OBJ, _OPT_TTL = "str", "opt_str", "opt_obj", "obj", "opt_ttl"

_SCHEMAS: dict[str, tuple[tuple[str, str], ...]] = {
    "rfq": (("need", _STR), ("maxPrice", _OPT_STR), ("currency", _OPT_STR), ("ttl", _OPT_TTL)),
    "offer": (("price", _STR), ("currency", _STR), ("terms", _OPT_STR), ("ttl", _OPT_TTL)),
    "accept": (("offerId", _STR),),
    "reject": (("reason", _OPT_STR),),
    "invoice": (("offerId", _STR), ("amount", _STR), ("currency", _STR), ("settlementMethod", _STR),
                ("settlementDetails", _OPT_OBJ)),
    "receipt": (("referenceId", _STR), ("amount", _STR), ("currency", _STR), ("settlementMethod", _STR),
                ("proof", _OBJ)),
    "deliver": (("type", _STR), ("content", _OPT_STR), ("contentType", _OPT_STR), ("uri", _OPT_STR),
                ("metadata", _OPT_OBJ)),
    "confirm": (("deliverId", _STR), ("message", _OPT_STR)),
    "info": (("message", _STR),),
    "text": (("message", _STR),),
}


def validate_body(type_: MessageType, body: dict) -> None:
    """Validate a body against its type's schema; failures are ``invalid_body``.

    Optional fields set to null are absent; unknown fields are ignored.
    """
    if not is_message_type(type_):
        raise ACEError("invalid_argument", "unknown message type")
    if type(body) is not dict:
        raise ACEError("invalid_body", "body must be a JSON object")
    for name, kind in _SCHEMAS[type_]:
        v = body.get(name)
        if v is None:
            if kind in (_STR, _OBJ):
                raise ACEError("invalid_body", f"{type_}.{name} is required")
            continue
        ok = (
            isinstance(v, str) if kind in (_STR, _OPT_STR)
            else type(v) is dict if kind in (_OBJ, _OPT_OBJ)
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


def decode_body(type_: MessageType, raw: bytes) -> dict:
    """Internal: decrypted bytes -> validated body (``invalid_body``)."""
    body = loads_body(raw)
    validate_body(type_, body)
    return body


# --- helpers ----------------------------------------------------------------------

def _event(env: ACEMessage) -> ThreadEvent:
    return ThreadEvent(env.conversation_id, env.thread_id, env.type, env.message_id, env.timestamp,
                       env.from_id, env.to_id)


# --- create -----------------------------------------------------------------------

def create_message(
    sender: ACEIdentity,
    recipient: VerifiedPeer,
    type_: MessageType,
    body: dict,
    threads: ThreadStateMachine,
    *,
    thread_id: str | None = None,
    timestamp: int | None = None,
) -> ACEMessage:
    """Encrypt, sign and record an outbound message (design §2.5 order)."""
    if not isinstance(recipient, VerifiedPeer):
        raise ACEError("invalid_argument", "recipient must be a VerifiedPeer")
    if not isinstance(threads, ThreadStateMachine):
        raise ACEError("invalid_argument", "threads must be a ThreadStateMachine")
    # 1. type, threadId, local identity
    if not is_message_type(type_):
        raise ACEError("invalid_argument", "unknown message type")
    if thread_id is not None and not is_thread_id(thread_id):
        raise ACEError("invalid_argument", "thread_id must be 1..256 code points without control characters")
    if thread_id is None and is_economic_type(type_):
        raise ACEError("invalid_argument", "economic messages require thread_id")
    from_id = sender.get_ace_id()
    if threads.local_ace_id != from_id:
        raise ACEError("invalid_argument", "threads.local_ace_id must be the sender")
    ts = unix_now(None) if timestamp is None else timestamp
    check_wire_int(ts, "timestamp")
    # 2. JSON values, then schema
    if type(body) is not dict:
        raise ACEError("invalid_body", "body must be a JSON object")
    check_json_value(body)
    validate_body(type_, body)
    # 3. conversation
    conversation_id = compute_conversation_id(sender.get_encryption_public_key(), recipient.encryption_public_key)
    message_id = str(uuid.uuid4())
    event = ThreadEvent(conversation_id, thread_id, type_, message_id, ts, from_id, recipient.ace_id)
    # 4. state machine pre-check
    threads.check(event, body)
    # 5. serialize
    plaintext = dumps_body(body)
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ACEError("limit_exceeded", f"body exceeds {MAX_PLAINTEXT_BYTES} bytes")
    # 6. encrypt
    kem_ciphertext, payload = encrypt(plaintext, recipient.encryption_public_key, conversation_id)
    scheme = sender.get_signing_scheme()
    env = ACEMessage(
        ace="1.0", message_id=message_id, from_id=from_id, to_id=recipient.ace_id,
        conversation_id=conversation_id, type=type_, timestamp=ts,
        encryption=EncryptionEnvelope(to_base64(kem_ciphertext), to_base64(payload)),
        signature=SignatureEnvelope(scheme, ""), thread_id=thread_id,
    )
    # 7. sign
    env.signature.value = encode_signature(sender.sign(message_sign_data(env)), scheme)
    # 8. commit
    threads.apply(event, body)
    return env


# --- parse ------------------------------------------------------------------------

def parse_message(
    env: ACEMessage,
    receiver: ACEIdentity,
    sender: VerifiedPeer,
    *,
    threads: ThreadStateMachine,
    replay: ReplayDetector,
    floor: int | None = None,
    clock: Callable[[], int] | None = None,
) -> ParsedMessage:
    """Verify, decrypt and validate an inbound message. The first failure wins:

    decode -> wrong_recipient -> from (invalid_envelope) -> scheme_mismatch ->
    conversationId (invalid_envelope) -> floor/timestamp (stale_timestamp) -> replay ->
    invalid_signature -> replay commit -> decrypt -> invalid_body -> state machine.
    """
    if not isinstance(sender, VerifiedPeer):
        raise ACEError("invalid_argument", "sender must be a VerifiedPeer")
    if not isinstance(threads, ThreadStateMachine) or not isinstance(replay, ReplayDetector):
        raise ACEError("invalid_argument", "threads and replay are required")
    receiver_id = receiver.get_ace_id()
    if threads.local_ace_id != receiver_id:
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
    if env.conversation_id != compute_conversation_id(sender.encryption_public_key, receiver.get_encryption_public_key()):
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
            decode_kem_ciphertext(env.encryption.kem_ciphertext), decode_payload(env.encryption.payload),
            env.conversation_id,
        )
    except ACEError:
        raise
    except Exception as exc:
        raise ACEError("identity_unavailable", f"identity decrypt failed: {type(exc).__name__}") from exc
    # 11-12
    body = decode_body(env.type, plaintext)
    # 13
    if is_economic_type(env.type):
        threads.apply(_event(env), body)
    return ParsedMessage(
        message_id=env.message_id, from_id=env.from_id, to_id=env.to_id,
        conversation_id=env.conversation_id, type=env.type, thread_id=env.thread_id,
        timestamp=env.timestamp, body=body,
    )
