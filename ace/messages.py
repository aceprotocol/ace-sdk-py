"""ACE Protocol message construction and schema validation."""

from __future__ import annotations

import json
import time
import uuid

from ._utils import from_base64, to_base64
from .discovery import VerifiedPeer, validate_registration_file
from .encryption import MAX_PAYLOAD_SIZE, compute_conversation_id, decode_kem_ciphertext, encrypt
from .identity import compute_ace_id
from .security import ReplayDetector, check_timestamp_freshness, validate_message_id
from .signing import (
    build_sign_data,
    decode_signature,
    encode_payload,
    encode_signature,
    verify_signature,
)
from .state_machine import InvalidTransitionError, ThreadStateMachine, validate_thread_id
from .types import (
    ACEIdentity,
    ACEMessage,
    EncryptionEnvelope,
    MessageType,
    ParsedMessage,
    RegistrationFile,
    SignatureEnvelope,
    is_economic_type,
)


def _normalize_thread_id(thread_id: str | None) -> str:
    return thread_id or ""


def _build_signed_message_payload(
    type_: MessageType,
    to_id: str,
    conversation_id: str,
    message_id: str,
    thread_id: str | None,
    kem_ciphertext: bytes,
    payload: bytes,
) -> bytes:
    # kem_ciphertext is signed too: it is what the recipient decapsulates to derive
    # the decryption key, so it is part of the sender's commitment. Omitting it
    # would let a relay swap the KEM ciphertext (garbling the message) without
    # breaking the signature.
    return encode_payload(
        type_, to_id, conversation_id, message_id, _normalize_thread_id(thread_id),
        kem_ciphertext, payload,
    )


# === Schema Validation ===

def _require_fields(body: dict, fields: list[str], type_name: str) -> None:
    for field in fields:
        if field not in body or body[field] is None:
            raise ValueError(f"{type_name} body requires '{field}' field")


def _require_string(body: dict, field: str, type_name: str) -> str:
    if field not in body or body[field] is None:
        raise ValueError(f"{type_name} body requires '{field}' field")
    value = body[field]
    if not isinstance(value, str):
        raise ValueError(f"{type_name}.{field} must be a string")
    return value


def _require_object(body: dict, field: str, type_name: str) -> None:
    if field not in body or body[field] is None:
        raise ValueError(f"{type_name} body requires '{field}' field")
    _validate_object(body[field], field, type_name)


def _validate_optional_string(body: dict, field: str, type_name: str) -> None:
    value = body.get(field)
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"{type_name}.{field} must be a string")


def _validate_optional_object(body: dict, field: str, type_name: str) -> None:
    value = body.get(field)
    if value is None:
        return
    _validate_object(value, field, type_name)


def _validate_optional_number(body: dict, field: str, type_name: str) -> None:
    value = body.get(field)
    if value is None:
        return
    if not _is_json_number(value):
        raise ValueError(f"{type_name}.{field} must be a number")


def _validate_object(value: object, field: str, type_name: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{type_name}.{field} must be an object")


def _is_json_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_body(type_: str, body: dict) -> None:
    """Validate message body against schema for the given type."""
    if type_ == "rfq":
        _require_string(body, "need", "rfq")
        _validate_optional_string(body, "maxPrice", "rfq")
        _validate_optional_string(body, "currency", "rfq")
        _validate_optional_number(body, "ttl", "rfq")
    elif type_ == "offer":
        _require_string(body, "price", "offer")
        _require_string(body, "currency", "offer")
        _validate_optional_string(body, "terms", "offer")
        _validate_optional_number(body, "ttl", "offer")
    elif type_ == "accept":
        _require_string(body, "offerId", "accept")
    elif type_ == "reject":
        _validate_optional_string(body, "reason", "reject")
    elif type_ == "invoice":
        _require_string(body, "offerId", "invoice")
        _require_string(body, "amount", "invoice")
        _require_string(body, "currency", "invoice")
        _require_string(body, "settlementMethod", "invoice")
        _validate_optional_object(body, "settlementDetails", "invoice")
    elif type_ == "receipt":
        _require_string(body, "invoiceId", "receipt")
        _require_string(body, "amount", "receipt")
        _require_string(body, "currency", "receipt")
        _require_string(body, "settlementMethod", "receipt")
        _require_object(body, "proof", "receipt")
    elif type_ == "deliver":
        deliver_type = _require_string(body, "type", "deliver")
        _validate_optional_string(body, "content", "deliver")
        _validate_optional_string(body, "contentType", "deliver")
        _validate_optional_string(body, "uri", "deliver")
        _validate_optional_object(body, "metadata", "deliver")
        if deliver_type == "inline":
            _require_string(body, "content", "deliver (inline)")
        elif deliver_type == "reference":
            _require_string(body, "uri", "deliver (reference)")
        else:
            raise ValueError(
                f"deliver.type must be 'inline' or 'reference', got '{deliver_type[:50]}'"
            )
    elif type_ == "confirm":
        _require_string(body, "deliverId", "confirm")
        _validate_optional_string(body, "message", "confirm")
    elif type_ == "info":
        _require_string(body, "message", "info")
    elif type_ == "text":
        _require_string(body, "message", "text")
    # Unknown types: no validation (forward compatibility)


def _thread_contains_message(
    state_machine: ThreadStateMachine,
    conversation_id: str,
    thread_id: str,
    message_type: MessageType,
    message_id: str,
) -> bool:
    snapshot = state_machine.get_snapshot(conversation_id, thread_id)
    return any(
        entry["type"] == message_type and entry["messageId"] == message_id
        for entry in snapshot.history
    )


def _validate_thread_references(
    type_: MessageType,
    body: dict,
    state_machine: ThreadStateMachine,
    conversation_id: str,
    thread_id: str,
) -> None:
    if not is_economic_type(type_) or not thread_id:
        return

    if type_ == "accept":
        offer_id = _require_string(body, "offerId", "accept")
        if not _thread_contains_message(state_machine, conversation_id, thread_id, "offer", offer_id):
            raise ValueError("accept.offerId must reference an offer in the same thread")
    elif type_ == "invoice":
        offer_id = _require_string(body, "offerId", "invoice")
        if not _thread_contains_message(state_machine, conversation_id, thread_id, "offer", offer_id):
            raise ValueError("invoice.offerId must reference an offer in the same thread")
    elif type_ == "receipt":
        invoice_id = _require_string(body, "invoiceId", "receipt")
        if not _thread_contains_message(state_machine, conversation_id, thread_id, "invoice", invoice_id):
            raise ValueError("receipt.invoiceId must reference an invoice in the same thread")
    elif type_ == "confirm":
        deliver_id = _require_string(body, "deliverId", "confirm")
        if not _thread_contains_message(state_machine, conversation_id, thread_id, "deliver", deliver_id):
            raise ValueError("confirm.deliverId must reference a deliver message in the same thread")


# === Message Construction ===

def create_message(
    sender: ACEIdentity,
    recipient_pub_key: bytes,
    recipient_ace_id: str,
    type_: MessageType,
    body: dict,
    state_machine: ThreadStateMachine,
    thread_id: str | None = None,
    timestamp: int | None = None,
) -> ACEMessage:
    """Create a full ACE message envelope (encrypt + sign)."""
    # 0. State machine enforcement
    if is_economic_type(type_) and not thread_id:
        raise ValueError("Economic messages require a thread_id")
    if thread_id is not None:
        validate_thread_id(thread_id)

    # 1. Validate body schema
    validate_body(type_, body)

    message_id = str(uuid.uuid4())
    ts = timestamp if timestamp is not None else int(time.time())
    from_id = sender.get_ace_id()
    to_id = recipient_ace_id
    conversation_id = compute_conversation_id(
        sender.get_encryption_public_key(),
        recipient_pub_key,
    )
    thread_key = _normalize_thread_id(thread_id)
    # Pre-check: fail fast before expensive crypto operations
    if not state_machine.can_transition(conversation_id, thread_key, type_):
        current = state_machine.get_state(conversation_id, thread_key)
        raise InvalidTransitionError(thread_key, current, type_)
    _validate_thread_references(type_, body, state_machine, conversation_id, thread_key)

    # 2. Encrypt body
    body_json = json.dumps(body, separators=(",", ":")).encode("utf-8")
    kem_ciphertext, payload = encrypt(body_json, recipient_pub_key, conversation_id)

    # 3. Build sign data and sign
    message_payload = _build_signed_message_payload(
        type_, to_id, conversation_id, message_id, thread_id, kem_ciphertext, payload
    )
    sign_data = build_sign_data("message", from_id, ts, message_payload)
    signature, scheme = sender.sign(sign_data)

    # 4. Commit state transition (only after all crypto succeeded)
    state_machine.transition(conversation_id, thread_key, type_, message_id, ts)

    return ACEMessage(
        ace="1.0",
        message_id=message_id,
        from_id=from_id,
        to_id=to_id,
        conversation_id=conversation_id,
        type=type_,
        timestamp=ts,
        encryption=EncryptionEnvelope(
            kem_ciphertext=to_base64(kem_ciphertext),
            payload=to_base64(payload),
        ),
        signature=SignatureEnvelope(
            scheme=scheme,
            value=encode_signature(signature, scheme),
        ),
        thread_id=thread_id,
    )


# === Message Parsing (Verify + Decrypt) ===

def parse_message(
    msg: ACEMessage,
    receiver: ACEIdentity,
    sender_signing_pub_key: bytes,
    state_machine: ThreadStateMachine,
    replay_detector: ReplayDetector,
    sender_encryption_pub_key: bytes | None = None,
    oldest_timestamp: int | None = None,
) -> ParsedMessage:
    """Verify signature, decrypt, and validate a received message.

    Args:
        oldest_timestamp: Offline acceptance floor; use it for every message, live
            ones included, until the backlog is done.
        sender_encryption_pub_key: Optional sender X-Wing public key. When
            provided, `conversation_id` is recomputed from the sender and
            recipient encryption keys and must match the envelope value.
    """
    # 1. Envelope validation (pipeline step 1)
    if msg.ace != "1.0":
        raise ValueError(f"Unsupported ACE version: '{msg.ace}'")
    if msg.to_id != receiver.get_ace_id():
        raise ValueError("Message not addressed to this recipient")
    if not msg.message_id or not msg.from_id or not msg.conversation_id or not msg.type:
        raise ValueError("Missing required envelope fields")
    if len(msg.conversation_id) > 256:
        raise ValueError("conversationId exceeds max length of 256 characters")
    validate_message_id(msg.message_id)

    # Validate encryption and signature sub-envelopes
    if not msg.encryption or not msg.encryption.payload or not msg.encryption.kem_ciphertext:
        raise ValueError("Missing required encryption fields")
    if not msg.signature or not msg.signature.scheme or not msg.signature.value:
        raise ValueError("Missing required signature fields")

    expected_from_id = compute_ace_id(sender_signing_pub_key)
    if msg.from_id != expected_from_id:
        raise ValueError("msg.from_id does not match sender signing public key")
    if sender_encryption_pub_key is not None:
        expected_conversation_id = compute_conversation_id(
            sender_encryption_pub_key,
            receiver.get_encryption_public_key(),
        )
        if msg.conversation_id != expected_conversation_id:
            raise ValueError(
                "msg.conversation_id does not match sender/recipient encryption keys"
            )
    if is_economic_type(msg.type) and not msg.thread_id:
        raise ValueError("Economic messages require a thread_id")
    if msg.thread_id is not None:
        validate_thread_id(msg.thread_id)

    # 2–3. Timestamp freshness, replay horizon and seen check — before expensive crypto ops
    check_timestamp_freshness(msg.timestamp, oldest_timestamp)
    replay_error = ValueError(
        f"Replay detected: message {msg.message_id} already processed or below replay horizon"
    )
    if not replay_detector.accepts(msg.message_id, msg.from_id, msg.timestamp):
        raise replay_error

    # 4. Verify signature BEFORE decryption (pipeline step 4).
    payload_bytes = from_base64(msg.encryption.payload, max_len=MAX_PAYLOAD_SIZE, what="Payload")
    # Length-checked before any signature or KEM work: a relay cannot make us
    # decapsulate a malformed ciphertext.
    kem_ciphertext = decode_kem_ciphertext(msg.encryption.kem_ciphertext)
    message_payload = _build_signed_message_payload(
        msg.type,
        msg.to_id,
        msg.conversation_id,
        msg.message_id,
        msg.thread_id,
        kem_ciphertext,
        payload_bytes,
    )
    sign_data = build_sign_data("message", msg.from_id, msg.timestamp, message_payload)
    sig_bytes = decode_signature(msg.signature.value, msg.signature.scheme)
    try:
        valid = verify_signature(
            sign_data, sig_bytes, msg.signature.scheme, sender_signing_pub_key,
        )
    except Exception:
        valid = False
    if not valid:
        raise ValueError("Signature verification failed")
    # Commit now: an authentic message is one-shot, even if a later step fails.
    if not replay_detector.commit(msg.message_id, msg.from_id, msg.timestamp, oldest_timestamp):
        raise replay_error

    # 5. Decrypt body (pipeline step 5) — kem_ciphertext is signature-verified
    # above, so decapsulation uses the authenticated ciphertext.
    decrypted = receiver.decrypt_payload(kem_ciphertext, payload_bytes, msg.conversation_id)
    body = json.loads(decrypted.decode("utf-8"))

    # 6. Validate body schema (pipeline step 6)
    validate_body(msg.type, body)
    thread_key = _normalize_thread_id(msg.thread_id)
    _validate_thread_references(msg.type, body, state_machine, msg.conversation_id, thread_key)

    # 7. State machine validation (pipeline step 7)
    state_machine.transition(
        msg.conversation_id, thread_key, msg.type, msg.message_id, msg.timestamp,
    )

    return ParsedMessage(
        message_id=msg.message_id,
        from_id=msg.from_id,
        to_id=msg.to_id,
        conversation_id=msg.conversation_id,
        type=msg.type,
        timestamp=msg.timestamp,
        body=body,
        thread_id=msg.thread_id,
    )


def parse_message_from_registration(
    msg: ACEMessage,
    receiver: ACEIdentity,
    sender_registration: RegistrationFile,
    state_machine: ThreadStateMachine,
    replay_detector: ReplayDetector,
    oldest_timestamp: int | None = None,
) -> ParsedMessage:
    """Strict parse path that derives sender keys from a validated registration file."""
    # validate_registration_file already checks the secp256k1 address against the
    # signing key, so the only remaining verify_registration_id check is the id.
    keys = validate_registration_file(sender_registration)
    if compute_ace_id(keys.signing_public_key) != sender_registration.id:
        raise ValueError("Sender registration file failed cryptographic verification")

    return parse_message(
        msg,
        receiver,
        keys.signing_public_key,
        state_machine=state_machine,
        replay_detector=replay_detector,
        sender_encryption_pub_key=keys.encryption_public_key,
        oldest_timestamp=oldest_timestamp,
    )


def parse_message_from_peer(
    msg: ACEMessage,
    receiver: ACEIdentity,
    sender: VerifiedPeer,
    state_machine: ThreadStateMachine,
    replay_detector: ReplayDetector,
    oldest_timestamp: int | None = None,
) -> ParsedMessage:
    """Safe path for messages whose sender keys came from a relay.

    ``sender`` must be a :class:`VerifiedPeer` — obtainable only after the sender's
    encryption-key binding was verified — so the recipient never encrypts against
    or trusts a relay-substituted encryption key.  ``conversation_id`` is recomputed
    from the verified encryption keys and must match the envelope.
    """
    return parse_message(
        msg,
        receiver,
        sender.signing_public_key,
        state_machine=state_machine,
        replay_detector=replay_detector,
        sender_encryption_pub_key=sender.encryption_public_key,
        oldest_timestamp=oldest_timestamp,
    )
