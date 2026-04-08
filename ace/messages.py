"""ACE Protocol message construction and schema validation."""

from __future__ import annotations

import json
import time
import uuid

from .types import (
    ACEIdentity, ACEMessage, EncryptionEnvelope, SignatureEnvelope,
    MessageType, ParsedMessage, RegistrationFile, is_economic_type,
)
from ._utils import to_base64, from_base64
from .encryption import compute_conversation_id, encrypt, MAX_PAYLOAD_SIZE
from .identity import compute_ace_id
from .signing import build_sign_data, encode_payload, verify_signature, encode_signature, decode_signature
from .security import check_timestamp_freshness, validate_message_id, ReplayDetector
from .discovery import (
    validate_registration_file,
    verify_registration_id,
    get_registration_signing_public_key,
    get_registration_encryption_public_key,
)
from .state_machine import ThreadStateMachine, validate_thread_id, InvalidTransitionError

def _estimate_base64_decoded_length(encoded: str) -> int:
    full_blocks = len(encoded) // 4
    decoded_length = full_blocks * 3
    if encoded.endswith("=="):
        decoded_length -= 2
    elif encoded.endswith("="):
        decoded_length -= 1
    return decoded_length


def _normalize_thread_id(thread_id: str | None) -> str:
    return thread_id or ""


def _build_signed_message_payload(
    type_: MessageType,
    to_id: str,
    conversation_id: str,
    message_id: str,
    thread_id: str | None,
    payload: bytes,
) -> bytes:
    return encode_payload(type_, to_id, conversation_id, message_id, _normalize_thread_id(thread_id), payload)


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
    ephemeral_pub_key, payload = encrypt(body_json, recipient_pub_key, conversation_id)

    # 3. Build sign data and sign
    message_payload = _build_signed_message_payload(
        type_, to_id, conversation_id, message_id, thread_id, payload
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
            ephemeral_pub_key=to_base64(ephemeral_pub_key),
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
    replay_detector: ReplayDetector | None = None,
    sender_encryption_pub_key: bytes | None = None,
) -> ParsedMessage:
    """Verify signature, decrypt, and validate a received message.

    Args:
        replay_detector: Optional ReplayDetector instance. When provided, the
            message will be checked for replay attacks and automatically reserved.
            Strongly recommended for production use.
        sender_encryption_pub_key: Optional sender X25519 public key. When
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
    if not msg.encryption or not msg.encryption.payload or not msg.encryption.ephemeral_pub_key:
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

    # 2. Timestamp freshness (pipeline step 2) — cheap check first
    check_timestamp_freshness(msg.timestamp)

    # 3. Replay detection (pipeline step 3) — before expensive crypto ops
    # Economic messages REQUIRE replay detection — replaying payment/receipt
    # messages could cause double-crediting or duplicate fulfillment.
    if is_economic_type(msg.type) and replay_detector is None:
        raise ValueError(
            f"Economic message type '{msg.type}' requires a ReplayDetector for security"
        )
    if replay_detector is not None:
        if not replay_detector.check_and_reserve(msg.message_id):
            raise ValueError(f"Replay detected: message {msg.message_id} already processed")

    # 4. Verify signature BEFORE decryption (pipeline step 4)
    estimated_payload_bytes = _estimate_base64_decoded_length(msg.encryption.payload)
    if estimated_payload_bytes > MAX_PAYLOAD_SIZE:
        if replay_detector is not None:
            replay_detector.release(msg.message_id)
        raise ValueError(
            f"Payload too large: estimated decoded size {estimated_payload_bytes} "
            f"bytes exceeds max {MAX_PAYLOAD_SIZE}"
        )
    payload_bytes = from_base64(msg.encryption.payload)
    message_payload = _build_signed_message_payload(
        msg.type,
        msg.to_id,
        msg.conversation_id,
        msg.message_id,
        msg.thread_id,
        payload_bytes,
    )
    sign_data = build_sign_data("message", msg.from_id, msg.timestamp, message_payload)

    sig_bytes = decode_signature(msg.signature.value, msg.signature.scheme)
    try:
        valid = verify_signature(
            sign_data, sig_bytes, msg.signature.scheme,
            sender_signing_pub_key,
        )
    except Exception:
        if replay_detector is not None:
            replay_detector.release(msg.message_id)
        raise ValueError("Signature verification failed")

    if not valid:
        if replay_detector is not None:
            replay_detector.release(msg.message_id)
        raise ValueError("Signature verification failed")

    # 5. Decrypt body (pipeline step 5)
    ephemeral_pub_key = from_base64(msg.encryption.ephemeral_pub_key)
    try:
        decrypted = receiver.decrypt_payload(ephemeral_pub_key, payload_bytes, msg.conversation_id)
    except Exception:
        if replay_detector is not None:
            replay_detector.release(msg.message_id)
        raise
    body = json.loads(decrypted.decode("utf-8"))

    # 6. Validate body schema (pipeline step 6)
    validate_body(msg.type, body)
    _validate_thread_references(
        msg.type,
        body,
        state_machine,
        msg.conversation_id,
        _normalize_thread_id(msg.thread_id),
    )

    # 7. State machine validation (pipeline step 7)
    state_machine.transition(
        msg.conversation_id,
        _normalize_thread_id(msg.thread_id),
        msg.type,
        msg.message_id,
        msg.timestamp,
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
    replay_detector: ReplayDetector | None = None,
) -> ParsedMessage:
    """Strict parse path that derives sender keys from a validated registration file."""
    validate_registration_file(sender_registration)
    if not verify_registration_id(sender_registration):
        raise ValueError("Sender registration file failed cryptographic verification")

    return parse_message(
        msg,
        receiver,
        get_registration_signing_public_key(sender_registration),
        state_machine=state_machine,
        replay_detector=replay_detector,
        sender_encryption_pub_key=get_registration_encryption_public_key(sender_registration),
    )
