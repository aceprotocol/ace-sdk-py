"""Public surface, errors and limits."""

import ace
from ace import ACEError
from ace.errors import _ALL_CODES

from .helpers import raises

EXPECTED = {
    "ACEIdentity", "SigningScheme", "IdentityTier", "HardwareBacking", "RegistrationFile", "SigningConfig",
    "Capability", "PricingInfo", "ChainInfo", "AgentProfile", "ProfilePricing", "DiscoverQuery", "PeerRecord",
    "ACEMessage", "MessageType", "EncryptionEnvelope", "SignatureEnvelope", "RfqBody", "OfferBody", "AcceptBody",
    "RejectBody", "InvoiceBody", "ReceiptBody", "DeliverBody", "ConfirmBody", "InfoBody", "TextBody", "JSONValue",
    "JSONObject", "ParsedMessage", "ThreadState", "ThreadSnapshot", "ThreadHistoryEntry", "ThreadEvent",
    "ReplayState", "RegistrationRequest", "RelayAuthRequest", "ACEErrorCode", "ACEErrorCategory",
    "SoftwareIdentityExport",
    "ACEError", "MESSAGE_TYPES", "ECONOMIC_TYPES", "is_message_type", "is_economic_type",
    "MAX_PLAINTEXT_BYTES", "MAX_PAYLOAD_BYTES", "MAX_ENVELOPE_BYTES", "MAX_JSON_DEPTH", "MAX_THREAD_ID_LENGTH",
    "TIMESTAMP_WINDOW_SECONDS", "OFFLINE_WINDOW_SECONDS", "MAX_REGISTRATION_FILE_BYTES", "MAX_INBOX_PAGE",
    "KEM_SEED_SIZE", "KEM_PUBLIC_KEY_SIZE", "KEM_CIPHERTEXT_SIZE", "DEFAULT_REPLAY_CAPACITY",
    "SoftwareIdentity", "compute_ace_id", "to_base64", "from_base64", "compute_conversation_id",
    "decrypt_with_seed", "kem_public_key_from_seed", "generate_kem_seed", "decode_envelope",
    "verify_envelope_signature", "envelope_fingerprint", "is_ace_id", "is_message_id", "is_thread_id",
    "is_conversation_id", "create_message", "parse_message", "validate_body", "VerifiedPeer",
    "verify_peer_record", "verify_registration_file", "fetch_registration_file", "validate_profile",
    "create_registration_request", "verify_registration_request", "create_auth_headers", "parse_auth_headers",
    "verify_auth_headers", "ReplayDetector", "ThreadStateMachine",
    # pipeline
    "ReceiveSource", "ReceiveOutcome", "PendingSend", "Intent", "ACEStore", "ThreadStore", "PeerStore",
    "Inbox", "Outbox", "RelayClient", "MemoryStore", "FileStore",
}


def test_exact_exports():
    assert set(ace.__all__) == EXPECTED
    assert len(ace.__all__) == len(EXPECTED)
    for name in ace.__all__:
        assert hasattr(ace, name), name


def test_removed_names_are_gone():
    for name in ("xwing", "encrypt", "decrypt", "InvalidTransitionError", "parse_message_from_peer",
                 "parse_message_from_registration", "build_sign_data", "verify_signature", "validate_ace_id",
                 "check_timestamp_freshness", "MAX_PAYLOAD_SIZE", "SYSTEM_TYPES", "DiscoverAgent"):
        assert name not in ace.__all__


def test_limits():
    assert ace.MAX_PLAINTEXT_BYTES == ace.MAX_PAYLOAD_BYTES - 28 == 65508
    assert (ace.MAX_ENVELOPE_BYTES, ace.MAX_JSON_DEPTH, ace.MAX_THREAD_ID_LENGTH) == (131072, 32, 256)
    assert (ace.TIMESTAMP_WINDOW_SECONDS, ace.OFFLINE_WINDOW_SECONDS, ace.MAX_INBOX_PAGE) == (300, 604800, 100)
    assert (ace.KEM_SEED_SIZE, ace.KEM_PUBLIC_KEY_SIZE, ace.KEM_CIPHERTEXT_SIZE) == (32, 1216, 1120)
    assert ace.MAX_REGISTRATION_FILE_BYTES == 1048576 and ace.DEFAULT_REPLAY_CAPACITY == 100000


def test_error_categories():
    assert len(_ALL_CODES) == 34
    for code in ("relay_unavailable", "relay_protocol_error", "fetch_failed"):
        e = ACEError(code)
        assert e.category == "transient" and e.is_transient
    for code in ("storage_failed", "identity_unavailable", "handler_failed", "receiver_busy"):
        e = ACEError(code)
        assert e.category == "local" and e.is_transient
    e = ACEError("replay", "x", status=409, relay_code="replay", retry_after_seconds=3)
    assert e.category == "permanent" and not e.is_transient
    assert (e.status, e.relay_code, e.retry_after_seconds, e.message) == (409, "replay", 3, "x")


def test_predicates_and_base64():
    assert ace.is_ace_id("ace:sha256:" + "0" * 64) and not ace.is_ace_id("ace:sha256:" + "A" * 64)
    assert ace.is_message_id("550e8400-e29b-41d4-a716-446655440000")
    assert not ace.is_message_id("550E8400-E29B-41D4-A716-446655440000")
    assert ace.is_conversation_id("a" * 64) and not ace.is_conversation_id("a" * 63)
    assert ace.is_thread_id("t") and not ace.is_thread_id("") and not ace.is_thread_id(None)
    assert not ace.is_thread_id("x" * 257) and not ace.is_thread_id("a\tb")
    assert ace.from_base64(ace.to_base64(b"\x00\xff")) == b"\x00\xff"
    with raises("invalid_argument"):
        ace.from_base64("QR==")
