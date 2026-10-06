"""ACE Protocol SDK — Agent Commerce Engine."""

from . import xwing
from .discovery import (
    VerifiedPeer,
    fetch_registration_file,
    get_registration_encryption_public_key,
    get_registration_signing_public_key,
    validate_ace_id,
    validate_profile,
    validate_registration_file,
    verify_encryption_key_binding,
    verify_registration_id,
)
from .encryption import (
    MAX_PAYLOAD_SIZE,
    compute_conversation_id,
    decode_kem_ciphertext,
    decode_kem_public_key,
    decrypt,
    encrypt,
    get_ace_kem_salt,
)
from .identity import SoftwareIdentity, compute_ace_id
from .messages import (
    create_message,
    parse_message,
    parse_message_from_peer,
    parse_message_from_registration,
    validate_body,
)
from .security import ReplayDetector, check_timestamp_freshness, validate_message_id
from .signing import (
    build_sign_data,
    decode_signature,
    encode_payload,
    encode_signature,
    verify_signature,
)
from .state_machine import (
    InvalidTransitionError,
    ThreadSnapshot,
    ThreadStateMachine,
    validate_thread_id,
)
from .types import (
    ECONOMIC_TYPES,
    SOCIAL_TYPES,
    SYSTEM_TYPES,
    ACEIdentity,
    ACEMessage,
    AgentProfile,
    Capability,
    ChainInfo,
    DiscoverAgent,
    DiscoverQuery,
    DiscoverResult,
    EncryptionEnvelope,
    HardwareBacking,
    IdentityTier,
    MessageType,
    ParsedMessage,
    PricingInfo,
    ProfilePricing,
    RegistrationFile,
    SignatureEnvelope,
    SigningConfig,
    SigningScheme,
    is_economic_type,
    is_social_type,
    is_system_type,
)

__all__ = [
    # Types
    "ACEIdentity", "SigningScheme", "IdentityTier", "HardwareBacking",
    "RegistrationFile", "SigningConfig", "Capability", "PricingInfo", "ChainInfo",
    "ACEMessage", "MessageType", "EncryptionEnvelope", "SignatureEnvelope", "ParsedMessage",
    "ProfilePricing", "AgentProfile", "DiscoverQuery", "DiscoverAgent", "DiscoverResult",
    "is_economic_type", "is_system_type", "is_social_type",
    "ECONOMIC_TYPES", "SYSTEM_TYPES", "SOCIAL_TYPES",
    # Identity
    "SoftwareIdentity", "compute_ace_id",
    # Encryption
    "compute_conversation_id", "encrypt", "decrypt", "get_ace_kem_salt", "MAX_PAYLOAD_SIZE",
    "decode_kem_public_key", "decode_kem_ciphertext", "xwing",
    # Signing
    "build_sign_data", "encode_payload",
    "verify_signature", "encode_signature", "decode_signature",
    # Messages
    "create_message", "parse_message", "parse_message_from_registration",
    "parse_message_from_peer", "validate_body",
    # Discovery
    "validate_registration_file", "validate_ace_id", "verify_registration_id",
    "get_registration_signing_public_key", "get_registration_encryption_public_key",
    "fetch_registration_file",
    "validate_profile",
    "verify_encryption_key_binding", "VerifiedPeer",
    # Security
    "check_timestamp_freshness", "validate_message_id", "ReplayDetector",
    # State Machine
    "ThreadStateMachine", "ThreadSnapshot", "InvalidTransitionError", "validate_thread_id",
]
