"""ACE Protocol SDK — Agent Commerce Engine."""

from .types import (
    ACEIdentity,
    SigningScheme,
    IdentityTier,
    HardwareBacking,
    RegistrationFile,
    SigningConfig,
    Capability,
    PricingInfo,
    ChainInfo,
    ACEMessage,
    MessageType,
    EncryptionEnvelope,
    SignatureEnvelope,
    ParsedMessage,
    ProfilePricing,
    AgentProfile,
    DiscoverQuery,
    DiscoverAgent,
    DiscoverResult,
    is_economic_type,
    is_system_type,
    is_social_type,
    ECONOMIC_TYPES,
    SYSTEM_TYPES,
    SOCIAL_TYPES,
)
from .identity import SoftwareIdentity, compute_ace_id
from .encryption import compute_conversation_id, encrypt, decrypt, get_ace_dh_salt, MAX_PAYLOAD_SIZE
from .signing import (
    build_sign_data, encode_payload,
    verify_signature, encode_signature, decode_signature,
)
from .messages import create_message, parse_message, parse_message_from_registration, validate_body
from .discovery import (
    validate_registration_file, validate_ace_id, verify_registration_id,
    get_registration_signing_public_key, get_registration_encryption_public_key,
    fetch_registration_file,
    validate_profile,
)
from .security import check_timestamp_freshness, validate_message_id, ReplayDetector
from .state_machine import ThreadStateMachine, ThreadSnapshot, InvalidTransitionError, validate_thread_id

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
    "compute_conversation_id", "encrypt", "decrypt", "get_ace_dh_salt", "MAX_PAYLOAD_SIZE",
    # Signing
    "build_sign_data", "encode_payload",
    "verify_signature", "encode_signature", "decode_signature",
    # Messages
    "create_message", "parse_message", "parse_message_from_registration", "validate_body",
    # Discovery
    "validate_registration_file", "validate_ace_id", "verify_registration_id",
    "get_registration_signing_public_key", "get_registration_encryption_public_key",
    "fetch_registration_file",
    "validate_profile",
    # Security
    "check_timestamp_freshness", "validate_message_id", "ReplayDetector",
    # State Machine
    "ThreadStateMachine", "ThreadSnapshot", "InvalidTransitionError", "validate_thread_id",
]
