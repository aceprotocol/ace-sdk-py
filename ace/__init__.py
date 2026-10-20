"""ACE: post-quantum identity, private packets and profile vocabulary for agents.

This module is the single public surface of the SDK.
"""

from ._encoding import (
    canonical_state_bytes,
    conversation_key,
    from_base64,
    is_ace_id,
    is_message_id,
    sha256_hex,
    to_base64,
)
from ._signing import encode_payload, signing_message, verify_signature
from .auth import create_auth_headers
from .card_record import (
    CardBundle,
    CardRecord,
    Contact,
    VerifiedCard,
    create_card_record,
    is_caip10_account,
    verify_card_bundle,
)
from .commerce import (
    CommerceRules,
    ThreadSnapshot,
    ThreadStore,
    commerce_rules,
    validate_commerce_ext,
)
from .delegation import (
    issue_delegation,
    validate_erc8004,
    verify_delegation,
    verify_erc8004_registration,
)
from .descriptor import (
    VerifiedAgent,
    check_stranger_source,
    create_published_agent,
    validate_card,
    verify_published_agent,
)
from .errors import ACEError, ACEErrorCategory, ACEErrorCode
from .identity import ACEIdentity, SoftwareIdentity, check_usable
from .inbox import Inbox, ReceiveOutcome, Reply, check_receipt_body
from .kel import (
    KelState,
    compute_ace_id,
    create_inception,
    create_rotation,
    create_signing_delegation,
    extend_kel,
    is_usable,
    verify_kel,
    verify_operational_signature,
)
from .keys import KeyProvider, SoftwareKey, generate_software_key, key_digest
from .limits import (
    MAX_PACKET_BYTES,
    MAX_PLAINTEXT_BYTES,
    OFFLINE_WINDOW_SECONDS,
    TIMESTAMP_WINDOW_SECONDS,
)
from .network import ContactRequest, NetworkClient
from .outbox import Attempt, Outbox, OutboxEntry
from .packet import (
    Packet,
    PrivateMessage,
    create_packet,
    decode_content,
    decode_packet,
    decrypt_packet,
    encode_content,
    verify_packet,
)
from .peers import PeerRecord, PeerStore
from .permit import create_permit, verify_permit
from .prekeys import Prekey, PrekeyVault, prekey_id
from .profiles import COMMERCE, CORE, TEXT, ProfileManifest, Profiles
from .registration import create_registration_request
from .relay import InboxPage, RelayClient, RelayEntry
from .replay import ReplayDetector
from .rules import MessageEvent, ProfileRules
from .store import ACEStore, FileStore, MemoryStore

__version__ = "0.5.0"

__all__ = [
    "ACEError",
    "ACEErrorCategory",
    "ACEErrorCode",
    "ACEIdentity",
    "ACEStore",
    "Attempt",
    "COMMERCE",
    "CORE",
    "CardBundle",
    "CardRecord",
    "CommerceRules",
    "Contact",
    "ContactRequest",
    "FileStore",
    "Inbox",
    "InboxPage",
    "KelState",
    "KeyProvider",
    "MAX_PACKET_BYTES",
    "MAX_PLAINTEXT_BYTES",
    "MemoryStore",
    "MessageEvent",
    "NetworkClient",
    "OFFLINE_WINDOW_SECONDS",
    "Outbox",
    "OutboxEntry",
    "Packet",
    "PeerRecord",
    "PeerStore",
    "Prekey",
    "PrekeyVault",
    "PrivateMessage",
    "ProfileManifest",
    "ProfileRules",
    "Profiles",
    "ReceiveOutcome",
    "RelayClient",
    "RelayEntry",
    "ReplayDetector",
    "Reply",
    "SoftwareIdentity",
    "SoftwareKey",
    "TEXT",
    "TIMESTAMP_WINDOW_SECONDS",
    "ThreadSnapshot",
    "ThreadStore",
    "VerifiedAgent",
    "VerifiedCard",
    "canonical_state_bytes",
    "check_receipt_body",
    "check_stranger_source",
    "check_usable",
    "commerce_rules",
    "compute_ace_id",
    "conversation_key",
    "create_auth_headers",
    "create_card_record",
    "create_inception",
    "create_packet",
    "create_permit",
    "create_published_agent",
    "create_registration_request",
    "create_rotation",
    "create_signing_delegation",
    "decode_content",
    "decode_packet",
    "decrypt_packet",
    "encode_content",
    "encode_payload",
    "extend_kel",
    "from_base64",
    "generate_software_key",
    "is_ace_id",
    "is_caip10_account",
    "is_message_id",
    "is_usable",
    "issue_delegation",
    "key_digest",
    "prekey_id",
    "sha256_hex",
    "signing_message",
    "to_base64",
    "validate_card",
    "validate_commerce_ext",
    "validate_erc8004",
    "verify_card_bundle",
    "verify_delegation",
    "verify_erc8004_registration",
    "verify_kel",
    "verify_operational_signature",
    "verify_packet",
    "verify_permit",
    "verify_published_agent",
    "verify_signature",
]
