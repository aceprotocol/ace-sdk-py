"""ACE Protocol type definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol

SigningScheme = Literal["ed25519", "secp256k1"]
IdentityTier = Literal[0, 1]
HardwareBacking = Literal["secure-enclave", "tpm", "hsm", "tee"]

MessageType = Literal[
    "rfq", "offer", "accept", "reject",
    "invoice", "receipt",
    "deliver", "confirm",
    "info", "text",
]

ECONOMIC_TYPES: frozenset[str] = frozenset({
    "rfq", "offer", "accept", "reject",
    "invoice", "receipt",
    "deliver", "confirm",
})

SYSTEM_TYPES: frozenset[str] = frozenset({"info"})
SOCIAL_TYPES: frozenset[str] = frozenset({"text"})


def is_economic_type(t: str) -> bool:
    return t in ECONOMIC_TYPES


def is_system_type(t: str) -> bool:
    return t in SYSTEM_TYPES


def is_social_type(t: str) -> bool:
    return t in SOCIAL_TYPES


class ACEIdentity(Protocol):
    """Interface that all ACE identity implementations must satisfy."""

    def get_encryption_public_key(self) -> bytes: ...
    def get_signing_public_key(self) -> bytes: ...
    def sign(self, data: bytes) -> tuple[bytes, SigningScheme]: ...
    def get_address(self) -> str: ...
    def get_signing_scheme(self) -> SigningScheme: ...
    def get_tier(self) -> IdentityTier: ...
    def get_ace_id(self) -> str: ...
    def decrypt_payload(self, ephemeral_pub_key: bytes, payload: bytes, conversation_id: str) -> bytes: ...


@dataclass
class PricingInfo:
    model: Literal["per-call", "per-token", "per-hour", "flat"]
    amount: str
    currency: str

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model, "amount": self.amount, "currency": self.currency}


@dataclass
class Capability:
    id: str
    description: str
    input: str | None = None
    output: str | None = None
    pricing: PricingInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "description": self.description}
        if self.input is not None:
            d["input"] = self.input
        if self.output is not None:
            d["output"] = self.output
        if self.pricing is not None:
            d["pricing"] = self.pricing.to_dict()
        return d


@dataclass
class ChainInfo:
    network: str  # CAIP-2 format
    address: str


@dataclass
class SigningConfig:
    scheme: SigningScheme
    address: str
    encryption_public_key: str  # Base64
    signing_public_key: str | None = None  # Base64, required for secp256k1


@dataclass
class RegistrationFile:
    ace: str  # "1.0"
    id: str
    name: str
    endpoint: str
    tier: IdentityTier
    signing: SigningConfig
    hardware_backing: HardwareBacking | None = None
    description: str | None = None
    capabilities: list[Capability] | None = None
    settlement: list[str] | None = None
    chains: list[ChainInfo] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ace": self.ace,
            "id": self.id,
            "name": self.name,
            "endpoint": self.endpoint,
            "tier": self.tier,
            "signing": {
                "scheme": self.signing.scheme,
                "address": self.signing.address,
                "encryptionPublicKey": self.signing.encryption_public_key,
            },
        }
        if self.hardware_backing is not None:
            d["hardwareBacking"] = self.hardware_backing
        if self.description is not None:
            d["description"] = self.description
        if self.signing.signing_public_key is not None:
            d["signing"]["signingPublicKey"] = self.signing.signing_public_key
        if self.capabilities is not None:
            d["capabilities"] = [c.to_dict() for c in self.capabilities]
        if self.settlement is not None:
            d["settlement"] = self.settlement
        if self.chains is not None:
            d["chains"] = [{"network": c.network, "address": c.address} for c in self.chains]
        return d


@dataclass
class EncryptionEnvelope:
    ephemeral_pub_key: str  # Base64
    payload: str  # Base64


@dataclass
class SignatureEnvelope:
    scheme: SigningScheme
    value: str


@dataclass
class ACEMessage:
    ace: str
    message_id: str
    from_id: str
    to_id: str
    conversation_id: str
    type: MessageType
    timestamp: int
    encryption: EncryptionEnvelope
    signature: SignatureEnvelope
    thread_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ace": self.ace,
            "messageId": self.message_id,
            "from": self.from_id,
            "to": self.to_id,
            "conversationId": self.conversation_id,
            "type": self.type,
            "timestamp": self.timestamp,
            "encryption": {
                "ephemeralPubKey": self.encryption.ephemeral_pub_key,
                "payload": self.encryption.payload,
            },
            "signature": {
                "scheme": self.signature.scheme,
                "value": self.signature.value,
            },
        }
        if self.thread_id is not None:
            d["threadId"] = self.thread_id
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ACEMessage":
        _REQUIRED_FIELDS = ("ace", "messageId", "from", "to", "conversationId", "type", "timestamp", "encryption", "signature")
        missing = [f for f in _REQUIRED_FIELDS if f not in d]
        if missing:
            raise ValueError(f"ACEMessage missing required fields: {missing}")

        enc = d["encryption"]
        if not isinstance(enc, dict) or "ephemeralPubKey" not in enc or "payload" not in enc:
            raise ValueError("ACEMessage.encryption must contain 'ephemeralPubKey' and 'payload'")

        sig = d["signature"]
        if not isinstance(sig, dict) or "scheme" not in sig or "value" not in sig:
            raise ValueError("ACEMessage.signature must contain 'scheme' and 'value'")

        return ACEMessage(
            ace=d["ace"],
            message_id=d["messageId"],
            from_id=d["from"],
            to_id=d["to"],
            conversation_id=d["conversationId"],
            type=d["type"],
            timestamp=d["timestamp"],
            encryption=EncryptionEnvelope(
                ephemeral_pub_key=enc["ephemeralPubKey"],
                payload=enc["payload"],
            ),
            signature=SignatureEnvelope(
                scheme=sig["scheme"],
                value=sig["value"],
            ),
            thread_id=d.get("threadId"),
        )


@dataclass
class ParsedMessage:
    message_id: str
    from_id: str
    to_id: str
    conversation_id: str
    type: MessageType
    timestamp: int
    body: dict[str, Any]
    thread_id: str | None = None


# --- Discovery Profile ---


def _get_wire_value(d: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    raise KeyError(keys[0])

@dataclass
class ProfilePricing:
    """Pricing reference for agent discovery."""
    currency: str
    max_amount: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"currency": self.currency}
        if self.max_amount is not None:
            d["maxAmount"] = self.max_amount
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ProfilePricing":
        if not isinstance(d, dict):
            raise TypeError("ProfilePricing.from_dict expects a dict")
        return ProfilePricing(
            currency=d["currency"],
            max_amount=d.get("maxAmount", d.get("max_amount")),
        )


@dataclass
class AgentProfile:
    """Agent profile for relay discovery. All fields optional."""
    name: str | None = None
    description: str | None = None
    image: str | None = None
    tags: list[str] | None = None
    capabilities: list[str] | None = None
    chains: list[str] | None = None
    endpoint: str | None = None
    pricing: ProfilePricing | None = None

    def __post_init__(self) -> None:
        if isinstance(self.pricing, dict):
            self.pricing = ProfilePricing.from_dict(self.pricing)
        elif self.pricing is not None and not isinstance(self.pricing, ProfilePricing):
            raise TypeError("AgentProfile.pricing must be a ProfilePricing or dict")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.name is not None:
            d["name"] = self.name
        if self.description is not None:
            d["description"] = self.description
        if self.image is not None:
            d["image"] = self.image
        if self.tags is not None:
            d["tags"] = list(self.tags)
        if self.capabilities is not None:
            d["capabilities"] = list(self.capabilities)
        if self.chains is not None:
            d["chains"] = list(self.chains)
        if self.endpoint is not None:
            d["endpoint"] = self.endpoint
        if self.pricing is not None:
            d["pricing"] = self.pricing.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "AgentProfile":
        if not isinstance(d, dict):
            raise TypeError("AgentProfile.from_dict expects a dict")
        pricing = d.get("pricing")
        return AgentProfile(
            name=d.get("name"),
            description=d.get("description"),
            image=d.get("image"),
            tags=d.get("tags"),
            capabilities=d.get("capabilities"),
            chains=d.get("chains"),
            endpoint=d.get("endpoint"),
            pricing=ProfilePricing.from_dict(pricing) if isinstance(pricing, dict) else pricing,
        )


@dataclass
class DiscoverQuery:
    """Query parameters for GET /v1/discover."""
    q: str | None = None
    tags: str | None = None
    chain: str | None = None
    scheme: str | None = None
    online: bool | None = None
    limit: int | None = None
    cursor: str | None = None


@dataclass
class DiscoverAgent:
    """Agent entry in discover response."""
    ace_id: str
    encryption_public_key: str
    signing_public_key: str
    scheme: SigningScheme
    profile: AgentProfile

    def __post_init__(self) -> None:
        if isinstance(self.profile, dict):
            self.profile = AgentProfile.from_dict(self.profile)
        elif not isinstance(self.profile, AgentProfile):
            raise TypeError("DiscoverAgent.profile must be an AgentProfile or dict")

    def to_dict(self) -> dict[str, Any]:
        return {
            "aceId": self.ace_id,
            "encryptionPublicKey": self.encryption_public_key,
            "signingPublicKey": self.signing_public_key,
            "scheme": self.scheme,
            "profile": self.profile.to_dict(),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "DiscoverAgent":
        if not isinstance(d, dict):
            raise TypeError("DiscoverAgent.from_dict expects a dict")
        return DiscoverAgent(
            ace_id=_get_wire_value(d, "aceId", "ace_id"),
            encryption_public_key=_get_wire_value(d, "encryptionPublicKey", "encryption_public_key"),
            signing_public_key=_get_wire_value(d, "signingPublicKey", "signing_public_key"),
            scheme=d["scheme"],
            profile=AgentProfile.from_dict(d["profile"]) if isinstance(d["profile"], dict) else d["profile"],
        )


@dataclass
class DiscoverResult:
    """Response from GET /v1/discover."""
    agents: list[DiscoverAgent]
    cursor: str | None = None

    def __post_init__(self) -> None:
        self.agents = [
            agent if isinstance(agent, DiscoverAgent) else DiscoverAgent.from_dict(agent)
            for agent in self.agents
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agents": [agent.to_dict() for agent in self.agents],
            "cursor": self.cursor,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "DiscoverResult":
        if not isinstance(d, dict):
            raise TypeError("DiscoverResult.from_dict expects a dict")
        return DiscoverResult(
            agents=[
                agent if isinstance(agent, DiscoverAgent) else DiscoverAgent.from_dict(agent)
                for agent in d.get("agents", [])
            ],
            cursor=d.get("cursor"),
        )
