"""ACE Protocol type definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Protocol, TypedDict, Union

from .errors import ACEError, ACEErrorCode
from .ext import NAMESPACED_ID_RE, ExtMap, validate_ext

SigningScheme = Literal["ed25519", "secp256k1"]
IdentityTier = Literal[0, 1]
HardwareBacking = Literal["secure-enclave", "tpm", "hsm", "tee"]

MessageType = str

MESSAGE_TYPES: tuple[str, ...] = (
    "rfq",
    "offer",
    "accept",
    "reject",
    "invoice",
    "receipt",
    "deliver",
    "confirm",
    "info",
    "text",
    "request",
    "decision",
    "report",
)
ECONOMIC_TYPES: tuple[str, ...] = MESSAGE_TYPES[:8]
PRINCIPAL_TYPES: tuple[str, ...] = MESSAGE_TYPES[10:]

SIGNING_SCHEMES: tuple[str, ...] = ("ed25519", "secp256k1")

JSONValue = Union[None, bool, int, float, str, List["JSONValue"], Dict[str, "JSONValue"]]
JSONObject = Dict[str, JSONValue]


def is_signing_scheme(s: object) -> bool:
    return isinstance(s, str) and s in SIGNING_SCHEMES


def is_message_type(t: object) -> bool:
    return isinstance(t, str) and (
        t in MESSAGE_TYPES or (len(t) <= 256 and NAMESPACED_ID_RE.fullmatch(t) is not None)
    )


def is_economic_type(t: object) -> bool:
    return isinstance(t, str) and t in ECONOMIC_TYPES


def is_principal_type(t: object) -> bool:
    return isinstance(t, str) and t in PRINCIPAL_TYPES


class ACEIdentity(Protocol):
    """What the SDK needs from an identity (software, Secure Enclave, HSM, ...).

    ``decrypt``: an :class:`ACEError` passes through unchanged; any other exception
    is reported by the SDK as ``identity_unavailable`` (local, retryable).
    """

    def get_ace_id(self) -> str: ...
    def get_signing_scheme(self) -> SigningScheme: ...
    def get_signing_public_key(self) -> bytes: ...
    def get_encryption_public_key(self) -> bytes: ...
    def sign(self, data: bytes) -> bytes: ...
    def decrypt(self, kem_ciphertext: bytes, payload: bytes, conversation_id: str) -> bytes: ...


class SoftwareIdentityExport(TypedDict):
    scheme: SigningScheme
    signingPrivateKey: str
    encryptionPrivateKey: str


# --- strict dict readers ------------------------------------------------------

_ABSENT = object()


def _opt(d: dict, key: str, kind: type, code: ACEErrorCode, what: str) -> Any:
    """Optional field: absent or null -> None; otherwise must be ``kind``."""
    v = d.get(key)
    if v is None:
        return None
    if not isinstance(v, kind) or isinstance(v, bool) and kind is not bool:
        raise ACEError(code, f"{what}.{key} must be a {kind.__name__}")
    return v


def _req(d: dict, key: str, kind: type, code: ACEErrorCode, what: str) -> Any:
    v = _opt(d, key, kind, code, what)
    if v is None:
        raise ACEError(code, f"{what}.{key} is required")
    return v


def _opt_str_list(d: dict, key: str, code: ACEErrorCode, what: str) -> list[str] | None:
    v = _opt(d, key, list, code, what)
    if v is not None and not all(isinstance(x, str) for x in v):
        raise ACEError(code, f"{what}.{key} must be an array of strings")
    return None if v is None else list(v)


# --- registration file ----------------------------------------------------------


@dataclass
class Capability:
    id: str
    description: str
    input: str | None = None
    output: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "description": self.description}
        if self.input is not None:
            d["input"] = self.input
        if self.output is not None:
            d["output"] = self.output
        return d


@dataclass
class SigningConfig:
    scheme: SigningScheme
    address: str
    encryption_public_key: str  # Base64 of the 1216-byte X-Wing public key
    signing_public_key: str | None = None  # Base64; required for secp256k1


@dataclass
class RegistrationFile:
    ace: str
    id: str
    name: str
    endpoint: str
    tier: IdentityTier
    signing: SigningConfig
    registered_at: int
    registration_signature: str
    hardware_backing: HardwareBacking | None = None
    description: str | None = None
    capabilities: list[Capability] | None = None
    #: Namespaced extensions (02 § Profile Fields rules); commerce data lives under
    #: ``urn:ace:commerce:1`` (04 § Commerce extension).
    ext: ExtMap | None = None
    principal: "PrincipalRecord | None" = None

    def to_dict(self) -> dict[str, Any]:
        signing: dict[str, Any] = {
            "scheme": self.signing.scheme,
            "address": self.signing.address,
            "encryptionPublicKey": self.signing.encryption_public_key,
        }
        if self.signing.signing_public_key is not None:
            signing["signingPublicKey"] = self.signing.signing_public_key
        d: dict[str, Any] = {
            "ace": self.ace,
            "id": self.id,
            "name": self.name,
            "endpoint": self.endpoint,
            "tier": self.tier,
            "signing": signing,
            "registeredAt": self.registered_at,
            "registrationSignature": self.registration_signature,
        }
        if self.hardware_backing is not None:
            d["hardwareBacking"] = self.hardware_backing
        if self.description is not None:
            d["description"] = self.description
        if self.capabilities is not None:
            d["capabilities"] = [c.to_dict() for c in self.capabilities]
        if self.ext is not None:
            d["ext"] = {k: dict(v) for k, v in self.ext.items()}
        if self.principal is not None:
            d["principal"] = self.principal.to_dict()
        return d

    @staticmethod
    def from_dict(d: object) -> "RegistrationFile":
        """Parse the wire JSON shape. Type errors raise ``ACEError(invalid_registration)``;
        ``ext`` follows the profile rules (``invalid_profile``) and is re-canonicalised.

        Unknown fields are ignored; optional fields that are ``null`` are absent.
        Semantic checks (ID hash, keys, URL grammar) are in ``verify_registration_file``.
        """
        code: ACEErrorCode = "invalid_registration"
        if not isinstance(d, dict):
            raise ACEError(code, "registration file must be a JSON object")
        signing = _req(d, "signing", dict, code, "registration")
        tier = d.get("tier")
        if isinstance(tier, bool) or not isinstance(tier, (int, float)) or tier not in (0, 1):
            raise ACEError(code, "registration.tier must be 0 or 1")
        caps = _opt(d, "capabilities", list, code, "registration")
        capabilities = None
        if caps is not None:
            capabilities = []
            for c in caps:
                if not isinstance(c, dict):
                    raise ACEError(code, "registration.capabilities entries must be objects")
                capabilities.append(
                    Capability(
                        id=_req(c, "id", str, code, "capability"),
                        description=_req(c, "description", str, code, "capability"),
                        input=_opt(c, "input", str, code, "capability"),
                        output=_opt(c, "output", str, code, "capability"),
                    )
                )
        return RegistrationFile(
            ace=_req(d, "ace", str, code, "registration"),
            id=_req(d, "id", str, code, "registration"),
            name=_req(d, "name", str, code, "registration"),
            endpoint=_req(d, "endpoint", str, code, "registration"),
            registered_at=d.get("registeredAt"),
            registration_signature=_req(d, "registrationSignature", str, code, "registration"),
            tier=int(tier),  # type: ignore[arg-type]
            signing=SigningConfig(
                scheme=_req(signing, "scheme", str, code, "signing"),
                address=_req(signing, "address", str, code, "signing"),
                encryption_public_key=_req(signing, "encryptionPublicKey", str, code, "signing"),
                signing_public_key=_opt(signing, "signingPublicKey", str, code, "signing"),
            ),
            hardware_backing=_opt(d, "hardwareBacking", str, code, "registration"),
            description=_opt(d, "description", str, code, "registration"),
            capabilities=capabilities,
            ext=validate_ext(d.get("ext"), "profile"),
            principal=None
            if d.get("principal") is None
            else PrincipalRecord.from_dict(d["principal"]),
        )


# --- principal record (09) ----------------------------------------------------------


@dataclass(frozen=True)
class PrincipalKey:
    scheme: str
    public_key: str  # canonical Base64, as in the record


@dataclass(frozen=True)
class PrincipalRecord:
    """09-principal § Principal Record. Semantic checks: ``validate_principal_record``."""

    account: str
    roles: tuple[str, ...]
    signer: PrincipalKey
    issued_at: int
    signature: str
    expires_at: int
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "account": self.account,
            "roles": list(self.roles),
            "signer": {"scheme": self.signer.scheme, "publicKey": self.signer.public_key},
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "signature": self.signature,
        }
        if self.scope is not None:
            d["scope"] = self.scope
        return d

    @staticmethod
    def from_dict(d: object) -> "PrincipalRecord":
        """Strict wire parse (09 § Validation rule 1); any type error is ``invalid_principal``.
        A ``null`` optional member is absent; unknown members are ignored."""
        from ._encoding import wire_int

        code: ACEErrorCode = "invalid_principal"
        if isinstance(d, PrincipalRecord):
            d = d.to_dict()
        if not isinstance(d, dict):
            raise ACEError(code, "principal must be a JSON object")
        signer = _req(d, "signer", dict, code, "principal")
        roles = d.get("roles")
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise ACEError(code, "principal.roles must be an array of strings")
        issued_at = wire_int(d.get("issuedAt"))
        if issued_at is None:
            raise ACEError(code, "principal.issuedAt must be a wire integer")
        expires_at = wire_int(d.get("expiresAt"))
        if expires_at is None:
            raise ACEError(code, "principal.expiresAt must be a wire integer")
        return PrincipalRecord(
            account=_req(d, "account", str, code, "principal"),
            roles=tuple(roles),
            signer=PrincipalKey(
                scheme=_req(signer, "scheme", str, code, "principal.signer"),
                public_key=_req(signer, "publicKey", str, code, "principal.signer"),
            ),
            issued_at=issued_at,
            signature=_req(d, "signature", str, code, "principal"),
            expires_at=expires_at,
            scope=_opt(d, "scope", str, code, "principal"),
        )


# --- discovery profile ------------------------------------------------------------


@dataclass
class AgentProfile:
    """Relay discovery profile (self-asserted metadata). All fields optional. ``ext`` holds
    namespaced extensions (02 § Profile Fields); commerce data (chains, pricing, settlement,
    accounts) lives under ``ext["urn:ace:commerce:1"]`` (04 § Commerce extension)."""

    name: str | None = None
    description: str | None = None
    image: str | None = None
    tags: list[str] | None = None
    capabilities: list[str] | None = None
    endpoint: str | None = None
    ext: ExtMap | None = None
    principal: PrincipalRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for key in ("name", "description", "image"):
            if getattr(self, key) is not None:
                d[key] = getattr(self, key)
        for key in ("tags", "capabilities"):
            if getattr(self, key) is not None:
                d[key] = list(getattr(self, key))
        if self.endpoint is not None:
            d["endpoint"] = self.endpoint
        if self.ext is not None:
            d["ext"] = {k: dict(v) for k, v in self.ext.items()}
        if self.principal is not None:
            d["principal"] = self.principal.to_dict()
        return d

    @staticmethod
    def from_dict(d: object) -> "AgentProfile":
        """Parse the wire shape; type errors raise ``ACEError(invalid_profile)``.

        Unknown top-level profile fields are ignored (never stored or signed); ``ext`` is
        validated by the 02 § Profile Fields rules and re-canonicalised (an empty ``ext`` is
        absent).
        """
        code: ACEErrorCode = "invalid_profile"
        if not isinstance(d, dict):
            raise ACEError(code, "profile must be a JSON object")
        profile = AgentProfile(
            name=_opt(d, "name", str, code, "profile"),
            description=_opt(d, "description", str, code, "profile"),
            image=_opt(d, "image", str, code, "profile"),
            tags=_opt_str_list(d, "tags", code, "profile"),
            capabilities=_opt_str_list(d, "capabilities", code, "profile"),
            endpoint=_opt(d, "endpoint", str, code, "profile"),
            ext=validate_ext(d.get("ext"), "profile"),
        )
        # The principal is parsed after the other members (R-P45, 08 order).
        if d.get("principal") is not None:
            profile.principal = PrincipalRecord.from_dict(d["principal"])
        return profile


@dataclass
class DiscoverQuery:
    """Query parameters for GET /v1/discover."""

    q: str | None = None
    tags: list[str] | tuple[str, ...] | None = None  # sent comma-joined
    scheme: str | None = None
    online: bool | None = None
    account: str | None = None
    limit: int | None = None
    cursor: str | None = None


class _PeerRecordRequired(TypedDict):
    aceId: str
    scheme: SigningScheme
    encryptionPublicKey: str
    signingPublicKey: str
    registrationSignature: str
    registeredAt: int


class PeerRecord(_PeerRecordRequired, total=False):
    """Wire shape of ``GET /v1/peer`` and each ``/v1/discover`` entry."""

    profile: dict


class _RegistrationRequestRequired(TypedDict):
    aceId: str
    encryptionPublicKey: str
    signingPublicKey: str
    scheme: SigningScheme
    timestamp: int
    signature: str
    authorization: str


class RegistrationRequest(_RegistrationRequestRequired, total=False):
    """``POST /v1/register`` body. Omitted profile = keep, None = remove, dict = replace."""

    profile: dict | None


class ReplayState(TypedDict):
    """Canonical replay.json: entries sorted by (timestamp, sender, messageId)."""

    entries: list[list[Any]]
    horizon: int
    senderHorizons: dict[str, int]
    version: int


# --- envelope -----------------------------------------------------------------------


@dataclass
class EncryptionEnvelope:
    kem_ciphertext: str  # wire: kemCiphertext
    payload: str


@dataclass
class SignatureEnvelope:
    scheme: SigningScheme
    value: str


@dataclass
class ACEMessage:
    """A decoded envelope. Obtain from ``decode_envelope`` or ``create_message``."""

    ace: str
    message_id: str
    from_id: str
    to_id: str
    conversation_id: str
    timestamp: int
    encryption: EncryptionEnvelope
    signature: SignatureEnvelope

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ace": self.ace,
            "messageId": self.message_id,
            "from": self.from_id,
            "to": self.to_id,
            "conversationId": self.conversation_id,
            "timestamp": self.timestamp,
            "encryption": {
                "kemCiphertext": self.encryption.kem_ciphertext,
                "payload": self.encryption.payload,
            },
            "signature": {"scheme": self.signature.scheme, "value": self.signature.value},
        }
        return d


@dataclass
class ParsedMessage:
    message_id: str
    from_id: str
    to_id: str
    conversation_id: str
    type: MessageType
    thread_id: str | None
    timestamp: int
    body: dict[str, Any]
    schema_digest: str


# --- bodies -------------------------------------------------------------------------


class _RfqRequired(TypedDict):
    need: str


class RfqBody(_RfqRequired, total=False):
    maxPrice: str
    currency: str
    ttl: int


class _OfferRequired(TypedDict):
    price: str
    currency: str


class OfferBody(_OfferRequired, total=False):
    terms: str
    ttl: int


class AcceptBody(TypedDict):
    offerId: str


class RejectBody(TypedDict, total=False):
    reason: str


class _InvoiceRequired(TypedDict):
    offerId: str
    amount: str
    currency: str
    settlementMethod: str


class InvoiceBody(_InvoiceRequired, total=False):
    settlementDetails: dict


class ReceiptBody(TypedDict):
    referenceId: str
    amount: str
    currency: str
    settlementMethod: str
    proof: dict


class _DeliverRequired(TypedDict):
    type: Literal["inline", "reference"]


class DeliverBody(_DeliverRequired, total=False):
    content: str
    contentType: str
    uri: str
    metadata: dict


class _ConfirmRequired(TypedDict):
    deliverId: str


class ConfirmBody(_ConfirmRequired, total=False):
    message: str


class InfoBody(TypedDict):
    message: str


class TextBody(TypedDict):
    message: str


class MessageRef(TypedDict, total=False):
    conversationId: str
    threadId: str
    messageId: str


class _RequestRequired(TypedDict):
    action: str
    summary: str


class RequestBody(_RequestRequired, total=False):
    ref: MessageRef
    amount: str
    currency: str
    details: dict
    ttl: int


class _DecisionRequired(TypedDict):
    requestId: str
    outcome: Literal["approve", "deny"]


class DecisionBody(_DecisionRequired, total=False):
    reason: str
    result: dict


class _ReportRequired(TypedDict):
    action: str
    summary: str
    outcome: Literal["ok", "failed", "skipped"]


class ReportBody(_ReportRequired, total=False):
    ref: MessageRef
    requestId: str
    proof: dict
