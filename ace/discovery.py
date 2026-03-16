"""ACE Protocol discovery: registration file validation and well-known fetch."""

from __future__ import annotations

import json
import re
from urllib.request import Request, urlopen
from urllib.error import URLError

import base58
from coincurve import PublicKey as SecpPublicKey

from urllib.parse import urlparse

from .types import (
    RegistrationFile, SigningConfig, SigningScheme, IdentityTier,
    Capability, PricingInfo, ChainInfo, ProfilePricing,
)
from .identity import compute_ace_id
from ._utils import from_base64, secp_pubkey_to_address, CONTROL_CHAR_RE

_ACE_ID_PATTERN = re.compile(r"^ace:sha256:[a-f0-9]{64}$")
_VALID_DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)

_DEFAULT_MAX_REGISTRATION_BYTES = 1_048_576


def _decode_ed25519_address(address: str) -> bytes:
    pub_key = base58.b58decode(address)
    if len(pub_key) != 32:
        raise ValueError(f"ed25519 signing.address must decode to 32 bytes, got {len(pub_key)}")
    return pub_key


def validate_ace_id(ace_id: str) -> bool:
    """Validate ACE ID format: ace:sha256:<64 hex chars>."""
    return bool(_ACE_ID_PATTERN.match(ace_id))


def validate_registration_file(reg: RegistrationFile) -> None:
    """Validate a registration file has all required fields and correct format."""
    if reg.ace != "1.0":
        raise ValueError(f"Invalid ace version: expected '1.0', got '{reg.ace}'")
    if not reg.id or not validate_ace_id(reg.id):
        raise ValueError(f"Invalid or missing ACE id: '{reg.id}'")
    if not reg.name:
        raise ValueError("Missing required field: name")
    if not reg.endpoint:
        raise ValueError("Missing required field: endpoint")
    if reg.tier not in (0, 1):
        raise ValueError(f"Invalid tier: {reg.tier}")
    if not reg.signing:
        raise ValueError("Missing required field: signing")
    if not reg.signing.scheme:
        raise ValueError("Missing required field: signing.scheme")
    if not reg.signing.address:
        raise ValueError("Missing required field: signing.address")
    if not reg.signing.encryption_public_key:
        raise ValueError("Missing required field: signing.encryptionPublicKey")
    if reg.signing.scheme == "ed25519":
        address_pub_key = _decode_ed25519_address(reg.signing.address)
        if reg.signing.signing_public_key:
            signing_pub_key_bytes = from_base64(reg.signing.signing_public_key)
            if signing_pub_key_bytes != address_pub_key:
                raise ValueError("ed25519 signing.signingPublicKey does not match signing.address")
    elif reg.signing.scheme == "secp256k1":
        if not reg.signing.signing_public_key:
            raise ValueError("secp256k1 scheme requires signing.signingPublicKey")
        signing_pub_key_bytes = from_base64(reg.signing.signing_public_key)
        uncompressed = SecpPublicKey(signing_pub_key_bytes).format(compressed=False)
        derived_address = secp_pubkey_to_address(uncompressed)
        if reg.signing.address != derived_address:
            raise ValueError("signing.address does not match signing.signingPublicKey")


def verify_registration_id(reg: RegistrationFile) -> bool:
    """Verify that a registration file's ACE ID matches its signing key."""
    signing_pub_key_bytes = get_registration_signing_public_key(reg)

    expected_id = compute_ace_id(signing_pub_key_bytes)
    if reg.id != expected_id:
        return False
    if reg.signing.scheme == "secp256k1":
        uncompressed = SecpPublicKey(signing_pub_key_bytes).format(compressed=False)
        expected_address = secp_pubkey_to_address(uncompressed)
        return reg.signing.address == expected_address
    return True


def get_registration_signing_public_key(reg: RegistrationFile) -> bytes:
    """Extract the signing public key from a validated registration file."""
    if reg.signing.scheme == "ed25519":
        address_pub_key = _decode_ed25519_address(reg.signing.address)
        if reg.signing.signing_public_key:
            signing_pub_key_bytes = from_base64(reg.signing.signing_public_key)
            if signing_pub_key_bytes != address_pub_key:
                raise ValueError("ed25519 signing.signingPublicKey does not match signing.address")
        return address_pub_key
    if reg.signing.signing_public_key:
        return from_base64(reg.signing.signing_public_key)
    raise ValueError("Cannot derive signing public key from registration file")


def get_registration_encryption_public_key(reg: RegistrationFile) -> bytes:
    """Extract the X25519 encryption public key from a validated registration file."""
    return from_base64(reg.signing.encryption_public_key)


def _parse_registration_json(data: dict) -> RegistrationFile:
    """Parse a raw JSON dict into a RegistrationFile dataclass."""
    signing_raw = data.get("signing", {})
    signing = SigningConfig(
        scheme=signing_raw["scheme"],
        address=signing_raw["address"],
        encryption_public_key=signing_raw["encryptionPublicKey"],
        signing_public_key=signing_raw.get("signingPublicKey"),
    )

    capabilities = None
    if "capabilities" in data:
        caps = []
        for c in data["capabilities"]:
            pricing = None
            if "pricing" in c:
                pricing = PricingInfo(
                    model=c["pricing"]["model"],
                    amount=c["pricing"]["amount"],
                    currency=c["pricing"]["currency"],
                )
            caps.append(Capability(
                id=c["id"],
                description=c["description"],
                input=c.get("input"),
                output=c.get("output"),
                pricing=pricing,
            ))
        capabilities = caps

    chains = None
    if "chains" in data:
        chains = [ChainInfo(network=ch["network"], address=ch["address"]) for ch in data["chains"]]

    return RegistrationFile(
        ace=data["ace"],
        id=data["id"],
        name=data["name"],
        endpoint=data["endpoint"],
        tier=data["tier"],
        signing=signing,
        hardware_backing=data.get("hardwareBacking"),
        description=data.get("description"),
        capabilities=capabilities,
        settlement=data.get("settlement"),
        chains=chains,
    )


def fetch_registration_file(
    domain: str, *, timeout: float = 10.0, max_bytes: int = _DEFAULT_MAX_REGISTRATION_BYTES
) -> RegistrationFile:
    """Fetch and validate a registration file from a well-known URL.

    Resolves ``https://<domain>/.well-known/ace.json``, validates the
    registration file structure, and verifies the ACE ID matches the
    signing key.
    """
    if not _VALID_DOMAIN_PATTERN.match(domain):
        raise ValueError(f"Invalid domain: '{domain[:100]}'")
    if timeout <= 0:
        raise ValueError(f"Invalid timeout: expected positive seconds, got {timeout!r}")
    if max_bytes <= 0:
        raise ValueError(f"Invalid max_bytes: expected positive integer, got {max_bytes!r}")

    url = f"https://{domain}/.well-known/ace.json"

    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise ValueError(
                    f"Failed to fetch registration file: {resp.status} {resp.reason}"
                )

            content_type = resp.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                raise ValueError(
                    f"Invalid or missing content-type: expected application/json, got '{content_type}'"
                )

            content_length = resp.headers.get("Content-Length")
            if content_length is not None:
                declared_length = int(content_length)
                if declared_length > max_bytes:
                    raise ValueError(
                        f"Registration file too large: {declared_length} bytes exceeds max {max_bytes}"
                    )

            raw_bytes = resp.read(max_bytes + 1)
            if len(raw_bytes) > max_bytes:
                raise ValueError(
                    f"Registration file too large: {len(raw_bytes)} bytes exceeds max {max_bytes}"
                )

            raw = json.loads(raw_bytes)
    except URLError as exc:
        raise ValueError(f"Failed to fetch registration file from {url}: {exc}") from exc

    reg = _parse_registration_json(raw)
    validate_registration_file(reg)
    if not verify_registration_id(reg):
        raise ValueError("Registration ACE ID does not match signing key")

    return reg


_TAG_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]*$')


def _validate_tag_like_list(items: list, field_name: str, max_count: int) -> None:
    """Validate a list of tag-like strings (tags or capabilities)."""
    if not isinstance(items, list) or len(items) > max_count:
        raise ValueError(f"Invalid profile: {field_name} must be a list of at most {max_count} items")
    for item in items:
        if not isinstance(item, str) or len(item) > 32 or not _TAG_PATTERN.match(item):
            raise ValueError(
                f"Invalid profile: each {field_name[:-1]} must be 1-32 lowercase alphanumeric chars or hyphens ({field_name})"
            )


def validate_profile(profile: "AgentProfile") -> None:
    """Validate an AgentProfile. Raises ValueError on invalid fields."""
    if profile.name is not None:
        if not isinstance(profile.name, str) or len(profile.name) < 1 or len(profile.name) > 64:
            raise ValueError("Invalid profile: name must be 1-64 characters")
        if CONTROL_CHAR_RE.search(profile.name):
            raise ValueError("Invalid profile: name must not contain control characters")

    if profile.description is not None:
        if not isinstance(profile.description, str) or len(profile.description) > 256:
            raise ValueError("Invalid profile: description must be at most 256 characters")
        if CONTROL_CHAR_RE.search(profile.description):
            raise ValueError("Invalid profile: description must not contain control characters")

    if profile.image is not None:
        if not isinstance(profile.image, str) or len(profile.image) > 512:
            raise ValueError("Invalid profile: image must be at most 512 characters")
        parsed_image = urlparse(profile.image)
        if parsed_image.scheme != "https" or not parsed_image.netloc:
            raise ValueError("Invalid profile: image must be a valid HTTPS URL (image)")

    if profile.tags is not None:
        _validate_tag_like_list(profile.tags, "tags", 10)

    if profile.capabilities is not None:
        _validate_tag_like_list(profile.capabilities, "capabilities", 20)

    if profile.chains is not None:
        if not isinstance(profile.chains, list) or len(profile.chains) > 10:
            raise ValueError("Invalid profile: chains must be a list of at most 10 items")
        for chain in profile.chains:
            if not isinstance(chain, str) or ":" not in chain:
                raise ValueError("Invalid profile: each chain must be a CAIP-2 identifier (chains)")
            parts = chain.split(":", 1)
            if not parts[0] or not parts[1]:
                raise ValueError("Invalid profile: each chain must be a CAIP-2 identifier with non-empty namespace and reference (chains)")

    if profile.endpoint is not None:
        if not isinstance(profile.endpoint, str):
            raise ValueError("Invalid profile: endpoint must be a string")
        parsed = urlparse(profile.endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("Invalid profile: endpoint must be a valid HTTPS URL with host (endpoint)")

    if profile.pricing is not None:
        if not isinstance(profile.pricing, ProfilePricing):
            raise ValueError("Invalid profile: pricing must be a ProfilePricing object (pricing)")
        if not profile.pricing.currency:
            raise ValueError("Invalid profile: pricing.currency is required (pricing)")
