"""ACE Protocol discovery: registration file validation and well-known fetch."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Any

import base58
from coincurve import PublicKey as SecpPublicKey

from urllib.parse import urlparse

from .types import (
    RegistrationFile, SigningConfig, SigningScheme, IdentityTier,
    Capability, PricingInfo, ChainInfo, ProfilePricing,
)
from .identity import compute_ace_id
from .signing import build_sign_data, encode_payload, verify_signature, decode_signature
from ._utils import from_base64, secp_pubkey_to_address, CONTROL_CHAR_RE

_VALID_SCHEMES: frozenset[str] = frozenset({"ed25519", "secp256k1"})

_ACE_ID_PATTERN = re.compile(r"^ace:sha256:[a-f0-9]{64}$")
_VALID_DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)

_DEFAULT_MAX_REGISTRATION_BYTES = 1_048_576


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _resolve_and_check_ssrf(domain: str) -> list[str]:
    """Resolve ``domain`` and reject if ANY address is private/internal.

    Returns the vetted IP strings so the caller can connect to exactly the address
    that was checked. Resolving here and connecting to the returned IP (rather than
    re-resolving the hostname) removes the DNS-rebinding TOCTOU window: the IP that
    passed the check is the IP we connect to.
    """
    try:
        results = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for '{domain[:100]}': {exc}") from exc

    vetted: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in results:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        ):
            raise ValueError(
                f"Refusing to connect to non-public IP {ip} resolved from '{domain[:100]}'"
            )
        if sockaddr[0] not in vetted:
            vetted.append(sockaddr[0])
    if not vetted:
        raise ValueError(f"No addresses resolved for '{domain[:100]}'")
    return vetted


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
    if not reg.endpoint.startswith("https://"):
        raise ValueError("endpoint must be an HTTPS URL")
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


# === Encryption-key binding (relay-sourced peer keys) ===
#
# ``ace_id`` self-certifies only the *signing* key (ace_id == sha256(signingKey)).
# The X25519 *encryption* key is a separate key; on its own it is an unauthenticated
# claim.  A relay that routes ciphertext is untrusted by design, so a relay could
# hand a client its own X25519 key and read messages the client believes are E2E
# encrypted.  The binding below is the proof that closes that gap: it is the very
# same signature the relay requires at registration, so verifying it needs no new
# trust anchor — just the identity's own signing key.

_MISSING = object()


def verify_encryption_key_binding(
    ace_id: str,
    scheme: SigningScheme,
    encryption_public_key: str,
    signing_public_key: str,
    timestamp: int,
    signature: str,
) -> bool:
    """Verify that ``encryption_public_key`` was authorized by ``ace_id``.

    The binding is identical to what ``POST /v1/register`` signs:

        build_sign_data("register", ace_id, timestamp,
                        encode_payload(encryptionPublicKey, signingPublicKey))

    signed by the identity's signing key.  This function also re-checks that
    ``ace_id == sha256(signingPublicKey)``, so a ``True`` result means: *this exact
    X25519 key was signed by the key that defines this identity*.

    ``encryption_public_key`` and ``signing_public_key`` MUST be the Base64 wire
    strings (the signature commits to those strings, not to raw bytes).  Returns
    ``False`` on any malformed input rather than raising, so callers can treat all
    verification failures uniformly.
    """
    if scheme not in _VALID_SCHEMES:
        return False
    if isinstance(timestamp, bool):
        return False
    if isinstance(timestamp, float):
        if not timestamp.is_integer():
            return False
        timestamp = int(timestamp)
    if not isinstance(timestamp, int):
        return False
    try:
        signing_pub_bytes = from_base64(signing_public_key)
    except (ValueError, TypeError):
        return False
    # The signing key must be the one that defines this identity.
    if compute_ace_id(signing_pub_bytes) != ace_id:
        return False
    try:
        payload = encode_payload(encryption_public_key, signing_public_key)
        sign_data = build_sign_data("register", ace_id, timestamp, payload)
        sig_bytes = decode_signature(signature, scheme)
    except (ValueError, TypeError):
        return False
    try:
        return verify_signature(sign_data, sig_bytes, scheme, signing_pub_bytes)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class VerifiedPeer:
    """A peer's public keys AFTER verifying its identity and encryption-key binding.

    Holding an instance is proof that ``ace_id`` matches the signing key AND that
    the X25519 ``encryption_public_key`` was signed by that identity.  Construct
    ONLY via :meth:`from_relay_response`; the bare constructor bypasses verification
    and must never be fed untrusted data.
    """

    ace_id: str
    scheme: SigningScheme
    signing_public_key: bytes
    encryption_public_key: bytes

    @classmethod
    def from_relay_response(cls, data: dict[str, Any]) -> "VerifiedPeer":
        """Build a verified peer from a relay ``GET /v1/peer`` or ``/v1/discover`` entry.

        Raises ``ValueError`` if the binding signature is absent or fails — a relay
        that substitutes an X25519 key cannot produce a passing binding, so an
        instance can only be obtained for a genuine key.
        """
        if not isinstance(data, dict):
            raise ValueError("Peer response must be a dict")
        ace_id = _peer_field(data, "aceId", "ace_id")
        scheme = _peer_field(data, "scheme")
        enc_pub_b64 = _peer_field(data, "encryptionPublicKey", "encryption_public_key")
        sign_pub_b64 = _peer_field(data, "signingPublicKey", "signing_public_key")
        signature = _peer_field(data, "registrationSignature", "registration_signature", default=None)
        registered_at = _peer_field(data, "registeredAt", "registered_at", default=None)

        if not isinstance(ace_id, str) or not validate_ace_id(ace_id):
            raise ValueError(f"Invalid peer aceId: '{str(ace_id)[:80]}'")
        if scheme not in _VALID_SCHEMES:
            raise ValueError(f"Unsupported peer signing scheme: '{str(scheme)[:32]}'")
        if not isinstance(enc_pub_b64, str) or not isinstance(sign_pub_b64, str):
            raise ValueError("Peer response signingPublicKey/encryptionPublicKey must be strings")
        if signature is None or registered_at is None:
            raise ValueError(
                "Peer response is missing the encryption-key binding "
                "(registrationSignature/registeredAt); its encryptionPublicKey cannot be "
                "trusted.  Without the binding a relay could substitute its own X25519 key "
                "and read messages meant to be end-to-end encrypted."
            )
        if not verify_encryption_key_binding(
            ace_id, scheme, enc_pub_b64, sign_pub_b64, registered_at, signature,
        ):
            raise ValueError(
                "Peer encryption-key binding failed verification: the encryptionPublicKey is "
                "not signed by this identity's signing key (possible key substitution / relay MITM)."
            )
        return cls(
            ace_id=ace_id,
            scheme=scheme,  # type: ignore[arg-type]
            signing_public_key=from_base64(sign_pub_b64),
            encryption_public_key=from_base64(enc_pub_b64),
        )


def _peer_field(d: dict[str, Any], *keys: str, default: Any = _MISSING) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    if default is not _MISSING:
        return default
    raise ValueError(f"Peer response missing required field '{keys[0]}'")


def _parse_registration_json(data: dict) -> RegistrationFile:
    """Parse a raw JSON dict into a RegistrationFile dataclass."""
    signing_raw = data.get("signing", {})
    try:
        signing = SigningConfig(
            scheme=signing_raw["scheme"],
            address=signing_raw["address"],
            encryption_public_key=signing_raw["encryptionPublicKey"],
            signing_public_key=signing_raw.get("signingPublicKey"),
        )
    except KeyError as e:
        raise ValueError(f"Missing required signing field: {e}") from None

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

    try:
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
    except KeyError as e:
        raise ValueError(f"Missing required registration field: {e}") from None


def _urlopen_pinned(domain: str, timeout: float) -> tuple[http.client.HTTPSConnection, http.client.HTTPResponse]:
    """IO shell: resolve+vet the domain, connect to the vetted IP, issue the GET.

    Pins the TCP connection to the exact address that passed the SSRF check (no
    re-resolution → no DNS-rebinding window) while validating TLS SNI/cert against
    the real domain. Returns ``(conn, response)``; the caller must close ``conn``.
    """
    vetted_ip = _resolve_and_check_ssrf(domain)[0]
    context = ssl.create_default_context()
    try:
        raw_sock = socket.create_connection((vetted_ip, 443), timeout=timeout)
    except OSError as exc:
        raise ValueError(
            f"Failed to connect to {vetted_ip} for '{domain[:100]}': {exc}"
        ) from exc

    conn = http.client.HTTPSConnection(domain, 443, timeout=timeout)
    try:
        # Pin the pre-vetted socket; wrap_socket(server_hostname=domain) sets SNI
        # and verifies the certificate against the real domain, not the IP.
        conn.sock = context.wrap_socket(raw_sock, server_hostname=domain)
        conn.request("GET", "/.well-known/ace.json", headers={"Accept": "application/json"})
        return conn, conn.getresponse()
    except (OSError, ssl.SSLError) as exc:
        conn.close()
        raise ValueError(
            f"Failed to fetch registration file from https://{domain}/.well-known/ace.json: {exc}"
        ) from exc


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

    conn, resp = _urlopen_pinned(domain, timeout)
    try:
        # Do NOT follow redirects — a redirect target would bypass SSRF vetting.
        if resp.status in _REDIRECT_STATUSES:
            location = resp.getheader("Location", "") or ""
            raise ValueError(
                f"Refusing to follow redirect ({resp.status}) to '{location[:100]}' "
                f"when fetching registration file"
            )
        if resp.status != 200:
            raise ValueError(
                f"Failed to fetch registration file: {resp.status} {resp.reason}"
            )

        content_type = resp.getheader("Content-Type", "") or ""
        if "application/json" not in content_type:
            raise ValueError(
                f"Invalid or missing content-type: expected application/json, got '{content_type}'"
            )

        content_length = resp.getheader("Content-Length")
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
    finally:
        conn.close()

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
