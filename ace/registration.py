"""Relay registration requests: public key binding plus private write authorization."""

from __future__ import annotations

import copy
import hashlib
from typing import Callable, NamedTuple

from ._encoding import (
    check_fresh,
    check_wire_int,
    decode_b64,
    decode_signature,
    encode_signature,
    is_ace_id,
    to_base64,
    unix_now,
    wire_int,
)
from ._signing import build_sign_data, encode_payload, verify_signature
from .discovery import (
    VerifiedPeer,
    _make_peer,
    binding_sign_data,
    decode_signing_key,
    validate_profile,
)
from .errors import ACEError
from .identity import compute_ace_id, signing_address
from .limits import KEM_PUBLIC_KEY_SIZE, TIMESTAMP_WINDOW_SECONDS
from .types import (
    SIGNING_SCHEMES,
    ACEIdentity,
    AgentProfile,
    Capability,
    ChainInfo,
    HardwareBacking,
    IdentityTier,
    RegistrationFile,
    RegistrationRequest,
    SigningConfig,
)


def create_registration_file(
    identity: ACEIdentity,
    *,
    name: str,
    endpoint: str,
    description: str | None = None,
    tier: IdentityTier = 0,
    hardware_backing: HardwareBacking | None = None,
    capabilities: list[Capability] | None = None,
    settlement: list[str] | None = None,
    chains: list[ChainInfo] | None = None,
) -> RegistrationFile:
    """Build the registration file (02) of any identity, software or hardware-backed;
    raises ``invalid_registration`` if the inputs are invalid."""
    from .discovery import verify_registration_file

    scheme = identity.get_signing_scheme()
    signing_public_key = bytes(identity.get_signing_public_key())
    reg = RegistrationFile(
        ace="1.0",
        id=identity.get_ace_id(),
        name=name,
        endpoint=endpoint,
        tier=tier,
        signing=SigningConfig(
            scheme=scheme,
            address=signing_address(scheme, signing_public_key),
            encryption_public_key=to_base64(bytes(identity.get_encryption_public_key())),
            signing_public_key=to_base64(signing_public_key) if scheme == "secp256k1" else None,
        ),
        hardware_backing=hardware_backing,
        description=description,
        capabilities=capabilities,
        settlement=settlement,
        chains=chains,
    )
    verify_registration_file(reg, pinned_at=0)
    return reg

_KEEP = object()


def registration_payload(enc_b64: str, sig_b64: str, scheme: str, profile: object = _KEEP) -> bytes:
    """The ``register-request`` payload (02).

    ``profile``: _KEEP, None, or a validated AgentProfile.
    """
    fields = (enc_b64, sig_b64, scheme)
    if profile is _KEEP:
        return encode_payload(*fields, "keep")
    if profile is None:
        return encode_payload(*fields, "remove")
    assert isinstance(profile, AgentProfile)
    pr = profile.pricing
    return encode_payload(
        *fields,
        "replace",
        profile.name or "",
        profile.description or "",
        profile.image or "",
        encode_payload(*(profile.tags or [])),
        encode_payload(*(profile.capabilities or [])),
        encode_payload(*(profile.chains or [])),
        profile.endpoint or "",
        "present" if pr else "absent",
        pr.currency if pr else "",
        (pr.max_amount or "") if pr else "",
    )


def create_registration_request(
    identity: ACEIdentity,
    profile: AgentProfile | dict | None | object = _KEEP,
    timestamp: int | None = None,
) -> RegistrationRequest:
    """Build a ``POST /v1/register`` body. Omitted profile keeps it; ``None`` removes it."""
    ts = unix_now(None) if timestamp is None else timestamp
    check_wire_int(ts, "timestamp")
    enc = identity.get_encryption_public_key()
    if not isinstance(enc, (bytes, bytearray)) or len(enc) != KEM_PUBLIC_KEY_SIZE:
        raise ACEError(
            "invalid_key", f"identity encryption public key must be {KEM_PUBLIC_KEY_SIZE} bytes"
        )
    snapshot = (
        profile if profile is _KEEP or profile is None else validate_profile(copy.deepcopy(profile))
    )  # type: ignore[arg-type]
    epk, spk = to_base64(enc), to_base64(identity.get_signing_public_key())
    ace_id, scheme = identity.get_ace_id(), identity.get_signing_scheme()
    signature = identity.sign(binding_sign_data(ace_id, ts, epk, spk))
    authorization = identity.sign(
        build_sign_data(
            "register-request", ace_id, ts, registration_payload(epk, spk, scheme, snapshot)
        )
    )
    result: RegistrationRequest = {
        "aceId": ace_id,
        "encryptionPublicKey": epk,
        "signingPublicKey": spk,
        "scheme": scheme,
        "timestamp": ts,
        "signature": encode_signature(signature, scheme),
        "authorization": encode_signature(authorization, scheme),
    }
    if snapshot is not _KEEP:
        result["profile"] = None if snapshot is None else snapshot.to_dict()  # type: ignore[union-attr]
    return result


class VerifiedRegistration(NamedTuple):
    request: RegistrationRequest
    peer: VerifiedPeer
    request_digest: str


def verify_registration_request(
    body: object,
    *,
    clock: Callable[[], int] | None = None,
    window_seconds: int = TIMESTAMP_WINDOW_SECONDS,
) -> VerifiedRegistration:
    """Verify a registration request. Check order (first failure wins):

    schema -> ``invalid_registration``; freshness -> ``stale_timestamp``; ID hash ->
    ``invalid_registration``; signing/encryption key -> ``invalid_key``; profile ->
    ``invalid_profile``; binding -> ``invalid_signature``; authorization ->
    ``invalid_authorization``.
    ``request_digest`` is hex SHA-256 of the ``register-request`` signData.
    """
    check_wire_int(window_seconds, "window_seconds")
    bad = "invalid_registration"
    if not isinstance(body, dict):
        raise ACEError(bad, "registration request must be an object")
    ace_id, scheme = body.get("aceId"), body.get("scheme")
    epk, spk = body.get("encryptionPublicKey"), body.get("signingPublicKey")
    ts = wire_int(body.get("timestamp"))
    if not is_ace_id(ace_id) or scheme not in SIGNING_SCHEMES or ts is None:
        raise ACEError(bad, "aceId, scheme and timestamp are required and well-formed")
    if not isinstance(epk, str) or not isinstance(spk, str):
        raise ACEError(bad, "encryptionPublicKey and signingPublicKey must be strings")
    sig = decode_signature(body.get("signature"), scheme, bad)  # type: ignore[arg-type]
    auth = decode_signature(body.get("authorization"), scheme, bad)  # type: ignore[arg-type]
    has_profile = "profile" in body
    raw_profile = body.get("profile")
    if raw_profile is not None and not isinstance(raw_profile, dict):
        raise ACEError(bad, "profile must be an object or null")

    spk_bytes = decode_b64(spk, bad, "signingPublicKey", max_bytes=64)
    enc_key = decode_b64(epk, bad, "encryptionPublicKey", max_bytes=KEM_PUBLIC_KEY_SIZE + 3)
    check_fresh(ts, clock, window_seconds, "registration timestamp")
    if compute_ace_id(spk_bytes) != ace_id:
        raise ACEError(bad, "aceId does not match signingPublicKey")
    signing_key = decode_signing_key(scheme, spk, "invalid_key")
    if len(enc_key) != KEM_PUBLIC_KEY_SIZE:
        raise ACEError("invalid_key", f"encryptionPublicKey must be {KEM_PUBLIC_KEY_SIZE} bytes")
    profile = None if raw_profile is None else validate_profile(raw_profile)
    if not verify_signature(binding_sign_data(ace_id, ts, epk, spk), sig, scheme, signing_key):  # type: ignore[arg-type]
        raise ACEError("invalid_signature", "registration binding signature does not verify")
    snapshot = profile if has_profile else _KEEP
    request_sign_data = build_sign_data(
        "register-request", ace_id, ts, registration_payload(epk, spk, scheme, snapshot)
    )  # type: ignore[arg-type]
    if not verify_signature(request_sign_data, auth, scheme, signing_key):  # type: ignore[arg-type]
        raise ACEError("invalid_authorization", "registration authorization does not verify")
    request: RegistrationRequest = {
        "aceId": ace_id,
        "encryptionPublicKey": epk,
        "signingPublicKey": spk,
        "scheme": scheme,  # type: ignore[typeddict-item]
        "timestamp": ts,
        "signature": body["signature"],
        "authorization": body["authorization"],
    }
    if has_profile:
        request["profile"] = None if profile is None else profile.to_dict()
    peer = _make_peer(
        ace_id=ace_id,
        scheme=scheme,
        signing_public_key=signing_key,
        encryption_public_key=enc_key,
        registered_at=ts,
        registration_signature=body["signature"],
        source="relay",
        profile=profile,
    )
    return VerifiedRegistration(request, peer, hashlib.sha256(request_sign_data).hexdigest())
