"""Relay registration: public key proof and private mutation authorization."""
from __future__ import annotations

import copy
import time

from ._utils import to_base64
from .discovery import validate_profile
from .signing import build_sign_data, encode_payload, encode_signature
from .types import ACEIdentity, AgentProfile, SigningScheme
from .xwing import check_public_key

_KEEP = object()


def build_registration_payload(
    encryption_public_key: str, signing_public_key: str, scheme: SigningScheme,
    profile: AgentProfile | None | object = _KEEP,
) -> bytes:
    fields = (encryption_public_key, signing_public_key, scheme)
    if profile is _KEEP:
        return encode_payload(*fields, "keep")
    if profile is None:
        return encode_payload(*fields, "remove")
    if not isinstance(profile, AgentProfile):
        raise ValueError("profile must be an AgentProfile or None")
    validate_profile(profile)
    return encode_payload(
        *fields, "replace", profile.name or "", profile.description or "", profile.image or "",
        encode_payload(*(profile.tags or [])), encode_payload(*(profile.capabilities or [])),
        encode_payload(*(profile.chains or [])), profile.endpoint or "",
        "present" if profile.pricing else "absent",
        profile.pricing.currency if profile.pricing else "",
        (profile.pricing.max_amount or "") if profile.pricing else "",
    )


def create_registration_request(
    identity: ACEIdentity, profile: AgentProfile | None | object = _KEEP,
    timestamp: int | None = None,
) -> dict:
    """Return a ready-to-send body. Omitted profile keeps it; None removes it."""
    timestamp = int(time.time()) if timestamp is None else timestamp
    enc = identity.get_encryption_public_key()
    check_public_key(enc)
    epk, spk = to_base64(enc), to_base64(identity.get_signing_public_key())
    ace_id, scheme = identity.get_ace_id(), identity.get_signing_scheme()
    snapshot = copy.deepcopy(profile) if isinstance(profile, AgentProfile) else profile
    payload = build_registration_payload(epk, spk, scheme, snapshot)
    signature, _ = identity.sign(build_sign_data("register", ace_id, timestamp, encode_payload(epk, spk)))
    authorization, _ = identity.sign(build_sign_data("register-request", ace_id, timestamp, payload))
    result = dict(aceId=ace_id, encryptionPublicKey=epk, signingPublicKey=spk, scheme=scheme,
                  timestamp=timestamp, signature=encode_signature(signature, scheme),
                  authorization=encode_signature(authorization, scheme))
    if snapshot is not _KEEP:
        result["profile"] = snapshot.to_dict() if isinstance(snapshot, AgentProfile) else None
    return result
