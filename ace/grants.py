"""Exact-intent capabilities, independent of message labels and account roles."""

from __future__ import annotations

import copy
import json
import re
import unicodedata
from dataclasses import dataclass

from ._encoding import (
    decode_b64,
    decode_signature,
    encode_signature,
    is_ace_id,
    is_message_id,
    is_sha256_hex,
    to_base64,
    wire_int,
)
from ._intent import intent_digest
from ._signing import build_sign_data, encode_payload, is_valid_signing_public_key, verify_signature
from .discovery import VerifiedPeer
from .errors import ACEError
from .identity import compute_ace_id
from .limits import MAX_EXECUTION_JSON_BYTES
from .types import ACEIdentity, is_message_type, is_signing_scheme


def _bad():
    return ACEError("invalid_authorization", "invalid execution intent or resource grant")


def _keys(o, names):
    return isinstance(o, dict) and set(o) == set(names.split(","))


def _name(s):
    return isinstance(s, str) and ":" in s and is_message_type(s)


def is_execution_units(s):
    return isinstance(s, str) and re.fullmatch(r"(0|[1-9][0-9]{0,77})", s) is not None


def execution_intent_digest(intent: dict) -> str:
    if (
        not _keys(intent, "operationId,audience,resource,action,schemaDigest,details,expiresAt")
        or not is_message_id(intent["operationId"])
        or not is_ace_id(intent["audience"])
        or not _name(intent["resource"])
        or not _name(intent["action"])
        or not is_sha256_hex(intent["schemaDigest"])
        or not isinstance(intent["details"], dict)
        or wire_int(intent["expiresAt"]) is None
    ):
        raise _bad()

    def depth(v, n):
        if n > 32:
            raise _bad()
        if isinstance(v, list):
            for child in v:
                depth(child, n + 1)
        if isinstance(v, dict):
            if not all(isinstance(k, str) and unicodedata.normalize("NFC", k) == k for k in v):
                raise _bad()
            for child in v.values():
                depth(child, n + 1)

    depth(intent, 0)
    if (
        len(json.dumps(intent, ensure_ascii=False, separators=(",", ":")).encode())
        > MAX_EXECUTION_JSON_BYTES
    ):
        raise _bad()
    return intent_digest(intent)


def _claims_digest(c):
    if (
        not _keys(
            c,
            "grantId,issuer,subject,audience,resource,intentDigest,issuedAt,expiresAt,epoch,parent,delegationDepth",
        )
        or not is_message_id(c["grantId"])
        or not is_ace_id(c["issuer"])
        or not is_ace_id(c["subject"])
        or not is_ace_id(c["audience"])
        or not _name(c["resource"])
        or not is_sha256_hex(c["intentDigest"])
        or any(
            wire_int(c[k]) is None for k in ["issuedAt", "expiresAt", "epoch", "delegationDepth"]
        )
        or c["issuedAt"] >= c["expiresAt"]
        or c["delegationDepth"] > 7
        or c["parent"] is not None
        and not is_sha256_hex(c["parent"])
    ):
        raise _bad()
    return intent_digest(c)


def _sign_data(c, claims_digest):
    return build_sign_data(
        "grant", c["issuer"], wire_int(c["issuedAt"]), encode_payload(claims_digest)
    )


def execution_grant_digest(grant: dict) -> str:
    """Parent references bind claims, independently of randomized signature bytes."""
    return _claims_digest(grant["claims"])


def create_execution_grant(signer: ACEIdentity, claims: dict) -> dict:
    c = copy.deepcopy(claims)
    if c.get("issuer") != signer.get_ace_id():
        raise _bad()
    scheme = signer.get_signing_scheme()
    return {
        "claims": c,
        "signingPublicKey": to_base64(signer.get_signing_public_key()),
        "signature": {
            "scheme": scheme,
            "value": encode_signature(signer.sign(_sign_data(c, _claims_digest(c))), scheme),
        },
    }


@dataclass(frozen=True)
class ResourcePolicy:
    """Locally trusted, authoritative policy, never supplied by the requesting agent."""

    resource: str
    authority: VerifiedPeer
    epoch: int
    revoked: tuple[str, ...] = ()


def verify_execution_grant_chain(
    chain, intent, sender, executor, policy: ResourcePolicy, now: int
) -> str:
    """Verify inside the authoritative reservation transaction with current policy."""
    try:
        digest = execution_intent_digest(intent)
        if (
            not isinstance(chain, (list, tuple))
            or not 1 <= len(chain) <= 8
            or not is_ace_id(sender)
            or not is_ace_id(executor)
            or not isinstance(policy.authority, VerifiedPeer)
            or wire_int(now) is None
            or wire_int(policy.epoch) is None
            or not isinstance(policy.revoked, (tuple, list))
            or not all(is_message_id(g) for g in policy.revoked)
            or intent["audience"] != executor
            or intent["resource"] != policy.resource
            or now >= intent["expiresAt"]
        ):
            raise _bad()
        previous = previous_digest = None
        ids = set()
        for g in chain:
            if (
                not _keys(g, "claims,signingPublicKey,signature")
                or not _keys(g["signature"], "scheme,value")
                or not is_signing_scheme(g["signature"]["scheme"])
            ):
                raise _bad()
            c, scheme = g["claims"], g["signature"]["scheme"]
            claims_digest = _claims_digest(c)
            key = decode_b64(
                g["signingPublicKey"], "invalid_authorization", "signingPublicKey", max_bytes=64
            )
            if (
                not is_valid_signing_public_key(scheme, key)
                or compute_ace_id(key) != c["issuer"]
                or not verify_signature(
                    _sign_data(c, claims_digest),
                    decode_signature(g["signature"]["value"], scheme, "invalid_authorization"),
                    scheme,
                    key,
                )
                or c["audience"] != executor
                or c["resource"] != policy.resource
                or c["intentDigest"] != digest
                or c["epoch"] != policy.epoch
                or now < c["issuedAt"]
                or now >= c["expiresAt"]
                or intent["expiresAt"] > c["expiresAt"]
                or c["grantId"] in policy.revoked
                or c["grantId"] in ids
            ):
                raise _bad()
            if previous:
                if (
                    c["parent"] != previous_digest
                    or c["issuer"] != previous["subject"]
                    or c["delegationDepth"] >= previous["delegationDepth"]
                    or c["issuedAt"] < previous["issuedAt"]
                    or c["expiresAt"] > previous["expiresAt"]
                ):
                    raise _bad()
            elif (
                c["parent"] is not None
                or c["issuer"] != policy.authority.ace_id
                or scheme != policy.authority.scheme
                or key != policy.authority.signing_public_key
            ):
                raise _bad()
            ids.add(c["grantId"])
            previous, previous_digest = c, claims_digest
        if previous["subject"] != sender:
            raise _bad()
        return digest
    except (ACEError, KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise _bad() from None
