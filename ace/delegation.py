"""Delegation credentials (an issuer declares that a subject acts on its behalf) and the
ERC-8004 binding helpers. Neither grants execution, payment or communication rights."""

from __future__ import annotations

import copy
import re

from ._documents import bad, check_lifetime, verify_claims
from ._encoding import is_ace_id, is_caip10_account, loads_json, resolve_now, wire_int
from .errors import ACEError
from .identity import ACEIdentity, sign_claims
from .kel import KelState, reconcile_kel, verify_kel
from .limits import MAX_DELEGATION_LIFETIME

_KEYS = {"issuer", "subject", "issuedAt", "expiresAt", "signature"}
_AGENT_ID_RE = re.compile(r"0|[1-9][0-9]{0,77}")
_NATIVE_AGENT_ID_RE = re.compile(r"[A-Za-z0-9]{1,128}")


def issue_delegation(
    identity: ACEIdentity,
    subject: str,
    *,
    now: int | None = None,
    lifetime: int = MAX_DELEGATION_LIFETIME,
) -> dict:
    """``{kel, credential}`` for a descriptor's ``delegations``: ``identity`` (the issuer, or
    controller) declares that ``subject`` (the delegate) acts on its behalf for ``lifetime``
    seconds (<= 7 days). Revocation is not renewing."""
    t = resolve_now(now)
    if not is_ace_id(subject) or subject == identity.get_ace_id():
        raise bad("invalid delegation subject")
    if type(lifetime) is not int or not 0 < lifetime <= MAX_DELEGATION_LIFETIME:
        raise bad("delegation lifetime must be in (0, 604800]")
    claims = {
        "issuer": identity.get_ace_id(),
        "subject": subject,
        "issuedAt": t,
        "expiresAt": t + lifetime,
    }
    return {"kel": identity.get_kel(), "credential": sign_claims(identity, "delegation", claims)}


def verify_delegation(
    entry: object, subject: str, *, now: int, pinned: KelState | None = None
) -> tuple[KelState, bool]:
    """Verify one ``{kel, credential}`` naming ``subject``: the issuer's KEL, then the signature
    under its current signing delegation, then the lifetime. Returns ``(issuer_state, live)``;
    an expired credential is ``live == False`` (dropped, not invalid). Anything else is
    ``invalid_authorization``.

    ``pinned``: the verifier's pin for the issuer, when it holds one. The carried KEL is then
    reconciled with it (01 § Pinning): a fork, or an older prefix whose credential is signed by
    a delegation the pin has superseded, is invalid."""
    if type(entry) is not dict or set(entry) != {"kel", "credential"}:
        raise bad("delegation must be {kel, credential}")
    c = entry["credential"]
    if (
        type(c) is not dict
        or set(c) != _KEYS
        or not is_ace_id(c["issuer"])
        or c["subject"] != subject
        or c["issuer"] == subject
    ):
        raise bad("invalid delegation credential")
    check_lifetime(c, now, MAX_DELEGATION_LIFETIME, allow_expired=True)
    try:
        state = verify_kel(entry["kel"], now)
        if pinned is not None and state.ace_id == pinned.ace_id:
            state, _ = reconcile_kel(pinned, state)
    except ACEError as exc:
        raise bad(f"delegation issuer kel: {exc.message}") from None
    if state.ace_id != c["issuer"]:
        raise bad("delegation kel must be the issuer's")
    try:  # 01 rule 5 makes the issuer usable at now
        verify_claims(state, "delegation", c, now)
    except ACEError as exc:  # 04 § Verification: any non-expiry failure of an entry
        raise bad(f"delegation: {exc.message}") from None
    return state, now < wire_int(c["expiresAt"])  # type: ignore[operator]


def validate_erc8004(entry: object) -> dict:
    """``{agentRegistry: CAIP-10, agentId}``: for an ``eip155`` registry a decimal string of at
    most 78 digits; for any other CAIP-2 namespace 1-128 characters of ``[A-Za-z0-9]`` (a
    chain-native identifier such as a Solana base58 address)."""
    if (
        type(entry) is not dict
        or set(entry) != {"agentRegistry", "agentId"}
        or not is_caip10_account(entry["agentRegistry"])
        or not isinstance(entry["agentId"], str)
    ):
        raise bad("erc8004 entry must be {agentRegistry: CAIP-10, agentId}")
    eip155 = entry["agentRegistry"].split(":", 1)[0] == "eip155"
    if (_AGENT_ID_RE if eip155 else _NATIVE_AGENT_ID_RE).fullmatch(entry["agentId"]) is None:
        raise bad("erc8004 agentId must be decimal (eip155) or 1-128 [A-Za-z0-9]")
    return copy.deepcopy(entry)


def verify_erc8004_registration(registration: object, ace_id: str) -> bool:
    """Whether an ERC-8004 registration file (tokenURI JSON, as a dict or JSON text) lists
    ``{"name": "ACE", "endpoint": ace_id}`` under ``services``. Reading the chain and the
    tokenURI is the host's job. Never raises."""
    try:
        if isinstance(registration, (str, bytes, bytearray)):
            registration = loads_json(registration)
    except ValueError:
        return False
    items = registration.get("services") if isinstance(registration, dict) else None
    return (
        is_ace_id(ace_id)
        and isinstance(items, list)
        and any(
            isinstance(s, dict) and s.get("name") == "ACE" and s.get("endpoint") == ace_id
            for s in items
        )
    )
