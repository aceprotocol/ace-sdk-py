"""Namespaced extensions (02-discovery § Profile Fields) and the bundled commerce extension
(04-messages § Commerce extension). One code path for profiles, registration files and intents."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Literal, TypedDict

from ._encoding import CONTROL_CHAR_RE, canonical_state_bytes, check_json_value
from .errors import ACEError, ACEErrorCode
from .limits import MAX_EXT_BYTES, MAX_EXT_DEPTH, MAX_EXT_KEY_BYTES, MAX_EXT_KEYS

if TYPE_CHECKING:
    from .relay import Intent
    from .types import AgentProfile, RegistrationFile

#: The bundled commerce extension namespace.
COMMERCE_EXT = "urn:ace:commerce:1"

#: What carries the ``ext``: a profile or registration file (``invalid_profile``) or an intent
#: (``invalid_argument``).
ExtCarrier = Literal["profile", "intent"]

#: A validated ``ext``: namespace -> JSON object.
ExtMap = dict[str, dict[str, Any]]

NAMESPACED_ID_RE = re.compile(r"[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_CAIP2_RE = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_AMOUNT_RE = re.compile(r"[0-9]+(\.[0-9]+)?")


class CommercePricing(TypedDict, total=False):
    currency: str
    maxAmount: str


class CommerceAccount(TypedDict):
    network: str  # CAIP-2
    address: str


class CommerceProfileExt(TypedDict, total=False):
    """``urn:ace:commerce:1`` in a profile or registration file."""

    chains: list[str]
    pricing: CommercePricing
    settlement: list[str]
    accounts: list[CommerceAccount]


class CommerceIntentExt(TypedDict, total=False):
    """``urn:ace:commerce:1`` in an intent: ``maxPrice`` and ``currency``, both or neither."""

    maxPrice: str
    currency: str


def _code(carrier: ExtCarrier) -> ACEErrorCode:
    return "invalid_argument" if carrier == "intent" else "invalid_profile"


def ext_canonical(ext: dict | None) -> str:
    """Canonical JSON text of ``ext`` (06 Appendix A form: the registration / intent payload
    field), or ``''`` when absent or empty."""
    if not ext:
        return ""
    return canonical_state_bytes(ext).decode("utf-8")


def validate_ext(value: object, carrier: ExtCarrier) -> ExtMap | None:
    """Validate an ``ext`` object (02 § Profile Fields): keys are namespaced identifiers of at
    most 256 bytes, values are JSON objects, at most 8 keys, canonical JSON at most 4096 bytes,
    nesting depth at most 8; ``urn:ace:commerce:1``, when present, must satisfy 04 § Commerce
    extension for the carrier. Other namespaces are opaque. Returns the re-canonicalised plain
    object, or ``None`` when ``ext`` is absent, ``null`` or empty."""
    code = _code(carrier)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ACEError(code, "ext must be a JSON object")
    if not value:
        return None
    if len(value) > MAX_EXT_KEYS:
        raise ACEError(code, f"ext has more than {MAX_EXT_KEYS} namespaces")
    for k, v in value.items():
        if (
            not isinstance(k, str)
            or len(k.encode("utf-8")) > MAX_EXT_KEY_BYTES
            or NAMESPACED_ID_RE.fullmatch(k) is None
        ):
            raise ACEError(
                code,
                f"ext key {json.dumps(str(k)[:64])} is not a namespaced identifier of at most "
                f"{MAX_EXT_KEY_BYTES} bytes",
            )
        if not isinstance(v, dict):
            raise ACEError(code, f"ext[{json.dumps(k)}] must be a JSON object")
    check_json_value(value, code, MAX_EXT_DEPTH)
    try:
        canonical = canonical_state_bytes(value)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ACEError(code, f"ext is not serializable: {exc}") from None
    if len(canonical) > MAX_EXT_BYTES:
        raise ACEError(code, f"ext exceeds {MAX_EXT_BYTES} bytes of canonical JSON")
    out: ExtMap = json.loads(canonical.decode("utf-8"))
    if COMMERCE_EXT in out:
        validate_commerce_ext(out[COMMERCE_EXT], carrier)
    return out


def _bad(code: ACEErrorCode, member: str, rule: str) -> ACEError:
    return ACEError(code, f'ext["{COMMERCE_EXT}"].{member} {rule}')


def _str_list(code: ACEErrorCode, v: object, member: str, max_items: int) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise _bad(code, member, "must be an array of strings")
    if len(v) > max_items:
        raise _bad(code, member, f"has more than {max_items} items")
    return list(v)


def _text(code: ACEErrorCode, v: object, member: str, lo: int, hi: int, no_control: bool) -> str:
    if not isinstance(v, str):
        raise _bad(code, member, "must be a string")
    if not lo <= len(v) <= hi or (no_control and CONTROL_CHAR_RE.search(v)):
        raise _bad(
            code,
            member,
            f"must be {lo}-{hi} characters{' without control characters' if no_control else ''}",
        )
    return v


def _only_members(code: ACEErrorCode, o: dict, allowed: tuple[str, ...], where: str) -> None:
    extra = [k for k in o if k not in allowed]
    if extra:
        raise ACEError(
            code, f'ext["{COMMERCE_EXT}"]{where} has unknown members: {",".join(extra[:3])}'
        )


def validate_commerce_ext(
    value: object, carrier: ExtCarrier
) -> CommerceProfileExt | CommerceIntentExt:
    """Validate the ``urn:ace:commerce:1`` object of a profile / registration file (``chains``,
    ``pricing``, ``settlement``, ``accounts``; ``invalid_profile``) or of an intent (``maxPrice``
    + ``currency``, both or neither; ``invalid_argument``). Unknown members are invalid.
    Returns the typed object."""
    code = _code(carrier)
    if not isinstance(value, dict):
        raise ACEError(code, f'ext["{COMMERCE_EXT}"] must be a JSON object')
    if carrier == "intent":
        _only_members(code, value, ("maxPrice", "currency"), "")
        intent: CommerceIntentExt = {}
        if ("maxPrice" in value) != ("currency" in value):
            raise ACEError(
                code, f'ext["{COMMERCE_EXT}"] needs both maxPrice and currency or neither'
            )
        if "maxPrice" in value:
            intent["maxPrice"] = _text(code, value["maxPrice"], "maxPrice", 1, 64, False)
            intent["currency"] = _text(code, value["currency"], "currency", 1, 16, False)
        return intent
    _only_members(code, value, ("chains", "pricing", "settlement", "accounts"), "")
    out: CommerceProfileExt = {}
    if "chains" in value:
        chains = _str_list(code, value["chains"], "chains", 10)
        if not all(_CAIP2_RE.fullmatch(c) for c in chains):
            raise _bad(code, "chains", "items must be CAIP-2 identifiers")
        out["chains"] = chains
    if "pricing" in value:
        p = value["pricing"]
        if not isinstance(p, dict):
            raise _bad(code, "pricing", "must be a JSON object")
        _only_members(code, p, ("currency", "maxAmount"), ".pricing")
        pricing: CommercePricing = {
            "currency": _text(code, p.get("currency"), "pricing.currency", 1, 16, True)
        }
        if "maxAmount" in p:
            m = _text(code, p["maxAmount"], "pricing.maxAmount", 1, 32, False)
            if _AMOUNT_RE.fullmatch(m) is None:
                raise _bad(code, "pricing.maxAmount", "must match ^[0-9]+(\\.[0-9]+)?$")
            pricing["maxAmount"] = m
        out["pricing"] = pricing
    if "settlement" in value:
        out["settlement"] = _str_list(code, value["settlement"], "settlement", 10)
    if "accounts" in value:
        a = value["accounts"]
        if not isinstance(a, list):
            raise _bad(code, "accounts", "must be an array")
        if len(a) > 10:
            raise _bad(code, "accounts", "has more than 10 items")
        accounts: list[CommerceAccount] = []
        for i, entry in enumerate(a):
            if not isinstance(entry, dict):
                raise _bad(code, f"accounts[{i}]", "must be a JSON object")
            _only_members(code, entry, ("network", "address"), f".accounts[{i}]")
            network, address = entry.get("network"), entry.get("address")
            if not isinstance(network, str) or _CAIP2_RE.fullmatch(network) is None:
                raise _bad(code, f"accounts[{i}].network", "must be a CAIP-2 identifier")
            if not isinstance(address, str):
                raise _bad(code, f"accounts[{i}].address", "must be a string")
            accounts.append({"network": network, "address": address})
        out["accounts"] = accounts
    return out


def commerce_ext(
    carrier: "AgentProfile | RegistrationFile | None",
) -> CommerceProfileExt | None:
    """The typed ``urn:ace:commerce:1`` member of a validated profile or registration file,
    or ``None``."""
    ext = None if carrier is None else carrier.ext
    return None if ext is None else ext.get(COMMERCE_EXT)  # type: ignore[return-value]


def intent_commerce_ext(intent: "Intent | None") -> CommerceIntentExt | None:
    """The typed ``urn:ace:commerce:1`` member of an intent from ``RelayClient.list_intents``,
    or ``None``."""
    return commerce_ext(intent)  # type: ignore[arg-type]
