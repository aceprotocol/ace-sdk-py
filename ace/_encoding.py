"""Strict wire encodings shared by every module (design §0). Internal."""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from typing import Any, Callable

from Crypto.Hash import keccak as _keccak

from .errors import ACEError, ACEErrorCode
from .limits import MAX_JSON_DEPTH, MAX_THREAD_ID_LENGTH

MAX_SAFE_INTEGER = (1 << 53) - 1

ACE_ID_RE = re.compile(r"ace:sha256:[0-9a-f]{64}")
MESSAGE_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
CONVERSATION_ID_RE = re.compile(r"[0-9a-f]{64}")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_SIG_RE = re.compile(r"0x[0-9a-f]{130}")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HTTPS_URL_RE = re.compile(
    r"https://(" + _LABEL + r"(?:\." + _LABEL + r")*)(?::([0-9]{1,5}))?"
    r"(?:[/?#][A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?"
)


# --- predicates -------------------------------------------------------------

def is_ace_id(value: object) -> bool:
    """``ace:sha256:<64 lowercase hex>``."""
    return isinstance(value, str) and ACE_ID_RE.fullmatch(value) is not None


def is_message_id(value: object) -> bool:
    """Lowercase UUIDv4."""
    return isinstance(value, str) and MESSAGE_ID_RE.fullmatch(value) is not None


def is_conversation_id(value: object) -> bool:
    """64 lowercase hex characters."""
    return isinstance(value, str) and CONVERSATION_ID_RE.fullmatch(value) is not None


def is_thread_id(value: object) -> bool:
    """1..256 code points, no U+0000-U+001F or U+007F."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_THREAD_ID_LENGTH
        and CONTROL_CHAR_RE.search(value) is None
    )


def is_https_url(value: object) -> bool:
    """The ACE HTTPS URL grammar (regex plus length/host/port checks)."""
    if not isinstance(value, str) or len(value) > 2048:
        return False
    m = _HTTPS_URL_RE.fullmatch(value)
    if m is None or len(m.group(1)) > 253:
        return False
    port = m.group(2)
    return port is None or 1 <= int(port) <= 65535


# --- integers ---------------------------------------------------------------

def wire_int(value: object) -> int | None:
    """The JSON wire-integer rule: an integral value in [0, 2^53-1]; bool rejected."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= MAX_SAFE_INTEGER else None
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer() and 0 <= value <= MAX_SAFE_INTEGER:
            return int(value)
    return None


def check_wire_int(value: object, what: str) -> int:
    """An ``int`` (not bool, not float) in [0, 2^53-1], or ``invalid_argument``."""
    if isinstance(value, bool) or not isinstance(value, int) or wire_int(value) is None:
        raise ACEError("invalid_argument", f"{what} must be an integer in [0, 2^53-1]")
    return value


def unix_now(clock: Callable[[], int] | None) -> int:
    """Unix seconds from ``clock`` (injected for tests) or the system clock."""
    return int(clock()) if clock is not None else int(time.time())


def decimal(n: int) -> str:
    return str(n)


# --- base64 / hex -----------------------------------------------------------

def to_base64(data: bytes) -> str:
    """Padded standard Base64."""
    return base64.b64encode(bytes(data)).decode("ascii")


def decode_b64(text: object, code: ACEErrorCode, what: str, *, max_bytes: int | None = None) -> bytes:
    """Canonical padded standard Base64, or ``ACEError(code)``."""
    if not isinstance(text, str):
        raise ACEError(code, f"{what} must be a Base64 string")
    if max_bytes is not None and len(text) > 4 * ((max_bytes + 2) // 3):
        raise ACEError(code, f"{what} is too large")
    if _B64_RE.fullmatch(text) is None:
        raise ACEError(code, f"{what} is not padded standard Base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ACEError(code, f"{what} is not valid Base64") from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ACEError(code, f"{what} is not canonical Base64")
    return raw


def from_base64(text: str) -> bytes:
    """Decode canonical padded standard Base64; ``invalid_argument`` otherwise."""
    return decode_b64(text, "invalid_argument", "value")


def encode_hex_signature(sig: bytes) -> str:
    return "0x" + bytes(sig).hex()


def decode_hex_signature(text: object, code: ACEErrorCode) -> bytes:
    if not isinstance(text, str) or _HEX_SIG_RE.fullmatch(text) is None:
        raise ACEError(code, "secp256k1 signature must match ^0x[0-9a-f]{130}$")
    return bytes.fromhex(text[2:])


def encode_signature(sig: bytes, scheme: str) -> str:
    return to_base64(sig) if scheme == "ed25519" else encode_hex_signature(sig)


def decode_signature(text: object, scheme: str, code: ACEErrorCode) -> bytes:
    if scheme == "ed25519":
        raw = decode_b64(text, code, "ed25519 signature", max_bytes=64)
        if len(raw) != 64:
            raise ACEError(code, "ed25519 signature must be 64 bytes")
        return raw
    if scheme == "secp256k1":
        return decode_hex_signature(text, code)
    raise ACEError(code, "unsupported signature scheme")


# --- hashing / addresses ----------------------------------------------------

def keccak256(data: bytes) -> bytes:
    k = _keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def eip55(address_hex40: str) -> str:
    addr = address_hex40.lower()
    h = keccak256(addr.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(addr))


# --- JSON values ------------------------------------------------------------

def check_json_value(value: object, code: ACEErrorCode = "invalid_body") -> None:
    """Sender-side JSON-value rules: plain JSON types, finite numbers, depth <= 32."""
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        v, depth = stack.pop()
        if v is None or isinstance(v, (bool, str)):
            continue
        if isinstance(v, int):
            _check_finite_int(v, code)
            continue
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ACEError(code, "non-finite number")
            continue
        if type(v) is dict or type(v) is list:
            if depth > MAX_JSON_DEPTH:
                raise ACEError(code, f"JSON nesting exceeds depth {MAX_JSON_DEPTH}")
            if type(v) is dict:
                for k, child in v.items():  # type: ignore[union-attr]
                    if not isinstance(k, str):
                        raise ACEError(code, "JSON object keys must be strings")
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in v)  # type: ignore[union-attr]
            continue
        raise ACEError(code, f"not a JSON value: {type(v).__name__}")


def _check_finite_int(v: int, code: ACEErrorCode) -> None:
    try:
        float(v)
    except OverflowError:
        raise ACEError(code, "number overflows a double") from None


def dumps_body(body: dict) -> bytes:
    """Compact UTF-8 JSON of a validated body, or ``invalid_body``."""
    try:
        return json.dumps(body, allow_nan=False, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ACEError("invalid_body", f"body is not serializable: {exc}") from None


def _reject_constant(name: str) -> Any:
    raise ACEError("invalid_body", f"non-finite number literal {name}")


def _parse_float(text: str) -> float:
    f = float(text)
    if not math.isfinite(f):
        raise ACEError("invalid_body", "number overflows a double")
    return f


def _parse_int(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        raise ACEError("invalid_body", "integer literal too long") from None
    _check_finite_int(n, "invalid_body")
    return n


def loads_body(raw: bytes) -> dict:
    """Decode a decrypted body: fatal UTF-8, no non-finite numbers, depth, object."""
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise ACEError("invalid_body", "body is not valid UTF-8") from None
    try:
        body = json.loads(
            text, parse_constant=_reject_constant, parse_float=_parse_float, parse_int=_parse_int,
        )
    except ACEError:
        raise
    except RecursionError:
        raise ACEError("invalid_body", f"JSON nesting exceeds depth {MAX_JSON_DEPTH}") from None
    except ValueError as exc:
        raise ACEError("invalid_body", f"body is not JSON: {exc}") from None
    if type(body) is not dict:
        raise ACEError("invalid_body", "body must be a JSON object")
    check_json_value(body)
    return body


def canonical_json(value: object) -> str:
    """Minimal RFC 8785 serializer for ASCII-keyed objects of strings/ints/objects."""
    if isinstance(value, dict):
        return "{" + ",".join(
            _jcs_string(k) + ":" + canonical_json(value[k]) for k in sorted(value)
        ) + "}"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("canonical_json supports objects, strings and integers only")
    return str(value)


_JCS_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _JCS_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical_state_bytes(obj: object) -> bytes:
    """Persisted-JSON writer: sorted keys, compact, UTF-8, '/' unescaped."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
