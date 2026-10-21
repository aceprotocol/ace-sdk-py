"""Strict wire encodings, the one canonical JSON writer, hashing and the clock. Internal."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import numbers
import re
import time
from decimal import Decimal
from typing import Any, Callable

from .errors import ACEError, ACEErrorCode
from .limits import MAX_JSON_DEPTH, MAX_THREAD_ID_LENGTH

MAX_SAFE_INTEGER = (1 << 53) - 1

ACE_ID_RE = re.compile(r"ace:sha256:[0-9a-f]{64}")
MESSAGE_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
HANDLE_RE = re.compile(r"[a-z][a-z0-9_-]{2,31}")
NAMESPACED_ID_RE = re.compile(r"[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
CAIP10_RE = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}")
CAIP19_RE = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_TIMESTAMP_RE = re.compile(r"0|[1-9][0-9]{0,15}")
_STREAM_ID_RE = re.compile(r"[0-9]{1,20}-[0-9]{1,20}")
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


def is_sha256_hex(value: object) -> bool:
    """64 lowercase hex characters (a SHA-256 digest)."""
    return isinstance(value, str) and SHA256_HEX_RE.fullmatch(value) is not None


def is_caip10_account(value: object) -> bool:
    """A CAIP-10 account id (``namespace:reference:address``)."""
    return isinstance(value, str) and CAIP10_RE.fullmatch(value) is not None


def is_handle(value: object) -> bool:
    return isinstance(value, str) and HANDLE_RE.fullmatch(value) is not None


def is_namespaced_id(value: object) -> bool:
    """A profile ID or message type: namespaced ASCII identifier of at most 256 bytes."""
    return (
        isinstance(value, str)
        and len(value) <= 256
        and NAMESPACED_ID_RE.fullmatch(value) is not None
    )


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


def is_stream_id(value: object) -> bool:
    """A relay stream ID ``<ms>-<seq>``, each part 1..20 digits."""
    return isinstance(value, str) and _STREAM_ID_RE.fullmatch(value) is not None


# --- integers and the clock ---------------------------------------------------


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
    if not isinstance(value, int) or wire_int(value) is None:
        raise ACEError("invalid_argument", f"{what} must be an integer in [0, 2^53-1]")
    return value


def parse_timestamp(value: str | None) -> int | None:
    """A decimal header value in [0, 2^53-1] without leading zeros, else None."""
    if value is None or _TIMESTAMP_RE.fullmatch(value) is None:
        return None
    n = int(value)
    return n if n <= MAX_SAFE_INTEGER else None


Clock = Callable[[], int]


def unix_now(clock: Clock | None = None) -> int:
    """Unix seconds from ``clock`` (injected for tests) or the system clock.

    A finite non-negative float is floored; NaN, infinities, negatives, ``bool`` and
    non-numbers are ``invalid_argument``."""
    value = clock() if clock is not None else time.time()
    bad = ACEError("invalid_argument", "clock must return integer Unix seconds")
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise bad
    try:
        if not 0 <= value <= MAX_SAFE_INTEGER:
            raise bad
        if not isinstance(value, numbers.Integral) and not math.isfinite(value):
            raise bad
        return int(value)
    except (TypeError, ValueError, ArithmeticError):
        raise bad from None


def resolve_now(now: object, what: str = "now") -> int:
    """``now`` as checked integer Unix seconds, or the system clock when it is ``None``."""
    return unix_now(None) if now is None else check_wire_int(now, what)


# --- hashing ------------------------------------------------------------------


def sha256_hex(*parts: str | bytes) -> str:
    """Lowercase hex SHA-256 over the parts (strings as UTF-8) joined by one zero byte."""
    return hashlib.sha256(
        b"\x00".join(p.encode("utf-8") if isinstance(p, str) else bytes(p) for p in parts)
    ).hexdigest()


def conversation_key(a: str, b: str) -> str:
    """``hex(SHA-256(min(a,b) || 0x00 || max(a,b)))`` over two ACE IDs (local only)."""
    return sha256_hex(*sorted((a.encode("utf-8"), b.encode("utf-8"))))


# --- base64 -------------------------------------------------------------------


def to_base64(data: bytes) -> str:
    """Padded standard Base64."""
    return base64.b64encode(bytes(data)).decode("ascii")


def decode_b64(
    text: object, code: ACEErrorCode, what: str, *, max_bytes: int | None = None
) -> bytes:
    """Canonical padded standard Base64, or ``ACEError(code)``; at most ``max_bytes`` decoded."""
    if not isinstance(text, str):
        raise ACEError(code, f"{what} must be a Base64 string")
    if max_bytes is not None and len(text) > 4 * ((max_bytes + 2) // 3):
        raise ACEError(code, f"{what} is too large")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ACEError(code, f"{what} is not valid Base64") from None
    if base64.b64encode(raw).decode("ascii") != text:  # padded standard alphabet, canonical bits
        raise ACEError(code, f"{what} is not canonical Base64")
    if max_bytes is not None and len(raw) > max_bytes:
        raise ACEError(code, f"{what} is too large")
    return raw


def from_base64(text: str) -> bytes:
    """Decode canonical padded standard Base64; ``invalid_argument`` otherwise."""
    return decode_b64(text, "invalid_argument", "value")


def decode_fixed_b64(text: object, size: int, code: ACEErrorCode, what: str) -> bytes:
    raw = decode_b64(text, code, what, max_bytes=size)
    if len(raw) != size:
        raise ACEError(code, f"{what} must be {size} bytes")
    return raw


# --- JSON ---------------------------------------------------------------------


def check_json_value(
    value: object, code: ACEErrorCode = "invalid_body", max_depth: int = MAX_JSON_DEPTH
) -> None:
    """Plain JSON types only, finite numbers, depth <= ``max_depth``."""
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        v, depth = stack.pop()
        if v is None or isinstance(v, (bool, str)):
            continue
        if isinstance(v, int):
            try:
                float(v)
            except OverflowError:
                raise ACEError(code, "number overflows a double") from None
            continue
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ACEError(code, "non-finite number")
            continue
        if type(v) is dict or type(v) is list:
            if depth > max_depth:
                raise ACEError(code, f"JSON nesting exceeds depth {max_depth}")
            if type(v) is dict:
                for k, child in v.items():  # type: ignore[union-attr]
                    if not isinstance(k, str):
                        raise ACEError(code, "JSON object keys must be strings")
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in v)  # type: ignore[union-attr]
            continue
        raise ACEError(code, f"not a JSON value: {type(v).__name__}")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number literal {name}")


def loads_json(raw: bytes | str) -> object:
    """Strict JSON from wire bytes: fatal UTF-8, no NaN/Infinity; ``ValueError`` otherwise."""
    try:
        text = raw if isinstance(raw, str) else bytes(raw).decode("utf-8")
        value = json.loads(text, parse_constant=_reject_constant)
    except RecursionError:
        raise ValueError("JSON nesting too deep") from None
    except UnicodeDecodeError as exc:
        raise ValueError(f"not UTF-8: {exc}") from None
    return value


def loads_object(raw: bytes, code: ACEErrorCode, what: str) -> dict:
    """A strict JSON object within ``MAX_JSON_DEPTH``, or ``ACEError(code)``."""
    try:
        value = loads_json(raw)
    except ValueError as exc:
        raise ACEError(code, f"{what} is not JSON: {exc}") from None
    if type(value) is not dict:
        raise ACEError(code, f"{what} must be a JSON object")
    check_json_value(value, code)
    return value


def _es_number(value: int | float) -> str:
    """ECMAScript ``Number::toString`` of a finite number (RFC 8785 § 3.2.2.3)."""
    if isinstance(value, int) and abs(value) <= MAX_SAFE_INTEGER:
        return str(value)
    try:
        x = float(value)
    except OverflowError:
        raise ValueError("number overflows a double") from None
    if not math.isfinite(x):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(x))).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len(digit_tuple) - len(digits)  # type: ignore[operator]
    k = len(digits)
    n = k + exponent  # type: ignore[operator]
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        e = n - 1
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        text = mantissa + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + text


def _canonical_text(value: object, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif isinstance(value, bool):
        out.append("true" if value else "false")
    elif isinstance(value, (int, float)):
        out.append(_es_number(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _canonical_text(item, out)
        out.append("]")
    elif isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise TypeError("JSON object keys must be strings")
        out.append("{")
        for i, k in enumerate(sorted(value)):  # str order is code-point order
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False))
            out.append(":")
            _canonical_text(value[k], out)
        out.append("}")
    else:
        raise TypeError(f"not a JSON value: {type(value).__name__}")


def canonical_state_bytes(obj: object) -> bytes:
    """The one canonical JSON writer (02 § Canonical JSON): keys sorted by code point, compact,
    UTF-8, '/' unescaped, numbers in ECMAScript ``Number::toString`` form."""
    out: list[str] = []
    _canonical_text(obj, out)
    return "".join(out).encode("utf-8")
