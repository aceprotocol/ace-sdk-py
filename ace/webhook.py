"""Webhook notification verification (08-relay § Webhooks)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Callable, NamedTuple

from ._encoding import check_fresh, is_ace_id
from .errors import ACEError
from .limits import TIMESTAMP_WINDOW_SECONDS

_TS_RE = re.compile(r"0|[1-9][0-9]{0,15}")
_MAX_SAFE_INTEGER = 2**53 - 1  # the TS SDK's Number.MAX_SAFE_INTEGER bound
_SIG_RE = re.compile(r"sha256=[0-9a-f]{64}")
_STREAM_RE = re.compile(r"[0-9]{1,20}-[0-9]{1,20}")


class WebhookNotification(NamedTuple):
    ace_id: str
    stream_id: str


def verify_webhook_notification(
    *,
    secret: str,
    timestamp: str,
    signature: str,
    body: bytes | str,
    clock: Callable[[], int] | None = None,
    window_seconds: int = TIMESTAMP_WINDOW_SECONDS,
) -> WebhookNotification:
    """Verify ``X-ACE-Webhook-Timestamp`` / ``X-ACE-Webhook-Signature`` over the raw ``body``.

    Check order (mirrors the TS SDK): non-string inputs, or a timestamp that is malformed or above
    2^53 - 1 -> ``invalid_argument``; a signature not shaped ``sha256=<64 lowercase hex>`` ->
    ``invalid_signature``; ``window_seconds`` not an int in [0, 2^53 - 1], or a secret / str body
    that is not UTF-8 encodable -> ``invalid_argument``; freshness -> ``stale_timestamp``; HMAC
    (constant-time) -> ``invalid_signature``; then the body must be
    ``{"event":"message","aceId","streamId"}`` (``invalid_argument``)."""
    if not isinstance(secret, str) or not isinstance(timestamp, str) or not isinstance(signature, str):
        raise ACEError("invalid_argument", "secret, timestamp and signature must be strings")
    if _TS_RE.fullmatch(timestamp) is None or int(timestamp) > _MAX_SAFE_INTEGER:
        raise ACEError("invalid_argument", "X-ACE-Webhook-Timestamp is malformed")
    if _SIG_RE.fullmatch(signature) is None:
        raise ACEError("invalid_signature", "X-ACE-Webhook-Signature is malformed")
    if type(window_seconds) is not int or not 0 <= window_seconds <= _MAX_SAFE_INTEGER:
        raise ACEError("invalid_argument", "window_seconds must be a non-negative integer")
    try:
        raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        key = secret.encode("utf-8")
    except UnicodeEncodeError:  # e.g. lone surrogates in a str
        raise ACEError("invalid_argument", "secret and body must be encodable as UTF-8") from None
    ts = int(timestamp)
    check_fresh(ts, clock, window_seconds, "X-ACE-Webhook-Timestamp")
    expected = hmac.new(key, f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature[len("sha256="):]):
        raise ACEError("invalid_signature", "X-ACE-Webhook-Signature does not verify")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ACEError("invalid_argument", "notification body is not JSON") from None
    if not isinstance(obj, dict) or obj.get("event") != "message" or not is_ace_id(obj.get("aceId")) \
            or not isinstance(obj.get("streamId"), str) or _STREAM_RE.fullmatch(obj["streamId"]) is None:
        raise ACEError("invalid_argument", "notification body must be {event: message, aceId, streamId}")
    return WebhookNotification(obj["aceId"], obj["streamId"])
