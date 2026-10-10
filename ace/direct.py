"""Direct delivery, sender side (08-relay § Direct Delivery, Sender).

A transport for secure delivery frames (``SecureRelayReplies``): direct endpoint first,
relay fallback. The receiver side is ``SecureMailbox.receive_direct``.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import urllib.parse
from typing import TYPE_CHECKING, Callable, Literal

from . import discovery as _discovery
from ._encoding import is_https_url
from .errors import ACEError
from .limits import MAX_DIRECT_BODY_BYTES
from .types import ACEMessage

if TYPE_CHECKING:
    from .relay import RelayClient

DEFAULT_DIRECT_TIMEOUT_SECONDS = 5.0
_MAX_REPLY_BYTES = 64 * 1024
_REMOTE_CODE_RE = re.compile(r"[a-z0-9_]{1,64}")

DeliveryPath = Literal["direct", "relay"]


def _unavailable(msg: str, status: int | None = None) -> ACEError:
    return ACEError("direct_unavailable", msg, status=status)


def post_direct(
    endpoint: str, message: ACEMessage, *, timeout: float = DEFAULT_DIRECT_TIMEOUT_SECONDS
) -> None:
    """``POST <endpoint>`` with ``{"message": envelope}``; returns when the receiver accepted it.

    ``endpoint`` must be an ACE HTTPS URL. Its host is resolved once and refused when any
    address is blocked (``is_blocked_address``); the request goes to a validated address
    (no second lookup; SNI and certificate checks use the host name). Redirects are not
    followed. ``timeout`` bounds the whole exchange (connect, request, reply headers and
    body); running past it is ``direct_unavailable``.

    Success iff the reply is 2xx with a JSON object body carrying ``"ok": true``. Errors:
    an invalid or unsafe endpoint (or argument) is ``invalid_argument``; 400 or 413 is
    ``direct_rejected`` with the receiver's ``error`` string in ``remote_code`` when it
    matches ``^[a-z0-9_]{1,64}$`` (else None; do not retry this envelope directly, and do
    not fall back to the relay); anything else (network failure, timeout, 429, 503, other
    statuses or bodies) is ``direct_unavailable``.
    """
    if not is_https_url(endpoint):
        raise ACEError("invalid_argument", "endpoint must be an ACE HTTPS URL")
    if not isinstance(message, ACEMessage):
        raise ACEError("invalid_argument", "message must be an ACEMessage")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
        raise ACEError("invalid_argument", "timeout must be positive")
    parts = urllib.parse.urlsplit(endpoint)
    host = (parts.hostname or "").lower()
    port = parts.port or 443
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    body = json.dumps(
        {"message": message.to_dict()}, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if len(body) > MAX_DIRECT_BODY_BYTES:
        raise ACEError("invalid_argument", "envelope exceeds MAX_DIRECT_BODY_BYTES")
    try:
        ip = _discovery._resolve(host, False, port)[0]
    except ACEError as exc:
        if exc.code == "blocked_address":
            raise ACEError("invalid_argument", f"unsafe endpoint: {exc.message}") from None
        raise _unavailable(exc.message) from None
    try:
        status, _, data = _discovery._pinned_request(
            host,
            ip,
            port,
            "POST",
            target,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=body,
            timeout=float(timeout),
            max_bytes=_MAX_REPLY_BYTES,
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise _unavailable(f"direct delivery failed: {type(exc).__name__}: {exc}") from None
    reply: object = None
    if len(data) <= _MAX_REPLY_BYTES:
        try:
            reply = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            reply = None
    if status in (400, 413):
        error = reply.get("error") if isinstance(reply, dict) else None
        # peer-controlled text: kept only when it looks like an error code
        remote = error if isinstance(error, str) and _REMOTE_CODE_RE.fullmatch(error) else None
        raise ACEError(
            "direct_rejected",
            f"receiver answered HTTP {status}" + (f" {remote}" if remote else ""),
            status=status,
            remote_code=remote,
        )
    if 200 <= status < 300 and isinstance(reply, dict) and reply.get("ok") is True:
        return
    raise _unavailable(f"receiver answered HTTP {status} without ok:true", status)


def deliver_direct_or_relay(
    relay: RelayClient,
    endpoint: str | None = None,
    *,
    timeout: float = DEFAULT_DIRECT_TIMEOUT_SECONDS,
) -> Callable[[ACEMessage], DeliveryPath]:
    """A transport for ``SecureRelayReplies`` / secure delivery frames (the ``send`` of
    ``SecureRelayReplies``): ``post_direct`` to ``endpoint`` when given, else (or on
    ``direct_unavailable`` or an unsafe/invalid endpoint) ``relay.send``. A
    ``direct_rejected`` error is raised as is: the recipient already rejected this frame,
    so it is not sent through the relay. Returns the path that delivered.

    Both paths carry the same frame (same ``messageId``); the receiver answers a second
    copy with the same reply.
    """

    def transport(message: ACEMessage) -> DeliveryPath:
        if endpoint is not None:
            try:
                post_direct(endpoint, message, timeout=timeout)
                return "direct"
            except ACEError as exc:
                if exc.code not in ("direct_unavailable", "invalid_argument"):
                    raise
        relay.send(message)
        return "relay"

    return transport
