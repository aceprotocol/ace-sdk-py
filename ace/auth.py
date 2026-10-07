"""Relay request authentication headers (08-relay)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Mapping, NamedTuple, Sequence

from ._encoding import (
    CONTROL_CHAR_RE,
    check_fresh,
    check_wire_int,
    decimal,
    decode_signature,
    encode_signature,
    is_ace_id,
    is_https_url,
    is_stream_id,
    parse_timestamp,
    wire_int,
)
from ._signing import build_sign_data, encode_payload, verify_signature
from .errors import ACEError
from .limits import MAX_INBOX_PAGE, TIMESTAMP_WINDOW_SECONDS
from .types import SIGNING_SCHEMES, ACEIdentity, SigningScheme

_WEBHOOK_METHODS = ("PUT", "GET", "DELETE")


def _bad(msg: str) -> ACEError:
    return ACEError("invalid_argument", msg)


@dataclass(frozen=True)
class RelayAuthRequest:
    """What an authenticated relay call signs. Build with the classmethods.

    ``listen(since)``, ``inbox(since, limit)``, ``unregister()``,
    ``intent(need, tags, max_price, currency, ttl)``, ``webhook(method, url, secret)``.
    ``since`` is ``"-"`` or ``<ms>-<seq>``.
    """

    action: Literal["listen", "inbox", "unregister", "intent", "webhook"]
    since: str | None = None
    limit: int | None = None
    need: str | None = None
    tags: tuple[str, ...] = ()
    max_price: str | None = None
    currency: str | None = None
    ttl: int | None = None
    method: str | None = None
    url: str = ""
    secret: str = ""

    def __post_init__(self) -> None:
        a = self.action
        if a in ("listen", "inbox"):
            if self.since != "-" and not is_stream_id(self.since):
                raise _bad("since must be '-' or '<ms>-<seq>'")
        if a == "inbox" and (type(self.limit) is not int or not 1 <= self.limit <= MAX_INBOX_PAGE):
            raise _bad(f"limit must be an integer in 1..{MAX_INBOX_PAGE}")
        if a == "intent":
            if not isinstance(self.need, str):
                raise _bad("need must be a string")
            if not isinstance(self.tags, tuple) or not all(
                isinstance(t, str) and "," not in t for t in self.tags
            ):
                raise _bad("tags must be strings without ','")
            for v in (self.max_price, self.currency):
                if v is not None and not isinstance(v, str):
                    raise _bad("max_price and currency must be strings or None")
            if type(self.ttl) is not int or wire_int(self.ttl) is None:
                raise _bad("ttl must be an integer in [0, 2^53-1]")
        elif a == "webhook":
            if self.method not in _WEBHOOK_METHODS:
                raise _bad("method must be PUT, GET or DELETE")
            if not isinstance(self.url, str) or not isinstance(self.secret, str):
                raise _bad("url and secret must be strings")
            if self.method == "PUT":
                if not is_https_url(self.url):
                    raise _bad("url must match the ACE HTTPS URL grammar")
                if (
                    not 16 <= len(self.secret) <= 128
                    or CONTROL_CHAR_RE.search(self.secret) is not None
                ):
                    raise _bad("secret must be 16..128 characters without control characters")
            elif self.url != "" or self.secret != "":
                raise _bad(f"{self.method} takes no url or secret")
        elif a not in ("listen", "inbox", "unregister"):
            raise _bad("unknown action")

    @classmethod
    def listen(cls, since: str = "-") -> "RelayAuthRequest":
        return cls("listen", since=since)

    @classmethod
    def inbox(cls, since: str = "-", limit: int = MAX_INBOX_PAGE) -> "RelayAuthRequest":
        return cls("inbox", since=since, limit=limit)

    @classmethod
    def unregister(cls) -> "RelayAuthRequest":
        return cls("unregister")

    @classmethod
    def intent(
        cls,
        need: str,
        tags: Sequence[str] = (),
        max_price: str | None = None,
        currency: str | None = None,
        ttl: int = 0,
    ) -> "RelayAuthRequest":
        if isinstance(tags, str):
            raise _bad("tags must be a sequence of strings")
        return cls(
            "intent", need=need, tags=tuple(tags), max_price=max_price, currency=currency, ttl=ttl
        )

    @classmethod
    def webhook(cls, method: str, url: str = "", secret: str = "") -> "RelayAuthRequest":
        return cls("webhook", method=method, url=url, secret=secret)

    def payload(self) -> bytes:
        if self.action == "listen":
            return encode_payload(self.since)  # type: ignore[arg-type]
        if self.action == "inbox":
            return encode_payload(self.since, decimal(self.limit))  # type: ignore[arg-type]
        if self.action == "unregister":
            return b""
        if self.action == "webhook":
            return encode_payload(self.method, self.url, self.secret)  # type: ignore[arg-type]
        return encode_payload(
            self.need,
            ",".join(self.tags),
            self.max_price or "",
            self.currency or "",
            decimal(self.ttl),  # type: ignore[arg-type]
        )


def _sign_data(req: RelayAuthRequest, ace_id: str, timestamp: int) -> bytes:
    return build_sign_data(req.action, ace_id, timestamp, req.payload())


def create_auth_headers(
    identity: ACEIdentity, req: RelayAuthRequest, timestamp: int
) -> dict[str, str]:
    """``X-ACE-Id`` / ``X-ACE-Timestamp`` / ``X-ACE-Signature`` for one relay call."""
    if not isinstance(req, RelayAuthRequest):
        raise _bad("expected a RelayAuthRequest")
    check_wire_int(timestamp, "timestamp")
    ace_id = identity.get_ace_id()
    sig = identity.sign(_sign_data(req, ace_id, timestamp))
    return {
        "X-ACE-Id": ace_id,
        "X-ACE-Timestamp": decimal(timestamp),
        "X-ACE-Signature": encode_signature(sig, identity.get_signing_scheme()),
    }


class RelayAuth(NamedTuple):
    ace_id: str
    timestamp: int
    signature: str


def parse_auth_headers(headers: Mapping[str, str | Sequence[str] | None]) -> RelayAuth:
    """Case-insensitive lookup, first value of a list; ``invalid_argument`` on bad input."""
    found: dict[str, str] = {}
    for k, v in headers.items():
        key = k.lower() if isinstance(k, str) else None
        if key not in ("x-ace-id", "x-ace-timestamp", "x-ace-signature") or key in found:
            continue
        if isinstance(v, (list, tuple)):
            v = v[0] if v else None
        if isinstance(v, str):
            found[key] = v
    ace_id, ts, sig = (
        found.get("x-ace-id"),
        found.get("x-ace-timestamp"),
        found.get("x-ace-signature"),
    )
    if not is_ace_id(ace_id):
        raise _bad("X-ACE-Id is missing or not an ACE ID")
    timestamp = parse_timestamp(ts)
    if timestamp is None:
        raise _bad("X-ACE-Timestamp is missing or malformed")
    if not sig or len(sig) > 512:
        raise _bad("X-ACE-Signature is missing")
    return RelayAuth(ace_id, timestamp, sig)  # type: ignore[arg-type]


def verify_auth_headers(
    auth: RelayAuth,
    req: RelayAuthRequest,
    *,
    ace_id: str,
    scheme: SigningScheme,
    signing_public_key: bytes,
    clock: Callable[[], int] | None = None,
    window_seconds: int = TIMESTAMP_WINDOW_SECONDS,
) -> None:
    """Check order: ``auth.ace_id != ace_id`` -> ``invalid_argument``; ``|now - ts| > window``
    -> ``stale_timestamp``; bad encoding or signature -> ``invalid_signature``.

    Stateless: it does not detect replays. The relay MUST additionally accept each
    ``(action, ace_id, signature)`` at most once while its timestamp is inside the window
    (409 ``replay``)."""
    if (
        not isinstance(auth, RelayAuth)
        or not isinstance(req, RelayAuthRequest)
        or scheme not in SIGNING_SCHEMES
    ):
        raise _bad("expected RelayAuth, RelayAuthRequest and a signing scheme")
    check_wire_int(window_seconds, "window_seconds")
    if auth.ace_id != ace_id:
        raise _bad("X-ACE-Id does not match the signer")
    check_fresh(auth.timestamp, clock, window_seconds, "X-ACE-Timestamp")
    sig = decode_signature(auth.signature, scheme, "invalid_signature")
    if not verify_signature(
        _sign_data(req, auth.ace_id, auth.timestamp), sig, scheme, signing_public_key
    ):
        raise ACEError("invalid_signature", "X-ACE-Signature does not verify")
