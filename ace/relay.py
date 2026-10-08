"""Relay HTTP client (08-relay): registration, discovery, send, inbox, SSE listen, intents."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Literal, NamedTuple

from ._encoding import is_ace_id, is_stream_id, unix_now, wire_int
from .auth import RelayAuthRequest, create_auth_headers
from .discovery import VerifiedPeer, verify_peer_record
from .errors import ACEError, ACEErrorCode
from .limits import MAX_ENVELOPE_BYTES, MAX_INBOX_PAGE
from .registration import _KEEP, create_registration_request
from .types import ACEIdentity, ACEMessage, AgentProfile, DiscoverQuery

DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_SSE_FRAME_LIMIT = MAX_ENVELOPE_BYTES + 512
_MAX_CONNECT_FAILURES = 10
_MAX_BACKOFF_SECONDS = 30
_REGISTER_STATUSES = ("registered", "idempotent", "refreshed", "rotated")

_sleep = time.sleep  # patched by tests


_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
_HOST_RE = re.compile(r"[A-Za-z0-9.-]+")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_relay_url(url: object) -> str:
    """Normalize a relay base URL (08-relay § Client Rules, Relay URL); ``invalid_argument``.

    ``http``/``https`` only; no ``?``, ``#``, userinfo, whitespace or control characters
    (nothing is trimmed). The host is ASCII ``[A-Za-z0-9.-]+`` or a bracketed IPv6 literal;
    a port has no leading zero. Scheme and host are lowercased, ``:443`` (https) / ``:80``
    (http) dropped and all trailing ``/`` removed; the rest of the path is kept verbatim.
    """
    if not isinstance(url, str):
        raise ACEError("invalid_argument", "relay URL must be a string")
    if "?" in url or "#" in url or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        raise ACEError(
            "invalid_argument", "relay URL must not contain '?', '#', whitespace or controls"
        )
    scheme, sep, rest = url.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in _DEFAULT_PORTS:
        raise ACEError("invalid_argument", "relay URL must be http(s)://host[:port][/path]")
    slash = rest.find("/")
    authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    if "@" in authority:
        raise ACEError("invalid_argument", "relay URL must not contain userinfo")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ACEError("invalid_argument", "invalid relay URL host")
        host, port_part = authority[: end + 1], authority[end + 1 :]
        if port_part and not port_part.startswith(":"):
            raise ACEError("invalid_argument", "invalid relay URL host")
        try:
            if "%" in host:  # no zone in a relay URL
                raise ValueError(host)
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise ACEError("invalid_argument", "invalid relay URL IPv6 host") from None
    else:
        host, colon, port_part = authority.partition(":")
        port_part = colon + port_part
        if _HOST_RE.fullmatch(host) is None:
            raise ACEError("invalid_argument", "relay URL host must be ASCII [A-Za-z0-9.-]")
    port: int | None = None
    if port_part:
        digits = port_part[1:]
        if _PORT_RE.fullmatch(digits) is None or not 1 <= int(digits) <= 65535:
            raise ACEError(
                "invalid_argument", "relay URL port must be 1..65535 without leading zeros"
            )
        port = int(digits)
    host = host.lower()
    netloc = host if port is None or port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return f"{scheme}://{netloc}{path.rstrip('/')}"


def compare_stream_ids(a: str, b: str) -> int:
    am, _, aseq = a.partition("-")
    bm, _, bseq = b.partition("-")
    ka, kb = (int(am), int(aseq)), (int(bm), int(bseq))
    return (ka > kb) - (ka < kb)


class RelayEntry(NamedTuple):
    """One queued envelope. ``message`` is its raw JSON bytes, undecoded: pass it to
    ``Inbox.receive``, which quarantines anything that is not an envelope."""

    stream_id: str
    message: bytes
    catchup: bool = False


class InboxPage(NamedTuple):
    entries: list[RelayEntry]
    cursor: str | None


class DiscoverResult(NamedTuple):
    agents: list[VerifiedPeer]
    rejected: int
    cursor: str | None


class PostedIntent(NamedTuple):
    intent_id: str
    expires_at: int


@dataclass(frozen=True)
class Intent:
    """A published intent (``GET /v1/intents``). Relay metadata: not signed end to end."""

    intent_id: str
    from_id: str
    need: str
    tags: tuple[str, ...]
    max_price: str | None
    currency: str | None
    ttl: int
    created_at: int
    expires_at: int


class IntentPage(NamedTuple):
    intents: list[Intent]
    cursor: str | None


@dataclass(frozen=True)
class Webhook:
    url: str
    status: Literal["active", "disabled"]
    failures: int
    updated_at: int
    last_delivered_at: int | None = None
    last_error: str | None = None


def _protocol(msg: str) -> ACEError:
    return ACEError("relay_protocol_error", msg)


def _join_tags(tags: object) -> str | None:
    """A list of tags as the comma-joined query value; None or empty is omitted."""
    if tags is None:
        return None
    if not isinstance(tags, (list, tuple)) or not all(
        isinstance(t, str) and t and "," not in t for t in tags
    ):
        raise ACEError("invalid_argument", "tags must be a list of non-empty strings without ','")
    return ",".join(tags) or None


def _raw_json(value: object) -> bytes:
    """Re-serialize a JSON value parsed from a relay response (compact UTF-8). A lone
    surrogate escape yields invalid UTF-8, which the Inbox quarantines."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return text.encode("utf-8", "surrogatepass")


_RETRY_AFTER_RE = re.compile(r"[0-9]+")


def _retry_after(value: str | None) -> int | None:
    """``Retry-After`` as delay-seconds only; an HTTP-date or anything else is ignored."""
    if value is None or _RETRY_AFTER_RE.fullmatch(value) is None:
        return None
    return int(value)


def _map_relay_response(status: int, body: bytes, retry_after: str | None) -> ACEError:
    """Map one relay response other than the call's expected success to an ``ACEError``
    (08-relay § Client Rules, Responses).

    The ``409 replay`` retry happens before this mapping. Internal; exercised by the
    ``relayErrors`` vectors.
    """
    relay_code = message = None
    try:
        obj = json.loads(body.decode("utf-8")) if body else None
        if isinstance(obj, dict) and isinstance(obj.get("error"), str):
            relay_code = obj["error"][:64]
            if isinstance(obj.get("message"), str):
                message = obj["message"][:500]
    except (UnicodeDecodeError, ValueError, RecursionError):
        pass
    text = (
        f"relay HTTP {status}"
        + (f" {relay_code}" if relay_code else "")
        + (f": {message}" if message else "")
    )
    code: ACEErrorCode
    if status < 400 or status >= 600:
        code = "relay_protocol_error"  # 1xx, an unexpected 2xx, 3xx, out of range
    elif status == 408 or status >= 500:
        code = "relay_unavailable"
    elif status == 429:
        code = "relay_unavailable" if relay_code in (None, "rate_limited") else "relay_rejected"
    elif 400 <= status < 500:
        code = {
            (400, "envelope_expired"): "envelope_expired",
            (403, "not_registered"): "not_registered",
            (404, "unknown_peer"): "unknown_peer",
        }.get((status, relay_code or ""), "relay_rejected")  # type: ignore[assignment]
    else:
        code = "relay_protocol_error"
    err = ACEError(code, text, status=status, relay_code=relay_code)
    if err.category == "transient":
        err.retry_after_seconds = _retry_after(retry_after)
    return err


_CONNECTED = object()  # internal listen marker: a connection was established


class RelayClient:
    """Synchronous client for one relay (``http.client``; one connection per request).

    Authenticated calls sign ``X-ACE-*`` headers with ``ts = max(now, last + 1)`` and retry
    once on ``409 replay``. Redirects are never followed. Network failures and timeouts are
    ``relay_unavailable``; oversized or malformed responses ``relay_protocol_error``; HTTP
    errors map as in 08-relay § Client Rules (errors keep ``status`` and ``relay_code``;
    ``retry_after_seconds`` only on transient ones).
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        clock: Callable[[], int] | None = None,
    ) -> None:
        #: The normalized relay URL; also the key of this relay's persisted inbox cursor.
        self.base_url = normalize_relay_url(base_url)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
            raise ACEError("invalid_argument", "timeout must be positive")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ACEError("invalid_argument", "max_response_bytes must be a positive integer")
        parts = urllib.parse.urlsplit(self.base_url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or ""
        self._port = parts.port
        self._prefix = parts.path
        self._timeout = float(timeout)
        self._max_bytes = max_response_bytes
        self._clock = clock
        self._ts_lock = threading.Lock()
        self._last_ts = -1

    # --- plumbing ---

    def _now(self) -> int:
        return unix_now(self._clock)

    def _next_ts(self) -> int:
        with self._ts_lock:
            self._last_ts = max(self._now(), self._last_ts + 1)
            return self._last_ts

    def _connection(self, timeout: float) -> http.client.HTTPConnection:
        cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        return cls(self._host, self._port, timeout=timeout)

    def _target(self, path: str, query: dict[str, Any] | None) -> str:
        target = self._prefix + path
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            if q:
                target += "?" + urllib.parse.urlencode(q)
        return target

    def _send_once(
        self,
        method: str,
        path: str,
        query: dict[str, Any] | None,
        body: bytes | None,
        headers: dict[str, str],
    ) -> tuple[int, bytes, str | None]:
        conn = self._connection(self._timeout)
        try:
            hdrs = {"Accept": "application/json", **headers}
            if body is not None:
                hdrs["Content-Type"] = "application/json"
            conn.request(method, self._target(path, query), body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(self._max_bytes + 1)
            return resp.status, data, resp.getheader("Retry-After")
        except (OSError, http.client.HTTPException) as exc:
            raise ACEError(
                "relay_unavailable", f"relay request failed: {type(exc).__name__}: {exc}"
            ) from None
        finally:
            conn.close()

    def _call(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: object = None,
        identity: ACEIdentity | None = None,
        auth: RelayAuthRequest | None = None,
        expect: tuple[int, ...] = (200,),
    ) -> Any:
        payload = (
            None
            if body is None
            else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        for attempt in (0, 1):
            headers = (
                create_auth_headers(identity, auth, self._next_ts()) if auth is not None else {}
            )  # type: ignore[arg-type]
            status, data, retry_after = self._send_once(method, path, query, payload, headers)
            if len(data) > self._max_bytes:
                raise _protocol("response exceeds max_response_bytes")
            if status in expect:
                try:
                    return json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, ValueError, RecursionError):
                    raise _protocol("response is not JSON") from None
            if 200 <= status < 300:
                raise _protocol(f"unexpected relay HTTP {status}")
            err = _map_relay_response(status, data, retry_after)
            if auth is not None and attempt == 0 and status == 409 and err.relay_code == "replay":
                continue
            raise err
        raise AssertionError("unreachable")

    @staticmethod
    def _object(obj: object, what: str) -> dict:
        if not isinstance(obj, dict):
            raise _protocol(f"{what} response must be a JSON object")
        return obj

    @staticmethod
    def _cursor(obj: dict) -> str | None:
        c = obj.get("cursor")
        if c is not None and not isinstance(c, str):
            raise _protocol("cursor must be a string or null")
        return c

    # --- endpoints ---

    def register(
        self, identity: ACEIdentity, profile: AgentProfile | dict | None | object = _KEEP
    ) -> str:
        """``POST /v1/register``. Omitted profile keeps it, ``None`` removes it.

        Returns ``"registered" | "idempotent" | "refreshed" | "rotated"``.
        """
        request = create_registration_request(identity, profile, self._next_ts())
        obj = self._object(self._call("POST", "/v1/register", body=request), "register")
        status = obj.get("status")
        if status not in _REGISTER_STATUSES:
            raise _protocol("unexpected register status")
        return status

    def unregister(self, identity: ACEIdentity) -> None:
        self._call("POST", "/v1/unregister", identity=identity, auth=RelayAuthRequest.unregister())

    def lookup_peer(self, ace_id: str) -> VerifiedPeer:
        """``GET /v1/peer``: the record must be for ``ace_id`` and verify (``invalid_peer``)."""
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "ace_id must be an ACE ID")
        obj = self._object(self._call("GET", "/v1/peer", query={"aceId": ace_id}), "peer")
        if obj.get("aceId") != ace_id:
            raise ACEError("invalid_peer", "relay returned a record for another aceId")
        return verify_peer_record(obj)

    def discover(self, query: DiscoverQuery | None = None) -> DiscoverResult:
        """``GET /v1/discover``. Unverifiable entries are dropped and counted in ``rejected``."""
        q = query or DiscoverQuery()
        params = {
            "q": q.q,
            "tags": _join_tags(q.tags),
            "chain": q.chain,
            "scheme": q.scheme,
            "online": None if q.online is None else ("true" if q.online else "false"),
            "account": q.account,
            "limit": q.limit,
            "cursor": q.cursor,
        }
        obj = self._object(self._call("GET", "/v1/discover", query=params), "discover")
        agents = obj.get("agents")
        if not isinstance(agents, list):
            raise _protocol("agents must be a list")
        verified, rejected = [], 0
        for record in agents:
            try:
                verified.append(verify_peer_record(record))
            except ACEError:
                rejected += 1
        return DiscoverResult(verified, rejected, self._cursor(obj))

    def send(self, env: ACEMessage) -> None:
        """``POST /v1/send``; a valid ``Outbox.deliver`` transport."""
        if not isinstance(env, ACEMessage):
            raise ACEError("invalid_argument", "send expects an ACEMessage")
        self._call("POST", "/v1/send", body={"message": env.to_dict()})

    def fetch_inbox(
        self, identity: ACEIdentity, *, since: str | None = None, limit: int | None = None
    ) -> InboxPage:
        req = RelayAuthRequest.inbox(since or "-", MAX_INBOX_PAGE if limit is None else limit)
        query = {"since": None if req.since == "-" else req.since, "limit": req.limit}
        obj = self._object(
            self._call("GET", "/v1/inbox", query=query, identity=identity, auth=req),
            "inbox",
        )
        messages = obj.get("messages")
        if not isinstance(messages, list) or len(messages) > req.limit:  # type: ignore[operator]
            raise _protocol("messages must be a list of at most limit entries")
        entries = []
        for m in messages:
            sid = m.get("streamId") if isinstance(m, dict) else None
            if not is_stream_id(sid) or "message" not in m:
                raise _protocol("inbox entries must be {streamId, message}")
            entries.append(RelayEntry(sid, _raw_json(m["message"]), False))
        return InboxPage(entries, self._cursor(obj))

    def post_intent(
        self,
        identity: ACEIdentity,
        need: str,
        *,
        ttl: int,
        tags: list[str] | None = None,
        max_price: str | None = None,
        currency: str | None = None,
    ) -> PostedIntent:
        req = RelayAuthRequest.intent(need, tags or (), max_price, currency, ttl)
        body: dict[str, Any] = {"need": need, "tags": list(req.tags), "ttl": ttl}
        if max_price is not None:
            body["maxPrice"] = max_price
        if currency is not None:
            body["currency"] = currency
        obj = self._object(
            self._call(
                "POST", "/v1/intents", body=body, identity=identity, auth=req, expect=(200, 201)
            ),
            "intent",
        )
        intent_id, expires_at = obj.get("intentId"), wire_int(obj.get("expiresAt"))
        if not isinstance(intent_id, str) or expires_at is None:
            raise _protocol("intent response must be {intentId, expiresAt}")
        return PostedIntent(intent_id, expires_at)

    def list_intents(
        self,
        *,
        q: str | None = None,
        tags: list[str] | tuple[str, ...] | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> IntentPage:
        query = {"q": q, "tags": _join_tags(tags), "limit": limit, "cursor": cursor}
        obj = self._object(self._call("GET", "/v1/intents", query=query), "intents")
        raw = obj.get("intents")
        if not isinstance(raw, list):
            raise _protocol("intents must be a list")
        out = []
        for i in raw:
            if not isinstance(i, dict):
                raise _protocol("intent entries must be objects")
            tags_v = i.get("tags")
            ints = [wire_int(i.get(k)) for k in ("ttl", "createdAt", "expiresAt")]
            opt = [i.get(k) for k in ("maxPrice", "currency")]
            # optional members: absent is fine, present but not a string (null included) is not
            if (
                not isinstance(i.get("intentId"), str)
                or not isinstance(i.get("from"), str)
                or not isinstance(i.get("need"), str)
                or not isinstance(tags_v, list)
                or not all(isinstance(t, str) for t in tags_v)
                or None in ints
                or any(k in i and not isinstance(i[k], str) for k in ("maxPrice", "currency"))
            ):
                raise _protocol("malformed intent entry")
            out.append(
                Intent(i["intentId"], i["from"], i["need"], tuple(tags_v), opt[0], opt[1], *ints)
            )  # type: ignore[arg-type]
        return IntentPage(out, self._cursor(obj))

    def set_webhook(self, identity: ACEIdentity, url: str, secret: str) -> None:
        req = RelayAuthRequest.webhook("PUT", url, secret)
        self._call(
            "PUT", "/v1/webhook", body={"url": url, "secret": secret}, identity=identity, auth=req
        )

    def get_webhook(self, identity: ACEIdentity) -> Webhook | None:
        obj = self._object(
            self._call(
                "GET", "/v1/webhook", identity=identity, auth=RelayAuthRequest.webhook("GET")
            ),
            "webhook",
        )
        w = obj.get("webhook")
        if w is None:
            return None
        if not isinstance(w, dict):
            raise _protocol("webhook must be an object or null")
        failures, updated_at = wire_int(w.get("failures")), wire_int(w.get("updatedAt"))
        # Optional fields: absent is fine; present but malformed (null included) is a
        # protocol error.
        delivered_at = wire_int(w["lastDeliveredAt"]) if "lastDeliveredAt" in w else None
        last_error = w.get("lastError")
        if (
            not isinstance(w.get("url"), str)
            or w.get("status") not in ("active", "disabled")
            or failures is None
            or updated_at is None
            or ("lastDeliveredAt" in w and delivered_at is None)
            or ("lastError" in w and not isinstance(last_error, str))
        ):
            raise _protocol("webhook response must be {url, status, failures, updatedAt, …}")
        return Webhook(w["url"], w["status"], failures, updated_at, delivered_at, last_error)

    def clear_webhook(self, identity: ACEIdentity) -> None:
        self._call(
            "DELETE", "/v1/webhook", identity=identity, auth=RelayAuthRequest.webhook("DELETE")
        )

    # --- SSE ---

    def listen(
        self,
        identity: ACEIdentity,
        *,
        since: str | None = None,
        stop: threading.Event | None = None,
        idle_timeout: float = 90.0,
        on_open: Callable[[], None] | None = None,
    ) -> Iterator[RelayEntry]:
        """``GET /v1/listen`` as a generator of ``RelayEntry`` (catchup, then live).

        Each entry's ``message`` is the frame's raw data, undecoded (the Inbox quarantines a
        frame that is not an envelope). Reconnects internally, resuming after the last
        yielded stream ID: immediately on ``event: drain`` or a clean end of stream once that
        connection carried a ``catchup``, ``message`` or ``drain`` frame, otherwise (including
        a stream that delivered only ``connected``, heartbeats or nothing) with backoff
        1, 2, 4 ... 30 s (``Retry-After`` honored, capped at 30 s). Only ``catchup``,
        ``message`` and ``drain`` frames reset the failure count; ten consecutive failures
        raise ``relay_unavailable``.
        A non-retryable status raises the mapped error (``relay_rejected`` etc.); a frame
        larger than ``MAX_ENVELOPE_BYTES + 512`` raises ``relay_protocol_error``. Setting
        ``stop`` (or closing the generator) ends the stream; a connection idle for
        ``idle_timeout`` seconds is treated as dropped. ``on_open`` runs each time a connection
        is established (the first and every reconnect); an exception from it ends the stream
        as is.
        """
        resume = since or "-"
        RelayAuthRequest.listen(resume)  # validate
        failures = 0
        stopped = (lambda: False) if stop is None else stop.is_set
        while not stopped():
            # Only the stream is inside the try: an error from on_open or thrown in at the
            # yield is the caller's and propagates as is. Once stopped, the watcher's socket
            # shutdown surfaces as a stream error or EOF, both of which end here.
            stream = self._listen_once(identity, resume, stop, idle_timeout)
            got_event = False  # a catchup / message / drain frame arrived on this connection
            try:
                while True:
                    failure: ACEError | None = None
                    try:
                        entry = next(stream)
                    except StopIteration:
                        if got_event:  # drain or EOF after progress: reconnect at once
                            failures = 0
                            break
                        failure = ACEError(
                            "relay_unavailable", "listen stream ended without progress"
                        )
                    except ACEError as exc:
                        if exc.code != "relay_unavailable" and not stopped():
                            raise
                        failure = exc
                    if failure is not None:
                        if stopped():
                            return
                        failures += 1
                        if failures >= _MAX_CONNECT_FAILURES:
                            raise failure
                        delay = min(2 ** (failures - 1), _MAX_BACKOFF_SECONDS)
                        if failure.retry_after_seconds is not None:
                            delay = min(
                                max(delay, failure.retry_after_seconds), _MAX_BACKOFF_SECONDS
                            )
                        if stop is not None:
                            if stop.wait(delay):
                                return
                        else:
                            _sleep(delay)
                        break
                    if stopped():  # buffered frames are not yielded after stop
                        return
                    if entry is _CONNECTED:
                        if on_open is not None:
                            on_open()
                        continue
                    failures, got_event = 0, True  # catchup / message / drain is progress
                    if entry is None:
                        continue  # drain
                    yield entry
                    resume = entry.stream_id
            finally:
                stream.close()

    def _listen_once(
        self,
        identity: ACEIdentity,
        since: str,
        stop: threading.Event | None,
        idle_timeout: float,
    ) -> Iterator[RelayEntry | object | None]:
        conn = self._connection(max(self._timeout, idle_timeout))
        done = threading.Event()
        watcher = None
        resp: http.client.HTTPResponse | None = None
        try:
            for attempt in (0, 1):
                req = RelayAuthRequest.listen(since)
                headers = {
                    **create_auth_headers(identity, req, self._next_ts()),
                    "Accept": "text/event-stream",
                }
                try:
                    conn.request(
                        "GET", self._target("/v1/listen", {"since": since}), headers=headers
                    )
                    sock = conn.sock  # getresponse() may detach it from the connection
                    resp = conn.getresponse()
                except (OSError, http.client.HTTPException) as exc:
                    raise ACEError("relay_unavailable", f"listen connect failed: {exc}") from None
                if resp.status == 200:
                    break
                data = resp.read(64 * 1024)
                if 200 <= resp.status < 300:
                    raise _protocol(f"unexpected listen HTTP {resp.status}")
                err = _map_relay_response(resp.status, data, resp.getheader("Retry-After"))
                if attempt == 0 and resp.status == 409 and err.relay_code == "replay":
                    conn.close()
                    conn = self._connection(max(self._timeout, idle_timeout))
                    continue
                raise err
            assert resp is not None
            media = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if media != "text/event-stream":
                raise _protocol("listen response is not text/event-stream")
            if stop is not None:

                def watch() -> None:
                    while not done.is_set():
                        if stop.wait(
                            0.5
                        ):  # the period only bounds how long the watcher outlives its stream
                            try:
                                if sock is not None:
                                    sock.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            return

                watcher = threading.Thread(target=watch, daemon=True)
                watcher.start()
            yield _CONNECTED
            yield from self._parse_sse(resp)
        finally:
            done.set()
            # A response that will close owns the socket after getresponse(); closing only the
            # connection would leave it to the GC, so close the response explicitly as well.
            if resp is not None:
                resp.close()
            conn.close()

    @staticmethod
    def _parse_sse(resp: http.client.HTTPResponse) -> Iterator[RelayEntry | None]:
        """Yield one entry per ``catchup`` / ``message`` event and ``None`` for ``drain`` (then
        return); other event types are skipped. Returns at a clean end of stream. Lines end
        with CR, LF or CRLF. An event is dispatched only if it has a ``data`` field; ``id`` and
        ``event`` apply to the event they appear in only."""
        reader = _SSELines(resp)
        event_id: str | None = None
        event_type = ""
        data: list[bytes] = []
        size = 0
        while True:
            line = reader.next_line()
            if line is None:
                return  # clean end of stream: reconnect immediately
            if line.startswith(b":"):
                continue  # heartbeat / comment
            size += len(line) + 1
            if size > _SSE_FRAME_LIMIT + 2:
                raise _protocol("SSE frame exceeds the size limit")
            if line:
                field, _, value = line.partition(b":")
                if value.startswith(b" "):
                    value = value[1:]
                if field == b"id":
                    event_id = value.decode("utf-8", "replace")
                elif field == b"event":
                    event_type = value.decode("utf-8", "replace")
                elif field == b"data":
                    data.append(value)
                continue
            # dispatch: only an event with a data field; id and type are per event
            if not data:
                event_id, event_type, size = None, "", 0
                continue
            etype, eid, payload = event_type or "message", event_id, b"\n".join(data)
            event_id, event_type, data, size = None, "", [], 0
            if etype == "drain":
                yield None  # progress: the relay asked for a reconnect, which is immediate
                return
            if etype not in ("catchup", "message"):
                continue  # connected, or an unknown type: not progress
            if not is_stream_id(eid):
                raise _protocol("SSE event without a valid stream id")
            yield RelayEntry(eid, payload, etype == "catchup")  # type: ignore[arg-type]


class _SSELines:
    """Split an SSE byte stream into lines ending in CR, LF or CRLF (CR LF is one ending).

    A line longer than the frame limit is ``relay_protocol_error``; a read error or a stream
    that ends mid-line is ``relay_unavailable``; a stream that ends at a line boundary
    returns None.
    """

    def __init__(self, resp: http.client.HTTPResponse) -> None:
        self._resp = resp
        self._buf = b""
        self._skip_lf = False

    def _fill(self) -> bool:
        try:
            chunk = self._resp.read1(8192)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise ACEError("relay_unavailable", f"listen stream dropped: {exc}") from None
        if not chunk:
            return False
        self._buf += chunk
        return True

    def next_line(self) -> bytes | None:
        while True:
            if self._skip_lf and self._buf:
                if self._buf.startswith(b"\n"):
                    self._buf = self._buf[1:]
                self._skip_lf = False
            cr, lf = self._buf.find(b"\r"), self._buf.find(b"\n")
            ends = [i for i in (cr, lf) if i >= 0]
            if ends:
                i = min(ends)
                line, self._buf = self._buf[:i], self._buf[i + 1 :]
                if i == cr:
                    self._skip_lf = True
                if len(line) > _SSE_FRAME_LIMIT:
                    raise _protocol("SSE frame exceeds the size limit")
                return line
            if len(self._buf) > _SSE_FRAME_LIMIT:
                raise _protocol("SSE frame exceeds the size limit")
            if not self._fill():
                if self._buf:
                    raise ACEError("relay_unavailable", "listen stream ended mid-line")
                return None
