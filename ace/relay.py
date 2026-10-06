"""Relay HTTP client (08-relay): registration, discovery, send, inbox, SSE listen, intents."""

from __future__ import annotations

import http.client
import json
import re
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Iterator, NamedTuple

from ._encoding import wire_int
from .auth import RelayAuthRequest, create_auth_headers
from .discovery import VerifiedPeer, verify_peer_record
from .errors import ACEError
from .limits import MAX_ENVELOPE_BYTES, MAX_INBOX_PAGE
from .registration import _KEEP, create_registration_request
from .types import ACEIdentity, ACEMessage, AgentProfile, DiscoverQuery

STREAM_ID_RE = re.compile(r"[0-9]+-[0-9]+")
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_SSE_FRAME_LIMIT = MAX_ENVELOPE_BYTES + 512
_MAX_CONNECT_FAILURES = 10
_MAX_BACKOFF_SECONDS = 30
_REGISTER_STATUSES = ("registered", "idempotent", "refreshed", "rotated")

_sleep = time.sleep  # patched by tests


def normalize_relay_url(url: object) -> str:
    """Lowercase scheme and host, no trailing ``/``. Only ``http``/``https`` are accepted."""
    if not isinstance(url, str):
        raise ACEError("invalid_argument", "relay URL must be a string")
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        raise ACEError("invalid_argument", "invalid relay URL") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ACEError("invalid_argument", "relay URL must be http(s)://host[:port][/path]")
    if parts.query or parts.fragment:
        raise ACEError("invalid_argument", "relay URL must not have a query or fragment")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        raise ACEError("invalid_argument", "invalid relay URL port") from None
    netloc = host if port is None else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}"


def compare_stream_ids(a: str, b: str) -> int:
    am, _, aseq = a.partition("-")
    bm, _, bseq = b.partition("-")
    ka, kb = (int(am), int(aseq)), (int(bm), int(bseq))
    return (ka > kb) - (ka < kb)


class RelayEntry(NamedTuple):
    """One queued envelope: ``message`` is the raw JSON object (decode it via the Inbox)."""

    stream_id: str
    message: Any
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


def _protocol(msg: str) -> ACEError:
    return ACEError("relay_protocol_error", msg)


def _retry_after(value: str | None) -> int | None:
    if value is None or not value.strip().isdigit():
        return None
    return int(value.strip())


def _map_status(status: int, body: bytes, retry_after: int | None) -> ACEError:
    relay_code = message = None
    try:
        obj = json.loads(body.decode("utf-8")) if body else None
        if isinstance(obj, dict) and isinstance(obj.get("error"), str):
            relay_code = obj["error"][:64]
            if isinstance(obj.get("message"), str):
                message = obj["message"][:500]
    except (UnicodeDecodeError, ValueError, RecursionError):
        pass
    text = f"relay HTTP {status}" + (f" {relay_code}" if relay_code else "") + (f": {message}" if message else "")
    kw: dict[str, Any] = {"status": status, "relay_code": relay_code}
    if status >= 500 or status in (408, 429):
        return ACEError("relay_unavailable", text, retry_after_seconds=retry_after, **kw)
    if 400 <= status < 500:
        mapped = {(400, "envelope_expired"): "envelope_expired", (404, "unknown_peer"): "unknown_peer",
                  (403, "not_registered"): "not_registered"}.get((status, relay_code or ""), "relay_rejected")
        return ACEError(mapped, text, **kw)  # type: ignore[arg-type]
    return _protocol(f"unexpected {text}")


_CONNECTED = object()  # internal listen marker: a connection was established


class RelayClient:
    """Synchronous client for one relay (``http.client``; one connection per request).

    Authenticated calls sign ``X-ACE-*`` headers with ``ts = max(now, last + 1)`` and retry
    once on ``409 replay``. Errors: network failures, timeouts, 5xx, 408 and 429 are
    ``relay_unavailable`` (with ``retry_after_seconds``); oversized or malformed responses
    ``relay_protocol_error``; 400 ``envelope_expired``, 404 ``unknown_peer`` and
    403 ``not_registered`` keep their code; other 4xx are ``relay_rejected`` (with
    ``status`` and ``relay_code``).
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
        return int(self._clock()) if self._clock is not None else int(time.time())

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
        self, method: str, path: str, query: dict[str, Any] | None, body: bytes | None, headers: dict[str, str],
    ) -> tuple[int, bytes, int | None]:
        conn = self._connection(self._timeout)
        try:
            hdrs = {"Accept": "application/json", **headers}
            if body is not None:
                hdrs["Content-Type"] = "application/json"
            conn.request(method, self._target(path, query), body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(self._max_bytes + 1)
            return resp.status, data, _retry_after(resp.getheader("Retry-After"))
        except (OSError, http.client.HTTPException) as exc:
            raise ACEError("relay_unavailable", f"relay request failed: {type(exc).__name__}: {exc}") from None
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
        payload = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for attempt in (0, 1):
            headers = create_auth_headers(identity, auth, self._next_ts()) if auth is not None else {}  # type: ignore[arg-type]
            status, data, retry_after = self._send_once(method, path, query, payload, headers)
            if len(data) > self._max_bytes:
                raise _protocol("response exceeds max_response_bytes")
            if status in expect:
                try:
                    return json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, ValueError, RecursionError):
                    raise _protocol("response is not JSON") from None
            err = _map_status(status, data, retry_after)
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

    def register(self, identity: ACEIdentity, profile: AgentProfile | dict | None | object = _KEEP) -> str:
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
        obj = self._object(self._call("GET", "/v1/peer", query={"aceId": ace_id}), "peer")
        if obj.get("aceId") != ace_id:
            raise ACEError("invalid_peer", "relay returned a record for another aceId")
        return verify_peer_record(obj)

    def discover(self, query: DiscoverQuery | None = None) -> DiscoverResult:
        """``GET /v1/discover``. Unverifiable entries are dropped and counted in ``rejected``."""
        q = query or DiscoverQuery()
        params = {
            "q": q.q, "tags": q.tags, "chain": q.chain, "scheme": q.scheme,
            "online": None if q.online is None else ("true" if q.online else "false"),
            "limit": q.limit, "cursor": q.cursor,
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

    def fetch_inbox(self, identity: ACEIdentity, *, since: str | None = None, limit: int | None = None) -> InboxPage:
        req = RelayAuthRequest.inbox(since or "-", MAX_INBOX_PAGE if limit is None else limit)
        obj = self._object(
            self._call("GET", "/v1/inbox", query={"since": req.since, "limit": req.limit}, identity=identity, auth=req),
            "inbox",
        )
        messages = obj.get("messages")
        if not isinstance(messages, list) or len(messages) > req.limit:  # type: ignore[operator]
            raise _protocol("messages must be a list of at most limit entries")
        entries = []
        for m in messages:
            sid = m.get("streamId") if isinstance(m, dict) else None
            if not isinstance(sid, str) or STREAM_ID_RE.fullmatch(sid) is None or "message" not in m:
                raise _protocol("inbox entries must be {streamId, message}")
            entries.append(RelayEntry(sid, m["message"], False))
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
            self._call("POST", "/v1/intents", body=body, identity=identity, auth=req, expect=(200, 201)), "intent",
        )
        intent_id, expires_at = obj.get("intentId"), wire_int(obj.get("expiresAt"))
        if not isinstance(intent_id, str) or expires_at is None:
            raise _protocol("intent response must be {intentId, expiresAt}")
        return PostedIntent(intent_id, expires_at)

    def list_intents(
        self, *, q: str | None = None, tags: str | None = None, limit: int | None = None, cursor: str | None = None,
    ) -> IntentPage:
        obj = self._object(
            self._call("GET", "/v1/intents", query={"q": q, "tags": tags, "limit": limit, "cursor": cursor}), "intents",
        )
        raw = obj.get("intents")
        if not isinstance(raw, list):
            raise _protocol("intents must be a list")
        out = []
        for i in raw:
            if not isinstance(i, dict):
                raise _protocol("intent entries must be objects")
            tags_v = i.get("tags", [])
            ints = [wire_int(i.get(k)) for k in ("ttl", "createdAt", "expiresAt")]
            opt = [i.get(k) for k in ("maxPrice", "currency")]
            if (
                not isinstance(i.get("intentId"), str) or not isinstance(i.get("from"), str)
                or not isinstance(i.get("need"), str) or not isinstance(tags_v, list)
                or not all(isinstance(t, str) for t in tags_v) or None in ints
                or not all(v is None or isinstance(v, str) for v in opt)
            ):
                raise _protocol("malformed intent entry")
            out.append(Intent(i["intentId"], i["from"], i["need"], tuple(tags_v), opt[0], opt[1], *ints))  # type: ignore[arg-type]
        return IntentPage(out, self._cursor(obj))

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

        Reconnects internally with backoff 1, 2, 4 ... 30 s (``Retry-After`` honored, capped
        at 30 s), resuming after the last yielded stream ID, and on ``event: drain``.
        Ten consecutive failed connects raise ``relay_unavailable``; a non-retryable status
        raises the mapped error (``relay_rejected`` etc.); a frame larger than
        ``MAX_ENVELOPE_BYTES + 512`` raises ``relay_protocol_error``. Setting ``stop`` (or
        closing the generator) ends the stream; a connection idle for ``idle_timeout``
        seconds is treated as dropped. ``on_open`` runs each time a connection is established
        (the first and every reconnect); an exception from it ends the stream as is.
        """
        resume = since or "-"
        RelayAuthRequest.listen(resume)  # validate
        failures = 0
        in_hook = False
        while stop is None or not stop.is_set():
            try:
                for entry in self._listen_once(identity, resume, stop, idle_timeout):
                    if entry is _CONNECTED:
                        if on_open is not None:
                            in_hook = True
                            on_open()
                            in_hook = False
                        continue
                    failures = 0
                    if entry is None:
                        continue  # connected / heartbeat-level progress
                    yield entry
                    resume = entry.stream_id
                    if stop is not None and stop.is_set():
                        return
                # clean end: drain or EOF -> reconnect immediately unless stopped
                failures = 0
                continue
            except ACEError as exc:
                if in_hook:
                    raise
                if stop is not None and stop.is_set():
                    return
                if exc.code != "relay_unavailable":
                    raise
                failures += 1
                if failures >= _MAX_CONNECT_FAILURES:
                    raise
                delay = min(2 ** (failures - 1), _MAX_BACKOFF_SECONDS)
                if exc.retry_after_seconds is not None:
                    delay = min(max(delay, exc.retry_after_seconds), _MAX_BACKOFF_SECONDS)
                if stop is not None:
                    if stop.wait(delay):
                        return
                else:
                    _sleep(delay)

    def _listen_once(
        self, identity: ACEIdentity, since: str, stop: threading.Event | None, idle_timeout: float,
    ) -> Iterator[RelayEntry | object | None]:
        conn = self._connection(max(self._timeout, idle_timeout))
        done = threading.Event()
        watcher = None
        resp: http.client.HTTPResponse | None = None
        try:
            for attempt in (0, 1):
                req = RelayAuthRequest.listen(since)
                headers = {**create_auth_headers(identity, req, self._next_ts()), "Accept": "text/event-stream"}
                try:
                    conn.request("GET", self._target("/v1/listen", {"since": since}), headers=headers)
                    sock = conn.sock  # getresponse() may detach it from the connection
                    resp = conn.getresponse()
                except (OSError, http.client.HTTPException) as exc:
                    raise ACEError("relay_unavailable", f"listen connect failed: {exc}") from None
                if resp.status == 200:
                    break
                data = resp.read(64 * 1024)
                err = _map_status(resp.status, data, _retry_after(resp.getheader("Retry-After")))
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
                        if stop.wait(0.05):
                            try:
                                if sock is not None:
                                    sock.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            return

                watcher = threading.Thread(target=watch, daemon=True)
                watcher.start()
            yield _CONNECTED
            yield from self._parse_sse(resp, stop)
        finally:
            done.set()
            # A response that will close owns the socket after getresponse(); closing only the
            # connection would leave it to the GC, so close the response explicitly as well.
            if resp is not None:
                resp.close()
            conn.close()

    @staticmethod
    def _parse_sse(resp: http.client.HTTPResponse, stop: threading.Event | None) -> Iterator[RelayEntry | None]:
        event_id: str | None = None
        event_type = ""
        data: list[bytes] = []
        size = 0
        while True:
            try:
                line = resp.readline(_SSE_FRAME_LIMIT + 2)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                if stop is not None and stop.is_set():
                    return
                raise ACEError("relay_unavailable", f"listen stream dropped: {exc}") from None
            if not line:
                if stop is not None and stop.is_set():
                    return
                raise ACEError("relay_unavailable", "listen stream closed by the relay")
            if not line.endswith(b"\n"):
                if len(line) > _SSE_FRAME_LIMIT:
                    raise _protocol("SSE frame exceeds the size limit")
                raise ACEError("relay_unavailable", "listen stream ended mid-line")
            if stop is not None and stop.is_set():
                return
            if line.startswith(b":"):
                continue  # heartbeat / comment
            size += len(line)
            if size > _SSE_FRAME_LIMIT + 2:
                raise _protocol("SSE frame exceeds the size limit")
            line = line.rstrip(b"\n").rstrip(b"\r")
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
            # dispatch
            if not data and event_id is None and not event_type:
                size = 0
                continue
            etype, eid, payload = event_type or "message", event_id, b"\n".join(data)
            event_id, event_type, data, size = None, "", [], 0
            if etype == "connected":
                yield None
                continue
            if etype == "drain":
                return
            if etype not in ("catchup", "message"):
                continue
            if eid is None or STREAM_ID_RE.fullmatch(eid) is None:
                raise _protocol("SSE event without a valid stream id")
            if len(payload) > MAX_ENVELOPE_BYTES:
                raise _protocol("SSE data exceeds MAX_ENVELOPE_BYTES")
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                raise _protocol("SSE data is not JSON") from None
            yield RelayEntry(eid, message, etype == "catchup")
