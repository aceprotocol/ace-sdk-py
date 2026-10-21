"""Relay HTTP client (07): registration, descriptors, card records and handles, directory, blocks,
send, inbox / ack, SSE listen and wake hints.

Every connection resolves the relay host once, refuses non-public addresses (loopback only with
``allow_loopback=True``, for local development) and connects to the vetted IP; plain HTTP is
accepted only for loopback. Each request has a total deadline of ``timeout`` seconds.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import threading
import time
import urllib.parse
from typing import Any, Callable, Iterator, NamedTuple, TypeVar

from . import _net
from ._encoding import (
    check_json_value,
    is_ace_id,
    is_handle,
    is_stream_id,
    loads_json,
    sha256_hex,
    unix_now,
    wire_int,
)
from ._relay_url import is_canonical_relay_url, normalize_relay_url
from ._signing import encode_payload
from .auth import create_auth_headers
from .card_record import VerifiedCard, verify_card_bundle
from .descriptor import VerifiedAgent, verify_published_agent
from .errors import ACEError, ACEErrorCode
from .identity import ACEIdentity
from .limits import (
    DEFAULT_PAGE_LIMIT,
    MAX_INBOX_PAGE,
    MAX_JSON_DEPTH,
    MAX_PACKET_BYTES,
    MAX_PAGE_BYTES,
)
from .registration import create_registration_request
from .store import load_record, write_record

_SSE_FRAME_LIMIT = MAX_PACKET_BYTES + 4096
#: A response or SSE data as a whole: its deepest wrapper, an inbox page, holds packets at
#: depth 3 (02 § JSON values).
_RESPONSE_DEPTH = MAX_JSON_DEPTH + 3
_MAX_CONNECT_FAILURES = 10
_MAX_BACKOFF_SECONDS = 30
_REGISTER_STATUSES = ("registered", "idempotent", "refreshed", "rotated")
_RETRY_AFTER_RE = re.compile(r"[0-9]+")
_RETRY_AFTER_MAX = 9_999_999_999  # ten digits; every use caps the delay far below
_CONTROLS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_EOL_RE = re.compile(rb"[\r\n]")
_WAKE_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{22,512}")

_sleep = time.sleep  # patched by tests

_Doc = TypeVar("_Doc", VerifiedAgent, VerifiedCard)


class RelayEntry(NamedTuple):
    """One queued packet, as raw JSON bytes (the Inbox parses it)."""

    stream_id: str
    packet: bytes
    catchup: bool = False


class InboxPage(NamedTuple):
    entries: list[RelayEntry]
    cursor: str | None


def _protocol(msg: str) -> ACEError:
    return ACEError("relay_protocol_error", msg)


def _loads(raw: bytes, what: str) -> object:
    """Received JSON within ``MAX_JSON_DEPTH + 3`` (02 § JSON values), else
    ``relay_protocol_error``."""
    try:
        value = loads_json(raw)
    except ValueError:
        raise _protocol(f"{what} is not JSON") from None
    check_json_value(value, "relay_protocol_error", _RESPONSE_DEPTH)
    return value


def _contained(value: object) -> object:
    """A packet, PublishedAgent or CardBundle inside a response is within ``MAX_JSON_DEPTH`` on
    its own; otherwise the whole response is ``relay_protocol_error``, never a skipped entry."""
    check_json_value(value, "relay_protocol_error")
    return value


def _raw_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8", "surrogatepass"
    )


def _retry_after(value: str | None) -> int | None:
    """Delay-seconds (07 § Client rules); more than ten significant digits clamp to
    ``_RETRY_AFTER_MAX`` (never an unbounded integer parse)."""
    if value is None or _RETRY_AFTER_RE.fullmatch(value) is None:
        return None
    digits = value.lstrip("0") or "0"
    return int(digits) if len(digits) <= 10 else _RETRY_AFTER_MAX


def map_relay_response(status: int, body: bytes, retry_after: str | None) -> ACEError:
    """Map a non-success relay response to an ``ACEError`` (keeps ``status``/``relay_code``)."""
    relay_code = message = None
    try:
        obj = _loads(body, "error body") if body else None
        # relay text enters our error (and the host's logs) without control characters
        if isinstance(obj, dict) and isinstance(obj.get("error"), str):
            relay_code = _CONTROLS_RE.sub("", obj["error"])[:64]
            if isinstance(obj.get("message"), str):
                message = _CONTROLS_RE.sub("", obj["message"])[:500]
    except ACEError:
        pass
    text = (
        f"relay HTTP {status}"
        + (f" {relay_code}" if relay_code else "")
        + (f": {message}" if message else "")
    )
    code: ACEErrorCode
    if status < 400 or status >= 600:
        code = "relay_protocol_error"
    elif status in (408, 429) or status >= 500:
        code = "relay_unavailable"  # any 429 is transient (07 § Client rules)
    else:
        code = {
            (403, "not_registered"): "not_registered",
            (403, "not_permitted"): "not_permitted",
            (404, "unknown_peer"): "unknown_peer",
        }.get((status, relay_code or ""), "relay_rejected")  # type: ignore[assignment]
    err = ACEError(code, text, status=status, relay_code=relay_code)
    if err.category == "transient":
        err.retry_after_seconds = _retry_after(retry_after)
    return err


_CONNECTED = object()


def _check_since(since: object) -> None:
    if since != "-" and not is_stream_id(since):
        raise ACEError("invalid_argument", "since must be '-' or '<ms>-<seq>'")


class RelayClient:
    """Synchronous client for one relay. Authenticated calls sign ``X-ACE-*`` headers and retry
    once on ``409 replay``. Redirects are never followed. Network failures and timeouts are
    ``relay_unavailable``; oversized or malformed responses ``relay_protocol_error``."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        allow_loopback: bool = False,
        max_response_bytes: int = MAX_PAGE_BYTES,
        clock: Callable[[], int] | None = None,
        store: Any = None,
    ) -> None:
        """``store`` (an ``ACEStore``): persist the last registration/unregister timestamp per
        (relay, identity) under the lock ``relay-registration`` so several processes sharing an
        identity keep it strictly increasing (07 § Registration); otherwise per instance."""
        self.base_url = normalize_relay_url(base_url)
        self._store = store
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
            raise ACEError("invalid_argument", "timeout must be positive")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ACEError("invalid_argument", "max_response_bytes must be a positive integer")
        parts = urllib.parse.urlsplit(self.base_url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or ""
        self._port = parts.port or (443 if self._https else 80)
        self._prefix = parts.path
        #: Explicit local development: loopback relay addresses and loopback HTTP relay URLs.
        self.allow_loopback = bool(allow_loopback)
        self._timeout = float(timeout)
        self._max_bytes = max_response_bytes
        self._clock = clock
        self._ts_lock = threading.Lock()
        self._last_registration_ts = -1

    # --- plumbing ---

    def _next_registration_ts(self, identity: ACEIdentity, floor: int) -> int:
        with self._ts_lock:
            if self._store is None:
                self._last_registration_ts = max(floor, self._last_registration_ts + 1)
                return self._last_registration_ts
            key = "relay/registration/" + sha256_hex(self.base_url, identity.get_ace_id()) + ".json"
            with self._store.lock("relay-registration"):
                rec = load_record(self._store, key)
                stored = -1 if rec is None else wire_int(rec.get("timestamp"))
                if stored is None:
                    raise ACEError("storage_failed", f"{key} is invalid")
                ts = max(floor, stored + 1, self._last_registration_ts + 1)
                write_record(self._store, key, {"timestamp": ts})
            self._last_registration_ts = ts
            return ts

    def _now(self) -> int:
        return unix_now(self._clock)

    def _connection(self, timeout: float, *, deadline: bool = True) -> http.client.HTTPConnection:
        ip = _net.resolve(self._host, self._port, allow_loopback=self.allow_loopback)
        if self._https:
            return _net.PinnedHTTPSConnection(self._host, ip, self._port, timeout, deadline)
        if not _net.is_loopback_address(ip):
            raise ACEError("blocked_address", "plain HTTP is allowed only for loopback relays")
        return _net.PinnedHTTPConnection(self._host, ip, self._port, timeout)

    def _target(self, path: str, query: dict[str, Any] | None) -> str:
        target = self._prefix + path
        q = {k: v for k, v in (query or {}).items() if v is not None}
        return target + ("?" + urllib.parse.urlencode(q) if q else "")

    def _send_once(
        self, method: str, path: str, query: dict | None, body: bytes | None, headers: dict
    ) -> tuple[int, bytes, str | None]:
        conn = self._connection(self._timeout)
        try:
            hdrs = {"Accept": "application/json", **headers}
            if body is not None:
                hdrs["Content-Type"] = "application/json"
            conn.request(method, self._target(path, query), body=body, headers=hdrs)
            resp = conn.getresponse()
            return resp.status, resp.read(self._max_bytes + 1), resp.getheader("Retry-After")
        except (OSError, http.client.HTTPException, ValueError, UnicodeError) as exc:
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
        auth: tuple[str, bytes] | None = None,
        expect: tuple[int, ...] = (200,),
    ) -> Any:
        """``auth``: ``(action, actionPayload)`` signed into ``X-ACE-*`` headers per attempt."""
        payload = (
            None
            if body is None
            else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        )
        for attempt in (0, 1):
            headers: dict[str, str] = {}
            if auth is not None:
                ts = self._now()
                if auth[0] == "unregister":
                    ts = self._next_registration_ts(identity, ts)  # type: ignore[arg-type]
                headers = create_auth_headers(identity, *auth, ts, audience=self.base_url)  # type: ignore[arg-type]
            status, data, retry_after = self._send_once(method, path, query, payload, headers)
            if len(data) > self._max_bytes:
                raise _protocol("response exceeds max_response_bytes")
            if status in expect:
                return _loads(data, "response")
            if 200 <= status < 300:
                raise _protocol(f"unexpected relay HTTP {status}")
            err = map_relay_response(status, data, retry_after)
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

    def _verified(
        self, value: object, verify: Callable[..., _Doc], what: str, ace_id: str | None
    ) -> _Doc:
        """A relay response verified by ``verify``, of identity ``ace_id`` when given. Any failure
        is ``relay_protocol_error``: a conformant relay refused the document on input, so serving
        it is the relay's fault, never a verdict on the peer (a permanent code would let one bad
        route end a lookup the next route serves)."""
        _contained(value)  # never a skipped entry
        try:
            doc = verify(value, now=self._now(), allow_loopback_relays=self.allow_loopback)
        except Exception as exc:
            detail = f": {exc.message}" if isinstance(exc, ACEError) else ""
            raise _protocol(f"relay served an invalid {what}{detail}") from exc
        if ace_id is not None and doc.ace_id != ace_id:
            raise _protocol(f"{what} identity mismatch")
        return doc

    def _agent(self, value: object, ace_id: str | None = None) -> VerifiedAgent:
        return self._verified(value, verify_published_agent, "descriptor", ace_id)

    # --- identity ---

    def register(self, identity: ACEIdentity) -> str:
        """``POST /v1/register``: ``registered | idempotent | refreshed | rotated``."""
        ts = self._next_registration_ts(identity, self._now())
        obj = self._object(
            self._call(
                "POST",
                "/v1/register",
                body=create_registration_request(identity, ts, audience=self.base_url),
            ),
            "register",
        )
        if obj.get("status") not in _REGISTER_STATUSES:
            raise _protocol("unexpected register status")
        return obj["status"]

    def unregister(self, identity: ACEIdentity) -> None:
        self._call("POST", "/v1/unregister", identity=identity, auth=("unregister", b""))

    # --- descriptors and directory ---

    def publish(self, source: dict) -> None:
        """``POST /v1/descriptor``: publish our own PublishedAgent."""
        self._agent(source)
        self._call("POST", "/v1/descriptor", body=source)

    def descriptor(self, ace_id: str) -> VerifiedAgent:
        """``GET /v1/descriptor/{aceId}``: anonymous; the unexpired descriptor of any registered
        identity."""
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "invalid ACE ID")
        return self._agent(
            self._call("GET", "/v1/descriptor/" + urllib.parse.quote(ace_id, safe="")), ace_id
        )

    # --- card records and handles ---

    def publish_card(self, bundle: dict) -> None:
        """``POST /v1/card``: publish our own CardBundle (its KEL must equal the registered KEL;
        the handle is set once per home, 07 § Descriptors and cards)."""
        verify_card_bundle(bundle, self._now(), allow_loopback_relays=self.allow_loopback)
        self._call("POST", "/v1/card", body=bundle)

    def _card(self, value: object, ace_id: str | None = None) -> VerifiedCard:
        return self._verified(value, verify_card_bundle, "card record", ace_id)

    def card(self, ace_id: str) -> VerifiedCard:
        """``GET /v1/card/{aceId}``: anonymous; the stored card record of a registered identity."""
        if not is_ace_id(ace_id):
            raise ACEError("invalid_argument", "invalid ACE ID")
        return self._card(
            self._call("GET", "/v1/card/" + urllib.parse.quote(ace_id, safe="")), ace_id
        )

    def handle(self, handle: str) -> VerifiedCard:
        """``GET /v1/handles/{handle}``: the card record of the identity the handle is bound to at
        this relay. A record whose ``home`` is not this relay or whose ``handle`` differs is
        ``unknown_peer`` (04 § Card record)."""
        if not is_handle(handle):
            raise ACEError("invalid_argument", "invalid handle")
        card = self._card(self._call("GET", "/v1/handles/" + handle))
        if card.home != self.base_url or card.handle != handle:
            raise ACEError("unknown_peer", "the record does not hold this handle at this relay")
        return card

    def directory(
        self,
        *,
        profile: str | None = None,
        cursor: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> tuple[list[VerifiedAgent], str | None]:
        """``GET /v1/descriptors``: the public directory (identities whose card record is
        listed). Each entry is verified on its own: one that fails verification permanently or
        does not list ``profile`` is skipped; the rest of the page is kept."""
        if type(limit) is not int or not 1 <= limit <= MAX_INBOX_PAGE:
            raise ACEError("invalid_argument", f"limit must be 1..{MAX_INBOX_PAGE}")
        page = self._object(
            self._call(
                "GET",
                "/v1/descriptors",
                query={"profile": profile, "cursor": cursor, "limit": limit},
            ),
            "descriptors",
        )
        agents = page.get("agents")
        if not isinstance(agents, list) or len(agents) > limit:
            raise _protocol("invalid descriptor page")
        out = []
        for value in agents:
            _contained(value)
            try:
                a = verify_published_agent(
                    value, now=self._now(), allow_loopback_relays=self.allow_loopback
                )
            except ACEError as exc:
                if exc.is_transient:
                    raise
                continue
            # listing the exact profile ID when one was requested
            if profile is None or any(p["id"] == profile for p in a.profiles):
                out.append(a)
        return out, self._cursor(page)

    # --- admission ---

    def set_block(self, identity: ACEIdentity, peer: str, blocked: bool, revision: int) -> None:
        """``POST /v1/blocks``: a signed block or unblock (``revision`` strictly increasing)."""
        if not is_ace_id(peer) or type(blocked) is not bool or wire_int(revision) is None:
            raise ACEError("invalid_argument", "block needs peer, blocked and revision")
        payload = encode_payload(peer, "block" if blocked else "unblock", str(revision))
        self._call(
            "POST",
            "/v1/blocks",
            body={"peer": peer, "blocked": blocked, "revision": revision},
            identity=identity,
            auth=("block", payload),
        )

    # --- wake hints ---

    def set_wake(self, identity: ACEIdentity, gateway: str, token: str) -> None:
        """``PUT /v1/wake``: register (or replace) the gateway this relay wakes when entries are
        queued for ``identity`` (07 § Wake hints). ``token`` is the gateway's opaque token. A relay
        without wake hints answers ``relay_rejected`` with relay code ``not_found``."""
        if (
            not isinstance(gateway, str)
            or not is_canonical_relay_url(gateway, allow_loopback=self.allow_loopback)
            or not isinstance(token, str)
            or _WAKE_TOKEN_RE.fullmatch(token) is None
        ):
            raise ACEError("invalid_argument", "wake needs a canonical https gateway and a token")
        self._call(
            "PUT",
            "/v1/wake",
            body={"gateway": gateway, "token": token},
            identity=identity,
            auth=("wake", encode_payload(gateway, token)),
        )

    def clear_wake(self, identity: ACEIdentity) -> None:
        """``DELETE /v1/wake``: remove the wake registration (idempotent)."""
        self._call("DELETE", "/v1/wake", identity=identity, auth=("wake", b""))

    # --- packets ---

    def send(self, packet: dict, permit: dict | None = None) -> None:
        """``POST /v1/send {packet, permit?}``. ``{ok: true}`` is not delivery: wait for the
        receipt."""
        body: dict[str, Any] = {"packet": packet}
        if permit is not None:
            # A permit is a bearer credential: only ever attach it to the packet it authorizes.
            if (
                not isinstance(packet, dict)
                or not isinstance(permit, dict)
                or permit.get("issuer") != packet.get("to")
                or permit.get("subject") != packet.get("from")
            ):
                raise ACEError(
                    "invalid_argument", "permit must be issued by packet.to to packet.from"
                )
            body["permit"] = permit
        obj = self._object(self._call("POST", "/v1/send", body=body), "send")
        if obj.get("ok") is not True:
            raise _protocol("send response must be {ok: true}")

    def inbox(
        self, identity: ACEIdentity, *, since: str = "-", limit: int = MAX_INBOX_PAGE
    ) -> InboxPage:
        """``GET /v1/inbox``: non-destructive read of ``{messages, cursor}``."""
        _check_since(since)
        if type(limit) is not int or not 1 <= limit <= MAX_INBOX_PAGE:
            raise ACEError("invalid_argument", f"limit must be 1..{MAX_INBOX_PAGE}")
        query = {"since": None if since == "-" else since, "limit": limit}
        auth = ("inbox", encode_payload(since, str(limit)))
        obj = self._object(
            self._call("GET", "/v1/inbox", query=query, identity=identity, auth=auth), "inbox"
        )
        messages = obj.get("messages")
        if not isinstance(messages, list) or len(messages) > limit:
            raise _protocol("messages must be a list of at most limit entries")
        entries = []
        for m in messages:
            if not isinstance(m, dict) or not is_stream_id(m.get("streamId")) or "packet" not in m:
                raise _protocol("inbox entries must be {streamId, packet}")
            entries.append(RelayEntry(m["streamId"], _raw_json(_contained(m["packet"]))))
        return InboxPage(entries, self._cursor(obj))

    def ack(self, identity: ACEIdentity, through: str) -> None:
        """``POST /v1/inbox/ack?through=``: delete the queued packets up to ``through``."""
        if not is_stream_id(through):
            raise ACEError("invalid_argument", "through must be a stream ID")
        auth = ("inbox-ack", encode_payload(through))
        self._call(
            "POST", "/v1/inbox/ack", query={"through": through}, identity=identity, auth=auth
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
        """``GET /v1/listen`` as a generator of ``RelayEntry`` (catchup, then live). Reconnects
        after the last yielded stream ID (immediately after progress, else with backoff
        1, 2, 4 ... 30 s); ten consecutive failures raise ``relay_unavailable``. Setting
        ``stop`` ends the stream."""
        resume = since or "-"
        _check_since(resume)
        failures = 0
        stopped = (lambda: False) if stop is None else stop.is_set
        while not stopped():
            stream = self._listen_once(identity, resume, stop, idle_timeout)
            got_event = False
            try:
                while True:
                    failure: ACEError | None = None
                    try:
                        entry = next(stream)
                    except StopIteration:
                        if got_event:
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
                    if stopped():
                        return
                    if entry is _CONNECTED:
                        if on_open is not None:
                            on_open()
                        continue
                    failures, got_event = 0, True
                    if entry is None:
                        continue
                    yield entry  # type: ignore[misc]
                    resume = entry.stream_id  # type: ignore[union-attr]
            finally:
                stream.close()

    def _listen_once(
        self, identity: ACEIdentity, since: str, stop: threading.Event | None, idle_timeout: float
    ) -> Iterator[RelayEntry | object | None]:
        done = threading.Event()
        resp: http.client.HTTPResponse | None = None
        conn: http.client.HTTPConnection | None = None
        try:
            for attempt in (0, 1):
                conn = self._connection(max(self._timeout, idle_timeout), deadline=False)
                headers = {
                    **create_auth_headers(
                        identity,
                        "listen",
                        encode_payload(since),
                        self._now(),
                        audience=self.base_url,
                    ),
                    "Accept": "text/event-stream",
                }
                try:
                    conn.request(
                        "GET", self._target("/v1/listen", {"since": since}), headers=headers
                    )
                    sock = conn.sock
                    resp = conn.getresponse()
                except (OSError, http.client.HTTPException, ValueError, UnicodeError) as exc:
                    raise ACEError("relay_unavailable", f"listen connect failed: {exc}") from None
                if resp.status == 200:
                    break
                data = resp.read(64 * 1024)
                if 200 <= resp.status < 300:
                    raise _protocol(f"unexpected listen HTTP {resp.status}")
                err = map_relay_response(resp.status, data, resp.getheader("Retry-After"))
                if attempt == 0 and resp.status == 409 and err.relay_code == "replay":
                    conn.close()
                    continue
                raise err
            assert resp is not None
            media = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if media != "text/event-stream":
                raise _protocol("listen response is not text/event-stream")
            if stop is not None:

                def watch() -> None:
                    while not done.is_set():
                        if stop.wait(0.5):
                            try:
                                if sock is not None:
                                    sock.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            return

                threading.Thread(target=watch, daemon=True).start()
            yield _CONNECTED
            yield from self._parse_sse(resp)
        finally:
            done.set()
            if resp is not None:
                resp.close()
            if conn is not None:
                conn.close()

    @staticmethod
    def _parse_sse(resp: http.client.HTTPResponse) -> Iterator[RelayEntry | None]:
        """One entry per ``catchup`` / ``message`` event, ``None`` for ``drain`` (then return)."""
        reader = _SSELines(resp)
        event_id: str | None = None
        event_type = ""
        data: list[bytes] = []
        size = 0
        while True:
            line = reader.next_line()
            if line is None:
                return
            if line.startswith(b":"):
                continue
            size += len(line) + 1
            if size > _SSE_FRAME_LIMIT + 2:
                raise _protocol("SSE frame exceeds the size limit")
            if line:
                name, _, value = line.partition(b":")
                if value.startswith(b" "):
                    value = value[1:]
                if name == b"id":
                    event_id = value.decode("utf-8", "replace")
                elif name == b"event":
                    event_type = value.decode("utf-8", "replace")
                elif name == b"data":
                    data.append(value)
                continue
            if not data:
                event_id, event_type, size = None, "", 0
                continue
            etype, eid, payload = event_type or "message", event_id, b"\n".join(data)
            event_id, event_type, data, size = None, "", [], 0
            if etype == "drain":
                yield None
                return
            if etype not in ("catchup", "message"):
                continue
            if not is_stream_id(eid):
                raise _protocol("SSE event without a valid stream id")
            frame = _loads(payload, "SSE data")
            if not isinstance(frame, dict) or "packet" not in frame:
                raise _protocol('SSE data must be {"packet": ...}')
            packet = _raw_json(_contained(frame["packet"]))
            yield RelayEntry(eid, packet, etype == "catchup")  # type: ignore[arg-type]


class _SSELines:
    """Split an SSE byte stream into lines ending in CR, LF or CRLF. Linear in the stream: each
    byte is scanned once (``_scan``) and consumed lines are dropped only before the next read."""

    def __init__(self, resp: http.client.HTTPResponse) -> None:
        self._resp = resp
        self._buf = bytearray()
        self._pos = 0  # start of the current line
        self._scan = 0  # bytes before this hold no line ending of the current line
        self._skip_lf = False

    def _fill(self) -> bool:
        try:
            chunk = self._resp.read1(8192)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise ACEError("relay_unavailable", f"listen stream dropped: {exc}") from None
        if not chunk:
            return False
        del self._buf[: self._pos]
        self._scan -= self._pos
        self._pos = 0
        self._buf += chunk
        return True

    def next_line(self) -> bytes | None:
        while True:
            if self._skip_lf and self._pos < len(self._buf):
                if self._buf[self._pos] == 0x0A:
                    self._pos = self._scan = self._pos + 1
                self._skip_lf = False
            m = _EOL_RE.search(self._buf, self._scan)
            if m is not None:
                i = m.start()
                line = bytes(self._buf[self._pos : i])
                self._skip_lf = self._buf[i] == 0x0D
                self._pos = self._scan = i + 1
                if len(line) > _SSE_FRAME_LIMIT:
                    raise _protocol("SSE frame exceeds the size limit")
                return line
            self._scan = len(self._buf)
            if self._scan - self._pos > _SSE_FRAME_LIMIT:
                raise _protocol("SSE frame exceeds the size limit")
            if not self._fill():
                if self._pos < len(self._buf):
                    raise ACEError("relay_unavailable", "listen stream ended mid-line")
                return None
