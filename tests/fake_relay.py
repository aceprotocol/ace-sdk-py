"""A minimal in-process relay implementing enough of 07-relay for client tests."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ace import (
    ACEError,
    canonical_state_bytes,
    decode_packet,
    encode_payload,
    extend_kel,
    is_usable,
    sha256_hex,
    signing_message,
    verify_card_bundle,
    verify_kel,
    verify_operational_signature,
    verify_permit,
    verify_published_agent,
    verify_signature,
)
from ace.kel import KelState


def _payload(action: str, query: dict, body) -> bytes:
    """The action payload of 02 § Signing actions for a request."""
    if action == "listen":
        return encode_payload(query.get("since", "-"))
    if action == "inbox":
        return encode_payload(query.get("since", "-"), query.get("limit", "100"))
    if action == "inbox-ack":
        return encode_payload(query["through"])
    if action == "block":
        word = "block" if body["blocked"] else "unblock"
        return encode_payload(body["peer"], word, str(body["revision"]))
    if action == "wake" and body is not None:
        return encode_payload(body["gateway"], body["token"])
    return b""


class FakeRelay:
    def __init__(self, clock=None) -> None:
        self.clock = clock or (lambda: int(time.time()))
        self.identities: dict[str, dict] = {}  # aceId -> {aceId, kel, registeredAt}
        self.descriptors: dict[str, dict] = {}  # aceId -> PublishedAgent
        self.cards: dict[str, dict] = {}  # aceId -> CardBundle
        self.handles: dict[str, str] = {}  # handle -> aceId (permanent, set once)
        self.states: dict[str, KelState] = {}  # aceId -> verified log state
        self.request_digests: dict[str, str] = {}
        self.streams: dict[str, list[tuple[str, dict]]] = {}
        self.blocks: dict[tuple[str, str], tuple[bool, int]] = {}  # (owner, peer) -> state
        self.wakes: dict[str, dict] = {}  # aceId -> {gateway, token}
        self.sent: list[dict] = []  # every accepted /v1/send body
        self.seen_auth: set[tuple[str, str]] = set()
        self.inject: list[tuple[str, int, str, dict]] = []  # (path, status, code, headers)
        self.drain_after: int | None = None
        self.requests: list[tuple[str, str]] = []
        self.queries: list[tuple[str, dict]] = []  # (path, query) per request
        self.auth_timestamps: list[int] = []
        self.raw_responses: dict[str, tuple[int, bytes, str] | list[tuple[int, bytes, str]]] = {}
        self._seq = 0
        self.cond = threading.Condition()
        self.stopping = False
        self.heartbeat = 0.2  # live-phase heartbeat interval, seconds
        self.open_listens = 0  # listen handlers still writing (a client disconnect ends one)
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: D401 - silence
                pass

            def do_GET(self):
                relay._dispatch(self, "GET")

            def do_POST(self):
                relay._dispatch(self, "POST")

            def do_PUT(self):
                relay._dispatch(self, "PUT")

            def do_DELETE(self):
                relay._dispatch(self, "DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        with self.cond:
            self.stopping = True
            self.cond.notify_all()
        self.server.shutdown()
        self.server.server_close()

    # --- helpers ---

    def _reply(self, h, status: int, obj=None, headers: dict | None = None) -> None:
        body = b"" if obj is None else json.dumps(obj).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.end_headers()
        h.wfile.write(body)

    def _error(self, h, status: int, code: str, headers=None) -> None:
        self._reply(h, status, {"error": code, "message": code}, headers)

    @staticmethod
    def _check_seq(seq: int, state: KelState) -> None:
        if seq < state.signing.seq:
            raise _HTTPError(401, "stale_seq")
        if seq > state.signing.seq:
            raise _HTTPError(409, "future_seq")

    def _auth(self, h, action: str, query: dict, body=None) -> str:
        """07 § Authentication, in order (a minimal reference for the client tests)."""
        hd = {k.lower(): v for k, v in h.headers.items()}
        ace_id, ts, seq = hd.get("x-ace-id"), hd.get("x-ace-timestamp"), hd.get("x-ace-seq")
        audience, nonce, sig = (
            hd.get("x-ace-audience"),
            hd.get("x-ace-nonce"),
            hd.get("x-ace-signature"),
        )
        if not all(isinstance(v, str) for v in (ace_id, ts, seq, audience, nonce, sig)):
            raise _HTTPError(400, "invalid_argument")
        if not ts.isdigit() or not seq.isdigit() or len(sig) != 4412:
            raise _HTTPError(400, "invalid_argument")
        ts_i, seq_i = int(ts), int(seq)
        self.auth_timestamps.append(ts_i)
        state = self.states.get(ace_id)
        if state is None or ace_id not in self.identities:
            raise _HTTPError(403, "not_registered")
        self._check_seq(seq_i, state)
        if audience != self.url:
            raise _HTTPError(401, "invalid_signature")
        now = self.clock()
        if abs(now - ts_i) > 300:
            raise _HTTPError(400, "stale_timestamp")
        na = state.signing.not_after
        if (na is not None and ts_i >= na) or not is_usable(state, now):
            raise _HTTPError(401, "stale_peer_binding")
        message = signing_message(
            ace_id, ts_i, seq_i, encode_payload(audience, nonce, _payload(action, query, body))
        )
        try:
            raw = base64.b64decode(sig, validate=True)
        except ValueError:
            raise _HTTPError(401, "invalid_signature") from None
        if not verify_signature(message, action, raw, state.signing.public_key):
            raise _HTTPError(401, "invalid_signature")
        key = (ace_id, nonce)
        if key in self.seen_auth:
            raise _HTTPError(409, "replay")
        self.seen_auth.add(key)
        return ace_id

    def _next_id(self) -> str:
        self._seq += 1
        return f"{1000 + self._seq}-0"

    def _after(self, ace_id: str, since: str) -> list[tuple[str, dict]]:
        def k(s):
            a, b = s.split("-")
            return (int(a), int(b))

        entries = self.streams.get(ace_id, [])
        if since == "-":
            return list(entries)
        return [e for e in entries if k(e[0]) > k(since)]

    def enqueue_raw(self, to: str, message: object) -> str:
        with self.cond:
            sid = self._next_id()
            self.streams.setdefault(to, []).append((sid, message))
            self.cond.notify_all()
            return sid

    # --- dispatch ---

    def _dispatch(self, h, method: str) -> None:
        parsed = urllib.parse.urlsplit(h.path)
        path = urllib.parse.unquote(parsed.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        self.requests.append((method, path))
        self.queries.append((path, query))
        for i, (p, status, code, headers) in enumerate(self.inject):
            if p == path:
                del self.inject[i]
                return self._error(h, status, code, headers)
        if path in self.raw_responses:
            raw_spec = self.raw_responses[path]
            if isinstance(raw_spec, list):  # a sequence: one per request, the last one repeats
                raw_spec = raw_spec.pop(0) if len(raw_spec) > 1 else raw_spec[0]
            status, body, ctype = raw_spec
            h.send_response(status)
            h.send_header("Content-Type", ctype)
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)
            return
        length = int(h.headers.get("Content-Length") or 0)
        raw = h.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else None
            if method == "GET" and path.startswith("/v1/descriptor/"):
                return self._get_v1_descriptor(h, path[len("/v1/descriptor/") :])
            if method == "GET" and path.startswith("/v1/card/"):
                return self._get_v1_card(h, path[len("/v1/card/") :])
            if method == "GET" and path.startswith("/v1/handles/"):
                return self._get_v1_handles(h, path[len("/v1/handles/") :])
            handler = getattr(self, f"_{method.lower()}_{path.strip('/').replace('/', '_')}", None)
            if handler is None:
                return self._error(h, 404, "not_found")
            return handler(h, query, body)
        except _HTTPError as exc:
            return self._error(h, exc.status, exc.code)
        except ACEError as exc:
            return self._error(h, 400, exc.code)

    def _verify_registration(self, body) -> tuple[dict, KelState, str]:
        """07 § Registration steps 1-5."""
        keys = {"aceId", "kel", "timestamp", "audience", "signature"}
        if not isinstance(body, dict) or set(body) != keys:
            raise _HTTPError(400, "invalid_registration")
        if body["audience"] != self.url:
            raise _HTTPError(401, "invalid_signature")
        now, ts = self.clock(), body["timestamp"]
        if abs(now - ts) > 300:
            raise _HTTPError(400, "stale_timestamp")
        state = verify_kel(body["kel"], now)
        if not is_usable(state, now):
            raise _HTTPError(400, "invalid_kel")
        if state.ace_id != body["aceId"]:
            raise _HTTPError(400, "invalid_registration")
        payload = encode_payload(state.last_hash, body["audience"])
        try:
            verify_operational_signature(
                state,
                body["signature"],
                payload,
                "register-request",
                ts,
                now,
                "invalid_authorization",
            )
        except ACEError as exc:
            raise _HTTPError(401, exc.code) from None
        digest = sha256_hex(signing_message(state.ace_id, ts, state.signing.seq, payload))
        return body, state, digest

    def _post_v1_register(self, h, query, body):
        """``registered`` / ``idempotent`` / ``refreshed`` / ``rotated``."""
        req, reg_state, reg_digest = self._verify_registration(body)
        prev, prev_state = self.identities.get(req["aceId"]), self.states.get(req["aceId"])
        if prev is None or prev_state is None:
            status, state = "registered", reg_state
        else:
            try:
                state, outcome = extend_kel(prev_state, req["kel"], self.clock())
            except ACEError as exc:
                raise _HTTPError(409, exc.code) from None  # kel_conflict
            if outcome == "unchanged" and len(prev_state.events) > len(req["kel"]):
                raise _HTTPError(401, "stale_seq")  # a strict prefix of the stored log
            if prev["registeredAt"] > req["timestamp"]:
                raise _HTTPError(409, "identity_conflict")
            if prev["registeredAt"] == req["timestamp"]:
                if self.request_digests.get(req["aceId"]) != reg_digest:
                    raise _HTTPError(409, "identity_conflict")  # same time, another request
                self._reply(h, 200, {"ok": True, "status": "idempotent"})
                return  # the identical request: nothing rewritten
            status = "rotated" if outcome != "unchanged" else "refreshed"
        record = {"aceId": req["aceId"], "kel": req["kel"], "registeredAt": req["timestamp"]}
        self.identities[req["aceId"]] = record
        self.states[req["aceId"]] = state
        self.request_digests[req["aceId"]] = reg_digest
        self._reply(h, 200, {"ok": True, "status": status})

    def _post_v1_unregister(self, h, query, body):
        ace_id = self._auth(h, "unregister", query)
        del self.identities[ace_id]
        self.descriptors.pop(ace_id, None)
        self.cards.pop(ace_id, None)  # the handle stays bound
        self.streams.pop(ace_id, None)
        self._reply(h, 200, {"ok": True})

    def _post_v1_descriptor(self, h, query, body):
        try:
            agent = verify_published_agent(body, now=self.clock(), allow_loopback_relays=True)
        except ACEError as exc:
            raise _HTTPError(401, "invalid_authorization") from exc
        state = self.states.get(agent.ace_id)
        if state is None:
            raise _HTTPError(403, "not_registered")
        if state.last_hash != agent.state.last_hash:
            raise _HTTPError(409, "kel_conflict")
        if self.url not in agent.relays:
            raise _HTTPError(400, "invalid_argument")
        old = self.descriptors.get(agent.ace_id)
        if old is not None and (
            old["descriptor"]["issuedAt"] > agent.issued_at
            or (old["descriptor"]["issuedAt"] == agent.issued_at and old != body)
        ):
            raise _HTTPError(409, "stale_descriptor")
        self.descriptors[agent.ace_id] = body
        self._reply(h, 200, {"ok": True})

    def _live(self, ace_id: str) -> dict | None:
        """The unexpired descriptor of a registered identity."""
        src = self.descriptors.get(ace_id)
        if src is None or ace_id not in self.identities:
            return None
        return src if src["descriptor"]["expiresAt"] > self.clock() else None

    def _card(self, ace_id: str | None) -> dict | None:
        """The stored card record of a registered identity; a record whose KEL is not the
        current registered KEL is absent (07 § Descriptors and cards)."""
        c = self.cards.get(ace_id) if ace_id is not None else None
        state = self.states.get(ace_id) if ace_id is not None else None
        if c is None or state is None or ace_id not in self.identities:
            return None
        last = verify_kel(c["kel"], self.clock()).last_hash
        return c if last == state.last_hash else None

    def _handle_of(self, ace_id: str) -> str | None:
        return next((h for h, owner in self.handles.items() if owner == ace_id), None)

    def _get_v1_descriptor(self, h, ace_id):
        src = self._live(urllib.parse.unquote(ace_id))
        if src is None:
            raise _HTTPError(404, "unknown_peer")
        self._reply(h, 200, src)

    def _post_v1_card(self, h, query, body):
        try:
            v = verify_card_bundle(body, self.clock(), allow_loopback_relays=True)
        except ACEError as exc:
            raise _HTTPError(401, "invalid_authorization") from exc
        state = self.states.get(v.ace_id)
        if state is None or v.ace_id not in self.identities:
            raise _HTTPError(403, "not_registered")
        if state.last_hash != v.state.last_hash:
            raise _HTTPError(409, "kel_conflict")
        old = self.cards.get(v.ace_id)
        if old is not None and (
            old["card"]["issuedAt"] > v.issued_at
            or (old["card"]["issuedAt"] == v.issued_at and old["card"] != body["card"])
        ):
            raise _HTTPError(409, "stale_descriptor")
        # Set once per identity at this home; a record naming another home claims nothing here.
        bound = self._handle_of(v.ace_id)
        if v.home == self.url:
            if bound is not None:
                if v.handle != bound:
                    raise _HTTPError(400, "invalid_argument")
            elif v.handle is not None:
                if v.handle in self.handles:
                    raise _HTTPError(409, "handle_taken")
                self.handles[v.handle] = v.ace_id
        self.cards[v.ace_id] = body
        self._reply(h, 200, {"ok": True})

    def _get_v1_card(self, h, ace_id):
        c = self._card(urllib.parse.unquote(ace_id))
        if c is None:
            raise _HTTPError(404, "unknown_peer")
        self._reply(h, 200, c)

    def _get_v1_handles(self, h, handle):
        c = self._card(self.handles.get(handle))
        if c is None or c["card"]["home"] != self.url:
            raise _HTTPError(404, "unknown_peer")
        self._reply(h, 200, c)

    def _get_v1_cards(self, h, query, body):
        cards = [
            (c, s)
            for a in sorted(self.descriptors)
            if (c := self._card(a)) is not None
            and c["card"]["listed"]
            and c["card"]["home"] == self.url
            and (s := self._live(a))
        ]
        if tag := query.get("tag"):
            cards = [(c, s) for c, s in cards if tag in c["card"]["card"].get("tags", [])]
        if profile := query.get("profile"):
            cards = [(c, s) for c, s in cards if any(p["id"] == profile for p in s["descriptor"]["profiles"])]
        page = [c for c, _ in cards[: int(query.get("limit", "100"))]]
        self._reply(h, 200, {"cards": page, "cursor": None})

    def _post_v1_blocks(self, h, query, body):
        ace_id = self._auth(h, "block", query, body)
        old = self.blocks.get((ace_id, body["peer"]))
        if old is not None and body["revision"] <= old[1]:
            raise _HTTPError(409, "stale_revision")
        self.blocks[(ace_id, body["peer"])] = (body["blocked"], body["revision"])
        self._reply(h, 200, {"ok": True})

    def _put_v1_wake(self, h, query, body):
        ace_id = self._auth(h, "wake", query, body)
        self.wakes[ace_id] = body
        self._reply(h, 200, {"ok": True})

    def _delete_v1_wake(self, h, query, body):
        ace_id = self._auth(h, "wake", query)
        self.wakes.pop(ace_id, None)
        self._reply(h, 200, {"ok": True})

    def _post_v1_send(self, h, query, body):
        if not isinstance(body, dict) or not set(body) <= {"packet", "permit"}:
            raise _HTTPError(400, "invalid_argument")
        try:
            p = decode_packet(body.get("packet"))
        except ACEError as exc:
            raise _HTTPError(400, exc.code) from None
        now = self.clock()
        if not now - 604800 <= p.timestamp <= now + 300:
            raise _HTTPError(400, "stale_timestamp")
        state = self.states.get(p.to_id)
        if state is None:
            raise _HTTPError(404, "unknown_peer")
        raw = canonical_state_bytes(body["packet"])
        with self.cond:
            if any(canonical_state_bytes(m) == raw for _, m in self.streams.get(p.to_id, [])):
                return self._reply(h, 200, {"ok": True})
        if self.blocks.get((p.to_id, p.from_id), (False, 0))[0]:
            raise _HTTPError(403, "not_permitted")
        if "permit" in body:
            try:
                verify_permit(body["permit"], state, p.from_id, now=now)
            except ACEError:
                raise _HTTPError(403, "not_permitted") from None
        else:
            c = self._card(p.to_id)
            if c is None or c["card"]["contact"] != "open" or self._live(p.to_id) is None:
                raise _HTTPError(403, "not_permitted")
        self.sent.append(body)
        self.enqueue_raw(p.to_id, body["packet"])
        self._reply(h, 200, {"ok": True})

    def _get_v1_inbox(self, h, query, body):
        since = query.get("since", "-")
        limit = int(query.get("limit", "100"))
        ace_id = self._auth(h, "inbox", query)
        with self.cond:
            entries = self._after(ace_id, since)[:limit]
        self._reply(
            h,
            200,
            {
                "messages": [{"streamId": s, "packet": m} for s, m in entries],
                "cursor": entries[-1][0] if entries else None,
            },
        )

    def _post_v1_inbox_ack(self, h, query, body):
        through = query["through"]
        ace_id = self._auth(h, "inbox-ack", query)
        with self.cond:
            keep = self._after(ace_id, through)
            self.streams[ace_id] = keep
        self._reply(h, 200, {"ok": True})

    def _get_v1_listen(self, h, query, body):
        since = query.get("since", "-")
        ace_id = self._auth(h, "listen", query)
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.end_headers()

        def frame(text: str) -> None:
            h.wfile.write(text.encode())
            h.wfile.flush()

        frame("event: connected\ndata: {}\n\n: heartbeat\n\n")
        with self.cond:
            self.open_listens += 1
        try:
            self._listen_loop(h, ace_id, since, frame)
        finally:
            with self.cond:
                self.open_listens -= 1

    def _listen_loop(self, h, ace_id, since, frame):
        sent = 0
        last = since
        catchup = True
        while True:
            with self.cond:
                entries = self._after(ace_id, last)
                while not entries and not self.stopping:
                    if not self.cond.wait(self.heartbeat):
                        break
                    entries = self._after(ace_id, last)
                if self.stopping:
                    return
            if not entries:
                try:
                    frame(": hb\n\n")
                except OSError:
                    return
                catchup = False
                continue
            for sid, msg in entries:
                if self.drain_after is not None and sent >= self.drain_after:
                    self.drain_after = None
                    frame("event: drain\ndata: {}\n\n")
                    return
                try:
                    frame(
                        f"id: {sid}\nevent: {'catchup' if catchup else 'message'}\n"
                        f"data: {json.dumps({'packet': msg})}\n\n"
                    )
                except OSError:
                    return
                sent += 1
                last = sid
            catchup = False


class _HTTPError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code
