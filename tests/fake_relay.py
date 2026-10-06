"""A minimal in-process relay implementing enough of 08-relay.md for client tests."""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ace import (
    ACEError,
    RelayAuthRequest,
    decode_envelope,
    envelope_fingerprint,
    parse_auth_headers,
    verify_auth_headers,
    verify_envelope_signature,
    verify_registration_request,
)
from ace._encoding import wire_int


class FakeRelay:
    def __init__(self, clock=None) -> None:
        self.clock = clock or (lambda: int(time.time()))
        self.identities: dict[str, dict] = {}   # aceId -> PeerRecord
        self.streams: dict[str, list[tuple[str, dict]]] = {}
        self.stored: dict[tuple[str, str], str] = {}  # (from, messageId) -> fingerprint
        self.seen_auth: set[tuple[str, str, str]] = set()
        self.intents: list[dict] = []
        self.extra_agents: list[dict] = []
        self.inject: list[tuple[str, int, str, dict]] = []  # (path, status, code, headers)
        self.drain_after: int | None = None
        self.requests: list[tuple[str, str]] = []
        self.auth_timestamps: list[int] = []
        self.raw_responses: dict[str, tuple[int, bytes, str]] = {}
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

    def _auth(self, h, req: RelayAuthRequest) -> str:
        auth = parse_auth_headers(dict(h.headers.items()))
        self.auth_timestamps.append(auth.timestamp)
        ident = self.identities.get(auth.ace_id)
        if ident is None:
            raise _HTTPError(403, "not_registered")
        from ace import from_base64
        try:
            verify_auth_headers(auth, req, ace_id=auth.ace_id, scheme=ident["scheme"],
                                signing_public_key=from_base64(ident["signingPublicKey"]), clock=self.clock)
        except ACEError as exc:
            raise _HTTPError(401 if exc.code == "invalid_signature" else 400, exc.code) from None
        key = (req.action, auth.ace_id, auth.signature)
        if key in self.seen_auth:
            raise _HTTPError(409, "replay")
        self.seen_auth.add(key)
        return auth.ace_id

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
        path = parsed.path
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        self.requests.append((method, path))
        for i, (p, status, code, headers) in enumerate(self.inject):
            if p == path:
                del self.inject[i]
                return self._error(h, status, code, headers)
        if path in self.raw_responses:
            status, body, ctype = self.raw_responses[path]
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
            handler = getattr(self, f"_{method.lower()}_{path.strip('/').replace('/', '_')}", None)
            if handler is None:
                return self._error(h, 404, "not_found")
            return handler(h, query, body)
        except _HTTPError as exc:
            return self._error(h, exc.status, exc.code)
        except ACEError as exc:
            return self._error(h, 400, exc.code)

    def _post_v1_register(self, h, query, body):
        reg = verify_registration_request(body, clock=self.clock)
        req = reg.request
        prev = self.identities.get(req["aceId"])
        record = {
            "aceId": req["aceId"], "scheme": req["scheme"], "encryptionPublicKey": req["encryptionPublicKey"],
            "signingPublicKey": req["signingPublicKey"], "registrationSignature": req["signature"],
            "registeredAt": req["timestamp"],
        }
        profile = req.get("profile", prev.get("profile") if prev else None)
        if profile is not None:
            record["profile"] = profile
        if prev is None:
            status = "registered"
        elif prev["registeredAt"] > req["timestamp"]:
            raise _HTTPError(409, "identity_conflict")
        elif prev["registeredAt"] == req["timestamp"]:
            status = "idempotent"
        elif prev["encryptionPublicKey"] == req["encryptionPublicKey"]:
            status = "refreshed"
        else:
            status = "rotated"
        self.identities[req["aceId"]] = record
        self._reply(h, 200, {"ok": True, "status": status})

    def _post_v1_unregister(self, h, query, body):
        ace_id = self._auth(h, RelayAuthRequest.unregister())
        del self.identities[ace_id]
        self._reply(h, 200, {"ok": True})

    def _get_v1_peer(self, h, query, body):
        rec = self.identities.get(query.get("aceId", ""))
        if rec is None:
            raise _HTTPError(404, "unknown_peer")
        self._reply(h, 200, rec)

    def _get_v1_discover(self, h, query, body):
        agents = [r for r in self.identities.values()
                  if not query.get("q") or query["q"].lower() in json.dumps(r.get("profile", {})).lower()]
        self._reply(h, 200, {"agents": agents + self.extra_agents, "cursor": None})

    def _post_v1_send(self, h, query, body):
        if not isinstance(body, dict) or not isinstance(body.get("message"), dict):
            raise _HTTPError(400, "invalid_envelope")
        try:
            env = decode_envelope(body["message"])
        except ACEError:
            raise _HTTPError(400, "invalid_envelope") from None
        sender = self.identities.get(env.from_id)
        if sender is None:
            raise _HTTPError(403, "not_registered")
        if env.to_id not in self.identities:
            raise _HTTPError(404, "unknown_peer")
        from ace import from_base64
        try:
            verify_envelope_signature(env, scheme=sender["scheme"], signing_public_key=from_base64(sender["signingPublicKey"]))
        except ACEError:
            raise _HTTPError(401, "invalid_signature") from None
        fp = envelope_fingerprint(env)
        prev = self.stored.get((env.from_id, env.message_id))
        if prev is not None:
            if prev == fp:
                return self._reply(h, 200, {"ok": True})
            raise _HTTPError(409, "message_id_conflict")
        if abs(self.clock() - env.timestamp) > 300:
            raise _HTTPError(400, "envelope_expired")
        self.stored[(env.from_id, env.message_id)] = fp
        self.enqueue_raw(env.to_id, body["message"])
        self._reply(h, 200, {"ok": True})

    def _get_v1_inbox(self, h, query, body):
        since = query.get("since", "-")
        limit = int(query.get("limit", "100"))
        ace_id = self._auth(h, RelayAuthRequest.inbox(since, limit))
        with self.cond:
            entries = self._after(ace_id, since)[:limit]
        self._reply(h, 200, {"messages": [{"streamId": s, "message": m} for s, m in entries],
                             "cursor": entries[-1][0] if entries else None})

    def _get_v1_listen(self, h, query, body):
        since = query.get("since", "-")
        ace_id = self._auth(h, RelayAuthRequest.listen(since))
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
                    frame(f"id: {sid}\nevent: {'catchup' if catchup else 'message'}\ndata: {json.dumps(msg)}\n\n")
                except OSError:
                    return
                sent += 1
                last = sid
            catchup = False

    def _post_v1_intents(self, h, query, body):
        req = RelayAuthRequest.intent(body["need"], body.get("tags") or (), body.get("maxPrice"),
                                      body.get("currency"), wire_int(body["ttl"]))
        ace_id = self._auth(h, req)
        now = self.clock()
        intent = {"intentId": str(uuid.uuid4()), "from": ace_id, "need": body["need"], "tags": body.get("tags") or [],
                  "ttl": body["ttl"], "createdAt": now, "expiresAt": now + body["ttl"]}
        for k in ("maxPrice", "currency"):
            if body.get(k) is not None:
                intent[k] = body[k]
        self.intents.append(intent)
        self._reply(h, 201, {"intentId": intent["intentId"], "expiresAt": intent["expiresAt"]})

    def _get_v1_intents(self, h, query, body):
        self._reply(h, 200, {"intents": self.intents, "cursor": None})


class _HTTPError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code
