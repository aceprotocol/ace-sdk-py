"""Direct delivery, sender side (08-relay § Direct Delivery)."""

from __future__ import annotations

import json
import socket
import time

import pytest

import ace.discovery as disc
from ace import deliver_direct_or_relay, is_blocked_address, post_direct

from .helpers import raises
from .pipeline import Agent, Clock

PUBLIC = "93.184.216.34"


@pytest.fixture
def env():
    clock = Clock()
    alice, bob = Agent("alice", "ed25519", clock), Agent("bob", "secp256k1", clock)
    alice.pin(bob)
    return alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "hi"}).message


class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n):
        return self._body[:n]


def _install(monkeypatch, *, status=200, body=b'{"ok":true}', addrs=(PUBLIC,), error=None):
    sent = []

    def resolver(host, port, *a, **k):
        sent.append(("resolve", host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in addrs]

    class Conn:
        def __init__(self, domain, ip, timeout, port):
            sent.append(("connect", domain, ip, port, timeout))

        def request(self, method, target, body=None, headers=None):
            if error is not None:
                raise error
            sent.append(("request", method, target, json.loads(body), headers["Content-Type"]))

        def getresponse(self):
            return _Resp(status, body)

        def close(self):
            pass

    monkeypatch.setattr(disc, "_getaddrinfo", resolver)
    monkeypatch.setattr(disc, "_PinnedHTTPSConnection", Conn)
    return sent


def test_post_direct_success(monkeypatch, env):
    sent = _install(monkeypatch)
    post_direct("https://Bob.Example:8443/ace/receive?x=1#frag", env, timeout=2)
    assert sent == [
        ("resolve", "bob.example", 8443),
        ("connect", "bob.example", PUBLIC, 8443, 2.0),
        ("request", "POST", "/ace/receive?x=1", {"message": env.to_dict()}, "application/json"),
    ]


@pytest.mark.parametrize(
    "status,body,code,remote",
    [
        (400, b'{"ok":false,"error":"invalid_signature"}', "direct_rejected", "invalid_signature"),
        (413, b'{"ok":false,"error":"payload_too_large"}', "direct_rejected", "payload_too_large"),
        (400, b"not json", "direct_rejected", None),
        (400, b'{"ok":false,"error":"Bad\\u001b[31m"}', "direct_rejected", None),
        (400, b'{"ok":false,"error":"' + b"a" * 65 + b'"}', "direct_rejected", None),
        (400, b'{"ok":false,"error":"' + b"a" * 64 + b'"}', "direct_rejected", "a" * 64),
        (400, b'{"ok":false,"error":""}', "direct_rejected", None),
        (503, b'{"ok":false,"error":"handler_failed"}', "direct_unavailable", None),
        (429, b'{"ok":false,"error":"rate_limited"}', "direct_unavailable", None),
        (302, b"", "direct_unavailable", None),
        (404, b"", "direct_unavailable", None),
        (200, b'{"ok":false}', "direct_unavailable", None),
        (200, b"OK", "direct_unavailable", None),
        (204, b"", "direct_unavailable", None),
    ],
)
def test_post_direct_reply_mapping(monkeypatch, env, status, body, code, remote):
    _install(monkeypatch, status=status, body=body)
    with raises(code) as info:
        post_direct("https://bob.example/ace", env)
    assert info.value.status == status and info.value.remote_code == remote
    assert info.value.is_transient == (code == "direct_unavailable")


def test_post_direct_unsafe_or_unreachable(monkeypatch, env):
    _install(monkeypatch, addrs=(PUBLIC, "10.0.0.7"))
    with raises("invalid_argument"):
        post_direct("https://bob.example/ace", env)  # any blocked address refuses the endpoint
    _install(monkeypatch, error=OSError("refused"))
    with raises("direct_unavailable"):
        post_direct("https://bob.example/ace", env)

    def failing(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(disc, "_getaddrinfo", failing)
    with raises("direct_unavailable"):
        post_direct("https://bob.example/ace", env)
    for endpoint in ("http://bob.example/ace", "bob.example", "https://", 5):
        with raises("invalid_argument"):
            post_direct(endpoint, env)  # type: ignore[arg-type]
    with raises("invalid_argument"):
        post_direct("https://bob.example/ace", env.to_dict())  # type: ignore[arg-type]
    with raises("invalid_argument"):
        post_direct("https://bob.example/ace", env, timeout=0)


class _Relay:
    def __init__(self):
        self.sent = []

    def send(self, message):
        self.sent.append(message.message_id)


def test_deliver_direct_or_relay(monkeypatch, env):
    relay = _Relay()
    _install(monkeypatch)
    assert deliver_direct_or_relay(relay, "https://bob.example/ace")(env) == "direct"
    assert deliver_direct_or_relay(relay)(env) == "relay"
    _install(monkeypatch, status=503, body=b"")
    assert deliver_direct_or_relay(relay, "https://bob.example/ace")(env) == "relay"
    _install(monkeypatch, addrs=("127.0.0.1",))
    assert deliver_direct_or_relay(relay, "https://bob.example/ace")(env) == "relay"
    assert deliver_direct_or_relay(relay, "not a url")(env) == "relay"
    assert relay.sent == [env.message_id] * 4
    _install(monkeypatch, status=400, body=b'{"ok":false,"error":"wrong_recipient"}')
    with raises("direct_rejected"):  # the recipient rejected it: no relay fallback
        deliver_direct_or_relay(relay, "https://bob.example/ace")(env)
    assert len(relay.sent) == 4


def test_deliver_direct_or_relay_with_outbox(monkeypatch):
    clock = Clock()
    alice, bob = Agent("alice", "ed25519", clock), Agent("bob", "secp256k1", clock)
    alice.pin(bob)
    pending = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "hi"})
    _install(monkeypatch)
    relay = _Relay()
    path = alice.outbox.deliver(
        pending.request_id, deliver_direct_or_relay(relay, "https://bob.example/ace")
    )
    assert path == "direct"
    assert alice.outbox.pending() == []
    pending = alice.outbox.stage(alice.peers.get(bob.id), "text", {"message": "again"})
    _install(monkeypatch, status=503, body=b"")
    path = alice.outbox.deliver(
        pending.request_id, deliver_direct_or_relay(relay, "https://bob.example/ace")
    )
    assert path == "relay"
    assert relay.sent == [pending.message.message_id]
    assert alice.outbox.pending() == []


def test_is_blocked_address_fails_closed_on_non_ip():
    for bad in ("example.com", "", "1.2.3", None, 3, "::g", "[::1]"):
        assert is_blocked_address(bad) is True  # type: ignore[arg-type]


def test_post_direct_total_deadline_against_slow_drip(monkeypatch, env):
    from .slow_tls import slow_drip_server

    reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"
    with slow_drip_server(monkeypatch, disc, reply + b'{"ok":true}', interval=0.1) as port:
        started = time.monotonic()
        with raises("direct_unavailable"):  # every byte arrives well within a per-read timeout
            post_direct(f"https://localhost:{port}/ace", env, timeout=1)
        assert time.monotonic() - started < 2.5
