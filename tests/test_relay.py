"""RelayClient against the in-process fake relay (07-relay)."""

from __future__ import annotations

import json
import socket
import threading

import pytest

import ace._net as net
import ace.relay as relay_mod
from ace import (
    TEXT,
    PrekeyVault,
    RelayClient,
    SoftwareIdentity,
    create_card_record,
    create_packet,
    create_permit,
    create_published_agent,
    encode_content,
)
from ace._relay_url import normalize_relay_url

from .helpers import raises

SSE = "text/event-stream"


class Agent:
    def __init__(self, relay, contact="open", handle=None, listed=True):
        self.identity = SoftwareIdentity.generate()
        self.id = self.identity.get_ace_id()
        self.vault = PrekeyVault()
        self.client = RelayClient(relay.url, allow_loopback=True)
        self.client.register(self.identity)
        self.source = create_published_agent(
            self.identity,
            relays=[relay.url],
            prekey=self.vault.current(),
            profiles=[TEXT.descriptor()],
            allow_loopback_relays=True,
        )
        self.client.publish(self.source)
        self.card = create_card_record(
            self.identity,
            home=relay.url,
            handle=handle,
            contact=contact,
            listed=listed,
            allow_loopback_relays=True,
        )
        self.client.publish_card(self.card)


@pytest.fixture
def pair(relay):
    return Agent(relay, handle="alice"), Agent(relay, contact="closed", listed=False)


def text_packet(sender, recipient, msg="hi"):
    plain = encode_content("ace:text:1", TEXT.messages["ace:text:1"].digest, {"message": msg})
    return create_packet(
        sender.identity, recipient.id, recipient.vault.current(), plain, timestamp=relay_now()
    )


def relay_now():
    import time

    return int(time.time())


def test_normalize_url():
    assert normalize_relay_url("HTTPS://Relay.Example.COM/") == "https://relay.example.com"
    for bad in ("ftp://x", "https://u:p@x", "https://x?q=1", 5):
        with raises("invalid_argument"):
            normalize_relay_url(bad)


def test_descriptor_lookups_directory_and_handles(relay, pair):
    alice, bob = pair
    c = alice.client
    assert c.descriptor(alice.id).ace_id == alice.id
    assert c.descriptor(bob.id).ace_id == bob.id  # every registered identity resolves by ACE ID
    assert c.handle("alice").ace_id == alice.id
    assert c.card(bob.id).contact == "closed" and c.card(bob.id).handle is None
    with raises("unknown_peer"):
        c.handle("nobody")
    # the directory lists identities whose card record is listed
    agents, cursor = c.directory()
    assert [a.ace_id for a in agents] == [alice.id] and cursor is None
    assert c.directory(profile="ace:commerce:1")[0] == []
    # a relay serving another identity's descriptor is a protocol error
    other = "ace:sha256:" + "1" * 64
    relay.raw_responses[f"/v1/descriptor/{other}"] = (
        200,
        json.dumps(alice.source).encode(),
        "application/json",
    )
    with raises("relay_protocol_error"):
        c.descriptor(other)
    relay.raw_responses[f"/v1/card/{other}"] = (
        200,
        json.dumps(alice.card).encode(),
        "application/json",
    )
    with raises("relay_protocol_error"):
        c.card(other)


def test_send_inbox_ack_and_blocks(relay, pair):
    alice, bob = pair
    p = text_packet(bob, alice)  # alice is public: no permit needed
    bob.client.send(p)
    bob.client.send(p)  # byte-identical duplicate is idempotent
    page = alice.client.inbox(alice.identity, limit=10)
    assert [json.loads(e.packet) for e in page.entries] == [p]
    assert page.cursor == page.entries[-1].stream_id
    alice.client.ack(alice.identity, page.cursor)
    assert alice.client.inbox(alice.identity).entries == []
    # bob is closed: alice needs his permit
    with raises("not_permitted"):
        alice.client.send(text_packet(alice, bob))
    permit = create_permit(bob.identity, alice.id)
    alice.client.send(text_packet(alice, bob), permit)
    bob.client.set_block(bob.identity, alice.id, True, 1)
    with raises("not_permitted"):
        alice.client.send(text_packet(alice, bob, "again"), permit)
    with raises("relay_rejected") as info:
        bob.client.set_block(bob.identity, alice.id, False, 1)
    assert info.value.relay_code == "stale_revision"
    bob.client.set_block(bob.identity, alice.id, False, 2)
    alice.client.send(text_packet(alice, bob, "again"), permit)


def test_wake_registration(relay, pair):
    alice, _ = pair
    gateway, token = "https://push.example/ace", "t" * 22
    alice.client.set_wake(alice.identity, gateway, token)
    assert relay.wakes[alice.id] == {"gateway": gateway, "token": token}
    assert relay.requests[-1] == ("PUT", "/v1/wake")
    alice.client.clear_wake(alice.identity)
    alice.client.clear_wake(alice.identity)  # idempotent
    assert relay.wakes == {} and relay.requests[-1] == ("DELETE", "/v1/wake")
    # a relay without wake hints
    relay.inject.append(("/v1/wake", 404, "not_found", {}))
    with raises("relay_rejected") as info:
        alice.client.set_wake(alice.identity, gateway, token)
    assert info.value.relay_code == "not_found"


def test_error_mapping_and_nonce_replay(relay, pair):
    alice, _ = pair
    path = f"/v1/descriptor/{alice.id}"
    for status, code, expected in [
        (429, "rate_limited", "relay_unavailable"),
        (503, "down", "relay_unavailable"),
        (403, "not_permitted", "not_permitted"),
        (403, "not_registered", "not_registered"),
        (404, "unknown_peer", "unknown_peer"),
        (409, "stale_descriptor", "relay_rejected"),
        (302, "moved", "relay_protocol_error"),
    ]:
        relay.inject.append((path, status, code, {"Retry-After": "7"}))
        with raises(expected) as info:
            alice.client.descriptor(alice.id)
        assert info.value.status == status and info.value.relay_code == code
        assert info.value.retry_after_seconds == (7 if info.value.is_transient else None)
    relay.inject.append(("/v1/inbox", 409, "replay", {}))
    alice.client.inbox(alice.identity)  # retried once with a fresh nonce
    with raises("relay_unavailable"):
        RelayClient("http://127.0.0.1:1", timeout=1, allow_loopback=True).descriptor(alice.id)


def test_ssrf_policy(monkeypatch):
    def resolver(ip):
        return lambda host, port, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(net, "_getaddrinfo", resolver("10.0.0.5"))
    with raises("blocked_address"):
        RelayClient("https://relay.evil.example").descriptor("ace:sha256:" + "2" * 64)
    monkeypatch.setattr(net, "_getaddrinfo", resolver("127.0.0.1"))
    with raises("blocked_address"):  # loopback only with explicit development opt-in
        RelayClient("https://relay.evil.example").descriptor("ace:sha256:" + "2" * 64)
    monkeypatch.setattr(net, "_getaddrinfo", resolver("93.184.216.34"))
    with raises("blocked_address"):  # plain HTTP only for loopback
        RelayClient("http://relay.example", allow_loopback=True).descriptor(
            "ace:sha256:" + "2" * 64
        )
    for ip in ("::ffff:10.0.0.1", "64:ff9b::7f00:1", "fe80::1", "169.254.1.1", "not-an-ip"):
        assert net.is_blocked_address(ip)
    assert not net.is_blocked_address("93.184.216.34")
    # 07 § Blocked addresses: IETF protocol assignments, site-local, documentation, SRv6 SIDs
    for ip in ("2001:1ff:ffff::1", "fec0::1", "feff::1", "3fff:fff::1", "5f00::1"):
        assert net.is_blocked_address(ip), ip
    for ip in ("2001:200::1", "3fff:1000::1", "5f01::1", "2606:4700::1"):
        assert not net.is_blocked_address(ip), ip


def test_listen_frames_and_drain(relay, pair):
    alice, bob = pair
    first = text_packet(bob, alice, "one")
    bob.client.send(first)
    relay.drain_after = 1
    stop = threading.Event()
    gen = alice.client.listen(alice.identity, stop=stop)
    entry = next(gen)
    assert entry.catchup and json.loads(entry.packet) == first
    second = text_packet(bob, alice, "two")
    bob.client.send(second)
    assert json.loads(next(gen).packet) == second  # reconnected after drain
    stop.set()
    assert list(gen) == []


def test_listen_protocol_errors(relay, pair, monkeypatch):
    alice, _ = pair
    monkeypatch.setattr(relay_mod, "_sleep", lambda s: None)
    relay.raw_responses["/v1/listen"] = (
        200,
        b'id: 1-0\nevent: message\ndata: {"packet":{"a":1}}\n\n',
        SSE,
    )
    assert next(alice.client.listen(alice.identity)) == relay_mod.RelayEntry(
        "1-0", b'{"a":1}', False
    )
    for body in (b"id: 1-0\nevent: message\ndata: {bad\n\n", b"event: message\ndata: {}\n\n"):
        relay.raw_responses["/v1/listen"] = (200, body, SSE)
        with raises("relay_protocol_error"):
            next(alice.client.listen(alice.identity))
    relay.raw_responses["/v1/listen"] = (200, b"event: connected\ndata: {}\n\n", SSE)
    with raises("relay_unavailable"):  # connected-only streams are not progress
        next(alice.client.listen(alice.identity))


def test_relay_json_is_depth_checked(relay, pair, monkeypatch):
    alice, _ = pair
    monkeypatch.setattr(relay_mod, "_sleep", lambda s: None)
    JSON = "application/json"
    for depth in (37, 5000):  # over MAX_JSON_DEPTH + 3, and deep enough to exhaust recursion
        packet = "[" * depth + "]" * depth
        relay.raw_responses["/v1/inbox"] = (
            200,
            f'{{"messages":[{{"id":"1-0","packet":{packet}}}],"cursor":null}}'.encode(),
            JSON,
        )
        with raises("relay_protocol_error"):
            alice.client.inbox(alice.identity)
        relay.raw_responses["/v1/listen"] = (
            200,
            f'id: 1-0\nevent: message\ndata: {{"packet":{packet}}}\n\n'.encode(),
            SSE,
        )
        with raises("relay_protocol_error"):
            next(alice.client.listen(alice.identity))
        relay.raw_responses["/v1/inbox"] = (400, f'{{"error":{packet}}}'.encode(), JSON)
        with raises("relay_rejected"):
            alice.client.inbox(alice.identity)


def _nest(n):
    """A JSON value whose deepest container is at depth ``n`` (its root at 0)."""
    return {} if n == 0 else {"a": _nest(n - 1)}


def _deep_agent(relay, n):
    """A PublishedAgent whose ext value (at depth 3) holds ``n`` more levels."""
    return create_published_agent(
        SoftwareIdentity.generate(),
        relays=[relay.url],
        prekey=PrekeyVault().current(),
        profiles=[{"id": "x:deep:1", "digest": "a" * 64}],
        ext={"x:deep:1": _nest(n)},
        allow_loopback_relays=True,
    )


def test_published_agent_depth_counts_from_its_root(relay):
    _deep_agent(relay, 29)  # depth 32
    with raises("invalid_authorization"):
        _deep_agent(relay, 30)  # depth 33 (ext alone is only 31)


def test_contained_objects_at_max_json_depth_pass_inside_wrappers(relay, pair, monkeypatch):
    """02 § JSON values: a response is parsed within MAX_JSON_DEPTH + 3; each packet and
    PublishedAgent in it within MAX_JSON_DEPTH, else relay_protocol_error for the whole page."""
    alice, _ = pair
    monkeypatch.setattr(relay_mod, "_sleep", lambda s: None)
    JSON = "application/json"
    ok = _deep_agent(relay, 29)
    bad = {**ok, "descriptor": {**ok["descriptor"], "ext": {"x:deep:1": _nest(30)}}}
    path = "/v1/descriptor/" + ok["descriptor"]["aceId"]
    relay.raw_responses[path] = (200, json.dumps(ok).encode(), JSON)
    assert alice.client.descriptor(ok["descriptor"]["aceId"]).ace_id == ok["descriptor"]["aceId"]
    relay.raw_responses[path] = (200, json.dumps(bad).encode(), JSON)
    with raises("relay_protocol_error"):
        alice.client.descriptor(ok["descriptor"]["aceId"])
    page = {"agents": [ok], "cursor": None}
    relay.raw_responses["/v1/descriptors"] = (200, json.dumps(page).encode(), JSON)
    assert len(alice.client.directory()[0]) == 1
    page["agents"].append(bad)  # never skipped: a conformant relay refused it on input
    relay.raw_responses["/v1/descriptors"] = (200, json.dumps(page).encode(), JSON)
    with raises("relay_protocol_error"):
        alice.client.directory()

    for n, passes in ((32, True), (33, False)):
        packet = json.dumps(_nest(n), separators=(",", ":"))
        inbox = f'{{"messages":[{{"streamId":"1-0","packet":{packet}}}],"cursor":"1-0"}}'
        relay.raw_responses["/v1/inbox"] = (200, inbox.encode(), JSON)
        frame = f'id: 1-0\nevent: message\ndata: {{"packet":{packet}}}\n\n'
        relay.raw_responses["/v1/listen"] = (200, frame.encode(), SSE)
        if passes:
            assert alice.client.inbox(alice.identity).entries[0].packet == packet.encode()
            assert next(alice.client.listen(alice.identity)).packet == packet.encode()
        else:
            with raises("relay_protocol_error"):
                alice.client.inbox(alice.identity)
            with raises("relay_protocol_error"):
                next(alice.client.listen(alice.identity))
