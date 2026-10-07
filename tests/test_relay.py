"""RelayClient against the in-process fake relay."""

from __future__ import annotations

import threading
import time

import pytest

import ace.relay as relay_mod
from ace import (
    ACEError,
    AgentProfile,
    DiscoverQuery,
    RelayClient,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    verify_registration_file,
)
from ace.relay import compare_stream_ids, normalize_relay_url

from .helpers import raises


@pytest.fixture
def ids():
    return SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("secp256k1")


def _rfq(sender, recipient, ts=None, thread_id="t1"):
    peer = verify_registration_file(recipient.to_registration_file(name="R", endpoint="https://r.example/ace"))
    return create_message(sender, peer, "rfq", {"need": "x"}, ThreadStateMachine(sender.get_ace_id()),
                          thread_id=thread_id, timestamp=ts)


def test_normalize_url():
    assert normalize_relay_url("HTTPS://Relay.Example.COM/") == "https://relay.example.com"
    assert normalize_relay_url("http://127.0.0.1:8080/base/") == "http://127.0.0.1:8080/base"
    for bad in ("ftp://x", "https://", "https://u:p@x", "https://x?q=1", 5):
        with raises("invalid_argument"):
            normalize_relay_url(bad)
    assert compare_stream_ids("10-2", "9-99") == 1 and compare_stream_ids("10-2", "10-10") == -1
    assert compare_stream_ids("1-1", "1-1") == 0


def test_register_lookup_discover(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url + "/")
    assert client.base_url == relay.url
    assert client.register(alice, AgentProfile(name="Alice", tags=["translate"])) == "registered"
    assert client.register(bob) == "registered"
    assert client.register(alice) == "refreshed"  # strictly increasing timestamps per client
    peer = client.lookup_peer(alice.get_ace_id())
    assert peer.encryption_public_key == alice.get_encryption_public_key() and peer.source == "relay"
    assert peer.profile is not None and peer.profile.name == "Alice"
    with raises("unknown_peer") as info:
        client.lookup_peer("ace:sha256:" + "0" * 64)
    assert info.value.status == 404 and info.value.relay_code == "unknown_peer"
    relay.extra_agents.append({**relay.identities[bob.get_ace_id()], "registeredAt": 5})  # bad binding
    result = client.discover(DiscoverQuery(limit=10))
    assert {p.ace_id for p in result.agents} == {alice.get_ace_id(), bob.get_ace_id()}
    assert result.rejected == 1 and result.cursor is None


def test_lookup_rejects_mismatched_record(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url)
    client.register(alice)
    client.register(bob)
    relay.identities["ace:sha256:" + "1" * 64] = relay.identities[alice.get_ace_id()]
    with raises("invalid_peer"):
        client.lookup_peer("ace:sha256:" + "1" * 64)


def test_send_and_fetch_inbox(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url)
    client.register(alice)
    with raises("unknown_peer"):
        client.send(_rfq(alice, bob))
    client.register(bob)
    envs = [_rfq(alice, bob, thread_id=f"t{i}") for i in range(3)]
    for env in envs:
        client.send(env)
    client.send(envs[0])  # exact duplicate is ok
    page = client.fetch_inbox(bob, limit=2)
    assert [e.message["messageId"] for e in page.entries] == [envs[0].message_id, envs[1].message_id]
    assert page.cursor == page.entries[-1].stream_id
    rest = client.fetch_inbox(bob, since=page.cursor)
    assert [e.message["messageId"] for e in rest.entries] == [envs[2].message_id]
    assert client.fetch_inbox(bob, since=rest.cursor).entries == []
    with raises("not_registered"):
        client.fetch_inbox(SoftwareIdentity.generate("ed25519"))
    with raises("invalid_argument"):
        client.fetch_inbox(bob, limit=101)


def test_auth_timestamps_monotonic_and_replay_retry(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url, clock=lambda: 1_000_000_000)  # frozen clock
    relay.clock = lambda: 1_000_000_000
    client.register(bob)
    for _ in range(3):
        client.fetch_inbox(bob)
    ts = relay.auth_timestamps
    assert ts == sorted(set(ts)) and len(ts) == 3
    relay.inject.append(("/v1/inbox", 409, "replay", {}))
    client.fetch_inbox(bob)  # retried once with a fresh timestamp
    relay.inject.extend([("/v1/inbox", 409, "replay", {}), ("/v1/inbox", 409, "replay", {})])
    with raises("relay_rejected") as info:
        client.fetch_inbox(bob)
    assert info.value.status == 409 and info.value.relay_code == "replay"


def test_error_mapping(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    cases = [
        (429, "rate_limited", {"Retry-After": "7"}, "relay_unavailable"),
        (503, "down", {}, "relay_unavailable"),
        (408, "timeout", {}, "relay_unavailable"),
        (400, "envelope_expired", {}, "envelope_expired"),
        (403, "not_registered", {}, "not_registered"),
        (404, "unknown_peer", {}, "unknown_peer"),
        (418, "teapot", {}, "relay_rejected"),
        (400, "invalid_envelope", {}, "relay_rejected"),
    ]
    for status, code, headers, expected in cases:
        relay.inject.append(("/v1/peer", status, code, headers))
        with raises(expected) as info:
            client.lookup_peer(bob.get_ace_id())
        assert info.value.status == status and info.value.relay_code == code
        if headers:
            assert info.value.retry_after_seconds == 7
    relay.raw_responses["/v1/peer"] = (200, b"{not json", "application/json")
    with raises("relay_protocol_error"):
        client.lookup_peer(bob.get_ace_id())
    relay.raw_responses["/v1/peer"] = (200, b"x" * 2000, "application/json")
    with raises("relay_protocol_error"):
        RelayClient(relay.url, max_response_bytes=1000).lookup_peer(bob.get_ace_id())
    relay.raw_responses["/v1/peer"] = (200, b"[1]", "application/json")
    with raises("relay_protocol_error"):
        client.lookup_peer(bob.get_ace_id())
    with raises("relay_unavailable"):
        RelayClient("http://127.0.0.1:1", timeout=1).lookup_peer(bob.get_ace_id())


def test_unregister_and_intents(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url)
    client.register(alice)
    posted = client.post_intent(alice, "translate 500 words", ttl=3600, tags=["translate", "fr"],
                                max_price="10", currency="USDC")
    page = client.list_intents()
    assert len(page.intents) == 1
    intent = page.intents[0]
    assert intent.intent_id == posted.intent_id and intent.from_id == alice.get_ace_id()
    assert intent.tags == ("translate", "fr") and intent.max_price == "10" and intent.expires_at == posted.expires_at
    client.unregister(alice)
    assert alice.get_ace_id() not in relay.identities
    with raises("not_registered"):
        client.unregister(alice)


def test_listen_catchup_live_and_drain(relay, ids):
    alice, bob = ids
    client = RelayClient(relay.url)
    client.register(alice)
    client.register(bob)
    first = _rfq(alice, bob, thread_id="a")
    client.send(first)
    relay.drain_after = 1
    stop = threading.Event()
    got = []
    opens = []
    gen = client.listen(bob, stop=stop, on_open=lambda: opens.append(1))
    entry = next(gen)
    got.append(entry)
    assert opens == [1]
    assert entry.catchup and entry.message["messageId"] == first.message_id
    second = _rfq(alice, bob, thread_id="b")
    client.send(second)
    entry = next(gen)  # after the drain the client reconnects from the last stream id
    assert entry.message["messageId"] == second.message_id
    assert compare_stream_ids(entry.stream_id, got[0].stream_id) > 0
    assert relay.requests.count(("GET", "/v1/listen")) == 2
    assert opens == [1, 1]  # on_open runs again after the reconnect
    stop.set()
    assert list(gen) == []


def test_listen_on_open_exception_ends_the_stream(relay, ids):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)

    def boom():
        raise RuntimeError("host hook failed")

    with pytest.raises(RuntimeError):
        next(client.listen(bob, on_open=boom))

    def transient():
        raise ACEError("relay_unavailable", "from the hook")

    with raises("relay_unavailable"):  # not mistaken for a connection failure: no retry
        next(client.listen(bob, on_open=transient))
    assert relay.requests.count(("GET", "/v1/listen")) == 2


def test_listen_error_thrown_at_yield_propagates(relay, ids):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    relay.enqueue_raw(bob.get_ace_id(), {"n": 0})
    gen = client.listen(bob)
    assert next(gen).message == {"n": 0}
    with raises("relay_unavailable"):  # the consumer's error, not a dropped stream: no retry
        gen.throw(ACEError("relay_unavailable", "from the consumer"))
    assert relay.requests.count(("GET", "/v1/listen")) == 1
    _until(lambda: relay.open_listens == 0)


def test_listen_stop_unblocks(relay, ids):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    stop = threading.Event()
    out = []
    t = threading.Thread(target=lambda: out.extend(client.listen(bob, stop=stop)))
    t.start()
    threading.Event().wait(0.3)
    stop.set()
    t.join(5)
    assert not t.is_alive() and out == []


def _until(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end, "condition not met in time"
        time.sleep(0.01)


def test_listen_stop_during_heartbeats_is_prompt(relay, ids):
    _, bob = ids
    relay.heartbeat = 0.01
    client = RelayClient(relay.url)
    client.register(bob)
    stop = threading.Event()
    out = []
    t = threading.Thread(target=lambda: out.extend(client.listen(bob, stop=stop)))
    t.start()
    _until(lambda: relay.open_listens == 1)
    time.sleep(0.1)  # several heartbeats
    t0 = time.monotonic()
    stop.set()
    t.join(5)
    assert not t.is_alive() and out == []
    assert time.monotonic() - t0 < 0.5
    _until(lambda: relay.open_listens == 0)


def test_listen_generator_close_closes_connection(relay, ids):
    _, bob = ids
    relay.heartbeat = 0.01
    client = RelayClient(relay.url)
    client.register(bob)
    relay.enqueue_raw(bob.get_ace_id(), {"n": 0})
    gen = client.listen(bob)
    assert next(gen).message == {"n": 0}
    assert relay.open_listens == 1
    gen.close()
    _until(lambda: relay.open_listens == 0)


def test_listen_stop_during_backoff_is_prompt(relay, ids):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    relay.inject.append(("/v1/listen", 503, "down", {"Retry-After": "30"}))
    stop = threading.Event()
    t = threading.Thread(target=lambda: list(client.listen(bob, stop=stop)))
    t.start()
    _until(lambda: ("GET", "/v1/listen") in relay.requests)
    time.sleep(0.05)
    t0 = time.monotonic()
    stop.set()
    t.join(5)
    assert not t.is_alive() and time.monotonic() - t0 < 0.5
    assert relay.requests.count(("GET", "/v1/listen")) == 1


def test_listen_backoff_and_retry_after(relay, ids, monkeypatch):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    sleeps = []
    monkeypatch.setattr(relay_mod, "_sleep", sleeps.append)
    relay.inject.extend([
        ("/v1/listen", 503, "down", {}), ("/v1/listen", 503, "down", {}),
        ("/v1/listen", 429, "rate_limited", {"Retry-After": "7"}), ("/v1/listen", 500, "x", {}),
        ("/v1/listen", 429, "rate_limited", {"Retry-After": "999"}),
    ])
    sid = relay.enqueue_raw(bob.get_ace_id(), {"hello": 1})
    entry = next(client.listen(bob))
    assert entry.stream_id == sid
    assert sleeps == [1, 2, 7, 8, 30]  # Retry-After honored, capped at 30 s


def test_listen_gives_up_and_rejects(relay, ids, monkeypatch):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    monkeypatch.setattr(relay_mod, "_sleep", lambda s: None)
    relay.inject.extend([("/v1/listen", 503, "down", {})] * 10)
    with raises("relay_unavailable"):
        next(client.listen(bob))
    relay.inject.append(("/v1/listen", 401, "invalid_signature", {}))
    with raises("relay_rejected"):
        next(client.listen(bob))


def test_listen_protocol_errors(relay, ids, monkeypatch):
    _, bob = ids
    client = RelayClient(relay.url)
    client.register(bob)
    relay.raw_responses["/v1/listen"] = (200, b"id: 1-0\nevent: message\ndata: {bad\n\n", "text/event-stream")
    with raises("relay_protocol_error"):
        next(client.listen(bob))
    big = b"id: 1-0\nevent: message\ndata: " + b"x" * (relay_mod.MAX_ENVELOPE_BYTES + 600) + b"\n\n"
    relay.raw_responses["/v1/listen"] = (200, big, "text/event-stream")
    with raises("relay_protocol_error"):
        next(client.listen(bob))
    relay.raw_responses["/v1/listen"] = (200, b"event: message\ndata: {}\n\n", "text/event-stream")
    with raises("relay_protocol_error"):
        next(client.listen(bob))
    relay.raw_responses["/v1/listen"] = (200, b"{}", "application/json")
    with raises("relay_protocol_error"):
        next(client.listen(bob))


def test_send_requires_message():
    with raises("invalid_argument"):
        RelayClient("https://relay.example").send({"ace": "1.0"})  # type: ignore[arg-type]
