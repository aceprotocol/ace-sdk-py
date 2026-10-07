import hashlib
import hmac
import json

import pytest

from ace import ACEError, RelayClient, SoftwareIdentity
from ace._signing import build_sign_data, encode_payload
from ace.auth import RelayAuthRequest
from ace.relay import Webhook
from ace.webhook import verify_webhook_notification

from .fake_relay import FakeRelay

SECRET = "0123456789abcdef0123456789abcdef"
TS = 1741000000
BODY = json.dumps({"event": "message", "aceId": "ace:sha256:" + "a" * 64, "streamId": "1741000000000-0"},
                  separators=(",", ":"))


def sig(secret: str = SECRET, ts: int = TS, body: str = BODY, prefix: str = "sha256=") -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body.encode(), hashlib.sha256).hexdigest()
    return prefix + mac


def test_webhook_auth_payloads():
    put = RelayAuthRequest.webhook("PUT", "https://example.com/hook", SECRET)
    assert put.action == "webhook"
    assert put.payload() == encode_payload("PUT", "https://example.com/hook", SECRET)
    assert RelayAuthRequest.webhook("GET").payload() == encode_payload("GET", "", "")
    assert RelayAuthRequest.webhook("DELETE").payload() == encode_payload("DELETE", "", "")
    # a signature under one method never verifies under another
    assert build_sign_data("webhook", "ace:sha256:" + "0" * 64, TS, put.payload()) != \
        build_sign_data("webhook", "ace:sha256:" + "0" * 64, TS, RelayAuthRequest.webhook("GET").payload())


@pytest.mark.parametrize("kwargs", [
    dict(method="PATCH"),
    dict(method="PUT", url="http://example.com", secret=SECRET),
    dict(method="PUT", url="https://example.com", secret="short"),
    dict(method="PUT", url="https://example.com", secret="x" * 129),
    dict(method="PUT", url="https://example.com", secret="has\x00control" + "a" * 16),
    dict(method="GET", url="https://example.com"),
    dict(method="DELETE", secret=SECRET),
])
def test_webhook_auth_rejects(kwargs):
    with pytest.raises(ACEError) as info:
        RelayAuthRequest.webhook(**kwargs)
    assert info.value.code == "invalid_argument"


def test_verify_notification_ok():
    n = verify_webhook_notification(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS + 10)
    assert n.ace_id == "ace:sha256:" + "a" * 64
    assert n.stream_id == "1741000000000-0"


def test_verify_notification_accepts_bytes_body():
    n = verify_webhook_notification(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY.encode(), clock=lambda: TS)
    assert n.stream_id == "1741000000000-0"


@pytest.mark.parametrize("kwargs, code", [
    (dict(signature=sig(secret="wrong-secret-wrong-secret")), "invalid_signature"),
    (dict(signature=sig(prefix="sha1=")), "invalid_signature"),
    (dict(signature=sig().upper()), "invalid_signature"),
    (dict(body=BODY.replace("1741000000000-0", "1741000000000-1")), "invalid_signature"),
    (dict(clock=lambda: TS + 301), "stale_timestamp"),
    (dict(timestamp="not-a-number"), "invalid_argument"),
    (dict(body='{"event":"message","aceId":"ace:sha256:' + "a" * 64 + '"}',
          signature=sig(body='{"event":"message","aceId":"ace:sha256:' + "a" * 64 + '"}')), "invalid_argument"),
])
def test_verify_notification_rejects(kwargs, code):
    args = dict(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS)
    args.update(kwargs)
    with pytest.raises(ACEError) as info:
        verify_webhook_notification(**args)
    assert info.value.code == code


@pytest.mark.parametrize("kwargs", [
    dict(window_seconds=-1),
    dict(window_seconds=1.5),
    dict(window_seconds="300"),
    dict(window_seconds=True),
    dict(window_seconds=None),
    dict(body="\ud800"),  # lone surrogate: not UTF-8 encodable
    dict(secret="0123456789abcdef\udfff"),
])
def test_verify_notification_rejects_bad_arguments(kwargs):
    args = dict(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS)
    args.update(kwargs)
    with pytest.raises(ACEError) as info:
        verify_webhook_notification(**args)
    assert info.value.code == "invalid_argument"


def test_verify_notification_window_zero_is_allowed():
    n = verify_webhook_notification(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS,
                                    window_seconds=0)
    assert n.stream_id == "1741000000000-0"


def test_verify_notification_stale_checked_before_hmac():
    with pytest.raises(ACEError) as info:
        verify_webhook_notification(secret=SECRET, timestamp=str(TS), signature=sig(secret="wrong-secret-wrong-secret"),
                                    body=BODY, clock=lambda: TS + 301)
    assert info.value.code == "stale_timestamp"


@pytest.mark.parametrize("timestamp", ["9007199254740992", "9007199254740993", "9999999999999999"])
def test_verify_notification_rejects_timestamp_above_max_safe_integer(timestamp):
    # 16 digits pass the format regex but exceed 2^53 - 1 (TS Number.MAX_SAFE_INTEGER)
    with pytest.raises(ACEError) as info:
        verify_webhook_notification(secret=SECRET, timestamp=timestamp, signature=sig(), body=BODY, clock=lambda: TS)
    assert info.value.code == "invalid_argument"


def test_verify_notification_accepts_timestamp_at_max_safe_integer():
    ts = 2**53 - 1
    n = verify_webhook_notification(secret=SECRET, timestamp=str(ts), signature=sig(ts=ts), body=BODY, clock=lambda: ts)
    assert n.stream_id == "1741000000000-0"


def test_verify_notification_rejects_window_above_max_safe_integer():
    with pytest.raises(ACEError) as info:
        verify_webhook_notification(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS,
                                    window_seconds=2**53)
    assert info.value.code == "invalid_argument"


BAD_SIG = "sha256=" + "Z" * 64


@pytest.mark.parametrize("kwargs, code", [
    # malformed timestamp wins over a malformed signature
    (dict(timestamp="nope", signature=BAD_SIG), "invalid_argument"),
    (dict(timestamp="9007199254740993", signature=BAD_SIG), "invalid_argument"),
    # malformed signature wins over a bad window_seconds and over staleness
    (dict(signature=BAD_SIG, window_seconds=-1), "invalid_signature"),
    (dict(signature=BAD_SIG, clock=lambda: TS + 301), "invalid_signature"),
    # well-formed but wrong HMAC: staleness is reported first
    (dict(signature=sig(secret="wrong-secret-wrong-secret"), clock=lambda: TS + 301), "stale_timestamp"),
    # bad window_seconds wins over staleness and a wrong HMAC
    (dict(signature=sig(secret="wrong-secret-wrong-secret"), window_seconds=-1, clock=lambda: TS + 301),
     "invalid_argument"),
])
def test_verify_notification_check_order(kwargs, code):
    args = dict(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS)
    args.update(kwargs)
    with pytest.raises(ACEError) as info:
        verify_webhook_notification(**args)
    assert info.value.code == code


# --- RelayClient webhook endpoints against the fake relay ---

@pytest.fixture
def relay():
    r = FakeRelay()
    yield r
    r.close()


def test_relay_webhook_round_trip(relay):
    alice = SoftwareIdentity.generate("ed25519")
    client = RelayClient(relay.url)
    client.register(alice)
    assert client.get_webhook(alice) is None
    client.set_webhook(alice, "https://example.com/hook", SECRET)
    assert relay.webhooks[alice.get_ace_id()]["url"] == "https://example.com/hook"
    assert relay.webhooks[alice.get_ace_id()]["secret"] == SECRET
    w = client.get_webhook(alice)
    assert isinstance(w, Webhook)
    assert (w.url, w.status, w.failures, w.last_delivered_at, w.last_error) == \
        ("https://example.com/hook", "active", 0, None, None)
    client.clear_webhook(alice)
    assert client.get_webhook(alice) is None
    assert relay.auth_actions == ["webhook"] * 5
    assert [r for r in relay.requests if r[1] == "/v1/webhook"] == [
        ("GET", "/v1/webhook"), ("PUT", "/v1/webhook"), ("GET", "/v1/webhook"),
        ("DELETE", "/v1/webhook"), ("GET", "/v1/webhook"),
    ]


def test_relay_set_webhook_validates_locally(relay):
    alice = SoftwareIdentity.generate("ed25519")
    with pytest.raises(ACEError) as info:
        RelayClient(relay.url).set_webhook(alice, "http://example.com/hook", SECRET)
    assert info.value.code == "invalid_argument"
    assert relay.requests == []


GOOD = {"url": "https://example.com/hook", "status": "disabled", "failures": 3, "updatedAt": TS}


@pytest.mark.parametrize("webhook", [
    "nope",
    {k: v for k, v in GOOD.items() if k != "updatedAt"},
    {**GOOD, "status": "paused"},
    {**GOOD, "failures": "x"},
    {**GOOD, "failures": -1},
    {**GOOD, "url": 5},
    {**GOOD, "lastDeliveredAt": "yesterday"},
    {**GOOD, "lastDeliveredAt": 1.5},
    {**GOOD, "lastError": 42},
])
def test_relay_get_webhook_rejects_malformed(relay, webhook):
    alice = SoftwareIdentity.generate("ed25519")
    relay.raw_responses["/v1/webhook"] = (200, json.dumps({"webhook": webhook}).encode(), "application/json")
    with pytest.raises(ACEError) as info:
        RelayClient(relay.url).get_webhook(alice)
    assert info.value.code == "relay_protocol_error"


def test_relay_get_webhook_coerces_wire_ints(relay):
    alice = SoftwareIdentity.generate("ed25519")
    raw = {**GOOD, "failures": 3.0, "updatedAt": float(TS), "lastDeliveredAt": float(TS - 5), "lastError": "HTTP 500"}
    relay.raw_responses["/v1/webhook"] = (200, json.dumps({"webhook": raw}).encode(), "application/json")
    w = RelayClient(relay.url).get_webhook(alice)
    assert w == Webhook("https://example.com/hook", "disabled", 3, TS, TS - 5, "HTTP 500")
    assert type(w.failures) is int and type(w.updated_at) is int and type(w.last_delivered_at) is int
