import hashlib
import hmac
import json

import pytest

from ace import RelayClient, SoftwareIdentity
from ace._encoding import MAX_SAFE_INTEGER
from ace._signing import build_sign_data, encode_payload
from ace.auth import RelayAuthRequest
from ace.relay import Webhook
from ace.webhook import verify_webhook_notification

from .helpers import raises

SECRET = "0123456789abcdef0123456789abcdef"
TS = 1741000000
BODY = json.dumps({"event": "message", "aceId": "ace:sha256:" + "a" * 64, "streamId": "1741000000000-0"},
                  separators=(",", ":"))


def sig(secret: str = SECRET, ts: int = TS, body: str = BODY, prefix: str = "sha256=") -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body.encode(), hashlib.sha256).hexdigest()
    return prefix + mac


def _verify(**overrides):
    args = dict(secret=SECRET, timestamp=str(TS), signature=sig(), body=BODY, clock=lambda: TS)
    return verify_webhook_notification(**{**args, **overrides})


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
    with raises("invalid_argument"):
        RelayAuthRequest.webhook(**kwargs)


MAX = MAX_SAFE_INTEGER
NO_STREAM = '{"event":"message","aceId":"ace:sha256:' + "a" * 64 + '"}'
LONG_STREAM = BODY.replace("1741000000000-0", "1" * 21 + "-0")


@pytest.mark.parametrize("kwargs", [
    dict(),
    dict(clock=lambda: TS + 10),
    dict(body=BODY.encode()),
    dict(window_seconds=0),
    dict(window_seconds=MAX),
    dict(timestamp=str(MAX), signature=sig(ts=MAX), clock=lambda: MAX),
])
def test_verify_notification_accepts(kwargs):
    assert _verify(**kwargs) == ("ace:sha256:" + "a" * 64, "1741000000000-0")


@pytest.mark.parametrize("kwargs, code", [
    (dict(signature=sig(secret="wrong-secret-wrong-secret")), "invalid_signature"),
    (dict(signature=sig(prefix="sha1=")), "invalid_signature"),
    (dict(signature=sig().upper()), "invalid_signature"),
    (dict(body=BODY.replace("1741000000000-0", "1741000000000-1")), "invalid_signature"),
    (dict(clock=lambda: TS + 301), "stale_timestamp"),
    (dict(timestamp="not-a-number"), "invalid_argument"),
    # 16 digits pass the format regex but exceed 2^53 - 1
    (dict(timestamp=str(MAX + 1)), "invalid_argument"),
    (dict(timestamp="9999999999999999"), "invalid_argument"),
    (dict(body=NO_STREAM, signature=sig(body=NO_STREAM)), "invalid_argument"),
    (dict(body=LONG_STREAM, signature=sig(body=LONG_STREAM)), "invalid_argument"),
    (dict(window_seconds=-1), "invalid_argument"),
    (dict(window_seconds=MAX + 1), "invalid_argument"),
    (dict(window_seconds=1.5), "invalid_argument"),
    (dict(window_seconds="300"), "invalid_argument"),
    (dict(window_seconds=True), "invalid_argument"),
    (dict(window_seconds=None), "invalid_argument"),
    (dict(body="\ud800"), "invalid_argument"),  # lone surrogate: not UTF-8 encodable
    (dict(secret="0123456789abcdef\udfff"), "invalid_argument"),
])
def test_verify_notification_rejects(kwargs, code):
    with raises(code):
        _verify(**kwargs)


BAD_SIG = "sha256=" + "Z" * 64


@pytest.mark.parametrize("kwargs, code", [
    # malformed timestamp wins over a malformed signature
    (dict(timestamp="nope", signature=BAD_SIG), "invalid_argument"),
    (dict(timestamp=str(MAX + 2), signature=BAD_SIG), "invalid_argument"),
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
    with raises(code):
        _verify(**kwargs)


# --- RelayClient webhook endpoints against the fake relay ---

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
    assert [r for r in relay.requests if r[1] == "/v1/webhook"] == [
        ("GET", "/v1/webhook"), ("PUT", "/v1/webhook"), ("GET", "/v1/webhook"),
        ("DELETE", "/v1/webhook"), ("GET", "/v1/webhook"),
    ]


def test_relay_set_webhook_validates_locally(relay):
    alice = SoftwareIdentity.generate("ed25519")
    with raises("invalid_argument"):
        RelayClient(relay.url).set_webhook(alice, "http://example.com/hook", SECRET)
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
    {**GOOD, "lastDeliveredAt": None},
    {**GOOD, "lastError": 42},
    {**GOOD, "lastError": None},
])
def test_relay_get_webhook_rejects_malformed(relay, webhook):
    alice = SoftwareIdentity.generate("ed25519")
    relay.raw_responses["/v1/webhook"] = (200, json.dumps({"webhook": webhook}).encode(), "application/json")
    with raises("relay_protocol_error"):
        RelayClient(relay.url).get_webhook(alice)


def test_relay_get_webhook_coerces_wire_ints(relay):
    alice = SoftwareIdentity.generate("ed25519")
    raw = {**GOOD, "failures": 3.0, "updatedAt": float(TS), "lastDeliveredAt": float(TS - 5), "lastError": "HTTP 500"}
    relay.raw_responses["/v1/webhook"] = (200, json.dumps({"webhook": raw}).encode(), "application/json")
    w = RelayClient(relay.url).get_webhook(alice)
    assert w == Webhook("https://example.com/hook", "disabled", 3, TS, TS - 5, "HTTP 500")
    assert type(w.failures) is int and type(w.updated_at) is int and type(w.last_delivered_at) is int
