import hashlib
import hmac
import json

import pytest

from ace import ACEError
from ace._signing import build_sign_data, encode_payload
from ace.auth import RelayAuthRequest
from ace.webhook import verify_webhook_notification

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
