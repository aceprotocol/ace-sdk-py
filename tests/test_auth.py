"""Relay request authentication headers (07 § Authentication), client side."""

from fractions import Fraction

import pytest

from ace import SoftwareIdentity
from ace._encoding import from_base64, unix_now
from ace._signing import encode_payload, signing_message, verify_signature
from ace.auth import create_auth_headers
from tests.helpers import BAD_CLOCK_VALUES, NOW, raises

AUD = "https://relay.example"
HEADERS = {
    "X-ACE-Id",
    "X-ACE-Timestamp",
    "X-ACE-Seq",
    "X-ACE-Signature",
    "X-ACE-Audience",
    "X-ACE-Nonce",
}


def test_headers_sign_one_message_with_the_action_as_context():
    a = SoftwareIdentity.generate(now=NOW)
    peer = "ace:sha256:" + "ab" * 32
    for action, payload in (
        ("listen", encode_payload("-")),
        ("inbox", encode_payload("1-0", "7")),
        ("unregister", b""),
        ("inbox-ack", encode_payload("5-1")),
        ("block", encode_payload(peer, "block", "3")),
    ):
        h = create_auth_headers(a, action, payload, NOW, audience=AUD)
        assert set(h) == HEADERS
        assert (h["X-ACE-Id"], h["X-ACE-Timestamp"], h["X-ACE-Seq"]) == (
            a.get_ace_id(),
            str(NOW),
            "1",
        )
        assert len(h["X-ACE-Signature"]) == 4412
        m = signing_message(a.get_ace_id(), NOW, 1, encode_payload(AUD, h["X-ACE-Nonce"], payload))
        sig = from_base64(h["X-ACE-Signature"])
        pk = a.get_signing_public_key()
        assert verify_signature(m, action, sig, pk)
        other = "listen" if action != "listen" else "inbox"
        assert not verify_signature(m, other, sig, pk)
    a.delegate(now=NOW + 1)
    assert create_auth_headers(a, "unregister", b"", NOW + 1, audience=AUD)["X-ACE-Seq"] == "2"


def test_create_auth_headers_refuses_unusable_identity_and_bad_arguments():
    a = SoftwareIdentity.generate(now=NOW)
    a.delegate(now=NOW + 1, not_after=NOW + 10)
    create_auth_headers(a, "unregister", b"", NOW + 9, audience=AUD)
    with raises("identity_unavailable"):
        create_auth_headers(a, "unregister", b"", NOW + 10, audience=AUD)
    with raises("invalid_argument"):
        create_auth_headers(a, "webhook", b"", NOW + 9, audience=AUD)
    with raises("invalid_argument"):
        create_auth_headers(a, "unregister", b"", NOW + 9, audience=AUD, nonce="AB" * 32)


@pytest.mark.parametrize("value", BAD_CLOCK_VALUES)
def test_bad_injected_clock_is_invalid_argument(value):
    with raises("invalid_argument") as info:
        unix_now(lambda: value)
    assert str(info.value) == "invalid_argument: clock must return integer Unix seconds"


def test_finite_float_clock_is_floored():
    assert unix_now(lambda: NOW + 0.9) == NOW
    assert unix_now(lambda: 0.0) == 0 and unix_now(lambda: (1 << 53) - 1) == (1 << 53) - 1
    assert unix_now(lambda: Fraction(2 * NOW + 1, 2)) == NOW


@pytest.mark.parametrize(
    "audience, ok",
    [
        ("https://relay.example", True),
        ("http://127.0.0.1:8080", True),  # a relay's loopback development setup
        ("http://[::1]:8080", True),
        ("http://relay.example", False),  # production HTTP is not a canonical relay URL (02)
    ],
)
def test_audience_must_be_https_or_loopback_http(audience, ok):
    a = SoftwareIdentity.generate(now=NOW)
    if ok:
        create_auth_headers(a, "unregister", b"", NOW, audience=audience)
    else:
        with raises("invalid_argument"):
            create_auth_headers(a, "unregister", b"", NOW, audience=audience)
