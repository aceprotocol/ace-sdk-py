"""Peer records, registration files, profiles, fetch, registration requests, auth headers."""

from __future__ import annotations

import base64
import socket
import ssl

import pytest

from ace import (
    AgentProfile,
    ProfilePricing,
    RegistrationFile,
    RelayAuthRequest,
    SoftwareIdentity,
    VerifiedPeer,
    create_auth_headers,
    create_registration_request,
    discovery as disc,
    fetch_registration_file,
    parse_auth_headers,
    validate_profile,
    verify_auth_headers,
    verify_peer_record,
    verify_registration_file,
    verify_registration_request,
)
from ace.registration import create_registration_file

from .helpers import raises

NOW = 1_800_000_000


def record_of(ident, ts=NOW, **override):
    r = create_registration_request(ident, timestamp=ts)
    rec = {
        "aceId": r["aceId"],
        "scheme": r["scheme"],
        "encryptionPublicKey": r["encryptionPublicKey"],
        "signingPublicKey": r["signingPublicKey"],
        "registrationSignature": r["signature"],
        "registeredAt": ts,
    }
    rec.update(override)
    return rec


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_verify_peer_record(scheme):
    ident = SoftwareIdentity.generate(scheme)
    peer = verify_peer_record(
        {**record_of(ident), "profile": {"name": "X", "unknown": 1}, "extra": True}
    )
    assert peer.source == "relay" and peer.registered_at == NOW and peer.profile.name == "X"
    assert peer.address == ident.get_address()
    other = SoftwareIdentity.generate(scheme)
    bad = [
        {"aceId": "nope"},
        {"scheme": "rsa"},
        {"aceId": other.get_ace_id()},
        {"encryptionPublicKey": base64.b64encode(b"\x00" * 1215).decode()},
        {"registeredAt": -1},
        {"registeredAt": NOW + 1},
        {"registrationSignature": None},
        {"profile": {"pricing": {"currency": "USDC", "x": 1}}},
        {"signingPublicKey": base64.b64encode(b"\x02" + b"\x00" * 32).decode()},
    ]
    for override in bad:
        with raises("invalid_peer"):
            verify_peer_record(record_of(ident, **override))
    with raises("invalid_peer"):
        verify_peer_record([])  # type: ignore[arg-type]


def test_verified_peer_cannot_be_forged():
    with raises("invalid_argument"):
        VerifiedPeer("ace:sha256:" + "0" * 64, "ed25519", b"", b"", 0, None, "relay", None)
    import dataclasses

    peer = verify_peer_record(record_of(SoftwareIdentity.generate("ed25519")))
    with raises("invalid_argument"):
        dataclasses.replace(peer, encryption_public_key=b"\x00" * 1216)


def test_verify_registration_file_rules():
    ed, secp = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("secp256k1")
    reg_ed = create_registration_file(ed, name="A", endpoint="https://a.example/ace").to_dict()
    reg_secp = create_registration_file(secp, name="B", endpoint="https://b.example/ace").to_dict()
    peer = verify_registration_file(reg_ed, clock=lambda: 42)
    assert (
        peer.registered_at == 42
        and peer.source == "registration"
        and peer.registration_signature is None
    )
    assert verify_registration_file(reg_secp, pinned_at=7).registered_at == 7
    lower = {
        **reg_secp,
        "signing": {**reg_secp["signing"], "address": reg_secp["signing"]["address"].lower()},
    }
    verify_registration_file(lower)  # case-insensitive address comparison
    with_unknown = {**reg_ed, "future": {"x": 1}, "description": None}
    verify_registration_file(with_unknown)

    def mut(reg, **kw):
        out = {**reg, **{k: v for k, v in kw.items() if k != "signing"}}
        if "signing" in kw:
            out["signing"] = {**reg["signing"], **kw["signing"]}
        return out

    bad = [
        mut(reg_ed, ace="1.1"),
        mut(reg_ed, id="ace:sha256:" + "0" * 64),
        mut(reg_ed, name=""),
        mut(reg_ed, name="a\nb"),
        mut(reg_ed, endpoint="http://a.example"),
        mut(reg_ed, tier=2),
        mut(reg_ed, tier=True),
        mut(reg_ed, signing={"scheme": "rsa"}),
        mut(reg_ed, signing={"signingPublicKey": base64.b64encode(b"\x01" * 32).decode()}),
        mut(reg_ed, signing={"address": "1" + reg_ed["signing"]["address"]}),
        mut(reg_ed, signing={"encryptionPublicKey": "AAAA"}),
        mut(reg_secp, signing={"signingPublicKey": None}),
        mut(reg_secp, signing={"address": "0x" + "0" * 40}),
        mut(reg_ed, capabilities=[{"id": "x"}]),
        mut(reg_ed, settlement=[1]),
        mut(reg_ed, chains=[{"network": "x"}]),
        {"ace": "1.0"},
    ]
    for reg in bad:
        with raises("invalid_registration"):
            verify_registration_file(reg)
    with raises("invalid_argument"):
        verify_registration_file(reg_ed, pinned_at=-1)
    assert isinstance(RegistrationFile.from_dict(reg_ed), RegistrationFile)


def test_validate_profile():
    p = validate_profile(
        {
            "name": "Agent",
            "tags": ["a-b"],
            "pricing": {"currency": "USDC", "maxAmount": "1.5"},
            "unknownField": 1,
            "image": None,
        }
    )
    assert p.pricing == ProfilePricing("USDC", "1.5") and p.image is None
    validate_profile(AgentProfile())
    bad = [
        {"name": ""},
        {"name": "x" * 65},
        {"name": "a\x7f"},
        {"description": "x" * 257},
        {"image": "http://x.example"},
        {"tags": ["UPPER"]},
        {"tags": ["a"] * 11},
        {"capabilities": ["x" * 33]},
        {"chains": ["eip155"]},
        {"endpoint": "https://"},
        {"pricing": {"currency": ""}},
        {"pricing": {"currency": "x" * 17}},
        {"pricing": {"currency": "USDC", "maxAmount": "1."}},
        {"pricing": {"currency": "USDC", "maxAmount": "-1"}},
        {"pricing": {"currency": "USDC", "maxAmount": "1" * 33}},
        {"pricing": {"currency": "USDC", "max_amount": "1"}},
        {"tags": "a"},
        {"name": 5},
    ]
    for prof in bad:
        with raises("invalid_profile"):
            validate_profile(prof)
    with raises("invalid_profile"):
        validate_profile(AgentProfile(name=5))  # type: ignore[arg-type]


def test_registration_request_modes():
    ident = SoftwareIdentity.generate("secp256k1")
    keep = create_registration_request(ident, timestamp=NOW)
    assert "profile" not in keep
    removed = create_registration_request(ident, None, timestamp=NOW)
    assert removed["profile"] is None
    replaced = create_registration_request(ident, {"name": "X", "ignored": 1}, timestamp=NOW)
    assert replaced["profile"] == {"name": "X"}
    for req in (keep, removed, replaced):
        result = verify_registration_request(req, clock=lambda: NOW)
        assert result.peer.registered_at == NOW and result.peer.source == "relay"
        assert len(result.request_digest) == 64
    assert (
        len(
            {
                verify_registration_request(r, clock=lambda: NOW).request_digest
                for r in (keep, removed, replaced)
            }
        )
        == 3
    )
    with raises("invalid_profile"):
        create_registration_request(ident, {"name": ""}, timestamp=NOW)
    with raises("invalid_argument"):
        verify_registration_request(keep, window_seconds=-1)
    with raises("invalid_registration"):
        verify_registration_request(
            {**keep, "signature": keep["signature"].upper()}, clock=lambda: NOW
        )
    with raises("invalid_registration"):
        verify_registration_request({**keep, "profile": "x"}, clock=lambda: NOW)


def test_auth_headers():
    ident = SoftwareIdentity.generate("ed25519")
    req = RelayAuthRequest.listen("5-0")
    headers = create_auth_headers(ident, req, NOW)
    auth = parse_auth_headers(
        {
            "x-ace-id": [headers["X-ACE-Id"]],
            "X-Ace-Timestamp": headers["X-ACE-Timestamp"],
            "x-ace-signature": headers["X-ACE-Signature"],
            "other": None,
        }
    )
    kw = dict(
        ace_id=ident.get_ace_id(),
        scheme="ed25519",
        signing_public_key=ident.get_signing_public_key(),
    )
    verify_auth_headers(auth, req, clock=lambda: NOW + 300, **kw)
    with raises("stale_timestamp"):
        verify_auth_headers(auth, req, clock=lambda: NOW + 301, **kw)
    with raises("invalid_signature"):
        verify_auth_headers(auth, RelayAuthRequest.listen("-"), clock=lambda: NOW, **kw)
    with raises("invalid_signature"):
        verify_auth_headers(auth, req, clock=lambda: NOW, **{**kw, "scheme": "secp256k1"})
    with raises("invalid_argument"):
        verify_auth_headers(
            auth, req, clock=lambda: NOW, **{**kw, "ace_id": "ace:sha256:" + "0" * 64}
        )
    for bad in (
        {},
        {**headers, "X-ACE-Timestamp": "01"},
        {**headers, "X-ACE-Timestamp": "9007199254740992"},
        {**headers, "X-ACE-Id": "x"},
        {**headers, "X-ACE-Signature": ""},
    ):
        with raises("invalid_argument"):
            parse_auth_headers(bad)
    for build in (
        lambda: RelayAuthRequest.listen("abc"),
        lambda: RelayAuthRequest.inbox("-", 101),
        lambda: RelayAuthRequest.inbox("-", 0),
        lambda: RelayAuthRequest.intent("x", ["a,b"]),
        lambda: RelayAuthRequest.intent("x", "ab"),
        lambda: RelayAuthRequest.intent("x", ttl=-1),
        lambda: RelayAuthRequest("bogus"),
    ):  # type: ignore[arg-type]
        with raises("invalid_argument"):
            build()
    assert RelayAuthRequest.unregister().payload() == b""


def test_blocked_addresses():
    blocked = [
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a00:1",
        "100::1",
        "2001:db8::1",
        "fc00::1",
        "fd12::1",
        "fe80::1%en0",
        "ff02::1",
    ]
    allowed = [
        "8.8.8.8",
        "1.1.1.1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2606:4700::1111",
        "172.32.0.1",
    ]
    assert all(disc.is_blocked_address(ip) for ip in blocked)
    assert not any(disc.is_blocked_address(ip) for ip in allowed)


def test_fetch_ssrf_and_argument_errors(monkeypatch):
    def fake_getaddrinfo(host, port, *a, **kw):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
        ]

    monkeypatch.setattr(disc, "_getaddrinfo", fake_getaddrinfo)
    with raises("blocked_address"):
        fetch_registration_file("example.com")

    def failing(*a, **kw):
        raise socket.gaierror("nope")

    monkeypatch.setattr(disc, "_getaddrinfo", failing)
    with raises("fetch_failed") as info:
        fetch_registration_file("example.com")
    assert info.value.is_transient
    for domain in ("localhost", "http://x.com", "a.b/c", "x.com:443"):
        with raises("invalid_argument"):
            fetch_registration_file(domain)
    with raises("invalid_argument"):
        fetch_registration_file("example.com", timeout=0)
    with raises("invalid_argument"):
        fetch_registration_file("example.com", max_bytes=0)


class _Resp:
    def __init__(self, status, ctype, body):
        self.status, self._ctype, self._body = status, ctype, body

    def getheader(self, name, default=None):
        return self._ctype if name.lower() == "content-type" else default

    def read(self, n):
        return self._body[:n]


@pytest.mark.parametrize(
    "status,ctype,body,code",
    [
        (302, "application/json", b"{}", "invalid_registration"),
        (404, "application/json", b"{}", "invalid_registration"),
        (503, "application/json", b"{}", "fetch_failed"),
        (429, "application/json", b"{}", "fetch_failed"),
        (200, "text/html", b"{}", "invalid_registration"),
        (200, "application/json; charset=utf-8", b"x" * 101, "invalid_registration"),
        (200, "application/json", b"not json", "invalid_registration"),
        (200, "application/json", b"{}", "invalid_registration"),
    ],
)
def test_fetch_response_mapping(monkeypatch, status, ctype, body, code):
    _install_fake_http(monkeypatch, _Resp(status, ctype, body))
    with raises(code):
        fetch_registration_file("example.com", max_bytes=100)


def test_fetch_success(monkeypatch):
    import json

    ident = SoftwareIdentity.generate("ed25519")
    body = json.dumps(
        create_registration_file(ident, name="A", endpoint="https://example.com/ace").to_dict()
    ).encode()
    _install_fake_http(monkeypatch, _Resp(200, "Application/JSON; charset=utf-8", body))
    assert fetch_registration_file("example.com").id == ident.get_ace_id()


def _install_fake_http(monkeypatch, resp):
    monkeypatch.setattr(
        disc,
        "_getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    class Conn:
        def __init__(self, domain, ip, timeout, port=443):
            assert (domain, ip, port) == ("example.com", "93.184.216.34", 443)

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return resp

        def close(self):
            pass

    monkeypatch.setattr(disc, "_PinnedHTTPSConnection", Conn)


def test_fetch_connects_to_validated_ip_without_re_resolving(monkeypatch):
    lookups, connects = [], []

    def resolver(host, port, *a, **kw):
        lookups.append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 443)),
        ]

    def create_connection(address, timeout=None):
        connects.append(address)
        raise OSError("unreachable in tests")

    monkeypatch.setattr(disc, "_getaddrinfo", resolver)
    monkeypatch.setattr(disc, "_create_connection", create_connection)
    with raises("fetch_failed"):
        fetch_registration_file("example.com")
    assert lookups == ["example.com"] and connects == [("93.184.216.34", 443)]
    conn = disc._PinnedHTTPSConnection("example.com", "93.184.216.34", 5)
    assert conn._ace_ctx.verify_mode == ssl.CERT_REQUIRED and conn._ace_ctx.check_hostname
    # any blocked address among the answers rejects the domain, before connecting
    monkeypatch.setattr(
        disc,
        "_getaddrinfo",
        lambda *a, **k: (
            resolver(*a, **k) + [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 443))]
        ),
    )
    connects.clear()
    with raises("blocked_address"):
        fetch_registration_file("example.com")
    assert connects == []


def test_fetch_total_deadline_against_slow_drip(monkeypatch):
    import time

    from .slow_tls import slow_drip_server

    # the well-known fetch always targets port 443: point the pinned connect at the server
    with slow_drip_server(monkeypatch, disc, b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 50) as port:
        real = disc._create_connection
        monkeypatch.setattr(
            disc, "_create_connection", lambda addr, timeout=None: real((addr[0], port), timeout)
        )
        started = time.monotonic()
        with raises("fetch_failed"):
            fetch_registration_file("ace.test", timeout=1)
        assert time.monotonic() - started < 2.5
