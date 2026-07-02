import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch

import pytest
from ace import SoftwareIdentity
from ace._utils import to_base64
from ace import discovery
from ace.discovery import (
    validate_ace_id, validate_registration_file, verify_registration_id,
    get_registration_signing_public_key, get_registration_encryption_public_key,
    fetch_registration_file, _parse_registration_json, _resolve_and_check_ssrf,
)
from ace.types import RegistrationFile, SigningConfig


def test_validate_ace_id_valid():
    assert validate_ace_id("ace:sha256:" + "a" * 64) is True


def test_validate_ace_id_invalid():
    assert validate_ace_id("invalid") is False
    assert validate_ace_id("ace:sha256:short") is False
    assert validate_ace_id("ace:md5:" + "a" * 64) is False


def _make_valid_reg() -> RegistrationFile:
    return RegistrationFile(
        ace="1.0",
        id="ace:sha256:" + "a" * 64,
        name="TestAgent",
        endpoint="https://test.example.com/ace",
        tier=0,
        signing=SigningConfig(
            scheme="ed25519",
            address="5Ht7RkVSupHeNbGWiHfwJ3RYn4RZfpAv5tk2UrQKbkWR",
            encryption_public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    )


def test_validate_reg_valid():
    validate_registration_file(_make_valid_reg())


def test_validate_reg_rejects_short_ed25519_address():
    reg = _make_valid_reg()
    reg.signing.address = "1234"
    with pytest.raises(ValueError, match="decode to 32 bytes"):
        validate_registration_file(reg)


def test_validate_reg_rejects_mismatched_ed25519_signing_key():
    identity = SoftwareIdentity.generate("ed25519")
    other = SoftwareIdentity.generate("ed25519")
    reg = identity.to_registration_file(name="Test", endpoint="https://test.com/ace")
    reg.signing.signing_public_key = to_base64(other.get_signing_public_key())

    with pytest.raises(ValueError, match="does not match"):
        validate_registration_file(reg)


def test_validate_reg_missing_endpoint():
    reg = _make_valid_reg()
    reg.endpoint = ""
    with pytest.raises(ValueError, match="endpoint"):
        validate_registration_file(reg)


def test_validate_reg_secp256k1_requires_signing_key():
    reg = _make_valid_reg()
    reg.signing = SigningConfig(
        scheme="secp256k1",
        address="0x" + "a" * 40,
        encryption_public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    with pytest.raises(ValueError, match="signingPublicKey"):
        validate_registration_file(reg)


def test_verify_registration_id_ed25519():
    id_ = SoftwareIdentity.generate("ed25519")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    assert verify_registration_id(reg) is True


def test_verify_registration_id_tampered():
    id_ = SoftwareIdentity.generate("ed25519")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    reg.id = "ace:sha256:" + "f" * 64
    assert verify_registration_id(reg) is False


def test_verify_registration_id_secp256k1():
    id_ = SoftwareIdentity.generate("secp256k1")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    assert verify_registration_id(reg) is True


def test_validate_reg_rejects_mismatched_secp256k1_address():
    id_ = SoftwareIdentity.generate("secp256k1")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    reg.signing.address = "0x" + "a" * 40
    with pytest.raises(ValueError, match="does not match"):
        validate_registration_file(reg)


def test_verify_registration_id_rejects_tampered_secp256k1_address():
    id_ = SoftwareIdentity.generate("secp256k1")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    reg.signing.address = "0x" + "f" * 40
    assert verify_registration_id(reg) is False


def test_extract_ed25519_registration_keys():
    id_ = SoftwareIdentity.generate("ed25519")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    assert get_registration_signing_public_key(reg) == id_.get_signing_public_key()
    assert get_registration_encryption_public_key(reg) == id_.get_encryption_public_key()


def test_extract_ed25519_registration_keys_rejects_mismatch():
    id_ = SoftwareIdentity.generate("ed25519")
    other = SoftwareIdentity.generate("ed25519")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    reg.signing.signing_public_key = to_base64(other.get_signing_public_key())

    with pytest.raises(ValueError, match="does not match"):
        get_registration_signing_public_key(reg)


def test_extract_secp256k1_registration_keys():
    id_ = SoftwareIdentity.generate("secp256k1")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    assert get_registration_signing_public_key(reg) == id_.get_signing_public_key()
    assert get_registration_encryption_public_key(reg) == id_.get_encryption_public_key()


# --- fetch_registration_file tests ---


def test_fetch_rejects_invalid_domain_with_path():
    with pytest.raises(ValueError, match="Invalid domain"):
        fetch_registration_file("evil.com/../../admin")


def test_fetch_rejects_domain_with_port():
    with pytest.raises(ValueError, match="Invalid domain"):
        fetch_registration_file("localhost:8080")


def test_fetch_rejects_single_label_domain():
    with pytest.raises(ValueError, match="Invalid domain"):
        fetch_registration_file("localhost")


class _DummyConn:
    closed = False

    def close(self):
        self.closed = True


class _DummyResponse:
    status = 200
    reason = "OK"

    def __init__(self, headers=None, body=b"{}", status=200):
        self._headers = headers if headers is not None else {"Content-Type": "application/json"}
        self._body = body
        self.status = status

    def getheader(self, name, default=None):
        return self._headers.get(name, default)

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]


def _patch_pinned(monkeypatch, response):
    conn = _DummyConn()
    monkeypatch.setattr("ace.discovery._urlopen_pinned", lambda domain, timeout: (conn, response))
    return conn


def test_fetch_rejects_oversized_content_length(monkeypatch):
    resp = _DummyResponse(headers={"Content-Type": "application/json", "Content-Length": str(1_048_577)})
    conn = _patch_pinned(monkeypatch, resp)
    with pytest.raises(ValueError, match="too large"):
        fetch_registration_file("example.com")
    assert conn.closed  # connection is always closed


def test_fetch_rejects_oversized_body(monkeypatch):
    class _BigBody(_DummyResponse):
        def read(self, size=-1):
            return b"a" * size

    _patch_pinned(monkeypatch, _BigBody())
    with pytest.raises(ValueError, match="too large"):
        fetch_registration_file("example.com")


def test_fetch_rejects_redirect(monkeypatch):
    resp = _DummyResponse(headers={"Location": "http://169.254.169.254/"}, body=b"", status=302)
    _patch_pinned(monkeypatch, resp)
    with pytest.raises(ValueError, match="Refusing to follow redirect"):
        fetch_registration_file("example.com")


def test_urlopen_pinned_connects_to_the_vetted_ip(monkeypatch):
    """Pinning: the socket connects to the vetted IP, and TLS/Host use the domain."""
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("93.184.216.34"))
    captured: dict = {}

    class _Sock:
        def close(self):
            pass

    def fake_create_connection(addr, timeout=None):
        captured["addr"] = addr
        return _Sock()

    class _Ctx:
        def wrap_socket(self, sock, server_hostname=None):
            captured["sni"] = server_hostname
            return sock

    class _Conn:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host

        sock = None

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return "RESP"

        def close(self):
            pass

    monkeypatch.setattr("ace.discovery.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("ace.discovery.ssl.create_default_context", lambda: _Ctx())
    monkeypatch.setattr("ace.discovery.http.client.HTTPSConnection", _Conn)

    conn, resp = discovery._urlopen_pinned("example.com", 10.0)
    assert captured["addr"] == ("93.184.216.34", 443)  # connected to the vetted IP, not re-resolved
    assert captured["sni"] == "example.com"            # TLS cert validated against the domain
    assert captured["host"] == "example.com"           # Host header is the domain
    assert resp == "RESP"


def test_parse_registration_json_ed25519():
    id_ = SoftwareIdentity.generate("ed25519")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    raw = reg.to_dict()
    parsed = _parse_registration_json(raw)
    assert parsed.ace == "1.0"
    assert parsed.id == reg.id
    assert parsed.name == "Test"
    assert parsed.signing.scheme == "ed25519"
    assert parsed.signing.address == reg.signing.address


def test_parse_registration_json_secp256k1():
    id_ = SoftwareIdentity.generate("secp256k1")
    reg = id_.to_registration_file(name="Test", endpoint="https://test.com/ace")
    raw = reg.to_dict()
    parsed = _parse_registration_json(raw)
    assert parsed.signing.scheme == "secp256k1"
    assert parsed.signing.signing_public_key == reg.signing.signing_public_key
    validate_registration_file(parsed)
    assert verify_registration_id(parsed)


def test_parse_registration_json_with_capabilities():
    id_ = SoftwareIdentity.generate("ed25519")
    from ace.types import Capability, PricingInfo
    reg = id_.to_registration_file(
        name="Test",
        endpoint="https://test.com/ace",
        capabilities=[
            Capability(
                id="translate",
                description="Translate text",
                input="text/plain",
                pricing=PricingInfo(model="per-call", amount="1.00", currency="USD"),
            )
        ],
        settlement=["crypto/instant"],
    )
    raw = reg.to_dict()
    parsed = _parse_registration_json(raw)
    assert parsed.capabilities is not None
    assert len(parsed.capabilities) == 1
    assert parsed.capabilities[0].id == "translate"
    assert parsed.capabilities[0].pricing is not None
    assert parsed.capabilities[0].pricing.amount == "1.00"
    assert parsed.settlement == ["crypto/instant"]


# --- SSRF protection tests ---


def _mock_getaddrinfo(ip_str):
    """Return a monkeypatch-ready getaddrinfo that resolves to the given IP."""
    import socket
    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip_str, port))]
    return fake_getaddrinfo


def test_check_ssrf_rejects_loopback(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("127.0.0.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _resolve_and_check_ssrf("evil.com")


def test_check_ssrf_rejects_private_10(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("10.0.0.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _resolve_and_check_ssrf("internal.corp")


def test_check_ssrf_rejects_private_192(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("192.168.1.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _resolve_and_check_ssrf("router.local")


def test_check_ssrf_rejects_link_local(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("169.254.1.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _resolve_and_check_ssrf("metadata.internal")


def test_check_ssrf_allows_public_ip(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("93.184.216.34"))
    _resolve_and_check_ssrf("example.com")  # should not raise


def test_check_ssrf_rejects_dns_failure(monkeypatch):
    import socket
    def fail(*args, **kwargs):
        raise socket.gaierror("Name resolution failed")
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", fail)
    with pytest.raises(ValueError, match="DNS resolution failed"):
        _resolve_and_check_ssrf("nonexistent.invalid")


def test_fetch_rejects_loopback_domain(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("127.0.0.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        fetch_registration_file("evil.example.com")
