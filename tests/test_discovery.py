import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch

import pytest
from ace import SoftwareIdentity
from ace._utils import to_base64
from ace.discovery import (
    validate_ace_id, validate_registration_file, verify_registration_id,
    get_registration_signing_public_key, get_registration_encryption_public_key,
    fetch_registration_file, _parse_registration_json, _check_ssrf,
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


def test_fetch_rejects_oversized_content_length(monkeypatch):
    class DummyResponse:
        status = 200
        reason = "OK"
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(1_048_577),
        }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, size=-1):
            return b"{}"

    monkeypatch.setattr("ace.discovery.urlopen", lambda req, timeout=10.0: DummyResponse())

    with pytest.raises(ValueError, match="too large"):
        fetch_registration_file("example.com")


def test_fetch_rejects_oversized_body(monkeypatch):
    class DummyResponse:
        status = 200
        reason = "OK"
        headers = {
            "Content-Type": "application/json",
        }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, size=-1):
            return b"a" * size

    monkeypatch.setattr("ace.discovery.urlopen", lambda req, timeout=10.0: DummyResponse())

    with pytest.raises(ValueError, match="too large"):
        fetch_registration_file("example.com")


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
        _check_ssrf("evil.com")


def test_check_ssrf_rejects_private_10(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("10.0.0.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _check_ssrf("internal.corp")


def test_check_ssrf_rejects_private_192(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("192.168.1.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _check_ssrf("router.local")


def test_check_ssrf_rejects_link_local(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("169.254.1.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        _check_ssrf("metadata.internal")


def test_check_ssrf_allows_public_ip(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("93.184.216.34"))
    _check_ssrf("example.com")  # should not raise


def test_check_ssrf_rejects_dns_failure(monkeypatch):
    import socket
    def fail(*args, **kwargs):
        raise socket.gaierror("Name resolution failed")
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", fail)
    with pytest.raises(ValueError, match="DNS resolution failed"):
        _check_ssrf("nonexistent.invalid")


def test_fetch_rejects_loopback_domain(monkeypatch):
    monkeypatch.setattr("ace.discovery.socket.getaddrinfo", _mock_getaddrinfo("127.0.0.1"))
    with pytest.raises(ValueError, match="non-public IP"):
        fetch_registration_file("evil.example.com")
