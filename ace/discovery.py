"""Peers: relay peer records, registration files, well-known fetch, profiles."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal

import base58

from ._encoding import (
    CONTROL_CHAR_RE,
    check_wire_int,
    decode_b64,
    decode_signature,
    is_ace_id,
    is_https_url,
    unix_now,
    wire_int,
)
from ._signing import build_sign_data, encode_payload, is_valid_signing_public_key, verify_signature
from .errors import ACEError, ACEErrorCode
from .identity import compute_ace_id, signing_address
from .limits import KEM_PUBLIC_KEY_SIZE, MAX_REGISTRATION_FILE_BYTES, TIMESTAMP_WINDOW_SECONDS
from .types import (
    SIGNING_SCHEMES,
    AgentProfile,
    PrincipalRecord,
    ProfilePricing,
    RegistrationFile,
    SigningScheme,
)

_MINTING = threading.local()  # module-private construction token
_CAIP2_RE = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
_AMOUNT_RE = re.compile(r"[0-9]+(\.[0-9]+)?")
_DOMAIN_RE = re.compile(
    r"[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"
)


@dataclass(frozen=True)
class VerifiedPeer:
    """A peer whose keys were verified. Obtain only from ``verify_peer_record``,
    ``verify_registration_file`` or ``verify_registration_request``.

    Only the identity and keys are verified. ``profile`` is unverified relay metadata: it is
    self-asserted by the peer and served by the relay, so never treat it as authenticated
    (name, endpoint, pricing, etc. may be anything the peer chose to publish).
    """

    ace_id: str
    scheme: SigningScheme
    signing_public_key: bytes
    encryption_public_key: bytes
    registered_at: int
    registration_signature: str | None
    source: Literal["relay", "registration"]
    profile: AgentProfile | None

    def __post_init__(self) -> None:
        # Also blocks dataclasses.replace(): a modified peer would no longer be verified.
        if getattr(_MINTING, "active", False) is not True:
            raise ACEError(
                "invalid_argument", "VerifiedPeer is created only by the verify_* functions"
            )

    @property
    def address(self) -> str:
        """ed25519: Base58 of the signing key; secp256k1: EIP-55 address."""
        return signing_address(self.scheme, self.signing_public_key)

    @property
    def principal(self) -> "PrincipalRecord | None":
        """The peer's principal record (verified when the peer was verified, 09)."""
        return None if self.profile is None else self.profile.principal


def _make_peer(**kw: Any) -> VerifiedPeer:
    _MINTING.active = True
    try:
        return VerifiedPeer(**kw)
    finally:
        _MINTING.active = False


# --- profile ------------------------------------------------------------------------


def _tag_list(items: list[str], name: str, max_count: int) -> None:
    if len(items) > max_count:
        raise ACEError("invalid_profile", f"profile.{name} has more than {max_count} items")
    for item in items:
        if len(item) > 32 or _TAG_RE.fullmatch(item) is None:
            raise ACEError("invalid_profile", f"profile.{name} items must be 1-32 of [a-z0-9-]")


def validate_profile(profile: AgentProfile | dict) -> AgentProfile:
    """Validate a discovery profile (``invalid_profile``); returns the parsed profile."""
    if isinstance(profile, dict):
        profile = AgentProfile.from_dict(profile)
    if not isinstance(profile, AgentProfile):
        raise ACEError("invalid_profile", "profile must be an AgentProfile")
    p = AgentProfile.from_dict(_raw_profile(profile))

    def text(value: str | None, name: str, lo: int, hi: int) -> None:
        if value is not None and (not lo <= len(value) <= hi or CONTROL_CHAR_RE.search(value)):
            raise ACEError(
                "invalid_profile",
                f"profile.{name} must be {lo}-{hi} characters without control characters",
            )

    text(p.name, "name", 1, 64)
    text(p.description, "description", 0, 256)
    if p.image is not None and (len(p.image) > 512 or not is_https_url(p.image)):
        raise ACEError(
            "invalid_profile", "profile.image must be an HTTPS URL of at most 512 characters"
        )
    if p.tags is not None:
        _tag_list(p.tags, "tags", 10)
    if p.capabilities is not None:
        _tag_list(p.capabilities, "capabilities", 20)
    if p.chains is not None:
        if len(p.chains) > 10 or not all(_CAIP2_RE.fullmatch(c) for c in p.chains):
            raise ACEError(
                "invalid_profile", "profile.chains must be at most 10 CAIP-2 identifiers"
            )
    if p.endpoint is not None and not is_https_url(p.endpoint):
        raise ACEError("invalid_profile", "profile.endpoint must be an HTTPS URL")
    if p.pricing is not None:
        text(p.pricing.currency, "pricing.currency", 1, 16)
        m = p.pricing.max_amount
        if m is not None and (len(m) > 32 or _AMOUNT_RE.fullmatch(m) is None):
            raise ACEError(
                "invalid_profile",
                "profile.pricing.maxAmount must match ^[0-9]+(\\.[0-9]+)?$ (1-32 chars)",
            )
    return p


def _raw_profile(p: AgentProfile) -> dict:
    """The attribute values of a (possibly hand-built) profile, for strict re-parsing."""
    d: dict[str, Any] = {
        k: getattr(p, k)
        for k in ("name", "description", "image", "tags", "capabilities", "chains", "endpoint")
    }
    pr = p.pricing
    d["pricing"] = (
        {"currency": pr.currency, "maxAmount": pr.max_amount}
        if isinstance(pr, ProfilePricing)
        else pr
    )
    pp = p.principal
    d["principal"] = pp.to_dict() if isinstance(pp, PrincipalRecord) else pp
    return d


def check_profile_principal(profile: AgentProfile | None, subject_key: bytes, now: int) -> None:
    """09 § Validation of ``profile.principal`` (``invalid_principal``)."""
    if profile is not None and profile.principal is not None:
        from .principal import validate_principal_record

        validate_principal_record(profile.principal, subject_key, now)


# --- keys / binding -------------------------------------------------------------------


def decode_signing_key(scheme: object, text: object, code: ACEErrorCode) -> bytes:
    raw = decode_b64(text, code, "signingPublicKey", max_bytes=64)
    if scheme not in SIGNING_SCHEMES or not is_valid_signing_public_key(scheme, raw):  # type: ignore[arg-type]
        raise ACEError(code, "signingPublicKey is not a valid key for the scheme")
    return raw


def decode_encryption_key(text: object, code: ACEErrorCode) -> bytes:
    raw = decode_b64(text, code, "encryptionPublicKey", max_bytes=KEM_PUBLIC_KEY_SIZE + 3)
    if len(raw) != KEM_PUBLIC_KEY_SIZE:
        raise ACEError(code, f"encryptionPublicKey must be {KEM_PUBLIC_KEY_SIZE} bytes")
    return raw


def binding_sign_data(ace_id: str, timestamp: int, enc_b64: str, sig_b64: str) -> bytes:
    return build_sign_data("register", ace_id, timestamp, encode_payload(enc_b64, sig_b64))


def decode_peer_binding(record: dict) -> tuple[str, SigningScheme, bytes, bytes, int]:
    """The unsigned part of a ``PeerRecord``: ``(ace_id, scheme, signing_key, enc_key,
    registered_at)``, with the ID bound to the signing key; failures are ``invalid_peer``."""
    code: ACEErrorCode = "invalid_peer"
    ace_id, scheme = record.get("aceId"), record.get("scheme")
    if not is_ace_id(ace_id):
        raise ACEError(code, "aceId is not an ACE ID")
    if scheme not in SIGNING_SCHEMES:
        raise ACEError(code, "unsupported scheme")
    signing_key = decode_signing_key(scheme, record.get("signingPublicKey"), code)
    if compute_ace_id(signing_key) != ace_id:
        raise ACEError(code, "aceId does not match the signing key")
    enc_key = decode_encryption_key(record.get("encryptionPublicKey"), code)
    registered_at = wire_int(record.get("registeredAt"))
    if registered_at is None:
        raise ACEError(code, "registeredAt must be an integer")
    return ace_id, scheme, signing_key, enc_key, registered_at  # type: ignore[return-value]


def verify_peer_record(record: dict, *, clock: Callable[[], int] | None = None) -> VerifiedPeer:
    """Verify a relay ``PeerRecord``; failures are ``invalid_peer``, except a present
    ``profile.principal`` that fails 09 validation (``invalid_principal``)."""
    code: ACEErrorCode = "invalid_peer"
    if not isinstance(record, dict):
        raise ACEError(code, "peer record must be an object")
    ace_id, scheme, signing_key, enc_key, registered_at = decode_peer_binding(record)
    enc_b64, sig_b64 = record["encryptionPublicKey"], record["signingPublicKey"]
    signature = record.get("registrationSignature")
    sig = decode_signature(signature, scheme, code)  # type: ignore[arg-type]
    if not verify_signature(
        binding_sign_data(ace_id, registered_at, enc_b64, sig_b64), sig, scheme, signing_key
    ):  # type: ignore[arg-type]
        raise ACEError(code, "registrationSignature does not verify")
    profile = None
    if record.get("profile") is not None:
        try:
            profile = validate_profile(record["profile"])
        except ACEError as exc:
            if exc.code == "invalid_principal":
                raise
            raise ACEError(code, exc.message) from None
    check_profile_principal(profile, signing_key, unix_now(clock))
    return _make_peer(
        ace_id=ace_id,
        scheme=scheme,
        signing_public_key=signing_key,
        encryption_public_key=enc_key,
        registered_at=registered_at,
        registration_signature=signature,
        source="relay",
        profile=profile,
    )


def verify_registration_file(
    reg: RegistrationFile | dict,
    *,
    pinned_at: int | None = None,
    clock: Callable[[], int] | None = None,
) -> VerifiedPeer:
    """Run all 01 rules (including the ID hash); failures are ``invalid_registration``.

    The peer's ``registered_at`` is ``pinned_at`` or now (a file has no signed timestamp).
    """
    code: ACEErrorCode = "invalid_registration"
    if pinned_at is not None:
        check_wire_int(pinned_at, "pinned_at")
    if isinstance(reg, dict):
        reg = RegistrationFile.from_dict(reg)
    if not isinstance(reg, RegistrationFile):
        raise ACEError("invalid_argument", "expected a RegistrationFile")
    # Re-parse to type-check hand-built dataclasses (unknown fields cannot appear here).
    reg = RegistrationFile.from_dict(reg.to_dict())
    if reg.ace != "1.0":
        raise ACEError(code, "ace must be '1.0'")
    if not is_ace_id(reg.id):
        raise ACEError(code, "id is not an ACE ID")
    if not reg.name or CONTROL_CHAR_RE.search(reg.name):
        raise ACEError(code, "name must be non-empty without control characters")
    if not is_https_url(reg.endpoint):
        raise ACEError(code, "endpoint must match the ACE HTTPS URL grammar")
    s = reg.signing
    if s.scheme not in SIGNING_SCHEMES:
        raise ACEError(code, "unsupported signing.scheme")
    if s.scheme == "ed25519":
        try:
            signing_key = base58.b58decode(s.address)
        except ValueError:
            raise ACEError(code, "signing.address is not Base58") from None
        if len(signing_key) != 32 or base58.b58encode(signing_key).decode("ascii") != s.address:
            raise ACEError(code, "signing.address must be the Base58 of a 32-byte key")
        if (
            s.signing_public_key is not None
            and decode_b64(s.signing_public_key, code, "signing.signingPublicKey") != signing_key
        ):
            raise ACEError(
                code, "signing.signingPublicKey must equal Base58Decode(signing.address)"
            )
    else:
        if s.signing_public_key is None:
            raise ACEError(code, "secp256k1 requires signing.signingPublicKey")
        signing_key = decode_signing_key("secp256k1", s.signing_public_key, code)
        if s.address.lower() != signing_address("secp256k1", signing_key).lower():
            raise ACEError(code, "signing.address does not match signing.signingPublicKey")
    if compute_ace_id(signing_key) != reg.id:
        raise ACEError(code, "id does not match the signing key")
    enc_key = decode_encryption_key(s.encryption_public_key, code)
    now = unix_now(clock)
    profile = None
    if reg.principal is not None:
        from .principal import validate_principal_record

        validated = validate_principal_record(reg.principal, bytes(signing_key), now)
        profile = AgentProfile(principal=validated)
    return _make_peer(
        ace_id=reg.id,
        scheme=s.scheme,
        signing_public_key=bytes(signing_key),
        encryption_public_key=enc_key,
        registered_at=now if pinned_at is None else pinned_at,
        registration_signature=None,
        source="registration",
        profile=profile,
    )


# --- peer binding (rollback barrier, 02) -------------------------------------------------

AdoptOutcome = Literal["adopted", "unchanged", "rotated"]


def _with_profile(pin: VerifiedPeer, profile: AgentProfile | None) -> VerifiedPeer:
    return _make_peer(
        ace_id=pin.ace_id,
        scheme=pin.scheme,
        signing_public_key=pin.signing_public_key,
        encryption_public_key=pin.encryption_public_key,
        registered_at=pin.registered_at,
        registration_signature=pin.registration_signature,
        source=pin.source,
        profile=profile,
    )


def adopt_decision(
    pin: VerifiedPeer | None, candidate: VerifiedPeer, now: int
) -> tuple[VerifiedPeer, AdoptOutcome]:
    """Internal pure rule used by PeerStore.adopt: returns the binding to store and the outcome.

    Rotation to a different encryption key requires a signed (relay) binding with a
    strictly newer ``registered_at``; an unsigned registration-file candidate is adopted
    only without a pin, or as ``unchanged`` when its key equals the pin (pin kept as is).
    """
    if candidate.registered_at > now + TIMESTAMP_WINDOW_SECONDS:
        raise ACEError("invalid_peer", "registeredAt is in the future")
    if pin is None:
        return candidate, "adopted"
    if pin.signing_public_key != candidate.signing_public_key or pin.scheme != candidate.scheme:
        raise ACEError("invalid_peer", "signing key or scheme differs from the pinned binding")
    unsigned = candidate.registration_signature is None
    if pin.encryption_public_key == candidate.encryption_public_key:
        if unsigned:
            # An unsigned (registration-file) source never changes the pinned binding, but
            # a kept candidate replaces the cached profile, including ``principal`` (02).
            return _with_profile(pin, candidate.profile), "unchanged"
        newer = candidate if candidate.registered_at > pin.registered_at else pin
        merged = _make_peer(
            ace_id=pin.ace_id,
            scheme=pin.scheme,
            signing_public_key=pin.signing_public_key,
            encryption_public_key=pin.encryption_public_key,
            registered_at=newer.registered_at,
            registration_signature=newer.registration_signature,
            source=newer.source,
            profile=candidate.profile,
        )
        return merged, "unchanged"
    if unsigned:
        raise ACEError(
            "stale_peer_binding", "an unsigned source cannot rotate a pinned encryption key"
        )
    if candidate.registered_at > pin.registered_at:
        return candidate, "rotated"
    raise ACEError("stale_peer_binding", "a different encryption key requires a newer registeredAt")


# --- well-known fetch --------------------------------------------------------------------

_V4_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
]
_V6_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "::/96",  # IPv4-compatible (deprecated); includes :: and ::1
        "::ffff:0:0:0/96",  # SIIT IPv4-translated
        "64:ff9b:1::/48",  # local-use NAT64
        "100::/64",
        "2001::/32",  # Teredo
        "2001:db8::/32",
        "2002::/16",  # 6to4
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]
_V6_EMBEDDED = [ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("64:ff9b::/96")]


def is_blocked_address(ip: str) -> bool:
    """True if the IP literal ``ip`` lies in a blocked range (08-relay § Client Rules,
    Blocked Addresses). A value that is not an IP literal is blocked (fail closed)."""
    if not isinstance(ip, str):
        return True
    if ":" in ip:  # only an IPv6 literal may carry a %zone
        ip = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        for net in _V6_EMBEDDED:
            if addr in net:
                addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
                break
        else:
            return any(addr in n for n in _V6_BLOCKED)
    return any(addr in n for n in _V4_BLOCKED)


_getaddrinfo = socket.getaddrinfo  # injectable resolver (tests)
_create_connection = socket.create_connection
_ssl_context = ssl.create_default_context  # injectable trust store (tests)


class _DeadlineSSLSocket(ssl.SSLSocket):
    """Before every send/receive, the socket timeout is set to the time left until the
    request deadline, so a peer that trickles bytes cannot stretch the total time."""

    _ace_deadline: float | None = None

    def _ace_arm(self) -> None:
        if self._ace_deadline is not None:
            left = self._ace_deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("request deadline exceeded")
            self.settimeout(left)

    def recv(self, *args: Any, **kwargs: Any) -> bytes:
        self._ace_arm()
        return super().recv(*args, **kwargs)

    def recv_into(self, *args: Any, **kwargs: Any) -> int:
        self._ace_arm()
        return super().recv_into(*args, **kwargs)

    def read(self, *args: Any, **kwargs: Any) -> Any:
        self._ace_arm()
        return super().read(*args, **kwargs)

    def send(self, *args: Any, **kwargs: Any) -> int:
        self._ace_arm()
        return super().send(*args, **kwargs)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-validated IP: no second DNS lookup; SNI and certificate
    verification still use ``domain``. ``timeout`` is a TOTAL deadline for connect,
    TLS handshake, request and response, counted from construction. Shared by the
    well-known fetch and ``post_direct`` (through ``_pinned_request``)."""

    def __init__(self, domain: str, ip: str, timeout: float, port: int = 443) -> None:
        super().__init__(domain, port, timeout=timeout)
        self._ace_ip = ip
        self._ace_deadline = time.monotonic() + timeout
        self._ace_ctx = _ssl_context()  # CERT_REQUIRED + hostname check
        self._ace_ctx.sslsocket_class = _DeadlineSSLSocket

    def _ace_left(self) -> float:
        left = self._ace_deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request deadline exceeded")
        return left

    def connect(self) -> None:
        raw = _create_connection((self._ace_ip, self.port), timeout=self._ace_left())
        try:
            raw.settimeout(self._ace_left())
            sock = self._ace_ctx.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise
        sock._ace_deadline = self._ace_deadline
        self.sock = sock


def _pinned_request(
    host: str,
    ip: str,
    port: int,
    method: str,
    target: str,
    *,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout: float,
    max_bytes: int,
) -> tuple[int, Any, bytes]:
    """One HTTPS request to the vetted ``ip`` within a total ``timeout``; reads at most
    ``max_bytes + 1`` body bytes. Returns ``(status, response, body)``. Raises ``OSError``
    (including ``TimeoutError``), ``ssl.SSLError`` or ``http.client.HTTPException``."""
    conn = _PinnedHTTPSConnection(host, ip, float(timeout), port)
    try:
        conn.request(method, target, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp, resp.read(max_bytes + 1)
    finally:
        conn.close()


def _resolve(domain: str, allow_private: bool, port: int = 443) -> list[str]:
    """Resolve once; ``blocked_address`` if ANY address is in a blocked range."""
    try:
        infos = _getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        raise ACEError("fetch_failed", f"DNS resolution failed: {exc}") from None
    ips: list[str] = []
    for *_, sockaddr in infos:
        ip = str(sockaddr[0])
        if not allow_private and is_blocked_address(ip):
            raise ACEError("blocked_address", f"{domain[:100]} resolves to a blocked address")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ACEError("fetch_failed", "no addresses resolved")
    return ips


def fetch_registration_file(
    domain: str,
    *,
    timeout: float = 10.0,
    max_bytes: int = MAX_REGISTRATION_FILE_BYTES,
    allow_private_addresses: bool = False,
) -> RegistrationFile:
    """GET ``https://<domain>/.well-known/ace.json`` with SSRF protection, then verify it.

    Connects to the vetted IP (no re-resolution), never follows redirects, requires
    ``application/json`` and reads at most ``max_bytes + 1`` bytes. ``timeout`` bounds the
    whole exchange (connect, headers and body). Network errors, timeouts, 5xx and 429 are
    ``fetch_failed``; everything else ``invalid_registration``.
    """
    if not isinstance(domain, str) or _DOMAIN_RE.fullmatch(domain) is None:
        raise ACEError("invalid_argument", "invalid domain")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
        raise ACEError("invalid_argument", "timeout must be positive")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ACEError("invalid_argument", "max_bytes must be a positive integer")
    ip = _resolve(domain, allow_private_addresses)[0]
    try:
        status, resp, body = _pinned_request(
            domain,
            ip,
            443,
            "GET",
            "/.well-known/ace.json",
            headers={"Accept": "application/json"},
            timeout=timeout,
            max_bytes=max_bytes,
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise ACEError("fetch_failed", f"fetch failed: {type(exc).__name__}: {exc}") from None
    if status >= 500 or status == 429:
        raise ACEError("fetch_failed", f"HTTP {status}", status=status)
    if status != 200:
        raise ACEError(
            "invalid_registration",
            f"HTTP {status} (redirects are not followed)",
            status=status,
        )
    media = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
    if media != "application/json":
        raise ACEError("invalid_registration", "content-type must be application/json")
    if len(body) > max_bytes:
        raise ACEError("invalid_registration", f"registration file exceeds {max_bytes} bytes")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ACEError("invalid_registration", "registration file is not JSON") from None
    reg = RegistrationFile.from_dict(data)
    verify_registration_file(reg)
    return reg
