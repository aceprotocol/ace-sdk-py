"""SSRF-safe outbound connections: resolve once, refuse blocked addresses, connect to the vetted
IP (TLS SNI and certificate checks still use the host name) within a total deadline. Internal."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from typing import Any, Callable

from .errors import ACEError

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
        "::/96",
        "::ffff:0:0:0/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
]
_V6_EMBEDDED = [ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("64:ff9b::/96")]


def _addr(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if ":" in ip:
        ip = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        for net in _V6_EMBEDDED:
            if addr in net:
                return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


def is_blocked_address(ip: object) -> bool:
    """True for private, loopback, link-local, multicast, documentation and other non-public
    ranges. A value that is not an IP literal is blocked (fail closed)."""
    addr = _addr(ip) if isinstance(ip, str) else None
    if addr is None:
        return True
    nets = _V4_BLOCKED if isinstance(addr, ipaddress.IPv4Address) else _V6_BLOCKED
    return any(addr in n for n in nets)


def is_loopback_address(ip: str) -> bool:
    addr = _addr(ip)
    return addr is not None and addr.is_loopback


_getaddrinfo = socket.getaddrinfo  # injectable resolver (tests)
_ssl_context = ssl.create_default_context  # injectable trust store (tests)


def resolve(host: str, port: int, *, allow_loopback: bool) -> str:
    """Resolve once and return the address to connect to. Every resolved address must be
    public; with ``allow_loopback`` (explicit local development) loopback ones are allowed too.
    Anything else is ``blocked_address``; resolution failure ``relay_unavailable``."""
    try:
        infos = _getaddrinfo(host.strip("[]"), port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        raise ACEError("relay_unavailable", f"DNS resolution failed: {exc}") from None
    ips = [str(sockaddr[0]) for *_, sockaddr in infos]
    for ip in ips:
        if is_blocked_address(ip) and not (allow_loopback and is_loopback_address(ip)):
            raise ACEError("blocked_address", f"{host[:100]} resolves to a blocked address")
    if not ips:
        raise ACEError("relay_unavailable", "no addresses resolved")
    return ips[0]


class _DeadlineSSLSocket(ssl.SSLSocket):
    """Arms the socket timeout with the time left before each I/O call."""

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


_context: tuple[Callable[[], ssl.SSLContext], ssl.SSLContext] | None = None
_context_lock = threading.Lock()


def _shared_context() -> ssl.SSLContext:
    """One TLS context per ``_ssl_context`` factory (loading the trust store is costly)."""
    global _context
    factory = _ssl_context
    with _context_lock:
        if _context is None or _context[0] is not factory:
            ctx = factory()
            ctx.sslsocket_class = _DeadlineSSLSocket
            _context = (factory, ctx)
        return _context[1]


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a vetted IP: no second DNS lookup; SNI and certificate verification use
    ``host``. With ``deadline`` the whole exchange is bounded (connect through response)."""

    def __init__(
        self, host: str, ip: str, port: int, timeout: float, deadline: bool = True
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ace_ip = ip
        self._ace_deadline = time.monotonic() + timeout if deadline else None
        self._ace_ctx = _shared_context()

    def _left(self) -> float:
        if self._ace_deadline is None:
            return self.timeout  # type: ignore[return-value]
        left = self._ace_deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request deadline exceeded")
        return left

    def connect(self) -> None:
        raw = socket.create_connection((self._ace_ip, self.port), timeout=self._left())
        try:
            raw.settimeout(self._left())
            sock = self._ace_ctx.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise
        sock._ace_deadline = self._ace_deadline
        self.sock = sock


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP to a vetted loopback IP (local development only)."""

    def __init__(self, host: str, ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ace_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ace_ip, self.port), timeout=self.timeout)
