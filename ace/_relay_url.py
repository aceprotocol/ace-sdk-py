"""Canonical relay audience URLs."""

import ipaddress
import re
from urllib.parse import urlsplit

from ._encoding import is_https_url
from .errors import ACEError

_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
_HOST_RE = re.compile(r"[A-Za-z0-9.-]+")
_DEFAULT_PORTS = {"http": 80, "https": 443}
_LOOPBACK = ("localhost", "127.0.0.1", "::1")


def normalize_relay_url(url: object) -> str:
    """Normalize a relay base URL (02 § Relay URLs, 07 § Client rules); ``invalid_argument``.

    ``http``/``https`` only; no ``?``, ``#``, userinfo, whitespace or control characters
    (nothing is trimmed). The host is ASCII ``[A-Za-z0-9.-]+`` or a bracketed IPv6 literal;
    a port has no leading zero. Scheme and host are lowercased, ``:443`` (https) / ``:80``
    (http) dropped and all trailing ``/`` removed; the rest of the path is kept verbatim.
    """
    if not isinstance(url, str):
        raise ACEError("invalid_argument", "relay URL must be a string")
    if "?" in url or "#" in url or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        raise ACEError(
            "invalid_argument", "relay URL must not contain '?', '#', whitespace or controls"
        )
    scheme, sep, rest = url.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in _DEFAULT_PORTS:
        raise ACEError("invalid_argument", "relay URL must be http(s)://host[:port][/path]")
    slash = rest.find("/")
    authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    if "@" in authority:
        raise ACEError("invalid_argument", "relay URL must not contain userinfo")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ACEError("invalid_argument", "invalid relay URL host")
        host, port_part = authority[: end + 1], authority[end + 1 :]
        if port_part and not port_part.startswith(":"):
            raise ACEError("invalid_argument", "invalid relay URL host")
        try:
            if "%" in host:  # no zone in a relay URL
                raise ValueError(host)
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise ACEError("invalid_argument", "invalid relay URL IPv6 host") from None
    else:
        host, colon, port_part = authority.partition(":")
        port_part = colon + port_part
        if _HOST_RE.fullmatch(host) is None:
            raise ACEError("invalid_argument", "relay URL host must be ASCII [A-Za-z0-9.-]")
    port: int | None = None
    if port_part:
        digits = port_part[1:]
        if _PORT_RE.fullmatch(digits) is None or not 1 <= int(digits) <= 65535:
            raise ACEError(
                "invalid_argument", "relay URL port must be 1..65535 without leading zeros"
            )
        port = int(digits)
    host = host.lower()
    netloc = host if port is None or port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return f"{scheme}://{netloc}{path.rstrip('/')}"


def is_canonical_relay_url(value: object, *, allow_loopback: bool) -> bool:
    """A canonical relay URL (02 § Relay URLs): ``https``, at most 2048 characters, already in
    ``normalize_relay_url`` form, host in the ACE HTTPS URL grammar (02 § HTTPS URLs: no IP
    literal, empty label, edge hyphen or trailing dot). ``allow_loopback`` (local development)
    also admits ``http`` to a loopback host; production verifiers reject it."""
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        if normalize_relay_url(value) != value:
            return False
    except ACEError:
        return False
    url = urlsplit(value)
    if url.scheme == "https":
        return is_https_url(value)
    return allow_loopback and url.hostname in _LOOPBACK
