"""Profile manifests (08): data-only message schemas identified by immutable digests.

    profile digest = SHA-256(canonical(manifest))
    message digest = SHA-256(canonical({type, schema}))

The official manifests ``ace:core:1`` (receipt, contact; always installed, never announced),
``ace:text:1`` and ``ace:commerce:1`` are bundled as package data. Third-party manifests may not
use the reserved ``ace:`` prefix. Installing a profile grants no host effect.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from importlib import resources
from typing import Iterable

from ._encoding import (
    MAX_SAFE_INTEGER as _MAX_SAFE,
    canonical_state_bytes,
    is_namespaced_id,
    sha256_hex,
)
from .errors import ACEError
from .limits import MAX_DESCRIPTOR_PROFILES, MAX_MANIFEST_BYTES

_TYPES = {"object", "array", "string", "integer", "boolean", "null"}
_SPECIFIC = {
    "object": {"properties", "required", "additionalProperties"},
    "array": {"items", "maxItems"},
    "string": {"maxLength"},
    "integer": {"minimum", "maximum"},
}
RECEIPT_TYPE = "ace:receipt:1"
CONTACT_TYPE = "ace:contact:1"


def _fail(message: str) -> None:
    raise ACEError("invalid_argument", message)


def _integer(v: object) -> bool:
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and abs(v) <= _MAX_SAFE
        and int(v) == v
    )


def _matches(s: dict, value: object) -> bool:
    if "enum" in s and not any(
        canonical_state_bytes(x) == canonical_state_bytes(value) for x in s["enum"]
    ):
        return False
    t = s["type"]
    if t == "object":
        return (
            isinstance(value, dict)
            and all(k in value for k in s["required"])
            and all(
                _matches(s["properties"][k], v)
                if k in s["properties"]
                else s["additionalProperties"]
                for k, v in value.items()
            )
        )
    if t == "array":
        return (
            isinstance(value, list)
            and len(value) <= s.get("maxItems", _MAX_SAFE)
            and all(_matches(s["items"], v) for v in value)
        )
    if t == "string":
        return isinstance(value, str) and len(value) <= s.get("maxLength", _MAX_SAFE)
    if t == "integer":
        return (
            _integer(value) and s.get("minimum", -_MAX_SAFE) <= value <= s.get("maximum", _MAX_SAFE)  # type: ignore[operator]
        )
    if t == "boolean":
        return isinstance(value, bool)
    return value is None


def _check(s: object, depth: int = 0) -> None:
    if (
        not isinstance(s, dict)
        or depth > 8
        or not isinstance(s.get("type"), str)
        or s["type"] not in _TYPES
        or set(s) - ({"type", "enum"} | _SPECIFIC.get(s["type"], set()))
    ):
        _fail("unsupported profile schema")
    assert isinstance(s, dict)
    if s["type"] == "object":
        p, r = s.get("properties"), s.get("required")
        if (
            not isinstance(p, dict)
            or len(p) > 64
            or not isinstance(r, list)
            or not all(isinstance(k, str) and k in p for k in r)
            or len(set(r)) != len(r)
            or not isinstance(s.get("additionalProperties"), bool)
        ):
            _fail("object schema needs properties, required and additionalProperties")
        for child in p.values():  # type: ignore[union-attr]
            _check(child, depth + 1)
    if s["type"] == "array":
        _check(s.get("items"), depth + 1)
    for k in ("maxItems", "maxLength", "minimum", "maximum"):
        if k in s and (not _integer(s[k]) or k in ("maxItems", "maxLength") and s[k] < 0):
            _fail("invalid schema bound")
    if s.get("minimum", -_MAX_SAFE) > s.get("maximum", _MAX_SAFE):
        _fail("inverted schema bounds")
    if "enum" in s:
        base = {k: v for k, v in s.items() if k != "enum"}
        if (
            not isinstance(s["enum"], list)
            or not 1 <= len(s["enum"]) <= 64
            or not all(_matches(base, v) for v in s["enum"])
        ):
            _fail("invalid schema enum")


def _reserved(v: str) -> bool:
    return v.startswith("ace:")


def message_digest(type_: str, schema: dict) -> str:
    return sha256_hex(canonical_state_bytes({"type": type_, "schema": schema}))


@dataclass(frozen=True)
class MessageSchema:
    type: str
    digest: str
    schema: dict


class ProfileManifest:
    """A validated manifest. ``ProfileManifest(value)`` is for third-party manifests (the
    reserved prefixes are rejected); the official ones are ``CORE``, ``TEXT``, ``DELEGATION``,
    ``COMMERCE``."""

    def __init__(self, value: object, *, _official: bool = False) -> None:
        if (
            not isinstance(value, dict)
            or set(value) != {"id", "messages"}
            or not is_namespaced_id(value["id"])
            or not isinstance(value["messages"], list)
            or not 1 <= len(value["messages"]) <= 32
        ):
            _fail("invalid profile manifest")
        assert isinstance(value, dict)
        if not _official and _reserved(value["id"]):
            _fail("the ace: prefix is reserved")
        canonical = canonical_state_bytes(value)
        if len(canonical) > MAX_MANIFEST_BYTES:
            _fail("oversized profile manifest")
        messages: dict[str, MessageSchema] = {}
        for m in value["messages"]:
            if (
                not isinstance(m, dict)
                or set(m) != {"type", "schema"}
                or not is_namespaced_id(m["type"])
                or (not _official and _reserved(m["type"]))
                or m["type"] in messages
            ):
                _fail("invalid or duplicate profile message type")
            _check(m["schema"])
            if m["schema"]["type"] != "object":
                _fail("message schema must describe an object")
            messages[m["type"]] = MessageSchema(
                m["type"], message_digest(m["type"], m["schema"]), copy.deepcopy(m["schema"])
            )
        self.id: str = value["id"]
        self.digest: str = sha256_hex(canonical)
        self.messages: dict[str, MessageSchema] = messages
        self.official = _official
        self._value = copy.deepcopy(value)

    def to_dict(self) -> dict:
        return copy.deepcopy(self._value)

    def descriptor(self) -> dict:
        """The descriptor ``profiles`` entry ``{id, digest}``."""
        return {"id": self.id, "digest": self.digest}

    def __repr__(self) -> str:
        return f"ProfileManifest({self.id!r}, {self.digest[:12]}…)"


def _bundled(name: str) -> ProfileManifest:
    text = resources.files("ace").joinpath("manifests", f"{name}.json").read_text("utf-8")
    return ProfileManifest(json.loads(text), _official=True)


CORE = _bundled("core")
TEXT = _bundled("text")
DELEGATION = _bundled("delegation")
COMMERCE = _bundled("commerce")


class Profiles:
    """The installed profile set: ``ace:core:1`` always, plus ``manifests`` (default text)."""

    def __init__(self, manifests: Iterable[ProfileManifest] = (TEXT,)) -> None:
        installed = [CORE]
        for m in manifests:
            if not isinstance(m, ProfileManifest):
                raise ACEError("invalid_argument", "profiles must be ProfileManifest instances")
            if m.id != CORE.id:
                installed.append(m)
        if len(installed) - 1 > MAX_DESCRIPTOR_PROFILES:
            raise ACEError("limit_exceeded", f"at most {MAX_DESCRIPTOR_PROFILES} enabled profiles")
        by_type: dict[tuple[str, str], tuple[ProfileManifest, MessageSchema]] = {}
        ids: set[str] = set()
        types: set[str] = set()
        for m in installed:
            if m.id in ids:
                raise ACEError("invalid_argument", f"profile {m.id} installed twice")
            ids.add(m.id)
            for ms in m.messages.values():
                if ms.type in types:
                    raise ACEError("invalid_argument", f"message type {ms.type} installed twice")
                types.add(ms.type)
                by_type[(ms.type, ms.digest)] = (m, ms)
        self._installed = installed
        self._by_type = by_type
        self._digest = {t: d for (t, d) in by_type}

    @property
    def manifests(self) -> list[ProfileManifest]:
        return list(self._installed)

    def entries(self) -> list[dict]:
        """Descriptor ``profiles`` entries (core excluded)."""
        return [m.descriptor() for m in self._installed if m.id != CORE.id]

    def get(self, profile_id: str) -> ProfileManifest | None:
        return next((m for m in self._installed if m.id == profile_id), None)

    def supports(self, entry: object) -> bool:
        """Whether a remote ``{id, digest}`` names an installed manifest exactly."""
        m = self.get(entry.get("id")) if isinstance(entry, dict) else None  # type: ignore[arg-type]
        return m is not None and m.digest == entry.get("digest")  # type: ignore[union-attr]

    def message_digest(self, type_: str) -> str:
        digest = self._digest.get(type_)
        if digest is None:
            raise ACEError("unsupported_schema", f"message type {type_[:64]!r} is not installed")
        return digest

    def validate(self, type_: str, schema_digest: str, body: object) -> None:
        """``unsupported_schema`` unless ``(type, digest)`` is installed; ``invalid_body`` unless
        the body matches its schema."""
        found = self._by_type.get((type_, schema_digest))
        if found is None:
            raise ACEError("unsupported_schema", "message type and schemaDigest are not installed")
        if not _matches(found[1].schema, body):
            raise ACEError("invalid_body", f"body does not match the {type_} schema")
