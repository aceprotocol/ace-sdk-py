"""Shared test helpers."""

from __future__ import annotations

import base64
import json
import pathlib
from contextlib import contextmanager

import pytest

from ace import ACEError, SoftwareIdentity, verify_registration_file

VECTORS = json.loads((pathlib.Path(__file__).parent / "fixtures" / "test-vectors.json").read_text())


@contextmanager
def raises(code: str):
    with pytest.raises(ACEError) as info:
        yield info
    assert info.value.code == code, f"expected {code}, got {info.value.code}: {info.value.message}"


def agent(name: str) -> SoftwareIdentity:
    a = VECTORS["agents"][name]
    return SoftwareIdentity(a["scheme"], base64.b64decode(a["signingPrivateKey"]), base64.b64decode(a["encryptionPrivateKey"]))


def peer_of(identity: SoftwareIdentity, pinned_at: int = 0):
    reg = identity.to_registration_file(name="Peer", endpoint="https://peer.example/ace")
    return verify_registration_file(reg, pinned_at=pinned_at)
