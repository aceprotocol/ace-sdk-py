"""PeerStore: pins, rollback barrier, TTL and relay fallback."""

from __future__ import annotations

import json

import pytest

from ace import ACEError, FileStore, MemoryStore, PeerStore, SoftwareIdentity, verify_peer_record
from ace.peers import _peer_key
from ace.registration import create_registration_file, create_registration_request

from .helpers import raises


class Clock:
    def __init__(self, t: int = 1_800_000_000) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t


class StubRelay:
    def __init__(self) -> None:
        self.records: dict[str, dict] = {}
        self.error: ACEError | None = None
        self.calls = 0

    def lookup_peer(self, ace_id):
        self.calls += 1
        if self.error is not None:
            raise self.error
        if ace_id not in self.records:
            raise ACEError("unknown_peer", "no such peer")
        return verify_peer_record(self.records[ace_id])


def relay_record(identity, ts, profile=None):
    req = (
        create_registration_request(identity, profile, ts)
        if profile
        else create_registration_request(identity, timestamp=ts)
    )
    rec = {k: req[k] for k in ("aceId", "scheme", "encryptionPublicKey", "signingPublicKey")}
    rec.update(registrationSignature=req["signature"], registeredAt=ts)
    if profile:
        rec["profile"] = profile
    return rec


def rotated(identity):
    """Same signing key, new encryption key."""
    exp = identity.export_private_key()
    other = SoftwareIdentity.generate(identity.get_signing_scheme()).export_private_key()
    return SoftwareIdentity.from_export(
        {**exp, "encryptionPrivateKey": other["encryptionPrivateKey"]}
    )


@pytest.fixture(params=["memory", "file"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else FileStore(tmp_path / "s")


def test_adopt_outcomes(store):
    clock = Clock()
    peers = PeerStore(store, clock=clock)
    bob = SoftwareIdentity.generate("ed25519")
    t = clock.t
    p1 = verify_peer_record(relay_record(bob, t - 100))
    assert peers.adopt(p1).outcome == "adopted"
    res = peers.adopt(verify_peer_record(relay_record(bob, t - 50, {"name": "Bob"})))
    assert (
        res.outcome == "unchanged"
        and res.peer.registered_at == t - 50
        and res.peer.profile.name == "Bob"
    )
    # older entry with same key keeps the newer timestamp
    assert peers.adopt(p1).peer.registered_at == t - 50
    bob2 = rotated(bob)
    with raises("stale_peer_binding"):
        peers.adopt(verify_peer_record(relay_record(bob2, t - 60)))
    res = peers.adopt(verify_peer_record(relay_record(bob2, t - 10)))
    assert (
        res.outcome == "rotated"
        and res.peer.encryption_public_key == bob2.get_encryption_public_key()
    )
    with raises("invalid_peer"):
        peers.adopt(verify_peer_record(relay_record(bob2, t + 301)))
    imposter = SoftwareIdentity.generate("secp256k1")
    assert peers.adopt(verify_peer_record(relay_record(imposter, t))).outcome == "adopted"
    assert peers.get(bob.get_ace_id()).encryption_public_key == bob2.get_encryption_public_key()


def test_registration_file_never_rotates(store):
    clock = Clock()
    peers = PeerStore(store, clock=clock)
    bob = SoftwareIdentity.generate("secp256k1")
    reg = create_registration_file(bob, name="Bob", endpoint="https://bob.example/ace")
    pinned = peers.pin_registration_file(reg, pinned_at=100)
    assert pinned.source == "registration" and pinned.registered_at == 100
    before = store.read(_peer_key(bob.get_ace_id()))
    clock.t += 1000
    assert peers.pin_registration_file(reg, pinned_at=500).registered_at == 100  # kept exactly
    # a kept candidate refreshes the cache's fetchedAt and profile (02 § Rollback Barrier);
    # the binding itself is unchanged
    after = store.read(_peer_key(bob.get_ace_id()))
    b_rec, a_rec = json.loads(before), json.loads(after)
    assert a_rec["fetchedAt"] == b_rec["fetchedAt"] + 1000
    assert {**a_rec, "fetchedAt": 0} == {**b_rec, "fetchedAt": 0}
    reg2 = create_registration_file(rotated(bob), name="Bob", endpoint="https://bob.example/ace")
    with raises("stale_peer_binding"):
        peers.pin_registration_file(reg2, pinned_at=10**9)
    # a signed relay binding with newer registeredAt may rotate a file pin
    res = peers.adopt(verify_peer_record(relay_record(rotated(bob), 200)))
    assert res.outcome == "rotated"


def test_persisted_format_and_reverify(tmp_path):
    clock = Clock()
    store = FileStore(tmp_path / "s")
    peers = PeerStore(store, clock=clock)
    bob = SoftwareIdentity.generate("ed25519")
    peers.adopt(verify_peer_record(relay_record(bob, clock.t, {"name": "Bob"})))
    raw = store.read(_peer_key(bob.get_ace_id()))
    d = json.loads(raw)
    assert raw == json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert set(d) == {
        "aceId",
        "encryptionPublicKey",
        "fetchedAt",
        "profile",
        "registeredAt",
        "registrationSignature",
        "scheme",
        "signingPublicKey",
        "source",
        "version",
    }
    assert d["fetchedAt"] == clock.t and d["source"] == "relay" and d["profile"] == {"name": "Bob"}
    # corrupt binding -> storage_failed, never overwritten
    d["registeredAt"] += 1
    store.write(_peer_key(bob.get_ace_id()), json.dumps(d).encode())
    with raises("storage_failed"):
        peers.get(bob.get_ace_id())
    with raises("storage_failed"):
        peers.adopt(verify_peer_record(relay_record(bob, clock.t)))
    store.write(_peer_key(bob.get_ace_id()), json.dumps({**d, "version": 2}).encode())
    with raises("storage_failed"):
        peers.get(bob.get_ace_id())


def test_resolve_ttl_and_fallbacks():
    clock = Clock()
    relay = StubRelay()
    peers = PeerStore(MemoryStore(), relay=relay, ttl_seconds=100, clock=clock)
    bob = SoftwareIdentity.generate("ed25519")
    with raises("unknown_peer"):
        peers.resolve(bob.get_ace_id())
    relay.records[bob.get_ace_id()] = relay_record(bob, clock.t)
    assert peers.resolve(bob.get_ace_id()).ace_id == bob.get_ace_id()
    assert relay.calls == 2
    peers.resolve(bob.get_ace_id())
    assert relay.calls == 2  # fresh pin
    clock.t += 101
    relay.error = ACEError("relay_unavailable", "down")
    assert peers.resolve(bob.get_ace_id()).ace_id == bob.get_ace_id()  # stale pin returned
    with raises("relay_unavailable"):
        peers.resolve(bob.get_ace_id(), max_age_seconds=0)
    relay.error = ACEError("storage_failed", "a local failure is retryable too")
    assert peers.resolve(bob.get_ace_id()).ace_id == bob.get_ace_id()
    relay.error = ACEError("relay_rejected", "nope")
    with raises("relay_rejected"):
        peers.resolve(bob.get_ace_id())
    relay.error = None
    del relay.records[bob.get_ace_id()]
    assert peers.resolve(bob.get_ace_id()) is not None  # unknown_peer -> pin
    # stale binding offered by the relay -> pin (maxAge > 0) or error (maxAge 0)
    relay.records[bob.get_ace_id()] = relay_record(rotated(bob), clock.t - 1000)
    assert peers.resolve(bob.get_ace_id()).encryption_public_key == bob.get_encryption_public_key()
    with raises("stale_peer_binding"):
        peers.resolve(bob.get_ace_id(), max_age_seconds=0)
    peers.remove(bob.get_ace_id())
    assert peers.get(bob.get_ace_id()) is None


def test_resolve_without_relay():
    peers = PeerStore(MemoryStore())
    bob = SoftwareIdentity.generate("ed25519")
    with raises("unknown_peer"):
        peers.resolve(bob.get_ace_id())
    peers.pin_registration_file(
        create_registration_file(bob, name="B", endpoint="https://b.example/a"), pinned_at=0
    )
    assert peers.resolve(bob.get_ace_id(), max_age_seconds=0).ace_id == bob.get_ace_id()
    with raises("invalid_argument"):
        peers.resolve("bob")


def test_file_refresh_drops_expired_cached_principal():
    from .test_principal import NOW, _file_candidate, _owner, _pin_with_principal

    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    peers, pin = _pin_with_principal(owner, me, clock, expires_at=NOW + 5)
    assert pin.principal is not None
    clock[0] = NOW + 100
    out = peers.adopt(_file_candidate(me, None)).peer
    assert out.principal is None
    assert peers.get(me.get_ace_id()).principal is None  # pin stays readable


def test_file_refresh_carries_unexpired_cached_principal():
    from .test_principal import NOW, _file_candidate, _owner, _pin_with_principal

    owner, me = _owner(), SoftwareIdentity.generate("ed25519")
    clock = [NOW]
    peers, pin = _pin_with_principal(owner, me, clock, expires_at=NOW + 500)
    clock[0] = NOW + 100
    out = peers.adopt(_file_candidate(me, None)).peer
    assert out.principal == pin.principal
    assert peers.get(me.get_ace_id()).principal == pin.principal
