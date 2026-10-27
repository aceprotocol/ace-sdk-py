"""PrekeyVault peer prekeys: offered, in-use and held keys (04 § Peer prekeys)."""

import json
import os
import stat

import pytest

from ace import PrekeyVault, SoftwareIdentity
from ace._encoding import to_base64
from ace.limits import OFFLINE_WINDOW_SECONDS as W
from ace.prekeys import Prekey, prekey_id, prekey_public_key
from tests.helpers import raises

now = 1_760_140_800
PIN = "a" * 64
OTHER_PIN = "b" * 64
A, B, C = (SoftwareIdentity.generate().get_ace_id() for _ in range(3))


def _prekey(i: int) -> Prekey:
    public = prekey_public_key(bytes([i]) * 32)
    return Prekey(prekey_id(public), public)


P1, P2, P3 = _prekey(1), _prekey(2), _prekey(3)


@pytest.fixture(params=["memory", "file"])
def vault(request, tmp_path):
    return PrekeyVault() if request.param == "memory" else PrekeyVault(tmp_path / "prekeys.json")


def test_offer_is_stable_until_used(vault):
    k = vault.offer(B, now)
    assert vault.offer(B, now + 1) == k and k.id == prekey_id(k.public_key)
    assert vault.open(k.id, now, sender=B).public_key == k.public_key
    vault.used(B, k.id, now)
    k2 = vault.offer(B, now)
    assert k2.id != k.id
    assert vault.open(k.id, now, sender=B).public_key == k.public_key  # in use
    with raises("unknown_prekey"):
        vault.open(k.id, now, sender=C)  # offered to another peer
    with raises("unknown_prekey"):
        vault.open(k.id, now)  # peer seeds are searched only for a sender


def test_offers_are_per_peer(vault):
    assert vault.offer(B, now).id != vault.offer(C, now).id


def test_used_deletes_previous_in_use(vault):
    k1 = vault.offer(B, now)
    vault.used(B, k1.id, now)
    k2 = vault.offer(B, now)
    vault.used(B, k2.id, now)
    with raises("unknown_prekey"):
        vault.open(k1.id, now, sender=B)
    assert vault.open(k2.id, now, sender=B).public_key == k2.public_key


def test_in_use_unchanged_on_reuse(vault):
    k1 = vault.offer(B, now)
    vault.used(B, k1.id, now)
    k2 = vault.offer(B, now)
    vault.used(B, k2.id, now)
    k3 = vault.offer(B, now)
    vault.used(B, k2.id, now + 1)  # the in-use key again: nothing changes
    assert vault.open(k2.id, now + 1, sender=B).public_key == k2.public_key
    assert vault.offer(B, now + 1) == k3
    vault.used(B, "f" * 64, now)  # an unknown ID changes nothing
    assert vault.offer(B, now + 1) == k3


def test_seed_expiry(vault):
    k = vault.offer(B, now)
    assert vault.open(k.id, now + W - 1, sender=B) is not None
    with raises("unknown_prekey"):
        vault.open(k.id, now + W, sender=B)
    assert B not in vault._state.peers  # the expired seed it met was deleted
    assert vault.offer(B, now + W).id != k.id


def test_offer_refreshes_the_window(vault):
    k = vault.offer(B, now)
    assert vault.offer(B, now + W - 1) == k  # carried again: its window restarts
    assert vault.open(k.id, now + W, sender=B) is not None
    vault.used(B, k.id, now + W)
    assert vault.open(k.id, now + 2 * W - 2, sender=B) is not None
    with raises("unknown_prekey"):
        vault.open(k.id, now + 2 * W - 1, sender=B)


def test_published_prekeys_open_without_and_with_sender(vault):
    pub = vault.current(now)
    assert vault.open(pub.id, now) is not None
    assert vault.open(pub.id, now, sender=B) is not None


def test_hold_newest_wins(vault):
    vault.hold(A, P1, 100, PIN)
    vault.hold(A, P2, 90, PIN)
    assert vault.held(A, PIN, 100) == P1
    vault.hold(A, P2, 100, PIN)  # equal timestamp: not newer
    assert vault.held(A, PIN, 100) == P1
    vault.hold(A, P3, 101, PIN)
    assert vault.held(A, PIN, 101) == P3


def test_held_pin_and_window(vault):
    vault.hold(A, P1, now, PIN)
    assert vault.held(A, OTHER_PIN, now) is None
    assert vault.held(A, PIN, now) is None  # deleted by the mismatch
    vault.hold(A, P1, now, PIN)
    assert vault.held(A, PIN, now + W - 1) == P1
    assert vault.held(A, PIN, now + W) is None
    assert vault.held(A, PIN, now) is None  # deleted once the window ended
    assert vault.held(C, PIN, now) is None  # nothing held


def test_hold_checks_its_arguments(vault):
    with raises("invalid_argument"):
        vault.hold(A, Prekey(P2.id, P1.public_key), now, PIN)
    with raises("invalid_argument"):
        vault.hold(A, P1, now, "A" * 64)
    with raises("invalid_argument"):
        vault.hold(A, P1, -1, PIN)


def test_drop_held(vault):
    vault.hold(A, P1, now, PIN)
    vault.drop_held(A)
    assert vault.held(A, PIN, now) is None
    vault.drop_held(A)  # nothing held: no error


def test_prune_removes_empty_peer(vault):
    k = vault.offer(B, now)
    vault.hold(A, P1, now + 10, PIN)
    vault.prune(now + W - 1)
    assert set(vault._state.peers) == {A, B}
    vault.prune(now + W)
    assert set(vault._state.peers) == {A}
    with raises("unknown_prekey"):
        vault.open(k.id, now, sender=B)
    vault.prune(now + 10 + W)
    assert vault._state.peers == {}


def test_drop_held_removes_empty_peer(vault):
    vault.hold(A, P1, now, PIN)
    vault.drop_held(A)
    assert vault._state.peers == {}


def test_version_1_file_is_storage_failed(tmp_path):
    path = tmp_path / "prekeys.json"
    doc = {"version": 1, "current": None, "retired": []}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    with raises("storage_failed"):
        PrekeyVault(path)


def test_file_format_version_2(tmp_path):
    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    pub = v.current(now)
    v.rotate(now + 1)
    k = v.offer(B, now)
    v.hold(A, P1, now, PIN)
    doc = json.loads(path.read_bytes())
    assert doc["version"] == 2 and set(doc) == {"version", "current", "retained", "peers"}
    assert [r["supersededAt"] for r in doc["retained"]] == [now + 1]
    assert doc["peers"][B]["offered"]["offeredAt"] == now
    assert doc["peers"][B]["inUse"] is None and doc["peers"][B]["held"] is None
    assert doc["peers"][A]["held"] == {
        "publicKey": to_base64(P1.public_key),
        "timestamp": now,
        "pin": PIN,
    }
    assert doc["peers"][A]["offered"] is None
    again = PrekeyVault(path)
    assert again.open(pub.id, now + 2) is not None
    assert again.open(k.id, now, sender=B) is not None
    assert again.held(A, PIN, now) == P1


def test_file_mode_0600_kept(tmp_path):
    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    k = v.offer(B, now)
    v.used(B, k.id, now)
    v.hold(A, P1, now, PIN)
    v.held(A, OTHER_PIN, now)
    v.drop_held(A)
    v.prune(now)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    os.chmod(path, 0o644)
    with raises("storage_failed"):
        PrekeyVault(path)


def test_file_vaults_sharing_a_path_see_each_others_peer_keys(tmp_path):
    path = tmp_path / "prekeys.json"
    send, receive = PrekeyVault(path), PrekeyVault(path)
    k = send.offer(B, now)
    assert receive.open(k.id, now, sender=B) is not None
    receive.used(B, k.id, now)
    assert send.offer(B, now).id != k.id
    receive.hold(A, P1, now, PIN)
    assert send.held(A, PIN, now) == P1


def test_failed_write_leaves_peer_state_unchanged(tmp_path, monkeypatch):
    import ace.prekeys

    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    k = v.offer(B, now)

    def fail(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(ace.prekeys, "write_file_atomic", fail)
    with raises("storage_failed"):
        v.used(B, k.id, now)
    with raises("storage_failed"):
        v.hold(A, P1, now, PIN)
    assert v.offer(B, now) == k and v._state.peers[B].in_use is None
    assert A not in v._state.peers


def test_peers_are_ace_ids(vault, tmp_path):
    for bad in ("b", "", None, A.upper()):
        with raises("invalid_argument"):
            vault.offer(bad, now)
        with raises("invalid_argument"):
            vault.hold(bad, P1, now, PIN)
    path = tmp_path / "bad.json"
    doc = {
        "version": 2,
        "current": None,
        "retained": [],
        "peers": {"b": {"offered": None, "inUse": None, "held": None}},
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    with raises("storage_failed"):
        PrekeyVault(path)


def test_held_public_key_that_is_not_an_xwing_key_is_storage_failed(tmp_path):
    path = tmp_path / "prekeys.json"
    held = {"publicKey": to_base64(b"\xff" * 1216), "timestamp": now, "pin": PIN}
    doc = {
        "version": 2,
        "current": None,
        "retained": [],
        "peers": {A: {"offered": None, "inUse": None, "held": held}},
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    with raises("storage_failed"):
        PrekeyVault(path)
    held["publicKey"] = to_base64(P1.public_key)  # the same file with a valid key loads
    os.chmod(path, 0o600)
    with open(path, "w") as f:
        json.dump(doc, f)
    assert PrekeyVault(path).held(A, PIN, now) == P1
