"""PrekeyVault peer prekeys: offered, in-use and held keys (04 § Peer prekeys)."""

import json
import os
import stat

import pytest

from ace import PrekeyVault
from ace._encoding import to_base64
from ace.limits import OFFLINE_WINDOW_SECONDS as W
from ace.prekeys import Prekey, prekey_id, prekey_public_key
from tests.helpers import raises

now = 1_760_140_800
PIN = "a" * 64
OTHER_PIN = "b" * 64


def _prekey(i: int) -> Prekey:
    public = prekey_public_key(bytes([i]) * 32)
    return Prekey(prekey_id(public), public)


P1, P2, P3 = _prekey(1), _prekey(2), _prekey(3)


@pytest.fixture(params=["memory", "file"])
def vault(request, tmp_path):
    return PrekeyVault() if request.param == "memory" else PrekeyVault(tmp_path / "prekeys.json")


def test_offer_is_stable_until_used(vault):
    k = vault.offer("b", now)
    assert vault.offer("b", now + 1) == k and k.id == prekey_id(k.public_key)
    assert vault.open(k.id, now, sender="b").public_key == k.public_key
    vault.used("b", k.id, now)
    k2 = vault.offer("b", now)
    assert k2.id != k.id
    assert vault.open(k.id, now, sender="b").public_key == k.public_key  # in use
    with raises("unknown_prekey"):
        vault.open(k.id, now, sender="c")  # offered to another peer
    with raises("unknown_prekey"):
        vault.open(k.id, now)  # peer seeds are searched only for a sender


def test_offers_are_per_peer(vault):
    assert vault.offer("b", now).id != vault.offer("c", now).id


def test_used_deletes_previous_in_use(vault):
    k1 = vault.offer("b", now)
    vault.used("b", k1.id, now)
    k2 = vault.offer("b", now)
    vault.used("b", k2.id, now)
    with raises("unknown_prekey"):
        vault.open(k1.id, now, sender="b")
    assert vault.open(k2.id, now, sender="b").public_key == k2.public_key


def test_in_use_unchanged_on_reuse(vault):
    k1 = vault.offer("b", now)
    vault.used("b", k1.id, now)
    k2 = vault.offer("b", now)
    vault.used("b", k2.id, now)
    k3 = vault.offer("b", now)
    vault.used("b", k2.id, now + 1)  # the in-use key again: nothing changes
    assert vault.open(k2.id, now + 1, sender="b").public_key == k2.public_key
    assert vault.offer("b", now + 1) == k3
    vault.used("b", "f" * 64, now)  # an unknown ID changes nothing
    assert vault.offer("b", now + 1) == k3


def test_seed_expiry(vault):
    k = vault.offer("b", now)
    assert vault.open(k.id, now + W - 1, sender="b") is not None
    with raises("unknown_prekey"):
        vault.open(k.id, now + W, sender="b")
    assert vault.offer("b", now + W).id != k.id


def test_offer_refreshes_the_window(vault):
    k = vault.offer("b", now)
    assert vault.offer("b", now + W - 1) == k  # carried again: its window restarts
    assert vault.open(k.id, now + W, sender="b") is not None
    vault.used("b", k.id, now + W)
    assert vault.open(k.id, now + 2 * W - 2, sender="b") is not None
    with raises("unknown_prekey"):
        vault.open(k.id, now + 2 * W - 1, sender="b")


def test_published_prekeys_open_without_and_with_sender(vault):
    pub = vault.current(now)
    assert vault.open(pub.id, now) is not None
    assert vault.open(pub.id, now, sender="b") is not None


def test_hold_newest_wins(vault):
    vault.hold("a", P1, 100, PIN)
    vault.hold("a", P2, 90, PIN)
    assert vault.held("a", PIN, 100) == P1
    vault.hold("a", P2, 100, PIN)  # equal timestamp: not newer
    assert vault.held("a", PIN, 100) == P1
    vault.hold("a", P3, 101, PIN)
    assert vault.held("a", PIN, 101) == P3


def test_held_pin_and_window(vault):
    vault.hold("a", P1, now, PIN)
    assert vault.held("a", OTHER_PIN, now) is None
    assert vault.held("a", PIN, now) is None  # deleted by the mismatch
    vault.hold("a", P1, now, PIN)
    assert vault.held("a", PIN, now + W - 1) == P1
    assert vault.held("a", PIN, now + W) is None
    assert vault.held("a", PIN, now) is None  # deleted once the window ended
    assert vault.held("nobody", PIN, now) is None


def test_hold_checks_its_arguments(vault):
    with raises("invalid_argument"):
        vault.hold("a", Prekey(P2.id, P1.public_key), now, PIN)
    with raises("invalid_argument"):
        vault.hold("a", P1, now, "A" * 64)
    with raises("invalid_argument"):
        vault.hold("a", P1, -1, PIN)


def test_drop_held(vault):
    vault.hold("a", P1, now, PIN)
    vault.drop_held("a")
    assert vault.held("a", PIN, now) is None
    vault.drop_held("a")  # nothing held: no error


def test_prune_removes_empty_peer(vault):
    k = vault.offer("b", now)
    vault.hold("a", P1, now + 10, PIN)
    vault.prune(now + W - 1)
    assert set(vault._state.peers) == {"a", "b"}
    vault.prune(now + W)
    assert set(vault._state.peers) == {"a"}
    with raises("unknown_prekey"):
        vault.open(k.id, now, sender="b")
    vault.prune(now + 10 + W)
    assert vault._state.peers == {}


def test_drop_held_removes_empty_peer(vault):
    vault.hold("a", P1, now, PIN)
    vault.drop_held("a")
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
    k = v.offer("b", now)
    v.hold("a", P1, now, PIN)
    doc = json.loads(path.read_bytes())
    assert doc["version"] == 2 and set(doc) == {"version", "current", "retained", "peers"}
    assert [r["supersededAt"] for r in doc["retained"]] == [now + 1]
    assert doc["peers"]["b"]["offered"]["offeredAt"] == now
    assert doc["peers"]["b"]["inUse"] is None and doc["peers"]["b"]["held"] is None
    assert doc["peers"]["a"]["held"] == {
        "publicKey": to_base64(P1.public_key),
        "timestamp": now,
        "pin": PIN,
    }
    assert doc["peers"]["a"]["offered"] is None
    again = PrekeyVault(path)
    assert again.open(pub.id, now + 2) is not None
    assert again.open(k.id, now, sender="b") is not None
    assert again.held("a", PIN, now) == P1


def test_file_mode_0600_kept(tmp_path):
    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    k = v.offer("b", now)
    v.used("b", k.id, now)
    v.hold("a", P1, now, PIN)
    v.held("a", OTHER_PIN, now)
    v.drop_held("a")
    v.prune(now)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    os.chmod(path, 0o644)
    with raises("storage_failed"):
        PrekeyVault(path)


def test_file_vaults_sharing_a_path_see_each_others_peer_keys(tmp_path):
    path = tmp_path / "prekeys.json"
    send, receive = PrekeyVault(path), PrekeyVault(path)
    k = send.offer("b", now)
    assert receive.open(k.id, now, sender="b") is not None
    receive.used("b", k.id, now)
    assert send.offer("b", now).id != k.id
    receive.hold("a", P1, now, PIN)
    assert send.held("a", PIN, now) == P1


def test_failed_write_leaves_peer_state_unchanged(tmp_path, monkeypatch):
    import ace.prekeys

    path = tmp_path / "prekeys.json"
    v = PrekeyVault(path)
    k = v.offer("b", now)

    def fail(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(ace.prekeys, "write_file_atomic", fail)
    with raises("storage_failed"):
        v.used("b", k.id, now)
    with raises("storage_failed"):
        v.hold("a", P1, now, PIN)
    assert v.offer("b", now) == k and v._state.peers["b"].in_use is None
    assert "a" not in v._state.peers
