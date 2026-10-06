import time

import pytest

from ace.security import ReplayDetector, check_timestamp_freshness, validate_message_id


def test_timestamp_fresh():
    now = int(time.time())
    check_timestamp_freshness(now)
    check_timestamp_freshness(now - 60)
    check_timestamp_freshness(now + 60)


def test_timestamp_stale():
    now = int(time.time())
    with pytest.raises(ValueError, match="fresh"):
        check_timestamp_freshness(now - 301)


def test_timestamp_future():
    now = int(time.time())
    with pytest.raises(ValueError, match="fresh"):
        check_timestamp_freshness(now + 301)


def test_validate_message_id_accepts_uuid_v4():
    validate_message_id("550e8400-e29b-41d4-a716-446655440000")


def test_validate_message_id_rejects_non_uuid():
    with pytest.raises(ValueError, match="UUID v4"):
        validate_message_id("msg-001")


T = 1_800_000_000


def _id(n: int) -> str:
    return f"550e8400-e29b-41d4-a716-4466554400{n:02d}"


ALICE, MALLORY = "ace:sha256:alice", "ace:sha256:mallory"


@pytest.fixture
def clock(monkeypatch):
    import types

    from ace import security
    c = types.SimpleNamespace(now=T)
    monkeypatch.setattr(security, "time", types.SimpleNamespace(time=lambda: c.now))
    return c


def test_replay_starts_with_horizon_now_minus_5_min(clock):
    assert ReplayDetector().horizon == T - 300


def test_replay_rejects_duplicates_and_timestamps_at_or_below_horizon(clock):
    d = ReplayDetector()
    assert d.commit(_id(1), ALICE, T) is True
    assert d.accepts(_id(1), ALICE, T) is False
    assert d.commit(_id(1), ALICE, T) is False
    assert d.accepts(_id(2), ALICE, T - 300) is False
    assert d.accepts(_id(2), ALICE, T - 299) is True


def test_replay_keeps_entry_until_below_floor_then_raises_horizon(clock):
    d = ReplayDetector()
    d.commit(_id(1), ALICE, T + 300)  # max future drift: acceptable until T + 600
    clock.now = T + 450
    d.commit(_id(2), ALICE, T + 450)
    assert d.accepts(_id(1), ALICE, T + 300) is False
    clock.now = T + 650
    d.commit(_id(3), ALICE, T + 650)  # floor T + 350 > T + 300: _id(1) removed
    assert d.horizon == T + 300
    assert d.accepts(_id(1), ALICE, T + 300) is False


def test_replay_fixed_earlier_floor_keeps_entries_until_capacity(clock):
    # A store that has been running since before the receiver went offline.
    d = ReplayDetector.from_export({"horizon": T - 7200, "senderHorizons": {}, "entries": []}, capacity=2)
    d.commit(_id(1), ALICE, T - 3000, T - 7200)
    d.commit(_id(2), ALICE, T - 1000, T - 7200)
    assert d.horizon == T - 7200  # nothing removed
    d.commit(_id(3), ALICE, T - 2000, T - 7200)
    assert d.horizon == T - 7200
    assert d.export()["senderHorizons"] == {ALICE: T - 3000}


def test_replay_capacity_removes_smallest_timestamp_and_raises_only_its_sender_horizon(clock):
    d = ReplayDetector(2)
    d.commit(_id(1), ALICE, T - 10)
    d.commit(_id(2), ALICE, T - 50)
    d.commit(_id(3), ALICE, T - 20)
    assert d.horizon == T - 300
    for n, ts in [(1, T - 10), (2, T - 50), (3, T - 20)]:
        assert d.accepts(_id(n), ALICE, ts) is False
    assert d.accepts(_id(4), ALICE, T - 50) is False
    assert d.accepts(_id(4), ALICE, T - 49) is True
    assert d.accepts(_id(4), MALLORY, T - 50) is True


def test_replay_flood_from_one_sender_cannot_block_others(clock):
    d = ReplayDetector(3)
    for n in range(1, 5):
        d.commit(_id(n), MALLORY, T + 300)
    assert d.horizon == T - 300
    assert d.accepts(_id(5), MALLORY, T + 300) is False
    assert d.commit(_id(5), ALICE, T) is True


def test_replay_sender_horizons_bounded_by_capacity_folding_lowest_into_horizon(clock):
    d = ReplayDetector(2)
    for n in range(1, 7):
        d.commit(_id(n), f"ace:sha256:s{n}", T + n)
    assert len(d.export()["senderHorizons"]) <= 2
    assert d.horizon > T - 300
    for n in range(1, 5):
        assert d.accepts(_id(n), f"ace:sha256:s{n}", T + n) is False


def test_replay_export_import_round_trip(clock):
    d = ReplayDetector(2)
    d.commit(_id(1), ALICE, T - 10)
    d.commit(_id(2), ALICE, T - 20)
    d.commit(_id(3), MALLORY, T - 5)  # evicts _id(2): ALICE horizon T - 20
    restored = ReplayDetector.from_export(d.export(), capacity=2)
    assert restored.horizon == d.horizon
    assert restored.export() == d.export()
    assert restored.accepts(_id(1), ALICE, T - 10) is False
    assert restored.accepts(_id(4), ALICE, T - 20) is False
    assert restored.accepts(_id(4), MALLORY, T - 20) is True


def test_replay_from_export_over_capacity_raises_sender_horizon(clock):
    entries = [[_id(1), ALICE, T - 30], [_id(2), ALICE, T - 10], [_id(3), ALICE, T - 20]]
    restored = ReplayDetector.from_export({"horizon": T - 300, "senderHorizons": {}, "entries": entries}, capacity=2)
    assert restored.horizon == T - 300
    assert restored.export()["senderHorizons"] == {ALICE: T - 30}
    assert len(restored.export()["entries"]) == 2


@pytest.mark.parametrize("state, error", [
    ({"horizon": -1, "senderHorizons": {}, "entries": []}, "invalid replay state"),
    ({"horizon": T, "entries": []}, "invalid replay state"),  # senderHorizons is required
    ({"horizon": T, "senderHorizons": {}, "entries": [[_id(1) + "\n", ALICE, T + 1]]}, "invalid message_id"),
    ({"horizon": T, "senderHorizons": {"": T}, "entries": []}, "invalid replay state"),
    ({"horizon": T, "senderHorizons": {ALICE: -1}, "entries": []}, "invalid replay state"),
    ({"horizon": T, "senderHorizons": [], "entries": []}, "invalid replay state"),
    ({"horizon": T, "senderHorizons": {}, "entries": [["msg-1", ALICE, T + 1]]}, "invalid message_id"),
    ({"horizon": T, "senderHorizons": {}, "entries": [[_id(1), T + 1]]}, "invalid message_id"),
    ({"horizon": T, "senderHorizons": {}, "entries": [[_id(1), "", T + 1]]}, "invalid entry"),
    ({"horizon": T, "senderHorizons": {}, "entries": [[_id(1), ALICE, T]]}, "invalid entry"),
    ({"horizon": T, "senderHorizons": {ALICE: T + 5}, "entries": [[_id(1), ALICE, T + 5]]}, "invalid entry"),
    ({"horizon": T, "senderHorizons": {}, "entries": [[_id(1), ALICE, T + 1], [_id(1), ALICE, T + 2]]}, "invalid entry"),
])
def test_replay_from_export_rejects_malformed_state(state, error):
    with pytest.raises(ValueError, match=error):
        ReplayDetector.from_export(state)


def test_replay_rejects_non_positive_capacity():
    with pytest.raises(ValueError, match="capacity"):
        ReplayDetector(0)


def test_replay_same_id_is_isolated_by_sender(clock):
    d = ReplayDetector()
    assert d.commit(_id(1), MALLORY, T)
    assert d.commit(_id(1), ALICE, T)
    restored = ReplayDetector.from_export(d.export())
    assert not restored.commit(_id(1), MALLORY, T)
    assert not restored.commit(_id(1), ALICE, T)


def test_replay_same_second_eviction_survives_restart(clock):
    d = ReplayDetector(2)
    for n in range(1, 4):
        assert d.commit(_id(n), ALICE, T)
    restored = ReplayDetector.from_export(d.export(), 2)
    for n in range(1, 4):
        assert not restored.accepts(_id(n), ALICE, T)
    assert restored.commit(_id(1), MALLORY, T)
    assert ReplayDetector.from_export(restored.export(), 2).export() == restored.export()
