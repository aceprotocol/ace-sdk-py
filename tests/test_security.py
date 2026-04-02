import time
import pytest
from ace.security import check_timestamp_freshness, validate_message_id, ReplayDetector


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


def test_replay_accept_new():
    d = ReplayDetector(100)
    assert d.check_and_reserve("msg-001") is True
    assert d.check_and_reserve("msg-002") is True


def test_replay_reject_duplicate():
    d = ReplayDetector(100)
    assert d.check_and_reserve("msg-001") is True
    assert d.check_and_reserve("msg-001") is False


def test_replay_eviction():
    d = ReplayDetector(3)
    d.check_and_reserve("a")
    d.check_and_reserve("b")
    d.check_and_reserve("c")
    d.check_and_reserve("d")
    assert d.check_and_reserve("a") is True  # evicted


def test_replay_export_import():
    d = ReplayDetector(100)
    d.check_and_reserve("msg-001")
    d.check_and_reserve("msg-002")

    exported = d.export()
    assert "msg-001" in exported

    restored = ReplayDetector.from_export(exported, 100)
    assert restored.check_and_reserve("msg-001") is False
    assert restored.check_and_reserve("msg-003") is True


def test_replay_from_export_respects_capacity():
    """from_export with small capacity should only keep the most recent entries."""
    ids = [f"msg-{i:03d}" for i in range(10)]
    restored = ReplayDetector.from_export(ids, capacity=3)
    # Only the last 3 should be retained
    assert restored.check_and_reserve("msg-007") is False  # retained
    assert restored.check_and_reserve("msg-008") is False  # retained
    assert restored.check_and_reserve("msg-009") is False  # retained
    assert restored.check_and_reserve("msg-000") is True   # evicted
    assert restored.check_and_reserve("msg-006") is True   # evicted
