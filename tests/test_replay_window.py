"""Replay horizon end to end: online future drift and offline backlog."""

import types

import pytest

from ace import (
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    parse_message,
    security,
)

T = 1_800_000_000


@pytest.fixture
def clock(monkeypatch):
    c = types.SimpleNamespace(now=T)
    monkeypatch.setattr(security, "time", types.SimpleNamespace(time=lambda: c.now))
    return c


@pytest.fixture
def agents():
    return SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")


def _create(agents, timestamp):
    alice, bob = agents
    return create_message(alice, bob.get_encryption_public_key(), bob.get_ace_id(), "text",
                          {"message": "offline"}, ThreadStateMachine(), timestamp=timestamp)


def _parse(agents, msg, store, oldest_timestamp=None):
    alice, bob = agents
    return parse_message(msg, bob, alice.get_signing_public_key(), ThreadStateMachine(), store,
                         oldest_timestamp=oldest_timestamp)


def _running_store(capacity=100_000):
    # A store that has been running since before the receiver went offline.
    return ReplayDetector.from_export({"horizon": T - 7200, "senderHorizons": {}, "entries": []}, capacity)


def test_online_max_future_drift_message_cannot_be_replayed_after_5_minutes(clock, agents):
    store = ReplayDetector()
    msg = _create(agents, T + 300)
    _parse(agents, msg, store)
    clock.now = T + 450
    with pytest.raises(ValueError, match="Replay"):
        _parse(agents, msg, store)


def test_offline_floor_admits_backlog_once_and_rejects_future_or_too_old(clock, agents):
    store = _running_store()
    old = _create(agents, T - 3600)
    with pytest.raises(ValueError, match="Timestamp"):
        _parse(agents, old, store)
    assert _parse(agents, old, store, T - 7200).body == {"message": "offline"}
    with pytest.raises(ValueError, match="Replay"):
        _parse(agents, old, store, T - 7200)
    for timestamp in (T + 3600, T - 7201):
        with pytest.raises(ValueError, match="Timestamp"):
            _parse(agents, _create(agents, timestamp), store, T - 7200)


def test_fresh_store_rejects_backlog_it_cannot_vouch_for(clock, agents):
    with pytest.raises(ValueError, match="Replay"):
        _parse(agents, _create(agents, T - 3600), ReplayDetector(), T - 7200)


def test_flood_from_one_sender_does_not_block_others(clock, agents):
    mallory, bob = SoftwareIdentity.generate("ed25519"), agents[1]
    store = ReplayDetector(capacity=3)
    for _ in range(4):
        flood = create_message(mallory, bob.get_encryption_public_key(), bob.get_ace_id(), "text",
                               {"message": "flood"}, ThreadStateMachine(), timestamp=T + 300)
        parse_message(flood, bob, mallory.get_signing_public_key(), ThreadStateMachine(), store)
    assert _parse(agents, _create(agents, T), store).body == {"message": "offline"}


def test_backlog_evicted_at_capacity_cannot_be_replayed(clock, agents):
    store = _running_store(capacity=1)
    a, b = _create(agents, T - 3600), _create(agents, T - 1800)
    _parse(agents, a, store, T - 7200)
    _parse(agents, b, store, T - 7200)
    with pytest.raises(ValueError, match="Replay"):
        _parse(agents, a, store, T - 7200)


def test_backlog_evicted_by_online_floor_cannot_be_replayed(clock, agents):
    store = _running_store()
    backlog, fresh = _create(agents, T - 3600), _create(agents, T)
    _parse(agents, backlog, store, T - 7200)
    _parse(agents, fresh, store)
    assert store.horizon == T - 3600
    with pytest.raises(ValueError, match="Replay"):
        _parse(agents, backlog, store, T - 7200)
