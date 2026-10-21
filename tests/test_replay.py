"""ReplayDetector: arguments, clone, persistence validation, quota."""

import json

from ace import ReplayDetector
from ace._encoding import canonical_state_bytes

from .helpers import raises

A, B = "ace:sha256:" + "a" * 64, "ace:sha256:" + "b" * 64


def mid(i):
    return f"00000000-0000-4000-8000-{i:012d}"


def test_defaults_use_clock():
    det = ReplayDetector(clock=lambda: 10_000)
    assert det.horizon == 9_700
    assert det.accepts(mid(1), A, 9_701) and not det.accepts(mid(1), A, 9_700)
    assert det.commit(mid(1), A, 9_800)  # floor defaults to now - 300
    assert det.export_state()["entries"] == [[mid(1), A, 9_800]]


def test_argument_validation():
    for cap in (0, -1, 1.5, True):
        with raises("invalid_argument"):
            ReplayDetector(capacity=cap)  # type: ignore[arg-type]
    det = ReplayDetector(horizon=0)
    with raises("invalid_argument"):
        det.accepts(mid(1), "", 1)
    with raises("invalid_argument"):
        det.commit("", A, 1)
    with raises("invalid_argument"):
        det.accepts("", A, 1)
    with raises("invalid_argument"):
        det.commit(mid(1), A, True)  # type: ignore[arg-type]
    with raises("invalid_argument"):
        det.commit(mid(1), A, 5, floor=-1)
    with raises("invalid_argument"):
        ReplayDetector(horizon=-1)


def test_quota_protects_honest_senders():
    det = ReplayDetector(capacity=48, horizon=0)
    assert det.commit(mid(1), B, 100, 0)
    for i in range(100):
        assert det.commit(mid(1000 + i), A, 10_000 + i, 0)
    assert not det.accepts(mid(1), B, 100)
    assert det.accepts(mid(2), B, 1)
    state = det.export_state()
    assert sum(1 for e in state["entries"] if e[1] == A) == 3
    assert state["senderHorizons"] == {A: 10_096}


def test_from_state_validation():
    good = {
        "version": 1,
        "horizon": 10,
        "senderHorizons": {A: 20},
        "entries": [[mid(1), A, 21], [mid(2), B, 11]],
    }
    det = ReplayDetector.from_state(good)
    assert canonical_state_bytes(det.export_state()) == (
        b'{"entries":[["'
        + mid(2).encode()
        + b'","'
        + B.encode()
        + b'",11],["'
        + mid(1).encode()
        + b'","'
        + A.encode()
        + b'",21]],"horizon":10,"senderHorizons":{"'
        + A.encode()
        + b'":20},"version":1}'
    )
    bad = [
        {**good, "version": 2},
        {**good, "version": True},
        {**good, "horizon": -1},
        {**good, "horizon": "10"},
        {**good, "senderHorizons": {"": 5}},
        {**good, "senderHorizons": {A: -1}},
        {**good, "entries": [[mid(1), A, 20]]},  # covered by SH[A]
        {**good, "entries": [[mid(1), B, 10]]},  # covered by H
        {**good, "entries": [[mid(1), B, 11], [mid(1), B, 12]]},  # duplicate
        {**good, "entries": [["X", B, 11]]},
        {**good, "entries": [[mid(1), "", 11]]},
        {**good, "entries": [[mid(1), B]]},
        {k: v for k, v in good.items() if k != "entries"},
        [],
    ]
    for state in bad:
        with raises("invalid_argument"):
            ReplayDetector.from_state(json.loads(json.dumps(state)))
    floaty = ReplayDetector.from_state({**good, "horizon": 10.0, "entries": [[mid(2), B, 11.0]]})
    assert floaty.export_state()["entries"] == [[mid(2), B, 11]]


def test_lazy_indexes_stay_bounded_without_changing_replay_semantics():
    det = ReplayDetector(capacity=16, horizon=0)
    oracle = ReplayDetector(capacity=16, horizon=0)
    assert det.commit(mid(1), B, 1, 0)
    assert oracle.commit(mid(1), B, 1, 0)
    for i in range(2, 2002):
        # The old entry from B prevents stale entries for A from reaching the global heap head.
        assert det.commit(mid(i), A, i, 0) == oracle.commit(mid(i), A, i, 0)
        expected = oracle.export_state()
        assert det.export_state() == expected
        oracle = ReplayDetector.from_state(expected, capacity=16)
        assert len(det._global) <= 2 * len(det._live) + 64
        assert sum(map(len, det._per_sender.values())) == det._sender_heap_size
        assert det._sender_heap_size <= 2 * len(det._live) + 64
        assert len(det._sh_heap) <= 2 * len(det._sh) + 64
    assert det.seen(mid(1), B)
    assert det.accepts(mid(3000), B, 2)
    assert det.covered(A, 2000) and not det.covered(A, 2001)
    # A later floor and horizon compaction must still work after repeated index rebuilding.
    for i in range(2002, 2050):
        sender = f"ace:sha256:{i:064x}"
        for j in range(2):
            ts = i * 2 + j
            assert det.commit(mid(ts), sender, ts, 3000) == oracle.commit(
                mid(ts), sender, ts, 3000
            )
        assert det.export_state() == oracle.export_state()
        oracle = ReplayDetector.from_state(oracle.export_state(), capacity=16)
