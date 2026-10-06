"""ThreadStateMachine: parties, roles, snapshots, limits."""

import dataclasses

from ace import ThreadEvent, ThreadHistoryEntry, ThreadSnapshot, ThreadStateMachine

from .helpers import raises

BUYER, SELLER, THIRD = ("ace:sha256:" + c * 64 for c in "abc")
CONV = "c" * 64


def ev(i, type_, frm, to, thread="t"):
    return ThreadEvent(CONV, thread, type_, f"00000000-0000-4000-8000-{i:012d}", 1000 + i, frm, to)


def deal(local=BUYER):
    sm = ThreadStateMachine(local)
    sm.apply(ev(1, "rfq", BUYER, SELLER), {"need": "x"})
    sm.apply(ev(2, "offer", SELLER, BUYER), {})
    return sm


def test_constructor_validation():
    with raises("invalid_argument"):
        ThreadStateMachine("nope")
    with raises("invalid_argument"):
        ThreadStateMachine(BUYER, max_threads=0)
    with raises("invalid_argument"):
        ThreadStateMachine(BUYER, max_history_per_thread=True)  # type: ignore[arg-type]


def test_non_economic_and_invalid_events():
    sm = ThreadStateMachine(BUYER)
    assert sm.apply(ev(1, "text", BUYER, SELLER), {}) == "idle"
    sm.check(ev(1, "info", BUYER, BUYER), {})  # no-op, no party rules
    with raises("invalid_envelope"):
        sm.apply(ev(1, "rfq", BUYER, SELLER, thread=None), {})
    with raises("invalid_envelope"):
        sm.apply(ev(1, "bid", BUYER, SELLER), {})
    with raises("invalid_argument"):
        sm.apply("rfq", {})  # type: ignore[arg-type]


def test_allowed_types_and_snapshot():
    sm = deal()
    assert sm.allowed_types(CONV, "t", BUYER) == ["accept", "reject"]
    assert sm.allowed_types(CONV, "t", SELLER) == ["offer"]
    assert sm.allowed_types(CONV, "t", THIRD) == []
    assert sm.allowed_types(CONV, "new", THIRD) == ["rfq"]
    snap = sm.get_snapshot(CONV, "t")
    assert snap.local_ace_id == BUYER and snap.peer_ace_id == SELLER and snap.state == "offered"
    assert snap.history[1] == ThreadHistoryEntry("offer", "00000000-0000-4000-8000-000000000002", 1002, SELLER)
    assert sm.get_snapshot(CONV, "missing") is None
    assert ThreadSnapshot.from_dict(snap.to_dict()) == snap
    assert sm.remove(CONV, "t") and not sm.remove(CONV, "t")


def test_check_does_not_mutate():
    sm = deal()
    before = sm.export_state()
    sm.check(ev(3, "accept", BUYER, SELLER), {"offerId": "00000000-0000-4000-8000-000000000002"})
    assert sm.export_state() == before


def test_limits_reject_never_evict():
    sm = ThreadStateMachine(BUYER, max_threads=1, max_history_per_thread=2)
    sm.apply(ev(1, "rfq", BUYER, SELLER, "a"), {})
    with raises("limit_exceeded"):
        sm.apply(ev(2, "rfq", BUYER, SELLER, "b"), {})
    sm.apply(ev(2, "offer", SELLER, BUYER, "a"), {})
    with raises("limit_exceeded"):
        sm.apply(ev(3, "offer", SELLER, BUYER, "a"), {})
    assert sm.get_state(CONV, "a") == "offered"


def test_from_state_round_trip_and_violations():
    sm = deal(SELLER)
    snaps = sm.export_state()
    restored = ThreadStateMachine.from_state(snaps, SELLER)
    assert restored.export_state() == snaps
    with raises("invalid_argument"):
        ThreadStateMachine.from_state(snaps, BUYER)
    s = snaps[0]
    bad_cases = [
        dataclasses.replace(s, state="accepted"),
        dataclasses.replace(s, peer_ace_id=SELLER),
        dataclasses.replace(s, history=()),
        dataclasses.replace(s, history=(s.history[1], s.history[0])),
        dataclasses.replace(s, history=(s.history[0], dataclasses.replace(s.history[1], from_id=BUYER))),
        dataclasses.replace(s, history=(s.history[0], dataclasses.replace(s.history[1], from_id=THIRD))),
        dataclasses.replace(s, history=(s.history[0], dataclasses.replace(s.history[1], message_id="x"))),
        dataclasses.replace(s, conversation_id="C" * 64),
        dataclasses.replace(s, thread_id=""),
    ]
    for bad in bad_cases:
        with raises("invalid_argument"):
            ThreadStateMachine.from_state([bad], SELLER)
    with raises("invalid_argument"):
        ThreadStateMachine.from_state([s, s], SELLER)
    with raises("invalid_argument"):
        ThreadStateMachine.from_state(snaps, SELLER, max_history_per_thread=1)
    with raises("invalid_argument"):
        ThreadSnapshot.from_dict({"history": [{"timestamp": -1}]})
