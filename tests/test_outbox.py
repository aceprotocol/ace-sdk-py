"""Outbox (06 § Outbox)."""

import threading

import pytest

from ace import ACEError, Outbox, Profiles, decode_packet
from ace.limits import OFFLINE_WINDOW_SECONDS
from ace.outbox import _key, _pending_key, backoff
from ace.store import write_record
from tests.helpers import Clock, Party, raises


def setup():
    clock = Clock()
    a, b = Party(clock), Party(clock)
    a.peers.adopt(b.source())
    return clock, a, b, Outbox(a.identity, a.store, Profiles(), clock=clock)


def test_backoff_schedule():
    assert [backoff(n) for n in range(1, 9)] == [60, 120, 240, 480, 960, 1920, 3600, 3600]


def test_each_attempt_reencrypts_to_the_current_prekey():
    clock, a, b, ob = setup()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    sent = []
    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731
    assert ob.deliver(mid, lambda p, ag: sent.append(p), resolve).result == "sent"
    assert ob.deliver(mid, lambda p, ag: sent.append(p), resolve).result == "skipped"  # not due
    clock.now += 60
    b.vault.rotate(clock.now)
    a.peers.adopt(b.source(now=clock.now))
    assert ob.deliver(mid, lambda p, ag: sent.append(p), resolve).result == "sent"
    first, second = (decode_packet(p) for p in sent)
    assert first.message_id == second.message_id == mid
    assert first.prekey_id != second.prekey_id and second.timestamp == first.timestamp + 60
    assert (
        ob.get(mid).attempts == 2 and ob.get(mid).status == "pending"
    )  # {ok:true} is not delivery


def test_failures_back_off_and_expire():
    clock, a, b, ob = setup()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})

    def down(p, ag):
        raise ACEError("relay_unavailable", "down")

    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731
    att = ob.deliver(mid, down, resolve)
    assert att.result == "failed" and ob.get(mid).next_attempt_at == clock.now + 60
    clock.now += OFFLINE_WINDOW_SECONDS
    assert [x.status for x in ob.flush(down, resolve)] == ["expired"]


def test_interrupted_attempt_is_not_an_attempt():
    clock, a, b, ob = setup()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    before = ob.get(mid)

    def interrupted(p, ag):
        raise KeyboardInterrupt

    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731
    with pytest.raises(KeyboardInterrupt):
        ob.deliver(mid, interrupted, resolve)
    assert ob.get(mid) == before  # lease released, attempts / code / schedule untouched
    assert ob.deliver(mid, lambda p, ag: None, resolve).result == "sent"


def test_in_flight_marker_prevents_double_send():
    clock, a, b, ob = setup()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    started, release, sent = threading.Event(), threading.Event(), []

    def slow(p, ag):
        started.set()
        release.wait(5)
        sent.append(p)

    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731
    t = threading.Thread(
        target=ob.deliver,
        args=(
            mid,
            slow,
            resolve,
        ),
        kwargs={"force": True},
    )
    t.start()
    started.wait(5)
    assert ob.deliver(mid, slow, resolve, force=True).result == "skipped"
    release.set()
    t.join()
    assert len(sent) == 1


def test_receipts_settle_and_unknown_prekey_refreshes_first():
    clock, a, b, ob = setup()
    resolve_calls = []

    def resolve(ace_id, refresh=False):
        resolve_calls.append(refresh)
        return a.peers.agent(ace_id)

    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    ob.deliver(mid, lambda p, ag: None, resolve)
    used = ob.get(mid).prekey
    ob.settle(mid, "rejected", "unknown_prekey", sender=a.id, prekey=used)  # wrong sender: ignored
    assert ob.get(mid).status == "pending" and not ob.get(mid).refresh
    # a receipt naming another attempt's prekey (late or replayed), or none, is ignored (L1)
    ob.settle(mid, "rejected", "unknown_prekey", sender=b.id, prekey="0" * 64)
    ob.settle(mid, "rejected", "unknown_prekey", sender=b.id)
    assert ob.get(mid).status == "pending" and not ob.get(mid).refresh
    ob.settle(mid, "rejected", "unknown_prekey", sender=b.id, prekey=used)
    assert ob.get(mid).status == "pending" and ob.get(mid).refresh
    ob.settle(mid, "rejected", "unknown_prekey", sender=b.id, prekey=used)  # applied once
    assert ob.get(mid).status == "pending"
    # refreshed descriptor still names the prekey we used: the rejection is final
    assert ob.deliver(mid, lambda p, ag: None, resolve).status == "rejected"
    assert resolve_calls[-1] is True
    mid2 = ob.enqueue(b.id, "ace:text:1", {"message": "again"})
    ob.deliver(mid2, lambda p, ag: None, resolve)
    ob.settle(mid2, "delivered", sender=b.id)
    assert ob.get(mid2).status == "delivered"


def test_delivered_during_a_refresh_is_never_downgraded():
    clock, a, b, ob = setup()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    ob.deliver(mid, lambda p, ag: None, lambda ace_id, refresh=False: a.peers.agent(ace_id))
    ob.settle(mid, "rejected", "unknown_prekey", sender=b.id, prekey=ob.get(mid).prekey)

    def resolve(ace_id, refresh=False):  # the earlier attempt's delivery lands mid-refresh
        ob.settle(mid, "delivered", sender=b.id)
        return a.peers.agent(ace_id)  # the prekey is unchanged

    assert ob.deliver(mid, lambda p, ag: None, resolve).status == "delivered"
    e = ob.get(mid)
    assert e.status == "delivered" and e.code is None and e.in_flight_at is None


def test_expired_means_outcome_unknown_and_receipts_still_settle():
    clock, a, b, ob = setup()
    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    ob.deliver(mid, lambda p, ag: None, resolve)
    ob.abandon(mid)
    used = ob.get(mid).prekey
    ob.settle(mid, "rejected", "unknown_prekey", sender=b.id, prekey=used)  # nothing retries
    assert ob.get(mid).status == "expired" and not ob.get(mid).refresh
    ob.settle(mid, "rejected", "invalid_body", sender=b.id)
    assert ob.get(mid).status == "rejected" and ob.get(mid).code == "invalid_body"
    mid2 = ob.enqueue(b.id, "ace:text:1", {"message": "again"})
    ob.deliver(mid2, lambda p, ag: None, resolve)
    clock.now += OFFLINE_WINDOW_SECONDS
    assert ob.deliver(mid2, lambda p, ag: None, resolve).status == "expired"
    ob.settle(mid2, "delivered", sender=b.id)
    assert ob.get(mid2).status == "delivered"


def test_enqueue_validation():
    clock, a, b, ob = setup()
    with raises("invalid_body"):
        ob.enqueue(b.id, "ace:text:1", {"message": 1})
    with raises("unsupported_schema"):
        ob.enqueue(b.id, "ace:commerce:rfq:1", {"need": "x"})
    with raises("invalid_argument"):
        ob.enqueue(b.id, "ace:receipt:1", {"messageId": "x", "outcome": "delivered"})
    with raises("invalid_argument"):
        ob.enqueue(a.id, "ace:text:1", {"message": "self"})


def test_retries_scan_the_pending_index_not_the_settled_history():
    clock, a, b, ob = setup()
    done = ob.enqueue(b.id, "ace:text:1", {"message": "old"})
    ob.settle(done, "delivered", sender=b.id)
    live = ob.enqueue(b.id, "ace:text:1", {"message": "new"})
    assert a.store.list("outbox-pending/") == [_pending_key(live)]
    read = []
    real = a.store.read
    a.store.read = lambda key: (read.append(key), real(key))[1]
    resolve = lambda ace_id, refresh=False: a.peers.agent(ace_id)  # noqa: E731
    assert [x.message_id for x in ob.flush(lambda p, ag: None, resolve)] == [live]
    assert _key(done) not in read and ob.get(done).status == "delivered"


def test_stale_pending_markers_are_dropped():
    clock, a, b, ob = setup()
    mid = ob.enqueue(b.id, "ace:text:1", {"message": "hi"})
    ob.abandon(mid)
    write_record(a.store, _pending_key(mid), {"messageId": mid})  # a stale marker
    assert ob.entries("pending") == [] and a.store.list("outbox-pending/") == []


def test_prune_keeps_settled_and_expired_entries_for_the_offline_window():
    clock, a, b, ob = setup()
    delivered = ob.enqueue(b.id, "ace:text:1", {"message": "1"})
    ob.settle(delivered, "delivered", sender=b.id)
    rejected = ob.enqueue(b.id, "ace:text:1", {"message": "2"})
    ob.settle(rejected, "rejected", "invalid_body", sender=b.id)
    expired = ob.enqueue(b.id, "ace:text:1", {"message": "3"})
    ob.abandon(expired)
    pending = ob.enqueue(b.id, "ace:text:1", {"message": "4"})
    assert ob.get(delivered).settled_at == clock.now
    clock.now += OFFLINE_WINDOW_SECONDS - 1
    assert ob.prune() == 0  # outcomes stay visible for the retention period
    assert ob.get(delivered).status == "delivered" and ob.get(rejected).status == "rejected"
    clock.now += 1
    assert ob.prune() == 3
    assert [ob.get(m) for m in (delivered, rejected, expired)] == [None, None, None]
    assert ob.get(pending).status == "pending"


def test_enqueue_counts_body_depth_from_the_content_root():
    _, _, b, ob = setup()
    body: dict = {"message": "hi", "x": []}
    for _ in range(31):  # the body's deepest container at depth 32: content depth 33
        body["x"] = [body["x"]]
    with raises("invalid_body") as info:
        ob.enqueue(b.id, "ace:text:1", body)
    assert "depth" in info.value.message
    assert ob.entries() == []
