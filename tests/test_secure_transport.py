import hashlib
import json
import os

import pytest

from ace import ACEError
from ace.secure_transport import SECURE_DELIVERY_SCHEMA, SECURE_DELIVERY_TYPE, SecureTransport
from ace.session import MLSError, NativeMLSEngine

from .helpers import raises
from .pipeline import Agent, Clock, CountingStore

pytestmark = pytest.mark.skipif(
    not os.getenv("ACE_MLS_LIBRARY"), reason="explicit native integration job"
)


@pytest.fixture
def pair():
    clock = Clock()
    a, b = Agent("a", "ed25519", clock), Agent("b", "secp256k1", clock)
    a.pin(b)
    b.pin(a)
    with NativeMLSEngine(os.environ["ACE_MLS_LIBRARY"]) as engine:
        ta, tb = (
            SecureTransport(a.identity, engine, a.store, clock),
            SecureTransport(b.identity, engine, b.store, clock),
        )
        ta.set_peer_allowed(a.store, b.id, True)
        tb.set_peer_allowed(b.store, a.id, True)
        inbox = b.open()
        pending = a.outbox.stage(
            a.peers.get(b.id), "text", {"message": "private"}, request_id="same"
        )

        def accept(raw):
            result = inbox.receive(raw)
            assert result.kind in ("delivered", "duplicate"), result
            return result.kind

        yield clock, a, b, ta, tb, pending, accept, engine
        ta.close()
        tb.close()
        inbox.close()


def test_real_pipeline_and_fresh_retry(pair):
    _, a, b, ta, tb, pending, accept, _ = pair
    counting = CountingStore(a.store)
    ta.store = counting
    frames = []

    def exchange(p, _):
        frames.append(p)
        return tb.respond(p, b.peers.get(a.id), accept)

    ta.deliver(pending.message, a.peers.get(b.id), exchange)
    a.outbox.deliver("same", lambda p: ta.deliver(p, a.peers.get(b.id), exchange))
    assert len(b.host.calls) == 1
    assert not a.outbox.pending()
    assert not any(k.startswith("secure/out/") for k in counting.writes)  # no sender journal
    assert a.store.list("secure/") == [k for k in a.store.list("secure/peers/")]
    rows = [json.loads(b.store.read(k)) for k in b.store.list("secure/in/")]
    assert sorted(r["outcome"] for r in rows) == ["delivered", "duplicate"]
    assert all(r["envelope"] is None and r["response"] is not None for r in rows)
    assert all("delivered" not in r for r in rows)
    assert SECURE_DELIVERY_TYPE == "urn:ace:secure-delivery:2"
    contract = (
        b"ace.secure-delivery.v2:hello,offer,data,ack;fresh-pairwise-mls;exact-envelope;"
        b"outcome-receipt;120s"
    )
    assert SECURE_DELIVERY_SCHEMA == hashlib.sha256(contract).hexdigest()


def test_rejected_envelope_receipt_round_trip(pair):
    clock, a, b, ta, tb, _, _, _ = pair
    b.inbox.close()
    digest = "ab" * 32

    def validator(m):
        assert set(m) == {"type", "schemaDigest", "threadId", "body"}
        if m["body"].get("task") != "ok":
            raise ACEError("bad_reference", "no such task")

    inbox = b.open(schemas={digest: validator})
    outcomes = []

    def accept(raw):
        outcome = inbox.receive(raw)
        outcomes.append(outcome)
        return f"rejected:{outcome.error.code}" if outcome.kind == "quarantined" else outcome.kind

    data = []

    def exchange(p, route):
        if route["kind"] == "ack":
            data.append(p)
        return tb.respond(p, b.peers.get(a.id), accept)

    bad = a.outbox.stage(
        a.peers.get(b.id), "urn:example:task", {"task": "no"}, schema_digest=digest, request_id="r"
    )
    with raises("delivery_rejected") as info:
        a.outbox.deliver("r", lambda p: ta.deliver(p, a.peers.get(b.id), exchange))
    assert info.value.remote_code == "bad_reference" and info.value.category == "permanent"
    assert [o.kind for o in outcomes] == ["quarantined"]
    assert outcomes[0].error.code == "bad_reference"
    assert b.store.read(f"quarantine/{outcomes[0].fingerprint}.json") is not None
    assert a.outbox.pending()[0].request_id == "r"  # permanent: the host decides to abandon
    (row_key,) = b.store.list("secure/in/")
    row = json.loads(b.store.read(row_key))
    assert row["outcome"] == "rejected:bad_reference" and row["envelope"] is None
    assert set(row) == {
        "version",
        "peer",
        "expiresAt",
        "generation",
        "input",
        "envelope",
        "response",
        "outcome",
    }
    # a replayed data frame re-sends the same receipt, without a second handover
    replay = tb.respond(data[0], b.peers.get(a.id), accept)
    assert replay.to_dict() == row["response"] and len(outcomes) == 1
    a.outbox.abandon("r")
    good = a.outbox.stage(
        a.peers.get(b.id), "urn:example:task", {"task": "ok"}, schema_digest=digest, request_id="g"
    )
    a.outbox.deliver("g", lambda p: ta.deliver(p, a.peers.get(b.id), exchange))
    assert b.host.calls == [(a.id, good.message.message_id)]
    assert [p.request_id for p in a.outbox.pending()] == ["same"]  # the fixture's own send
    assert bad.message.message_id != good.message.message_id


def test_accept_outcome_is_validated(pair):
    _, a, b, ta, tb, pending, _, _ = pair
    for bogus in (None, "accepted", "rejected:Bad-Code", "rejected:" + "a" * 65):
        with pytest.raises(MLSError, match="invalid_delivery_outcome"):
            ta.deliver(
                pending.message,
                a.peers.get(b.id),
                lambda p, _: tb.respond(p, b.peers.get(a.id), lambda raw: bogus),
            )
    assert not b.host.calls


def test_forged_receipt_outcome_is_rejected(pair):
    _, a, b, ta, tb, pending, accept, _ = pair
    from ace import secure_transport as st

    original = st._proof

    def forged(f, outcome=""):
        return original(f, "paid" if outcome else "")

    st._proof = forged
    try:
        with pytest.raises(MLSError, match="invalid_delivery_receipt"):
            ta.deliver(
                pending.message,
                a.peers.get(b.id),
                lambda p, _: tb.respond(p, b.peers.get(a.id), accept),
            )
    finally:
        st._proof = original


def test_no_downgrade_or_revoked_peer(pair):
    _, a, b, ta, tb, pending, accept, _ = pair
    with pytest.raises(MLSError, match="secure_delivery_required"):
        tb.respond(pending.message, b.peers.get(a.id), accept)
    tb.set_peer_allowed(b.store, a.id, False)
    with pytest.raises(MLSError, match="delivery_peer_disabled"):
        ta.deliver(
            pending.message,
            a.peers.get(b.id),
            lambda p, _: tb.respond(p, b.peers.get(a.id), accept),
        )
    assert not b.host.calls


def test_failed_handover_kills_the_attempt_and_a_fresh_attempt_is_deduplicated(pair):
    clock, a, b, ta, tb, pending, accept, engine = pair
    state = {"receiver": tb, "fail": True, "restart": False}
    frames = []

    def commit_then_fail(raw):  # the Inbox committed, the receipt was never released
        outcome = accept(raw)
        if state["fail"]:
            state["fail"] = False
            raise RuntimeError("crash after commit")
        return outcome

    def exchange(packet, route):
        frames.append(packet)
        if state["restart"]:
            state["restart"] = False
            state["receiver"].close()  # the receiver process is lost
            state["receiver"] = SecureTransport(b.identity, engine, b.store, clock)
        return state["receiver"].respond(packet, b.peers.get(a.id), commit_then_fail)

    try:
        with pytest.raises(RuntimeError):
            ta.deliver(pending.message, a.peers.get(b.id), exchange)
        (row_key,) = b.store.list("secure/in/")
        row = json.loads(b.store.read(row_key))
        assert row["outcome"] is None and row["envelope"] is not None
        assert row["response"] is None
        # the context is gone: a replayed data frame is session_closed, in or out of process
        with pytest.raises(MLSError, match="session_closed"):
            tb.respond(frames[-1], b.peers.get(a.id), commit_then_fail)
        state["restart"] = True
        with pytest.raises(MLSError, match="session_closed"):
            state["receiver"].respond(frames[-1], b.peers.get(a.id), commit_then_fail)
        assert json.loads(b.store.read(row_key))["outcome"] is None
        # the sender's fresh attempt is deduplicated by the Inbox
        a.outbox.deliver("same", lambda p: ta.deliver(p, a.peers.get(b.id), exchange))
        assert len(b.host.calls) == 1 and not a.outbox.pending()
        rows = [json.loads(b.store.read(k)) for k in b.store.list("secure/in/")]
        assert sorted(str(r["outcome"]) for r in rows) == ["None", "duplicate"]
    finally:
        state["receiver"].close()


def test_old_offer_never_enrolls_new_group(pair):
    _, a, b, ta, tb, pending, accept, _ = pair
    old = []

    def exchange(packet, _):
        response = tb.respond(packet, b.peers.get(a.id), accept)
        if not old:
            old.append(response)
        return response

    ta.deliver(pending.message, a.peers.get(b.id), exchange)
    with pytest.raises(MLSError, match="invalid_delivery_frame"):
        ta.deliver(pending.message, a.peers.get(b.id), lambda *_: old[0])


def test_is_peer_allowed_reads_policy_without_raising(pair):
    _, a, b, ta, tb, _, _, _ = pair
    assert SecureTransport.is_peer_allowed(b.store, a.id)
    assert ta.is_peer_allowed(b.store, a.id)  # callable through an instance too
    stranger = Agent("eve", "ed25519", Clock())
    assert not SecureTransport.is_peer_allowed(b.store, stranger.id)
    assert not SecureTransport.is_peer_allowed(b.store, "not an ace id")
    tb.set_peer_allowed(b.store, a.id, False)
    assert not SecureTransport.is_peer_allowed(b.store, a.id)
    b.store.write(f"secure/peers/{hashlib.sha256(a.id.encode()).hexdigest()}.json", b"{bad")
    assert not SecureTransport.is_peer_allowed(b.store, a.id)
    with pytest.raises(MLSError, match="delivery_peer_disabled"):
        tb._allowed(a.id)


def test_control_expiry_keeps_original_operation_pending(pair):
    clock, a, b, ta, _, pending, _, _ = pair

    def expired(*_):
        raise ACEError("envelope_expired", "control frame rejected")

    with pytest.raises(MLSError, match="delivery_expired"):
        a.outbox.deliver("same", lambda p: ta.deliver(p, a.peers.get(b.id), expired))
    assert a.outbox.pending()[0].status == "pending"
    clock.t += 604801
    with raises("envelope_expired"):
        a.outbox.deliver("same", lambda p: ta.deliver(p, a.peers.get(b.id), expired))
    assert a.outbox.pending()[0].status == "expired"
