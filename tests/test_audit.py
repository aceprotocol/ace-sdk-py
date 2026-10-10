from dataclasses import replace

import pytest

from ace import (
    AuditCheckpoint,
    AuditTree,
    AuditWitnessPolicy,
    AuditWitnessReceipt,
    SoftwareIdentity,
    audit_checkpoint_digest,
    audit_commitment,
    create_audit_checkpoint,
    create_audit_opening,
    create_audit_witness_receipt,
    verify_audit_checkpoint,
    verify_audit_consistency,
    verify_audit_inclusion,
    verify_audit_witness_quorum,
    verify_audit_witness_receipt,
)
from tests.helpers import VECTORS, agent, peer_of, raises

V = VECTORS["vectors"]["audit"]
LOG = "550e8400-e29b-41d4-a716-446655440000"
COMMITMENTS = [audit_commitment(bytes([i]), bytes(32)) for i in range(35)]


def test_audit_vectors():
    cs = [o["commitment"] for o in V["openings"]]
    tree = AuditTree(cs)
    for o in V["openings"]:
        assert (
            audit_commitment(bytes.fromhex(o["statementHex"]), bytes.fromhex(o["saltHex"]))
            == o["commitment"]
        )
    for n, root in enumerate(V["roots"]):
        assert tree.root(n) == root
    for v in V["inclusions"]:
        assert tree.inclusion(v["index"], v["size"]) == v["proof"]
        assert verify_audit_inclusion(
            cs[v["index"]], v["index"], v["size"], V["roots"][v["size"]], v["proof"]
        )
    for v in V["consistencies"]:
        assert tree.consistency(v["first"], v["second"]) == v["proof"]
        assert verify_audit_consistency(
            v["first"], v["second"], V["roots"][v["first"]], V["roots"][v["second"]], v["proof"]
        )
    for name, c in zip(["alice", "bob"], V["checkpoints"]):
        checkpoint = AuditCheckpoint.from_dict(c)
        verify_audit_checkpoint(checkpoint, peer_of(agent(name)))
        assert checkpoint.to_dict() == c
        with raises("invalid_argument"):
            AuditCheckpoint.from_dict({**c, "extra": "unsigned"})
    for w in V["witnesses"]:
        c, r = (
            AuditCheckpoint.from_dict(w["checkpoint"]),
            AuditWitnessReceipt.from_dict(w["receipt"]),
        )
        op, witness = peer_of(agent(w["operator"])), peer_of(agent(w["witness"]))
        assert audit_checkpoint_digest(c) == w["checkpointDigest"]
        verify_audit_witness_receipt(r, c, op, witness)
        assert r.to_dict() == w["receipt"]
        with raises("invalid_argument"):
            AuditWitnessReceipt.from_dict({**w["receipt"], "extra": "unsigned"})
        for altered in [
            replace(r, timestamp=r.timestamp + 1),
            replace(r, operator=r.witness),
            replace(r, log_id="00000000-0000-4000-8000-000000000001"),
            replace(r, checkpoint_digest="ab" * 32),
        ]:
            with raises("invalid_signature"):
                verify_audit_witness_receipt(altered, c, op, witness)


def test_witness_quorum():
    op = peer_of(agent("alice"))
    ids = [agent("bob")] + [SoftwareIdentity.generate("ed25519") for _ in range(3)]
    ws = tuple(peer_of(i) for i in ids)
    c = create_audit_checkpoint(AuditTree(COMMITMENTS), LOG, agent("alice"), 100)
    rs = [create_audit_witness_receipt(c, op, i, 101) for i in ids]
    p = AuditWitnessPolicy(ws, 3, 1, 10, 1)
    verify_audit_witness_quorum(c, rs[:3], op, p, 102)
    for receipts, policy, now in [
        (rs[:2], p, 102),
        ([rs[0], rs[0], rs[1]], p, 102),
        (rs, replace(p, threshold=2), 102),
        (rs, p, 112),
        (rs, p, 99),
        (rs, replace(p, witnesses=ws + (op,)), 102),
    ]:
        with raises("invalid_signature"):
            verify_audit_witness_quorum(c, receipts, op, policy, now)
    with raises("invalid_argument"):
        create_audit_witness_receipt(c, op, agent("alice"), 101)


def test_openings():
    salt, c = create_audit_opening(b"pay 1")
    assert len(salt) == 32 and audit_commitment(b"pay 1", salt) == c
    assert create_audit_opening(b"pay 1")[1] != c
    assert audit_commitment(b"pay 2", salt) != c
    with raises("invalid_argument"):
        audit_commitment(b"pay 1", bytes(31))


def test_every_prefix_and_leaf_and_tampering():
    tree = AuditTree(COMMITMENTS)
    for n in range(1, 36):
        for i in range(n):
            p = tree.inclusion(i, n)
            assert verify_audit_inclusion(COMMITMENTS[i], i, n, tree.root(n), p)
            assert not verify_audit_inclusion(
                COMMITMENTS[i], i, n, tree.root(n), p + [COMMITMENTS[0]]
            )
            assert not verify_audit_inclusion(COMMITMENTS[(i + 1) % 35], i, n, tree.root(n), p)
            if p:
                assert not verify_audit_inclusion(COMMITMENTS[i], i, n, tree.root(n), p[:-1])
        for m in range(n + 1):
            p = tree.consistency(m, n)
            assert verify_audit_consistency(m, n, tree.root(m), tree.root(n), p)
            assert not verify_audit_consistency(
                m, n, tree.root(m), tree.root(n), p + [COMMITMENTS[0]]
            )
            if p:
                assert not verify_audit_consistency(m, n, tree.root(m), tree.root(n), p[:-1])
    assert not verify_audit_consistency(2, 1, tree.root(2), tree.root(1), [])
    assert not verify_audit_inclusion(COMMITMENTS[0], 0, 0, tree.root(0), [])
    assert not verify_audit_consistency(0, 0, COMMITMENTS[0], COMMITMENTS[0], [])
    for n in [True, -1, 2**53, 1.5]:
        assert not verify_audit_inclusion(COMMITMENTS[0], 0, n, tree.root(1), [])


@pytest.mark.parametrize("name", ["alice", "bob"])
def test_checkpoint_bindings_and_forks(name):
    a = agent(name)
    tree = AuditTree(COMMITMENTS)
    first = create_audit_checkpoint(AuditTree(COMMITMENTS[:5]), LOG, a, 100)
    next_ = create_audit_checkpoint(tree, LOG, a, 101)
    verify_audit_checkpoint(first, peer_of(a))
    verify_audit_checkpoint(next_, peer_of(a), first, tree.consistency(5))
    for change in [
        dict(size=4),
        dict(root=COMMITMENTS[0]),
        dict(timestamp=99),
        dict(log_id="00000000-0000-4000-8000-000000000001"),
    ]:
        with raises("invalid_signature"):
            verify_audit_checkpoint(
                replace(next_, **change), peer_of(a), first, tree.consistency(5)
            )
    fork = create_audit_checkpoint(AuditTree(COMMITMENTS[1:]), LOG, a, 102)
    with raises("invalid_signature"):
        verify_audit_checkpoint(fork, peer_of(a), next_)
    with raises("invalid_signature"):
        verify_audit_checkpoint(next_, peer_of(agent("bob" if name == "alice" else "alice")))
