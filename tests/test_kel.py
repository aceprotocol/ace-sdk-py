import copy
import hashlib

from ace import _xwing
from ace._encoding import from_base64, to_base64
from ace._signing import encode_payload, signing_message, verify_signature
from ace.kel import (
    MAX_KEL_EVENTS,
    compute_ace_id,
    create_inception,
    create_rotation,
    create_signing_delegation,
    event_bytes,
    extend_kel,
    is_usable,
    verify_kel,
    verify_operational_signature,
)
from ace.keys import SoftwareKey, key_digest
from tests.helpers import raises

NOW = 1760140800
R0, R1, R2 = (SoftwareKey(bytes([i]) * 32) for i in (1, 2, 3))
S0, S1 = SoftwareKey(bytes([9]) * 32), SoftwareKey(bytes([10]) * 32)


def chain(not_after=None):
    icp = create_inception(R0, key_digest(R1.scheme, R1.public_key()), NOW)
    d1 = create_signing_delegation(verify_kel([icp], NOW), R0, S0.public_key(), NOW + 1, not_after)
    return [icp, d1]


def test_inception_id_and_signature():
    ev = chain()
    assert (
        compute_ace_id(event_bytes(ev[0]))
        == "ace:sha256:" + hashlib.sha256(event_bytes(ev[0])).hexdigest()
    )
    st = verify_kel(ev, NOW + 2)
    assert st.signing.public_key == S0.public_key() and st.signing.seq == 1
    assert is_usable(st, NOW + 10**9)
    m = signing_message(st.ace_id, NOW, None, event_bytes(ev[0]))
    assert verify_signature(m, "kel", from_base64(ev[0]["sig"]["value"]), R0.public_key())


def test_dlg_canonical_bytes_have_no_role():
    ev = chain(not_after=NOW + 100)
    d = ev[1]
    assert set(d) == {"t", "seq", "ts", "prev", "key", "notAfter", "sig"}
    assert event_bytes(d) == encode_payload(
        "dlg", "1", str(NOW + 1), d["prev"], "ml-dsa-65", S0.public_key(), str(NOW + 100)
    )
    d2 = {k: v for k, v in d.items() if k != "notAfter"}
    assert event_bytes(d2).endswith(b"\x00\x00\x00\x00")  # empty notAfter field


def test_role_member_and_encryption_keys_are_rejected():
    ev = chain()
    bad = copy.deepcopy(ev)
    bad[1]["role"] = "signing"
    with raises("invalid_kel"):
        verify_kel(bad, NOW + 2)
    xw = _xwing.DecapsulationKey(bytes([7]) * 32).public_key
    st = verify_kel(ev[:1], NOW)
    ev2 = {
        "t": "dlg",
        "seq": 1,
        "ts": NOW,
        "prev": st.last_hash,
        "key": {"scheme": "x-wing", "publicKey": to_base64(xw)},
    }
    ev2["sig"] = {
        "scheme": "ml-dsa-65",
        "value": to_base64(R0.sign(signing_message(st.ace_id, NOW, None, event_bytes(ev2)), "kel")),
    }
    with raises("invalid_kel"):
        verify_kel([ev[0], ev2], NOW)


def test_delegation_expiry():
    st = verify_kel(chain(not_after=NOW + 50), NOW + 2)
    assert is_usable(st, NOW + 49) and not is_usable(st, NOW + 50)
    assert not is_usable(verify_kel(chain()[:1], NOW), NOW)


def test_rotation_reveals_committed_root_and_clears_signing():
    ev = chain()
    st = verify_kel(ev, NOW + 2)
    rot = create_rotation(st, R1, key_digest(R2.scheme, R2.public_key()), NOW + 3)
    st2 = verify_kel([*ev, rot], NOW + 3)
    assert st2.signing is None and st2.root_public_key == R1.public_key()
    with raises("invalid_kel"):
        create_rotation(st, R2, key_digest(R2.scheme, R2.public_key()), NOW + 3)
    forged = copy.deepcopy(rot)
    forged["sig"]["value"] = to_base64(
        R0.sign(signing_message(st.ace_id, NOW + 3, None, event_bytes(rot)), "kel")
    )
    with raises("invalid_signature"):
        verify_kel([*ev, forged], NOW + 3)


def test_structural_rejections_and_limits():
    ev = chain()
    for mutate in (
        lambda e: e[1].update(seq=5),
        lambda e: e[1].update(prev="00" * 32),
        lambda e: e[1].update(ts=NOW - 1),
        lambda e: e.insert(1, copy.deepcopy(e[0])),
    ):
        bad = copy.deepcopy(ev)
        mutate(bad)
        with raises("invalid_kel"):
            verify_kel(bad, NOW + 10)
    with raises("invalid_kel"):
        verify_kel(ev, NOW - 400)  # ts beyond now + 300
    with raises("invalid_kel"):
        verify_kel([ev[0]] * (MAX_KEL_EVENTS + 1), NOW)


def test_extend_and_fork_rules():
    ev = chain()
    st0 = verify_kel(ev[:1], NOW)
    assert extend_kel(None, ev, NOW + 2)[1] == "adopted"
    assert extend_kel(st0, ev, NOW + 2)[1] == "extended"
    full = verify_kel(ev, NOW + 2)
    assert extend_kel(full, ev[:1], NOW + 2)[1] == "unchanged"
    other = create_signing_delegation(st0, R0, S1.public_key(), NOW + 1)
    with raises("kel_conflict"):
        extend_kel(full, [ev[0], other], NOW + 2)
    rot = create_rotation(st0, R1, key_digest(R2.scheme, R2.public_key()), NOW + 2)
    assert extend_kel(full, [ev[0], rot], NOW + 3)[1] == "recovered"


def test_operational_signature_checks():
    ev = chain(not_after=NOW + 100)
    st = verify_kel(ev, NOW + 2)
    value = to_base64(S0.sign(signing_message(st.ace_id, NOW + 5, 1, b"payload"), "packet"))
    sig = {"scheme": "ml-dsa-65", "seq": 1, "value": value}
    verify_operational_signature(st, sig, b"payload", "packet", NOW + 5, NOW + 5)
    with raises("invalid_signature"):
        verify_operational_signature(st, sig, b"payload", "agent-descriptor", NOW + 5, NOW + 5)
    with raises("stale_peer_binding"):  # rule 2
        verify_operational_signature(st, {**sig, "seq": 2}, b"payload", "packet", NOW + 5, NOW + 5)
    with raises("stale_peer_binding"):  # rule 3: signed after notAfter
        verify_operational_signature(st, sig, b"payload", "packet", NOW + 100, NOW + 5)
    with raises("invalid_signature"):  # rule 1
        verify_operational_signature(
            st, {**sig, "scheme": "ml-dsa-87"}, b"payload", "packet", NOW + 5, NOW + 5
        )
    with raises("stale_peer_binding"):  # rule 5: signed while live, verified after notAfter
        verify_operational_signature(st, sig, b"payload", "packet", NOW + 5, NOW + 100)


def test_signing_key_lifetime_constant():
    import ace.kel
    from ace.limits import MAX_SIGNING_KEY_LIFETIME

    assert MAX_SIGNING_KEY_LIFETIME == 31_622_400 and not hasattr(ace.kel, "MAX_DELEGATION_SECONDS")
