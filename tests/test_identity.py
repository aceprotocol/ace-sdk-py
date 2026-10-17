from ace import SoftwareIdentity, check_usable, verify_kel
from ace.keys import SoftwareKey, generate_software_key, key_digest
from tests.helpers import NOW, raises


def test_generate_export_round_trip_has_no_encryption_seed():
    a = SoftwareIdentity.generate(now=NOW)
    exp = a.export_private_key()
    assert set(exp) == {"rootSeed", "nextRootSeed", "signingSeed", "kel"}
    b = SoftwareIdentity.from_export(exp, now=NOW + 1)
    assert b.get_ace_id() == a.get_ace_id() and b.get_signing_seq() == 1
    assert [e["t"] for e in a.get_kel()] == ["icp", "dlg"]
    with raises("invalid_argument"):
        SoftwareIdentity.from_export({**exp, "encryptionSeed": exp["rootSeed"]}, now=NOW)


def test_rotate_delegate_and_recover():
    a = SoftwareIdentity.generate(now=NOW)
    a.rotate(now=NOW + 1)
    assert [e["t"] for e in a.get_kel()] == ["icp", "dlg", "rot", "dlg"]
    assert check_usable(a, NOW + 1).signing.seq == 3
    a.delegate(now=NOW + 2, not_after=NOW + 100)
    assert a.get_signing_seq() == 4
    with raises("identity_unavailable"):
        check_usable(a, NOW + 100)
    # recovery from the committed next root kept elsewhere
    nxt = generate_software_key()
    b = SoftwareIdentity.generate(
        now=NOW, next_root_digest=key_digest(nxt.scheme, nxt.public_key())
    )
    b.delegate(now=NOW + 1)
    r = SoftwareIdentity.recover(b.get_kel(), nxt, now=NOW + 2)
    assert r.get_ace_id() == b.get_ace_id()
    assert [e["t"] for e in r.get_kel()] == ["icp", "rot", "dlg"]
    verify_kel(r.get_kel(), NOW + 2)


def test_signer_refuses_mismatched_keys():
    a = SoftwareIdentity.generate(now=NOW)
    exp = a.export_private_key()
    other = SoftwareKey(bytes([4]) * 32)
    with raises("invalid_argument"):
        SoftwareIdentity.from_export(
            {**exp, "signingSeed": __import__("ace").to_base64(other.seed)}, now=NOW
        )
