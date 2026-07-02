"""secp256k1 signature malleability must be rejected (canonical low-S only).

A high-S signature recovers the same public key as its low-S twin, so accepting it
lets an observer re-mint a valid-but-different signature and slip past the relay's
signature-keyed replay guard. These tests pin that verification rejects high-S.
"""

from coincurve import PublicKey as SecpPublicKey

from ace import SoftwareIdentity
from ace.signing import build_sign_data, encode_payload, verify_signature

_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_MSG_ID = "550e8400-e29b-41d4-a716-446655440000"


def _sign_data():
    payload = encode_payload("text", "ace:sha256:x", "conv", _MSG_ID, "", b"hi")
    return payload


def _make(idn):
    sd = build_sign_data("message", idn.get_ace_id(), 1741000000, _sign_data())
    sig, scheme = idn.sign(sd)
    return sd, sig, scheme


def _malleate(sig65: bytes) -> bytes:
    """(r, s, v) -> (r, n - s, v ^ 1): the canonical ECDSA malleability transform."""
    r = sig65[:32]
    s = int.from_bytes(sig65[32:64], "big")
    v = sig65[64]
    return r + (_ORDER - s).to_bytes(32, "big") + bytes([v ^ 1])


def test_sdk_signs_low_s_and_verifies():
    idn = SoftwareIdentity.generate("secp256k1")
    sd, sig, scheme = _make(idn)
    assert verify_signature(sd, sig, scheme, idn.get_signing_public_key())
    assert int.from_bytes(sig[32:64], "big") <= _ORDER // 2  # SDK emits low-S


def test_high_s_recovers_same_key_but_is_rejected():
    idn = SoftwareIdentity.generate("secp256k1")
    sd, sig, scheme = _make(idn)
    malleated = _malleate(sig)

    # The malleated signature IS a valid signature for this identity...
    recovered = SecpPublicKey.from_signature_and_message(
        malleated, sd, hasher=None
    ).format(compressed=True)
    assert recovered == idn.get_signing_public_key()

    # ...but verification must reject it as non-canonical (high-S).
    assert verify_signature(sd, malleated, scheme, idn.get_signing_public_key()) is False


def test_reject_invalid_recovery_id():
    idn = SoftwareIdentity.generate("secp256k1")
    sd, sig, _ = _make(idn)
    bad = sig[:64] + bytes([2])
    assert verify_signature(sd, bad, "secp256k1", idn.get_signing_public_key()) is False
