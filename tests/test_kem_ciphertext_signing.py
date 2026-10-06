"""The KEM ciphertext is part of the signed commitment.

The signature covers the KEM ciphertext as well as the AEAD payload, so a relay
that swaps the KEM ciphertext (even for another valid one encapsulated to the same
recipient) is caught at signature verification, not merely at decryption. A
ciphertext of the wrong length is rejected before any decapsulation.
"""

import pytest

from ace import (
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    parse_message,
    xwing,
)
from ace._utils import to_base64


def _roundtrip_pair():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    msg = create_message(
        sender, receiver.get_encryption_public_key(), receiver.get_ace_id(),
        "text", {"message": "hi"}, ThreadStateMachine(),
    )
    return sender, receiver, msg


def test_swapped_kem_ciphertext_fails_signature():
    sender, receiver, msg = _roundtrip_pair()

    # Swap in a different (valid, same-recipient) KEM ciphertext, as a malicious
    # relay might. It decapsulates fine — only the signature can catch it.
    _ss, other_ct = xwing.encapsulate(receiver.get_encryption_public_key())
    assert len(other_ct) == xwing.CIPHERTEXT_SIZE
    msg.encryption.kem_ciphertext = to_base64(other_ct)

    with pytest.raises(ValueError, match="Signature verification failed"):
        parse_message(
            msg, receiver, sender.get_signing_public_key(),
            ThreadStateMachine(), ReplayDetector(),
        )


def test_single_bit_flip_in_kem_ciphertext_fails_signature():
    sender, receiver, msg = _roundtrip_pair()
    from ace._utils import from_base64
    ct = bytearray(from_base64(msg.encryption.kem_ciphertext))
    ct[0] ^= 0x01
    msg.encryption.kem_ciphertext = to_base64(bytes(ct))

    with pytest.raises(ValueError, match="Signature verification failed"):
        parse_message(
            msg, receiver, sender.get_signing_public_key(),
            ThreadStateMachine(), ReplayDetector(),
        )


@pytest.mark.parametrize("length", [1119, 1121])
def test_wrong_length_kem_ciphertext_rejected_before_decapsulation(length, monkeypatch):
    sender, receiver, msg = _roundtrip_pair()
    msg.encryption.kem_ciphertext = to_base64(b"\xaa" * length)

    def _boom(*_a, **_k):  # pragma: no cover - must never be reached
        raise AssertionError("decapsulate must not run for a wrong-length ciphertext")

    monkeypatch.setattr(xwing, "decapsulate", _boom)
    detector = ReplayDetector()
    with pytest.raises(ValueError, match="1120"):
        parse_message(
            msg, receiver, sender.get_signing_public_key(),
            ThreadStateMachine(), detector,
        )
    # Nothing enters the seen store before the signature verifies.
    assert detector.accepts(msg.message_id, msg.timestamp) is True


def test_untampered_message_still_roundtrips():
    sender = SoftwareIdentity.generate("secp256k1")
    receiver = SoftwareIdentity.generate("ed25519")

    msg = create_message(
        sender, receiver.get_encryption_public_key(), receiver.get_ace_id(),
        "text", {"message": "hello"}, ThreadStateMachine(),
    )
    parsed = parse_message(
        msg, receiver, sender.get_signing_public_key(),
        ThreadStateMachine(), ReplayDetector(),
    )
    assert parsed.body == {"message": "hello"}
