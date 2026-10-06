"""Replay reservation lifecycle in parse_message.

A failure BEFORE the signature verifies releases the reservation: a forged
envelope that reuses a victim's messageId with a malformed kemCiphertext /
payload / signature must not make the genuine message look like a replay later.
Once the signature has verified, the reservation is kept on any later failure:
an authentic message is one-shot regardless of outcome, so a captured message
that was rejected (e.g. by decryption or the state machine) cannot be replayed.
"""

import os

import pytest

from ace import ReplayDetector, SoftwareIdentity, ThreadStateMachine, create_message, parse_message
from ace._utils import from_base64
from ace.types import ACEMessage


def _pair():
    alice = SoftwareIdentity.generate("ed25519")
    bob = SoftwareIdentity.generate("secp256k1")
    msg = create_message(alice, bob.get_encryption_public_key(), bob.get_ace_id(), "text",
                         {"message": "hi"}, ThreadStateMachine())
    return alice, bob, msg


def _parse(msg, bob, alice, detector):
    return parse_message(msg, bob, alice.get_signing_public_key(), ThreadStateMachine(),
                         replay_detector=detector)


@pytest.mark.parametrize("field", ["kemCiphertext", "payload"])
def test_invalid_base64_releases_reservation(field):
    alice, bob, msg = _pair()
    d = msg.to_dict()
    d["encryption"][field] = "!!!not-base64!!!"
    forged = ACEMessage.from_dict(d)
    detector = ReplayDetector()
    with pytest.raises(Exception):
        _parse(forged, bob, alice, detector)
    # Reservation released: the genuine message with this id still parses.
    assert _parse(msg, bob, alice, detector).body == {"message": "hi"}


def test_invalid_signature_encoding_releases_reservation():
    alice, bob, msg = _pair()
    d = msg.to_dict()
    d["signature"]["value"] = "!!!not-base64!!!"
    forged = ACEMessage.from_dict(d)
    detector = ReplayDetector()
    with pytest.raises(Exception):
        _parse(forged, bob, alice, detector)
    assert _parse(msg, bob, alice, detector).body == {"message": "hi"}


def test_decryption_failure_after_valid_signature_consumes_message_id():
    """A validly signed, correctly addressed message that fails to decrypt keeps the id.

    The receiver shares Bob's signing key (so ``to`` and the signature check out)
    but holds a different X-Wing seed, so AES-GCM authentication fails after the
    signature verified. The messageId stays reserved: the authentic message is
    one-shot and cannot be presented again.
    """
    alice, bob, msg = _pair()
    bob_signing_priv = from_base64(bob.to_dict(include_private_keys=True)["signingPrivateKey"])
    wrong_seed_bob = SoftwareIdentity(bob.get_signing_scheme(), bob_signing_priv, os.urandom(32))
    assert wrong_seed_bob.get_ace_id() == bob.get_ace_id()

    detector = ReplayDetector()
    with pytest.raises(Exception):
        _parse(msg, wrong_seed_bob, alice, detector)
    assert detector.check_and_reserve(msg.message_id) is False
    with pytest.raises(ValueError, match="Replay detected"):
        _parse(msg, bob, alice, detector)
