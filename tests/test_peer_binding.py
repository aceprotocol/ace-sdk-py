"""Encryption-key binding: a relay must not be able to substitute an X25519 key.

These tests pin the fix for the E2E-MITM finding — the ace_id self-certifies only
the signing key, so the encryption key must be verified against a signature by that
signing key before any message is encrypted to it.
"""

import copy

import pytest

from ace import (
    SoftwareIdentity, VerifiedPeer, verify_encryption_key_binding,
    ThreadStateMachine, ReplayDetector,
    create_message, parse_message_from_peer,
)
from ace.signing import build_sign_data, encode_payload, encode_signature
from ace._utils import to_base64


def _relay_peer_response(identity: SoftwareIdentity, registered_at: int = 1741000000) -> dict:
    """Reproduce exactly what the relay stores/serves for GET /v1/peer."""
    enc_b64 = to_base64(identity.get_encryption_public_key())
    sign_b64 = to_base64(identity.get_signing_public_key())
    sign_data = build_sign_data(
        "register", identity.get_ace_id(), registered_at,
        encode_payload(enc_b64, sign_b64),
    )
    sig, scheme = identity.sign(sign_data)
    return {
        "aceId": identity.get_ace_id(),
        "encryptionPublicKey": enc_b64,
        "signingPublicKey": sign_b64,
        "scheme": scheme,
        "registrationSignature": encode_signature(sig, scheme),
        "registeredAt": registered_at,
    }


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_verified_peer_accepts_genuine_binding(scheme):
    identity = SoftwareIdentity.generate(scheme)
    resp = _relay_peer_response(identity)

    peer = VerifiedPeer.from_relay_response(resp)

    assert peer.ace_id == identity.get_ace_id()
    assert peer.signing_public_key == identity.get_signing_public_key()
    assert peer.encryption_public_key == identity.get_encryption_public_key()


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_verified_peer_rejects_substituted_encryption_key(scheme):
    """The core MITM: relay keeps the real signing key/aceId but swaps the X25519 key."""
    victim = SoftwareIdentity.generate(scheme)
    attacker = SoftwareIdentity.generate(scheme)

    poisoned = _relay_peer_response(victim)
    poisoned["encryptionPublicKey"] = to_base64(attacker.get_encryption_public_key())

    # aceId still matches the (untouched) signing key, so a naive check would pass —
    # only the binding signature catches the swap.
    assert verify_encryption_key_binding(
        poisoned["aceId"], poisoned["scheme"],
        poisoned["encryptionPublicKey"], poisoned["signingPublicKey"],
        poisoned["registeredAt"], poisoned["registrationSignature"],
    ) is False

    with pytest.raises(ValueError, match="binding failed verification"):
        VerifiedPeer.from_relay_response(poisoned)


def test_verified_peer_rejects_missing_binding_signature():
    identity = SoftwareIdentity.generate("secp256k1")
    resp = _relay_peer_response(identity)
    del resp["registrationSignature"]

    with pytest.raises(ValueError, match="missing the encryption-key binding"):
        VerifiedPeer.from_relay_response(resp)


def test_verified_peer_rejects_ace_id_not_matching_signing_key():
    identity = SoftwareIdentity.generate("ed25519")
    other = SoftwareIdentity.generate("ed25519")
    resp = _relay_peer_response(identity)
    resp["aceId"] = other.get_ace_id()  # lie about identity

    with pytest.raises(ValueError):
        VerifiedPeer.from_relay_response(resp)


def test_binding_rejects_tampered_registered_at():
    identity = SoftwareIdentity.generate("secp256k1")
    resp = _relay_peer_response(identity, registered_at=1741000000)
    # timestamp is part of the signed data — changing it breaks the binding
    assert verify_encryption_key_binding(
        resp["aceId"], resp["scheme"], resp["encryptionPublicKey"],
        resp["signingPublicKey"], 1741000001, resp["registrationSignature"],
    ) is False


@pytest.mark.parametrize("scheme", ["ed25519", "secp256k1"])
def test_parse_message_from_peer_roundtrip(scheme):
    sender = SoftwareIdentity.generate(scheme)
    receiver = SoftwareIdentity.generate("ed25519")
    sm_send = ThreadStateMachine()
    sm_recv = ThreadStateMachine()

    msg = create_message(
        sender=sender,
        recipient_pub_key=receiver.get_encryption_public_key(),
        recipient_ace_id=receiver.get_ace_id(),
        type_="text",
        body={"message": "hello"},
        state_machine=sm_send,
    )

    # Receiver resolves the sender's keys from the relay — safely.
    sender_peer = VerifiedPeer.from_relay_response(_relay_peer_response(sender))
    parsed = parse_message_from_peer(msg, receiver, sender_peer, sm_recv, ReplayDetector())

    assert parsed.body == {"message": "hello"}
    assert parsed.from_id == sender.get_ace_id()
