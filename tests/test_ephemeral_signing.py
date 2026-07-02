"""The ephemeral public key is part of the signed commitment (#6).

Before this change the signature covered the ciphertext but not the ephemeral key,
so a relay could swap the ephemeral key and the signature would still verify (the
message merely failed to decrypt). Now such tampering is caught at signature check.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ace import (
    SoftwareIdentity, ThreadStateMachine, ReplayDetector,
    create_message, parse_message,
)
from ace._utils import to_base64


def test_tampering_ephemeral_pub_key_fails_signature():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")

    msg = create_message(
        sender, receiver.get_encryption_public_key(), receiver.get_ace_id(),
        "text", {"message": "hi"}, ThreadStateMachine(),
    )

    # Swap in a different (valid) ephemeral X25519 key, as a malicious relay might.
    other_eph = X25519PrivateKey.generate().public_key().public_bytes_raw()
    msg.encryption.ephemeral_pub_key = to_base64(other_eph)

    with pytest.raises(ValueError, match="Signature verification failed"):
        parse_message(
            msg, receiver, sender.get_signing_public_key(),
            ThreadStateMachine(), ReplayDetector(),
        )


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
