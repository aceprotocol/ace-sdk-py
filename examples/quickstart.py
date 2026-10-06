from ace import (
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    parse_message,
)

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("ed25519")
message = create_message(
    sender=alice,
    recipient_pub_key=bob.get_encryption_public_key(),
    recipient_ace_id=bob.get_ace_id(),
    type_="rfq",
    body={"need": "Translate 500 words EN→FR", "maxPrice": "10", "currency": "USDC"},
    thread_id="translation-1",
    state_machine=ThreadStateMachine(),
)

# The keys are trusted here because both identities were created locally.
parsed = parse_message(
    message, bob, alice.get_signing_public_key(),
    sender_encryption_pub_key=alice.get_encryption_public_key(),
    state_machine=ThreadStateMachine(),
    replay_detector=ReplayDetector(),
)
print(parsed.body)
