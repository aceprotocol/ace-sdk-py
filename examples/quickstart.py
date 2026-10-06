from ace import (
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    decode_envelope,
    parse_message,
    verify_registration_file,
)

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("secp256k1")

# Each side verifies the other's registration file (normally fetched with
# fetch_registration_file or resolved from a relay with verify_peer_record).
alice_peer = verify_registration_file(
    alice.to_registration_file(name="Alice", endpoint="https://alice.example/ace")
)
bob_peer = verify_registration_file(
    bob.to_registration_file(name="Bob", endpoint="https://bob.example/ace")
)

alice_threads = ThreadStateMachine(alice.get_ace_id())
bob_threads = ThreadStateMachine(bob.get_ace_id())
bob_replay = ReplayDetector()

envelope = create_message(
    alice,
    bob_peer,
    "rfq",
    {"need": "Translate 500 words EN→FR", "maxPrice": "10", "currency": "USDC"},
    alice_threads,
    thread_id="translation-1",
)

# On the wire the envelope is JSON; the receiver decodes it strictly first.
wire = envelope.to_dict()
parsed = parse_message(
    decode_envelope(wire), bob, alice_peer, threads=bob_threads, replay=bob_replay
)
print(parsed.type, parsed.body)
print(bob_threads.allowed_types(parsed.conversation_id, "translation-1", bob.get_ace_id()))
