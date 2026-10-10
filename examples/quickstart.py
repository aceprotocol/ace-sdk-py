import json

from ace import (
    Inbox,
    MemoryStore,
    Outbox,
    PeerStore,
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    ThreadStore,
    create_message,
    create_registration_file,
    decode_envelope,
    parse_message,
    verify_registration_file,
)

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("secp256k1")

# --- 1. Pure local: create and parse one message ------------------------------------------

# Each side verifies the other's registration file (normally fetched with
# fetch_registration_file or resolved from a relay with verify_peer_record).
# create_registration_file works for any ACEIdentity, hardware-backed ones included.
alice_reg = create_registration_file(alice, name="Alice", endpoint="https://alice.example/ace")
bob_reg = create_registration_file(bob, name="Bob", endpoint="https://bob.example/ace")
alice_peer = verify_registration_file(alice_reg)
bob_peer = verify_registration_file(bob_reg)

envelope = create_message(
    alice,
    bob_peer,
    "rfq",
    {"need": "Translate 500 words EN→FR", "maxPrice": "10", "currency": "USDC"},
    ThreadStateMachine(alice.get_ace_id()),
    thread_id="translation-1",
)

# On the wire the envelope is JSON; the receiver decodes it strictly first.
bob_threads = ThreadStateMachine(bob.get_ace_id())
parsed = parse_message(
    decode_envelope(envelope.to_dict()),
    bob,
    alice_peer,
    threads=bob_threads,
    replay=ReplayDetector(),
)
print(parsed.type, parsed.body)
print(bob_threads.allowed_types(parsed.conversation_id, "translation-1", bob.get_ace_id()))

# --- 2. Durable pipeline: Outbox -> transport -> Inbox ------------------------------------

# Application-layer demonstration only. For network delivery use SecureTransport and
# SecureMailbox / SecureRelayReplies from ace.secure_mailbox (see secure_relay.py).
# Never expose this inner Inbox directly as an application's network receiver.
alice_store, bob_store = MemoryStore(), MemoryStore()
alice_peers, bob_peers = PeerStore(alice_store), PeerStore(bob_store)
alice_peers.pin_registration_file(bob_reg)
bob_peers.pin_registration_file(alice_reg)

received = {}  # the host's own durable, idempotent store keyed by (from, messageId)


def on_message(m):
    received[(m.from_id, m.message_id)] = m


inbox = Inbox.open(bob, bob_store, bob_peers, on_message, commerce=True)
outbox = Outbox.open(alice, alice_store, commerce=True)

pending = outbox.stage(
    alice_peers.resolve(bob.get_ace_id()), "rfq", {"need": "Summarize a PDF"}, thread_id="deal-1"
)


# In-process application boundary: the receiver's Inbox decodes the raw envelope bytes.
# On the network, SecureMailbox feeds it the same bytes as authenticated MLS plaintext.
def transport(env):
    outcome = inbox.receive(json.dumps(env.to_dict()).encode())
    print(outcome.kind)


outbox.deliver(pending.request_id, transport)

(message,) = received.values()
print(message.type, message.body)
print(ThreadStore(bob_store, bob.get_ace_id()).get(message.conversation_id, "deal-1").state)
inbox.close()
