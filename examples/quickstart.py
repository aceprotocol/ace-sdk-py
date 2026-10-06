from ace import (
    Inbox,
    MemoryStore,
    Outbox,
    PeerStore,
    ReceiveSource,
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    ThreadStore,
    create_message,
    decode_envelope,
    parse_message,
    verify_registration_file,
)

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("secp256k1")

# --- 1. Pure local: create and parse one message ------------------------------------------

# Each side verifies the other's registration file (normally fetched with
# fetch_registration_file or resolved from a relay with verify_peer_record).
alice_peer = verify_registration_file(
    alice.to_registration_file(name="Alice", endpoint="https://alice.example/ace")
)
bob_peer = verify_registration_file(
    bob.to_registration_file(name="Bob", endpoint="https://bob.example/ace")
)

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
    decode_envelope(envelope.to_dict()), bob, alice_peer, threads=bob_threads, replay=ReplayDetector()
)
print(parsed.type, parsed.body)
print(bob_threads.allowed_types(parsed.conversation_id, "translation-1", bob.get_ace_id()))

# --- 2. Durable pipeline: Outbox -> transport -> Inbox ------------------------------------

# Use FileStore("~/.ace/state") for real agents. With a relay:
#   relay = RelayClient("https://relay.example"); relay.register(identity)
#   peers = PeerStore(store, relay=relay); outbox.deliver(id, relay.send); inbox.pull(relay)
alice_store, bob_store = MemoryStore(), MemoryStore()
alice_peers, bob_peers = PeerStore(alice_store), PeerStore(bob_store)
alice_peers.pin_registration_file(bob.to_registration_file(name="Bob", endpoint="https://bob.example/ace"))
bob_peers.pin_registration_file(alice.to_registration_file(name="Alice", endpoint="https://alice.example/ace"))

received = {}  # the host's own durable, idempotent store keyed by (from, messageId)


def on_message(m):
    received[(m.from_id, m.message_id)] = m


inbox = Inbox.open(bob, bob_store, bob_peers, on_message)
outbox = Outbox(alice, alice_store)

pending = outbox.stage(
    alice_peers.resolve(bob.get_ace_id()), "rfq", {"need": "Summarize a PDF"}, thread_id="deal-1"
)
# The transport here hands the envelope straight to Bob's inbox (direct delivery).
outbox.deliver(
    pending.request_id, lambda env: print(inbox.receive(env.to_dict(), ReceiveSource.direct()).kind)
)

(message,) = received.values()
print(message.type, message.body)
print(ThreadStore(bob_store, bob.get_ace_id()).get(message.conversation_id, "deal-1").state)
inbox.close()
