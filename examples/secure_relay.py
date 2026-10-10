"""Two locally generated demo agents; run against a relay you control.

python examples/secure_relay.py --relay http://127.0.0.1:3100 --library /trusted/core.so
Use persistent identities, FileStore and an idempotent durable callback in an application.
"""

import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

from ace import (
    MemoryStore,
    NativeMLSEngine,
    Outbox,
    PeerStore,
    RelayClient,
    SecureTransport,
    SoftwareIdentity,
    deliver_secure,
    open_secure_mailbox,
)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--relay", required=True)
    args.add_argument("--library", required=True)
    config = args.parse_args()
    relay = RelayClient(config.relay)
    alice, bob = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("secp256k1")
    relay.register(alice)
    relay.register(bob)
    sa, sb = MemoryStore(), MemoryStore()
    peers_a, peers_b = PeerStore(sa, relay=relay), PeerStore(sb, relay=relay)
    # Explicit admission is safe here because the demo created both identities locally.
    # In production verify full identities through a trusted pairing flow first.
    SecureTransport.set_peer_allowed(sa, bob.get_ace_id(), True)
    SecureTransport.set_peer_allowed(sb, alice.get_ace_id(), True)
    with NativeMLSEngine(config.library) as engine:
        # Receiving: one object owns the Inbox, the transport and the engine; close() releases
        # all three (the engine is shared with the sender below, so the sender closes first).
        mailbox = open_secure_mailbox(
            identity=bob, store=sb, peers=peers_b, relay=relay, engine=engine,
            inbox={"on_message": lambda message: print(message.body)},
        )
        tx = SecureTransport(alice, engine, sa)
        stop = threading.Event()

        def receive():
            for outcome in mailbox.follow(stop=stop):
                if outcome.error:
                    raise outcome.error

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                listener = pool.submit(receive)
                try:
                    peer = peers_a.resolve(bob.get_ace_id())
                    outbox = Outbox.open(alice, sa)
                    pending = outbox.stage(peer, "text", {"message": "hello privately"})
                    # Sending: returns once bob's Inbox durably committed the envelope.
                    deliver_secure(
                        outbox,
                        pending.request_id,
                        identity=alice,
                        secure=tx,
                        relay=relay,
                        peer=peer,
                    )
                finally:
                    stop.set()
                    listener.result()
        finally:
            tx.close()
            mailbox.close()


if __name__ == "__main__":
    main()
