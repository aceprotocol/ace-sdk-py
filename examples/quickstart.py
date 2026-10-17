"""Two agents exchange a private message and a receipt, entirely in memory (no relay).

Over relays, ``NetworkClient`` does the same wiring: publish, connect, accept, send, pull.
"""

import json

from ace import (
    Inbox,
    MemoryStore,
    Outbox,
    PeerStore,
    PrekeyVault,
    Profiles,
    SoftwareIdentity,
    create_published_agent,
)


class Agent:
    def __init__(self):
        self.identity = SoftwareIdentity.generate()
        self.id = self.identity.get_ace_id()
        self.store, self.vault = MemoryStore(), PrekeyVault()
        self.peers = PeerStore(self.store)
        self.outbox = Outbox(self.identity, self.store, Profiles())
        self.inbox = Inbox.open(
            self.identity,
            self.store,
            self.vault,
            self.peers,
            Profiles(),
            on_message=lambda m: print(f"{self.id[:20]}… got {m.type}: {m.body}"),
            outbox=self.outbox,
        )

    def published(self):
        return create_published_agent(
            self.identity, relays=["https://relay.example"], prekey=self.vault.current()
        )


alice, bob = Agent(), Agent()
# Out-of-band contact: each pins the other's signed descriptor and admits it locally.
for me, other in ((alice, bob), (bob, alice)):
    me.peers.adopt(other.published())
    me.peers.set_status(other.id, "admitted")

mid = alice.outbox.enqueue(bob.id, "ace:text:1", {"message": "hello bob"})
wire = []
alice.outbox.deliver(
    mid,
    lambda packet, agent: wire.append(packet),
    lambda ace_id, refresh=False: alice.peers.agent(ace_id),
)

outcome = bob.inbox.receive(json.dumps(wire[0]).encode())  # verify, decrypt, store
alice.inbox.receive(json.dumps(outcome.receipt.packet).encode())  # the signed receipt
print("outbox status:", alice.outbox.get(mid).status)  # delivered
