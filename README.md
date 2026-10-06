# ace-sdk

ACE Protocol SDK for Python — Agent Commerce Engine.

## Install

```bash
pip install ace-sdk
```

Requires Python 3.10+ and `cryptography>=48` (ML-KEM-768 support). Everything is synchronous.

## Quick start

`examples/quickstart.py` is the tested example. The low-level API creates and parses one
message:

```python
from ace import (
    ReplayDetector, SoftwareIdentity, ThreadStateMachine,
    create_message, create_registration_file, decode_envelope, parse_message, verify_registration_file,
)

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("secp256k1")
# create_registration_file works for any ACEIdentity (hardware-backed ones included)
alice_peer = verify_registration_file(create_registration_file(alice, name="Alice", endpoint="https://alice.example/ace"))
bob_peer = verify_registration_file(create_registration_file(bob, name="Bob", endpoint="https://bob.example/ace"))

envelope = create_message(alice, bob_peer, "rfq", {"need": "translate"},
                          ThreadStateMachine(alice.get_ace_id()), thread_id="deal-1")
parsed = parse_message(decode_envelope(envelope.to_dict()), bob, alice_peer,
                       threads=ThreadStateMachine(bob.get_ace_id()), replay=ReplayDetector())
```

## Pipeline (store, peers, relay, outbox, inbox)

Real agents use the durable pipeline, which persists peers, threads, the replay store,
pending sends and delivery records, and survives crashes at any point:

```python
from ace import ACEError, FileStore, Inbox, Outbox, PeerStore, ReceiveSource, RelayClient

store = FileStore("/home/agent/.ace/state")        # or MemoryStore(), or your own ACEStore
relay = RelayClient("https://relay.example")
relay.register(identity)                           # signed registration request
peers = PeerStore(store, relay=relay)              # pinned bindings + rollback barrier

def on_message(m):                                 # persist durably, idempotent on (from_id, message_id)
    db.save_inbound(m.from_id, m.message_id, m.type, m.body)

inbox = Inbox.open(identity, store, peers, on_message)   # holds the "receive" lock until close()
outbox = Outbox.open(identity, store)

# send: stage (signed + persisted with its thread state), then deliver
pending = outbox.stage(peers.resolve(seller_id), "rfq", {"need": "translate"}, thread_id="deal-1")
try:
    outbox.deliver(pending.request_id, relay.send)
except ACEError as e:
    if e.code == "envelope_expired":               # offline too long: re-sign, same messageId
        outbox.resign(pending.request_id)
        outbox.deliver(pending.request_id, relay.send)
    elif not e.is_transient:
        raise                                      # transient: retry deliver() later

# receive: poll, or stream with SSE (reconnects with backoff)
result = inbox.pull(relay)                         # PullResult(outcomes, blocked)
for outcome in result.outcomes:                    # ReceiveOutcome(kind="delivered" | "duplicate" | "quarantined")
    ...
if result.blocked:                                 # the retryable error that stopped the drain
    ...
# follow yields the initial pull's outcomes, then live ones; on_live runs once caught up and
# connected, and again after every reconnect
for outcome in inbox.follow(relay, stop=stop_event, on_live=lambda: print("live")):
    ...
print(inbox.cursor(relay))                         # persisted cursor, keyed by relay.base_url
# direct (HTTP endpoint) delivery: inbox.receive(body["message"], ReceiveSource.direct())
```

- **`ACEStore`** is a small synchronous key-value protocol (`read`, `write`, `delete`, `list`,
  `lock`). `MemoryStore` is in-process; `FileStore(root)` writes atomically (temp file with
  `O_EXCL|O_NOFOLLOW`, fsync, rename, directory fsync), uses 0700/0600 permissions, refuses
  symlinks and uses lock files that are taken over from dead processes. The persisted JSON
  layout is the one in `ace-spec/06-security.md` Appendix A, so other SDKs can read it.
- **`PeerStore`** pins each peer's keys. A pin younger than `ttl_seconds` is used as is;
  otherwise it is refreshed from the relay. A different encryption key is only adopted from
  a relay-signed binding with a newer `registeredAt` (`stale_peer_binding` otherwise); a
  registration file never rotates a pin. `VerifiedPeer.profile` is relay metadata
  (self-asserted, unverified): only the keys are verified.
- **`Outbox`** keeps one pending send per thread (`pending_send_conflict`). Retries reuse the
  same envelope; a pending send is cleared on acknowledgement or when a later inbound message
  on the thread proves delivery. It is never abandoned automatically (`abandon` drops it).
- **`Inbox`** commits each message in the 06 order (delivery record, thread state, replay
  state, `on_message`, ack, cursor), recovers on `open`, and hands every message to
  `on_message` at least once — exactly once to a host that dedups on `(from_id, message_id)`.
  Permanent failures from the relay are quarantined (`quarantine/`, at most 1000 records);
  `retryable` outcomes (relay down, storage, handler errors) stop `pull` without advancing
  the cursor and are reported as `PullResult.blocked` (`outcomes` holds every other
  outcome; `messages`, `delivered`, `duplicates` and `quarantined` are convenience views).
  A message that would open more than `MAX_OPEN_THREADS_PER_PEER` (1000) non-terminal
  threads with one peer is quarantined `limit_exceeded`; `Outbox.stage` raises it.
- **`ThreadStore`** keeps a per-peer index of non-terminal threads (`threads/index/`) and
  prunes threads idle for 30 days that are terminal or hold no local message.
- **`RelayClient`** implements `08-relay.md`: `register`, `unregister`, `lookup_peer`,
  `discover`, `send`, `fetch_inbox`, `listen` (SSE generator; `on_open` per connection),
  `post_intent`, `list_intents`. `base_url` is the normalized URL (the inbox cursor key). Auth timestamps are strictly increasing per client and a `409 replay` is
  retried once. Network errors, 5xx, 408 and 429 are `relay_unavailable` (with
  `retry_after_seconds`).

## Concepts

- **Errors.** Every SDK failure is an `ACEError` with a stable `code` (e.g. `invalid_envelope`,
  `replay`, `wrong_role`) and a `category`: `permanent`, `transient` or `local`.
  `is_transient` is true for the last two (retry instead of quarantining).
- **Registration files.** `create_registration_file(identity, *, name, endpoint, ...)` builds
  the `.well-known/ace.json` document of any `ACEIdentity`;
  `SoftwareIdentity.to_registration_file` delegates to it.
- **Peers.** Keys are trusted only through a `VerifiedPeer`, obtained from
  `verify_peer_record` (relay `GET /v1/peer`; the encryption key binding is checked),
  `verify_registration_file` / `fetch_registration_file` (`.well-known/ace.json`, with SSRF
  protection) or `verify_registration_request` (relays).
- **Envelopes.** `decode_envelope` applies the strict 04 decoding rules (canonical Base64,
  lowercase IDs, wire integers, size limits); `envelope_fingerprint` is the SHA-256 of the
  RFC 8785 form of the known fields.
- **Receive pipeline.** `parse_message` runs the 06-security steps in a fixed order:
  recipient, sender, scheme, conversationId, timestamp window/floor, replay check, signature,
  replay commit, decrypt, body, thread state machine.
- **Threads.** `ThreadStateMachine(local_ace_id)` enforces the two parties of a thread, the
  buyer/seller roles (the `rfq` sender is the buyer) and fixed reference positions
  (`accept.offerId` = latest offer, `invoice.offerId` = accepted offer, `receipt.referenceId` /
  `confirm.deliverId` = latest entry). Persist with `export_state()` / `from_state()`.
- **Replay.** `ReplayDetector` keeps a seen store with a global horizon, per-sender horizons and
  a per-sender quota (`max(1, capacity // 16)`), so a flooding sender only evicts its own
  entries. `clone()` supports tentative commits; `export_state()` is canonical.
- **Relay auth.** `create_auth_headers(identity, RelayAuthRequest.inbox("-", 100), ts)` builds
  `X-ACE-Id` / `X-ACE-Timestamp` / `X-ACE-Signature`; relays use `parse_auth_headers` +
  `verify_auth_headers`.
- **Limits.** `MAX_PLAINTEXT_BYTES`, `MAX_PAYLOAD_BYTES`, `MAX_ENVELOPE_BYTES`, … mirror the
  04 "Size Limits" table.

## Encryption

```
X-Wing (X25519 + ML-KEM-768)  →  HKDF-SHA256  →  AES-256-GCM
```

X-Wing follows draft-connolly-cfrg-xwing-kem-11; the SDK reproduces all three draft test
vectors from the shared `ace-spec/test-vectors.json`.

- The static encryption key is a 1216-byte X-Wing public key; its private key is a 32-byte
  seed (`encryptionPrivateKey` in `SoftwareIdentity.export_private_key()`).
- Each message carries a fresh 1120-byte KEM ciphertext and
  `payload = nonce[12] || ciphertext || tag[16]` (at most 65536 bytes). The KEM ciphertext is
  part of the signed payload.
- Custom identities (Secure Enclave, HSM) implement `ACEIdentity.decrypt` by borrowing their
  seed and calling `decrypt_with_seed`; `kem_public_key_from_seed` and `generate_kem_seed`
  complete the set. Crypto failures are `decryption_failed`; any non-`ACEError` exception
  raised by an identity is reported as `identity_unavailable` (retryable).

Forward secrecy: compromising a **sender** reveals nothing about past messages. Compromising a
**recipient's** static seed reveals every message encrypted to that key — rotate keys by
re-registering.

Signing uses Ed25519 (strict: canonical points, small-order keys rejected, `S < L`) or
secp256k1 (low-S, `v ∈ {0, 1}`, `0x` + 130 lowercase hex). The ACE ID is
`ace:sha256:hex(sha256(signingPublicKey))`.

## Development

```bash
pip install -e ".[dev]" && ruff check ace tests && pytest -q
```

## License

Apache-2.0
