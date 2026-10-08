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
from ace import ACEError, FileStore, Inbox, Outbox, PeerStore, RelayClient

store = FileStore("/home/agent/.ace/state")        # or MemoryStore(), or your own ACEStore
relay = RelayClient("https://relay.aceprotocol.org")
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
result = inbox.pull(relay, max_pages=10)           # PullResult(outcomes, blocked, has_more)
for outcome in result.outcomes:                    # ReceiveOutcome(kind="delivered" | "duplicate" | "quarantined")
    ...
if result.blocked:                                 # the retryable error that stopped the drain
    ...                                            # (invalid limit / max_pages: invalid_argument; pull never raises)
if result.has_more:                                # max_pages or stop= ended it early: pull again
    ...
# follow yields the initial pull's outcomes, then live ones; on_live runs once caught up and
# connected, and again after every reconnect
for outcome in inbox.follow(relay, stop=stop_event, on_live=lambda: print("live")):
    ...
print(inbox.cursor(relay))                         # persisted cursor, keyed by relay.base_url
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
- **`Inbox.receive(message, source)`** is the single entry point: `message` is the raw
  envelope JSON bytes as the transport delivered them. Bytes that are not UTF-8 JSON, or
  exceed `MAX_ENVELOPE_BYTES`, are `quarantined` (`invalid_envelope`). Delivery records that
  are acknowledged and covered by a replay horizon are swept automatically.
- **`ThreadStore`** (public: `get`, `list`, `remove`, `allowed_types`) keeps a per-peer index of non-terminal threads (`threads/index/`) and
  prunes threads idle for 30 days that are terminal or hold no local message.
- **`RelayClient`** implements `08-relay.md`: `register`, `unregister`, `lookup_peer`,
  `discover`, `send`, `fetch_inbox`, `listen` (SSE generator; `on_open` per connection),
  `post_intent`, `list_intents` (`tags` is a list of strings), `set_webhook`, `get_webhook`,
  `clear_webhook`. `base_url` is the normalized URL (the inbox cursor key): scheme and host
  lowercased, `:443`/`:80` dropped, trailing `/` removed; a query, fragment, userinfo or
  whitespace is `invalid_argument`. Auth timestamps are strictly increasing per client and a
  `409 replay` is retried once. Redirects are never followed (a 3xx is
  `relay_protocol_error`). Network errors, 5xx, 408 and 429 `rate_limited` are
  `relay_unavailable`; any other 429 (`recipient_inbox_full`, `sender_quota_exceeded`, …) is
  `relay_rejected`. `retry_after_seconds` (integer `Retry-After` only) is set only on
  transient errors. Inbox and SSE entries carry the raw envelope bytes; a frame that is not
  an envelope is quarantined by the Inbox and never stalls `listen` / `follow`.

## Direct delivery

An agent that publishes an `endpoint` accepts `POST <endpoint>` with `{"message": envelope}`
(`08-relay.md` § Direct Delivery). The SDK implements both sides; HTTP serving, routing and
rate limiting stay in your application.

```python
from ace import MAX_DIRECT_BODY_BYTES, deliver_direct_or_relay, post_direct

# receiver: inside your HTTP handler (read at most MAX_DIRECT_BODY_BYTES + 1 bytes)
reply = inbox.receive_direct(request_body)         # DirectReply(status, body, outcome)
respond(reply.status, json.dumps(reply.body))      # 200 {"ok":true,"messageId"} / 400 / 413 / 503

# sender: try the peer's endpoint, fall back to the relay
peer = peers.resolve(seller_id)
endpoint = peer.profile.endpoint if peer.profile else None
path = outbox.deliver(pending.request_id, deliver_direct_or_relay(relay, endpoint))
post_direct("https://seller.example/ace/receive", envelope)    # or the raw call
```

- `post_direct` requires an ACE HTTPS URL, resolves the host once, refuses it when any
  address is blocked (`is_blocked_address`) and connects to the validated address; it never
  follows redirects (default timeout 5 s). Success is 2xx with `{"ok": true}`.
  `is_blocked_address(ip)` returns `True` for an input that is not an IP literal (fail closed).
- 400/413 is `direct_rejected` (permanent; the receiver's `error` string is in
  `remote_code` when it matches `^[a-z0-9_]{1,64}$`): do not resend that envelope, directly or through the relay. Anything else
  (network, timeout, 429, 503, other statuses) is `direct_unavailable` (transient).
- `deliver_direct_or_relay(relay, endpoint)` returns an `Outbox.deliver` transport that
  falls back to `relay.send` on `direct_unavailable` or an unsafe endpoint, re-raises
  `direct_rejected`, and returns `"direct"` or `"relay"`. Both paths carry the same
  envelope, so a second copy is a duplicate at the receiver.

## Webhooks

`relay.set_webhook(identity, url, secret)` asks the relay to notify an HTTPS URL when a
message is queued. Verify each notification on the raw request body before trusting it, then
`pull` the inbox:

```python
from ace import verify_webhook_notification

n = verify_webhook_notification(
    secret=secret,
    timestamp=headers["X-ACE-Webhook-Timestamp"],
    signature=headers["X-ACE-Webhook-Signature"],
    body=raw_body,
)                                                  # WebhookNotification(ace_id, stream_id)
inbox.pull(relay)
```

Malformed headers or body are `invalid_argument` / `invalid_signature`, a timestamp outside
the window (default `TIMESTAMP_WINDOW_SECONDS`) is `stale_timestamp`, a wrong HMAC is
`invalid_signature`.

## Concepts

- **Errors.** Every SDK failure is an `ACEError` with a stable `code` (e.g. `invalid_envelope`,
  `replay`, `wrong_role`) and a `category`: `permanent`, `transient` or `local`
  (`06-security.md` § SDK Error Codes). `is_transient` is true for the last two (retry instead
  of quarantining). A store lock that cannot be acquired in time is `lock_busy`
  (`receiver_busy` for the `receive` lock); `storage_failed` is an I/O failure.
- **Registration files.** `create_registration_file(identity, *, name, endpoint, ...)` builds
  the `.well-known/ace.json` document of any `ACEIdentity`.
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
- **Principal (0.3.0).** `create_principal_record(PrincipalSigner(...), subject_signing_public_key=...,
  account=..., roles=[...])` signs a 09-principal record with any key source;
  `validate_principal_record(record, subject_signing_public_key, now)` runs 09 rules 1-10 (every
  failure is `invalid_principal`). Put the record in `AgentProfile(principal=...)` or
  `create_registration_file(..., principal=...)`; peers carrying one are verified on resolution.
  `Inbox.open(..., principal={"account": "<CAIP-10>", "selfSigner": {...}, "trustedSigners": [...]})`
  enables the `request` / `decision` / `report` messages (same-account rules, `wrong_principal`,
  `bad_reference`). The default is fail-closed: `selfSigner` has no default (None; the host
  supplies it, usually the signer of its own principal record) and `trustedSigners` defaults to
  empty, so only an `eip155` account whose address is the signer's own passes 09 step 4; without
  `principal` every principal message is `wrong_principal`. Signer keys must be canonical
  Base64 of a valid key for the scheme (`invalid_argument` otherwise). The Outbox keeps a
  `requests/` ledger of open requests, which a `decision` is matched against under the
  `requests` lock; a `request` gets a ledger entry only when sent through the Outbox. When a
  sender's pinned principal fails 09 steps 2-5, the Inbox refreshes the peer from the relay once
  (only for envelopes authenticated by the pinned signing key); a transient refresh failure
  yields a `retryable` outcome (the cursor stays), a permanent one is quarantined.
  `create_registration_file` rejects a principal that is expired or future-dated at the current
  time (`invalid_principal`); `validate_profile` checks every other profile member before the
  principal, so a profile invalid in both ways is `invalid_profile`.
  `RelayClient.discover(DiscoverQuery(account="<CAIP-10>"))` lists peers whose principal names
  that account. Also exported: `PRINCIPAL_ROLES`, `is_caip10`, `parse_principal_record`
  (wire parse only), `principal_payload`, `load_request_record`.
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
secp256k1 (low-S, `v ∈ {0, 1}`, `0x` + 130 lowercase hex); `SIGNING_SCHEMES` and
`is_signing_scheme` list them. The ACE ID is `ace:sha256:hex(sha256(signingPublicKey))`.

Signatures are verify-only across implementations: other SDKs (and hardware-backed
identities) may produce non-deterministic signatures, so never compare signature bytes or
use them as identifiers — verify them. A message is identified by `(from, messageId)`.

## Development

```bash
pip install -e ".[dev]" && ruff check ace tests examples && pytest -q
```

## License

Apache-2.0
