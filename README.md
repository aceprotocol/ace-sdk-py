# ace-sdk

Network ingress must use `SecureMailbox`, and Outbox transport must use `SecureTransport`.
The `Inbox`/`createMessage` examples also expose lower-level application codecs; those
alone are not the authenticated secure network boundary. See “Authenticated secure delivery”.

Message packet **2.0** carries `{type,schemaDigest,threadId?,body}` entirely inside the ciphertext. Custom namespaced types require an immutable `schemaDigest`; unknown schemas are data and never execute. Durable Inbox/Outbox defaults do not install commerce state transitions. Set `commerce: true` (Python `commerce=True`) for the bundled commerce profile. The optional `principal` policy validates account coordination; receiving without it grants no execution rights.


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

## Pipeline (store, peers, relay, outbox, secure transport, mailbox, inbox)

Real agents use the durable pipeline, which persists peers, threads, the replay store,
pending sends and delivery records, and survives crashes at any point. The network has
exactly one receive boundary, `SecureMailbox`; `Inbox` is the application receive engine
it feeds with authenticated MLS plaintext:

```python
from ace import (
    ACEError, FileStore, NativeMLSEngine, Outbox, PeerStore, RelayClient, SecureTransport,
    deliver_secure, inbox_principal_from_own_record, open_secure_mailbox,
)

store = FileStore("/home/agent/.ace/state")        # or MemoryStore(), or your own ACEStore
relay = RelayClient("https://relay.aceprotocol.org")
relay.register(identity)                           # signed registration request
peers = PeerStore(store, relay=relay)              # pinned bindings + rollback barrier

def on_message(m):                                 # persist durably, idempotent on (from_id, message_id)
    db.save_inbound(m.from_id, m.message_id, m.type, m.body)

SecureTransport.set_peer_allowed(store, seller_id, True)     # local administrative decision per peer
# receive boundary: one object owns the Inbox (holds "receive" until close()), the transport
# and the engine; close() releases all three
principal, warning = inbox_principal_from_own_record(saved_profile.principal, identity)
if warning:                                        # saved record invalid or expired: no principal
    log.error("saved principal ignored (%s)", warning)
mailbox = open_secure_mailbox(
    identity=identity, store=store, peers=peers, relay=relay,
    engine=NativeMLSEngine("/trusted/libace_session_core.so"),  # explicit, verified library path
    inbox={"on_message": on_message, "commerce": True, "principal": principal},
)
outbox = Outbox.open(identity, store)

# send: stage (signed + persisted with its thread state), then deliver through a fresh MLS group;
# deliver_secure returns only once the peer's Inbox durably committed the envelope
engine = NativeMLSEngine("/trusted/libace_session_core.so")  # the sender's own engine (see below)
secure = SecureTransport(identity, engine, store)
peer = peers.resolve(seller_id)
pending = outbox.stage(peer, "rfq", {"need": "translate"}, thread_id="deal-1")
send = dict(identity=identity, secure=secure, relay=relay, peer=peer)  # send=deliver_direct_or_relay(relay, endpoint)
try:
    deliver_secure(outbox, pending.request_id, **send)
except ACEError as e:
    if e.code == "envelope_expired":               # offline too long: re-sign, same messageId
        outbox.resign(pending.request_id)
        deliver_secure(outbox, pending.request_id, **send)
    elif e.code == "delivery_rejected":            # the peer's Inbox rejected it (e.remote_code):
        outbox.abandon(pending.request_id)         # permanent, authenticated by the receipt
    elif not e.is_transient:
        raise                                      # transient (or an MLSError such as delivery_expired):
                                                   # the operation stays pending, retry deliver() later

# receive: poll, or stream with SSE (reconnects with backoff); stay online while sending
result = mailbox.pull(max_pages=10)                # PullResult(outcomes, blocked, has_more)
for outcome in result.outcomes:                    # ReceiveOutcome(kind="delivered" | "duplicate" | "quarantined")
    ...
if result.blocked:                                 # the retryable error that stopped the drain
    ...                                            # (invalid limit / max_pages: invalid_argument; pull never raises)
if result.has_more:                                # max_pages or stop= ended it early: pull again
    ...
# follow yields the initial pull's outcomes, then live ones; on_live runs once caught up and
# connected, and again after every reconnect
for outcome in mailbox.follow(stop=stop_event, on_live=lambda: print("live")):
    ...
print(mailbox.cursor(relay))                       # persisted cursor, keyed by relay.base_url
secure.close(); engine.close()                     # the sender's transport and engine
mailbox.close()                                    # closes the transport, the inbox and its engine
```

The helpers are thin: `open_secure_mailbox` is `Inbox.open(identity, store, peers, **inbox)`
→ `SecureTransport(identity, engine, store, clock)` → `SecureMailbox(..., close_transport=True,
dispose=engine.close)`, and `deliver_secure` is `outbox.deliver(request_id,
secure_transport_for(...))` where `secure_transport_for` builds the `SecureRelayReplies`
(frames through `send`, default `relay.send`) and returns
`lambda env: secure.deliver(env, peer, replies.exchange)`. Compose them by hand when you
need a shared transport or your own reply reader:

```python
from ace import Inbox, SecureMailbox, SecureRelayReplies, SecureTransport

secure = SecureTransport(identity, engine, store)
inbox = Inbox.open(identity, store, peers, on_message, commerce=True, principal=principal)
mailbox = SecureMailbox(identity, store, peers, relay, secure, inbox)  # close_transport=True, dispose=None
replies = SecureRelayReplies(identity, secure, relay, peer)            # reads the peer's handshake replies
outbox.deliver(pending.request_id, lambda env: secure.deliver(env, peer, replies.exchange))
```

- **`ACEStore`** is a small synchronous key-value protocol (`read`, `write`, `delete`, `list`,
  `lock`). A custom store validates its inputs with the SDK's own rules: `check_key(key)` and
  `check_lock_name(name)` return the value or raise `invalid_argument`. `MemoryStore` is in-process; `FileStore(root)` writes atomically (temp file with
  `O_EXCL|O_NOFOLLOW`, fsync, rename, directory fsync), uses 0700/0600 permissions, refuses
  symlinks and uses POSIX kernel locks over permanent files; process exit releases ownership. The persisted JSON
  layout is the one in `ace-spec/06-security.md` Appendix A, so other SDKs can read it:
  `replay.json`, `deliveries/`, `quarantine/`, `threads/`, `peers/`, `outbox/`, `requests/`,
  plus the secure boundary's `secure/cursors/<sha256(normalized relay URL)>.json` (mailbox
  cursor), `secure/peers/<sha256(aceId)>.json` (admission policy + generation),
  `secure/in/<attempt>.json` (the receiver's handshake journal; the sender keeps none) and
  `mls/gates/…` (public gate metadata only). No secrets are persisted.
- **`PeerStore`** pins each peer's keys. A pin younger than `ttl_seconds` is used as is;
  otherwise it is refreshed from the relay. A different encryption key is only adopted from
  a relay-signed binding with a strictly newer `registeredAt` (`stale_peer_binding` otherwise); a
  signed registration file rotates a pin under the same rule. `VerifiedPeer.profile` is relay metadata
  (self-asserted, unverified): only the keys are verified.
- **`Outbox`** keeps one pending send per thread (`pending_send_conflict`). Retries reuse the
  same envelope; a pending send is cleared on acknowledgement or when a later inbound message
  on the thread proves delivery. It is never abandoned automatically (`abandon` drops it).
- **`Inbox`** commits each message in the 06 order (delivery record, thread state,
  `on_message`, ack; the delivery records journal the seen store, and `replay.json` is
  rewritten every 1024 commits and at `close()`), recovers on `open`, and hands every message to `on_message`
  at least once — exactly once to a host that dedups on `(from_id, message_id)`. It is the
  application receive engine only: `SecureMailbox` feeds it authenticated MLS plaintext
  (in-process code and tests call it directly) and it knows nothing about relays, cursors,
  pages or HTTP. Permanent failures are quarantined (`quarantine/`, at most 1000 records);
  `retryable` outcomes (relay down, storage, handler errors) stop `SecureMailbox.pull`
  without advancing the cursor and are reported as `PullResult.blocked` (`outcomes` holds
  every other outcome; `messages`, `delivered`, `duplicates` and `quarantined` are
  convenience views). A message that would open more than `MAX_OPEN_THREADS_PER_PEER`
  (1000) non-terminal threads with one peer is quarantined `limit_exceeded`; `Outbox.stage`
  raises it.
- **`Inbox.receive(message)`** is its single entry point: `message` is the raw envelope JSON
  bytes (the MLS plaintext). Bytes that are not UTF-8 JSON, or exceed `MAX_ENVELOPE_BYTES`,
  are `quarantined` (`invalid_envelope`). Delivery records that are acknowledged and covered
  by a replay horizon are swept automatically.
- **`SecureMailbox(identity, store, peers, relay, secure, inbox)`** is the only network
  receive boundary: `pull(limit=, max_pages=, stop=)`, `follow(stop=, on_live=)`,
  `receive_direct(body)` and `cursor(relay)`. Every relay entry or direct request is a
  13-session-core handshake frame: local admission is checked first
  (`SecureTransport.is_peer_allowed`; an unadmitted sender is quarantined
  `delivery_peer_disabled` without any relay lookup or pin), static application packets are
  refused (`secure_delivery_required`, no downgrade fallback), the inner envelope reaches
  `Inbox.receive` only after a fresh MLS group authenticated it, and the receipt is sent
  after the Inbox durably committed. The receipt carries the Inbox outcome (`delivered`,
  `duplicate` or `rejected:<code>`): a quarantined inner envelope is still an accepted frame
  (direct: HTTP 200), and the sender's `deliver` raises `delivery_rejected` with the code in
  `remote_code`. The cursor lives under `secure/cursors/`; `close()`
  closes the transport (unless `close_transport=False`), the inbox, then runs `dispose`
  (keyword, default none) before releasing the `secure-mailbox` lock.
- **`open_secure_mailbox(identity=, store=, peers=, relay=, engine=, inbox=, clock=None)`**
  is the recommended way to open it: `Inbox.open` with `inbox` (a dict of the remaining
  `Inbox.open` keyword arguments: `on_message`, `commerce`, `principal`, `schemas`, `clock`,
  …), a `SecureTransport` over `engine`, then a `SecureMailbox` owning both
  (`close_transport=True`, `dispose=engine.close` when the engine has one). A failure after
  the Inbox opened closes it (no leaked `receive` lock) and leaves the engine to the caller.
- **`deliver_secure(outbox, request_id, identity=, secure=, relay=, peer=, send=None)`** /
  **`secure_transport_for(...)`** are the sending side (see [Authenticated secure
  delivery](#authenticated-secure-delivery)).
- **`inbox_principal_from_own_record(record, identity, now=None, trusted_signers=None)`** →
  `(principal, warning)`: the `principal` option for a host's own saved principal record
  (R-B12a). `None` → `(None, None)`; a record that does not validate for `identity`'s signing
  key at `now` (default wall clock) → `(None, "<code>: <detail>")` for the host to surface
  (never raises); a valid one → `InboxPrincipal(account, self_signer=record.signer,
  trusted_signers)`. `Inbox.open(principal=...)` accepts an `InboxPrincipal` or its
  `to_dict()` shape.
- **`ThreadStore`** (public: `get`, `list`, `remove`, `allowed_types`) keeps a per-peer index of non-terminal threads (`threads/index/`) and
  prunes threads idle for 30 days that are terminal or hold no local message.
- **`RelayClient`** implements `08-relay.md`: `register`, `unregister`, `lookup_peer`,
  `discover`, `send`, `fetch_inbox`, `listen` (SSE generator; `on_open` per connection),
  `post_intent(identity, need, ttl=..., tags=[...], ext={...})`, `list_intents` (`tags` is a
  list of strings; each `Intent.ext` is the served extensions object, read the commerce one with
  `intent_commerce_ext`), `set_webhook`, `get_webhook`, `clear_webhook`. `base_url` is the normalized URL (the mailbox cursor key): scheme and host
  lowercased, `:443`/`:80` dropped, trailing `/` removed; a query, fragment, userinfo or
  whitespace is `invalid_argument`. Auth timestamps are strictly increasing per client and a
  `409 replay` is retried once. Redirects are never followed (a 3xx is
  `relay_protocol_error`). Network errors, 5xx, 408 and 429 `rate_limited` are
  `relay_unavailable`; any other 429 (`recipient_inbox_full`, `sender_quota_exceeded`, …) is
  `relay_rejected`. `retry_after_seconds` (integer `Retry-After` only) is set only on
  transient errors. Inbox and SSE entries carry the raw envelope bytes; a frame that is not
  an envelope is quarantined by `SecureMailbox` and never stalls `listen` / `follow`.

## Direct delivery

An agent that publishes an `endpoint` accepts `POST <endpoint>` with `{"message": envelope}`
(`08-relay.md` § Direct Delivery), where the envelope is a secure delivery frame (`hello`,
`data`); the peer's replies (`offer`, `ack`) always come back through the relay. The SDK
implements both sides; HTTP serving, routing and rate limiting stay in your application.

```python
from ace import MAX_DIRECT_BODY_BYTES, deliver_direct_or_relay, post_direct

# receiver: inside your HTTP handler (read at most MAX_DIRECT_BODY_BYTES + 1 bytes)
reply = mailbox.receive_direct(request_body)       # DirectReply(status, body, outcome)
respond(reply.status, json.dumps(reply.body))      # 200 {"ok":true,"messageId"} / 400 / 413 / 503

# sender: handshake frames go to the peer's endpoint first, then the relay
peer = peers.resolve(seller_id)
endpoint = peer.profile.endpoint if peer.profile else None
replies = SecureRelayReplies(identity, secure, relay, peer, send=deliver_direct_or_relay(relay, endpoint))
outbox.deliver(pending.request_id, lambda env: secure.deliver(env, peer, replies.exchange))
post_direct("https://seller.example/ace/receive", frame)       # or the raw call
```

- `post_direct` requires an ACE HTTPS URL, resolves the host once, refuses it when any
  address is blocked (`is_blocked_address`) and connects to the validated address; it never
  follows redirects (default timeout 5 s). Success is 2xx with `{"ok": true}`.
  `is_blocked_address(ip)` returns `True` for an input that is not an IP literal (fail closed).
- 400/413 is `direct_rejected` (permanent; the receiver's `error` string is in
  `remote_code` when it matches `^[a-z0-9_]{1,64}$`): do not resend that frame, directly or through the relay. Anything else
  (network, timeout, 429, 503, other statuses) is `direct_unavailable` (transient).
- `deliver_direct_or_relay(relay, endpoint)` returns a transport for secure delivery frames
  (the `send` of `SecureRelayReplies`) that falls back to `relay.send` on
  `direct_unavailable` or an unsafe endpoint, re-raises `direct_rejected`, and returns
  `"direct"` or `"relay"`. Both paths carry the same frame, so the receiver answers a second
  copy with the same reply. `receive_direct` answers 200 for an accepted frame; the
  application envelope is delivered to `on_message` only when the `data` frame commits.

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
mailbox.pull()
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
- **Profiles and extensions.** `AgentProfile(name, description, image, tags, capabilities,
  endpoint, ext, principal)` is the relay discovery profile; `validate_profile` checks it
  (`invalid_profile`). `ext` holds namespaced extensions (02 § Profile Fields: each key a
  namespaced identifier of at most 256 bytes, each value an object, at most 8 keys, canonical
  JSON at most 4096 bytes, depth at most 8); it is re-canonicalised (`validate_ext`,
  `ext_canonical`) and an empty `ext` is absent. The registration authorization and the intent
  signature bind its canonical JSON. Commerce data lives under `COMMERCE_EXT`
  (`urn:ace:commerce:1`, 04 § Commerce extension): profiles and registration files carry
  `chains`, `pricing {currency, maxAmount?}`, `settlement`, `accounts`; intents carry `maxPrice`
  + `currency`. `validate_commerce_ext(value, carrier)` enforces it whenever the namespace is
  present; `commerce_ext(profile_or_file)` / `intent_commerce_ext(intent)` read it typed. Other
  namespaces are opaque. `create_registration_file(..., ext={...})` puts it in the file; a
  verified file supplies `profile.ext` and `profile.principal` to the peer cache.
- **Principal (0.3.0).** `create_principal_record(PrincipalSigner(...), subject_signing_public_key=...,
  account=..., roles=[...])` signs a 09-principal record with any key source (`roles` is
  `["controller"]`, `["delegate"]` or `["controller", "delegate"]`: the `delegate` acts, the
  `controller` approves);
  `validate_principal_record(record, subject_signing_public_key, now)` runs 09 rules 1-10 (every
  failure is `invalid_principal`). Put the record in `AgentProfile(principal=...)` or
  `create_registration_file(..., principal=...)`; peers carrying one are verified on resolution.
  `Inbox.open(..., principal={"account": "<CAIP-10>", "selfSigner": {...}, "trustedSigners": [...]})`
  enables the `request` / `decision` / `report` messages (same-account rules, `wrong_principal`,
  `bad_reference`). The default is fail-closed: `selfSigner` has no default (None; the host
  supplies it, usually the signer of its own principal record) and `trustedSigners` defaults to
  empty, so only an `eip155` account whose address is the signer's own passes 09 step 4. Without
  `principal` no account policy is installed: principal messages are delivered as plain data,
  unverified (a `decision` never fills `requests/`), so never treat their type as authority
  (09 roles do not authorize execution; use resource grants). Signer keys must be canonical
  Base64 of a valid key for the scheme (`invalid_argument` otherwise). The Outbox keeps a
  `requests/` ledger of open requests, which a `decision` is matched against under the
  `requests` lock; a `request` gets a ledger entry only when sent through the Outbox. When a
  sender's pinned principal fails 09 steps 2-5, the Inbox refreshes the peer from the relay once
  (only for envelopes authenticated by the pinned signing key); a transient refresh failure
  yields a `retryable` outcome (the cursor stays), a permanent one is quarantined.
  `create_registration_file` rejects a principal that is expired or future-dated at the current
  time (`invalid_principal`); `validate_profile` checks every other profile member before the
  principal, so a profile invalid in both ways is `invalid_profile`.
  `RelayClient.discover(DiscoverQuery(account="<CAIP-10>"))` lists registrations whose principal
  *claims* that account (an unauthenticated claim list); apply 09 same-account rule 4 (signer
  binding) before treating any entry as a delegate. Also exported: `PRINCIPAL_ROLES`
  (`("controller", "delegate")`), `is_caip10`, `parse_principal_record`
  (wire parse only), `principal_payload`, `load_request_record`.
- **Installed schemas.** Bundled types are validated by the SDK; a custom namespaced type is
  authenticated data unless the host installs a deterministic validator for its
  `schemaDigest`: `Inbox.open(..., schemas={digest: validator})` and
  `Outbox.open(..., schemas={...})`, where `validator` (a `SchemaValidator`) receives
  `{"type", "schemaDigest", "threadId", "body"}` and returns None when the body is valid.
  The Inbox runs it at the body-validation step (after decryption, before the thread and
  principal checks): an `ACEError` with a permanent code quarantines the message with that
  code, any other exception quarantines it `invalid_body`, and the secure-delivery receipt
  reports the rejection to the sender. `Outbox.stage` runs it before persisting anything and
  raises the same way. A validator installed for a bundled digest runs in addition to the
  built-in check. Keys must be 64 lowercase hex and values callable (`invalid_argument`).
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

Raw X-Wing packets have no recipient-key forward secrecy. SecureTransport adds fresh
MLS delivery; retained application plaintext and original Outbox envelopes remain exposed
to endpoint compromise. Rotate compromised static keys through a newer signed binding.

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

## Resource execution and audit

Exact-intent grants bind a resource, executor, immutable effect digest, absolute deadline and policy epoch. Verification starts from a locally trusted authority and validates every ancestor; message labels confer no rights. See [resource grants](https://github.com/aceprotocol/ace-spec/blob/main/10-resource-grants.md). The TypeScript and Swift `ExecutionAuthority` coordinators reserve all profile-derived budgets atomically and consume one authorization release under current policy. `hasReservation` reads a permanent binding after expiry/revocation; it never permits another effect. All three SDKs expose the closed `urn:ace:execute:1` request schema. SoulPass has opt-in sponsored Solana/EVM execution with local or explicitly configured pinned quorum storage; generic applications must install their own deterministic effect validators and durable executors.

Optional audit APIs create private salted commitments, Merkle inclusion/consistency proofs and signed checkpoints. They do not publish records automatically. See [private audit](https://github.com/aceprotocol/ace-spec/blob/main/11-audit.md). The secure network boundary and its narrower confidentiality claim are described below; private application logs and backups still require protection.

### Authenticated secure delivery

Use `SecureTransport` around Outbox and `SecureMailbox` for network ingress. The SDK owns the
glue every host needs: open the receive boundary with `open_secure_mailbox` and send with
`deliver_secure`; the principal option for your own saved record comes from
`inbox_principal_from_own_record`:

```python
from ace import (
    NativeMLSEngine, SecureTransport, deliver_secure, inbox_principal_from_own_record,
    open_secure_mailbox,
)

# Receiving: one object owns the Inbox, the transport and the engine; close() releases all three.
principal, warning = inbox_principal_from_own_record(saved_profile.principal, identity)
if warning:
    log.error("saved principal ignored (%s)", warning)
mailbox = open_secure_mailbox(
    identity=identity, store=store, peers=peers, relay=relay, engine=NativeMLSEngine(library),
    inbox={"on_message": persist, "commerce": True, "principal": principal},
)
for outcome in mailbox.follow(stop=stop):
    ...
mailbox.close()

# Sending: the Outbox operation completes only once the peer's Inbox durably committed the envelope.
engine = NativeMLSEngine(library)
secure = SecureTransport(identity, engine, store)
try:
    deliver_secure(outbox, pending.request_id, identity=identity, secure=secure, relay=relay,
                   peer=peer)                      # send=deliver_direct_or_relay(relay, endpoint)
finally:
    secure.close()
    engine.close()
```

A host that shares one engine between a mailbox and a sender (as `examples/secure_relay.py`
does) closes the sender before the mailbox, or passes the mailbox an engine view without
`close`. The manual composition (`Inbox.open` → `SecureTransport` → `SecureMailbox`,
`SecureRelayReplies` → `outbox.deliver`) remains available for hosts that need a shared
transport or their own reply reader. Each attempt
uses a fresh MLS group from the shared OpenMLS engine and ends with an authenticated
receipt after the original Inbox durably commits. `RelayClient.send` acknowledges relay
storage only; it is not an application-delivery receipt. Static application packets are
refused by SecureMailbox, with no downgrade fallback.

Both endpoints must explicitly enable the full peer identity through local policy
(`SecureTransport.set_peer_allowed`; `is_peer_allowed` reads it without resolving anything);
discovery and principal roles do not enable communication or grant execution rights.
Revocation advances the policy generation, so re-enabling cannot revive old handshakes.
The receiver must be online; a timeout leaves the original Outbox operation pending.
Retry that operation ID. The receipt (`ace.delivery.outcome.v1:…:<outcome>`) tells the
sender whether the peer's Inbox delivered, deduplicated or rejected the envelope;
`delivery_rejected` is permanent and never retried by the SDK. The complete inner signed envelope is limited to 40,000 bytes,
and a handshake to 120 seconds. Keep HTTP timeouts bounded and callbacks idempotent.

After ephemeral state erasure, later static-key theft alone cannot decrypt captured past
application deliveries under classical MLS assumptions. Stored plaintext, original Outbox
envelopes and host snapshots are excluded. This is not post-quantum forward secrecy or
authentication. Independent cryptographic review remains a production-release gate.
See [the protocol and failure model](https://github.com/aceprotocol/ace-spec/blob/main/13-session-core.md)
and [source build/packaging](https://github.com/aceprotocol/ace-session-core#readme).

Python: `NativeMLSEngine(trusted_absolute_library_path)`, `SecureTransport` (with `set_peer_allowed`), `SecureMailbox`, `SecureRelayReplies`, `open_secure_mailbox`, `secure_transport_for`, `deliver_secure`, `PairwiseMLS` and `MLSError` are exported from `ace` (and from `ace.session`, `ace.secure_transport`, `ace.secure_mailbox`). Keep the receiver alive across pulls or run `follow`; `pull` alone may only issue an offer. See `examples/secure_relay.py`.
