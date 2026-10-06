# ace-sdk

ACE Protocol SDK for Python — Agent Commerce Engine.

## Install

```bash
pip install ace-sdk
```

Requires Python 3.10+ and `cryptography>=48` (ML-KEM-768 support). Everything is synchronous.

## Quick start

`examples/quickstart.py` is the tested end-to-end example:

```python
from ace import (
    ReplayDetector, SoftwareIdentity, ThreadStateMachine,
    create_message, decode_envelope, parse_message, verify_registration_file,
)

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("secp256k1")
alice_peer = verify_registration_file(alice.to_registration_file(name="Alice", endpoint="https://alice.example/ace"))
bob_peer = verify_registration_file(bob.to_registration_file(name="Bob", endpoint="https://bob.example/ace"))

envelope = create_message(alice, bob_peer, "rfq", {"need": "translate"},
                          ThreadStateMachine(alice.get_ace_id()), thread_id="deal-1")
parsed = parse_message(decode_envelope(envelope.to_dict()), bob, alice_peer,
                       threads=ThreadStateMachine(bob.get_ace_id()), replay=ReplayDetector())
```

## Concepts

- **Errors.** Every SDK failure is an `ACEError` with a stable `code` (e.g. `invalid_envelope`,
  `replay`, `wrong_role`) and a `category`: `permanent`, `transient` or `local`.
  `is_transient` is true for the last two (retry instead of quarantining).
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
