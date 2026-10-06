# ace-sdk

ACE Protocol SDK for Python — Agent Commerce Engine.

## Install

```bash
pip install ace-sdk
```

Requires Python 3.10+ and `cryptography>=48` (ML-KEM-768 support).

## Encryption

Messages are end-to-end encrypted with a hybrid post-quantum pipeline:

```
X-Wing (X25519 + ML-KEM-768)  →  HKDF-SHA256  →  AES-256-GCM
```

X-Wing is specified in draft-connolly-cfrg-xwing-kem-11; the SDK reproduces the
draft's test vector 1 from the shared `ace-spec/test-vectors.json`
(`tests/test_interop_vectors.py`).

- The recipient's static encryption key is an X-Wing public key (1216 bytes);
  its private key is a 32-byte seed (`encryptionPrivateKey` in exported identities).
- Each message carries a fresh 1120-byte KEM ciphertext (`encryption.kemCiphertext`)
  and `encryption.payload = nonce[12] || ciphertext || tag[16]`.
- `aesKey = HKDF-SHA256(ikm = sharedSecret, salt = SHA-256("ace.protocol.kem.v1"),
  info = conversationId, L = 32)`; the conversation ID is also the GCM AAD.
- The KEM ciphertext is part of the signed message payload, so a relay that swaps
  it breaks the signature, not just decryption.

Forward secrecy: compromising a **sender** reveals nothing about past messages.
Compromising a **recipient's** static seed reveals every past and future message
encrypted to that key — rotate keys by publishing a new registration file.

Signing uses Ed25519 or secp256k1 (the ACE ID is `sha256(signingPublicKey)`);
`ml-dsa-65` is reserved in the signing-scheme registry but not implemented.

```python
from ace import ReplayDetector, SoftwareIdentity, ThreadStateMachine, create_message, parse_message

alice = SoftwareIdentity.generate("ed25519")
bob = SoftwareIdentity.generate("secp256k1")

msg = create_message(
    alice, bob.get_encryption_public_key(), bob.get_ace_id(),
    "text", {"message": "hello"}, ThreadStateMachine(),
)
parsed = parse_message(msg, bob, alice.get_signing_public_key(), ThreadStateMachine(), ReplayDetector())
assert parsed.body == {"message": "hello"}
```

`ReplayDetector` is the seen store with a replay horizon; persist it across restarts with
`export()` / `ReplayDetector.from_export()`.

The low-level primitives are in `ace.xwing` (`public_key_from_seed`, `encapsulate`,
`decapsulate`, plus the byte-length checks `check_public_key` / `check_ciphertext` /
`check_seed`) and `ace.encryption` (`encrypt`, `decrypt`, `compute_conversation_id`,
`get_ace_kem_salt`, and the Base64 decoders `decode_kem_public_key` /
`decode_kem_ciphertext`). A private key is `os.urandom(32)`; its public key is
`xwing.public_key_from_seed(seed)`.

## Development

```bash
pip install -e ".[dev]" && ruff check ace tests && pytest -q
```

## License

Apache-2.0
