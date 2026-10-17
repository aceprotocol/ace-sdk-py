# ace-sdk

Python reference SDK for the ACE protocol: post-quantum agent identity (ML-DSA key event logs),
private asynchronous packets (X-Wing prekeys + AES-256-GCM, ML-DSA signatures), signed receipts,
admission (permits, contact requests, blocks) and data-only profile manifests.
ACE lets agents express intent, see which interaction rules a peer supports and exchange
information safely. Who to work with, what to agree and whether to pay are application decisions.

Requires Python 3.10+ and `cryptography>=48`. Everything is synchronous. `ace/__init__.py` is the
only public module.

```bash
pip install ace-sdk
```

## Pieces

| Area | API |
|---|---|
| Identity | `SoftwareIdentity.generate/from_export/recover`, `.rotate()`, `.delegate()`, `verify_kel`, `extend_kel` |
| Prekeys | `PrekeyVault()` (memory) / `PrekeyVault(path)` (0600 file): `current()`, `rotate(now)`, `open(id)`, `prune(now)` |
| Packets | `encode_content`, `create_packet`, `decode_packet`, `verify_packet`, `decrypt_packet` |
| Descriptors | `create_published_agent`, `verify_published_agent` -> `VerifiedAgent`; `issue_delegation`; `verify_erc8004_registration(json, ace_id)` |
| Admission | `create_permit`, `verify_permit`, `PeerStore` (pins, `pending/admitted/blocked`, permits); `NetworkClient.create_invitation/import_invitation` |
| Delivery | `Outbox` (persist, re-encrypt per attempt, backoff 60 s→1 h, expiry after 7 days, `prune`), `Inbox.open` (receive pipeline, receipts, quarantine) |
| Profiles | `Profiles([TEXT, COMMERCE, ProfileManifest(custom)])`; core (`ace:receipt:1`, `ace:contact:1`) is always installed |
| Rules | `ProfileRules` (`types`, `check(event, body)`, `commit(event, body)`; send-side `commit` on the `delivered` receipt, `thread_busy` while a governed message is in flight); optional `commerce_rules(store, ace_id)` |
| Network | `RelayClient` (SSRF-safe; `allow_loopback=True` only for local development), `NetworkClient.open`; optional wake hints `set_wake(gateway, token)` / `clear_wake()` (07 § Wake hints) |
| Relay auth | `create_auth_headers`, `create_registration_request` (relay-side verification lives in the relay) |

## Over a relay

```python
from ace import FileStore, NetworkClient, PrekeyVault, RelayClient, SoftwareIdentity, TEXT

me = SoftwareIdentity.generate()
net = NetworkClient.open(
    me,
    FileStore("state"),
    RelayClient("https://relay.aceprotocol.org"),
    PrekeyVault("state/prekeys.json"),
    visibility="public",
    handle="alice",
    on_message=print,
    on_receipt=lambda frm, body, entry: print(body),
)
net.publish()  # registers on demand; prekey rotates every 24 h
net.connect("@bob@relay.aceprotocol.org", profile=TEXT.id, note="hi")
net.pull()  # receive, send receipts, ack (or net.follow())
for request in net.requests():  # requests never admit anyone by themselves
    net.accept(request.from_id)
mid = net.send(peer_id, "ace:text:1", {"message": "hello"})
net.maintain()  # publish, push permits, sync blocks, retry, prune
```

The host calls `net.maintain()` once at start and then at least every 3600 seconds.

A relay's `{ok: true}` is not delivery: only a signed receipt settles an Outbox entry.
`examples/quickstart.py` is a tested in-memory walkthrough.

Only one process may hold the receive role of a store (``Inbox``, lock ``receive``); others create
``NetworkClient.open(..., receive=False)`` to publish and send. Pass ``store=`` to ``RelayClient`` so registration
timestamps stay strictly increasing across processes sharing an identity.

## Commerce

```python
from ace import COMMERCE, TEXT, Profiles, commerce_rules

profiles = Profiles([TEXT, COMMERCE])
rules = [commerce_rules(store, me.get_ace_id())]  # pass to NetworkClient / Inbox / Outbox
```

The state machine is `idle → requested → offered → accepted | rejected`, then
`invoiced → paid → delivered → confirmed`. Settlement is `stablecoin` (CAIP-19 asset) or
`stripe-link`. A received commerce message never authorizes a payment.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```
