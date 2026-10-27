"""Packet: the only wire object (prekey encryption + ML-DSA signature).

    header  = encodePayload("ace.v1.packet", from, to, messageId, decimal(timestamp),
                            prekeyId, kemCiphertextBytes)
    (ss, kemCiphertext) = XWing.Encapsulate(prekey.publicKey)
    key     = HKDF-SHA256(ikm=ss, salt="" (empty), info=header, L=32)
    payload = nonce[12] || AES-256-GCM(key, nonce, pad(plaintext), aad=header)
    signature: action "packet", aceId = from, timestamp,
               payload encodePayload(to, messageId, prekeyId, kemCiphertextBytes, payloadBytes)

The header binds from, to and messageId, so a packet whose signature is stripped and re-signed
by another identity no longer decrypts. ``pad`` hides the content length up to a power-of-two
bucket (at least ``MIN_PLAINTEXT_BUCKET``): u32be(len) || content || zeros.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _xwing
from ._encoding import (
    canonical_state_bytes,
    check_json_value,
    check_wire_int,
    conversation_key,
    decode_b64,
    decode_fixed_b64,
    is_ace_id,
    is_message_id,
    is_namespaced_id,
    is_sha256_hex,
    is_thread_id,
    loads_object,
    to_base64,
    wire_int,
)
from ._signing import SCHEME, SIGNATURE_SIZE, encode_payload
from .errors import ACEError
from .identity import ACEIdentity, sign_operational
from .kel import KelState, verify_operational_signature
from .limits import (
    KEM_CIPHERTEXT_SIZE,
    KEM_PUBLIC_KEY_SIZE,
    MAX_PACKET_BYTES,
    MAX_PLAINTEXT_BYTES,
    MIN_PLAINTEXT_BUCKET,
    OFFLINE_WINDOW_SECONDS,
    TIMESTAMP_WINDOW_SECONDS,
)
from .prekeys import Prekey, PrekeyVault, decode_prekey_public_key, prekey_id
from .profiles import CONTACT_TYPE, RECEIPT_TYPE

PACKET_VERSION = "1"
_LABEL = "ace.v1.packet"
_NONCE = 12
_MIN_PAYLOAD = _NONCE + 16  # nonce + AES-GCM tag
_LENGTH_PREFIX = 4
_LARGEST_BUCKET = MAX_PLAINTEXT_BYTES + _LENGTH_PREFIX
_MAX_PAYLOAD = _LARGEST_BUCKET + _MIN_PAYLOAD
_KEYS = {"ace", "messageId", "from", "to", "timestamp", "encryption", "signature"}


@dataclass(frozen=True)
class Packet:
    """A shape-checked packet with its binary fields decoded."""

    message_id: str
    from_id: str
    to_id: str
    timestamp: int
    prekey_id: str
    kem_ciphertext: bytes
    payload: bytes
    signature: dict

    def to_dict(self) -> dict[str, Any]:
        return {
            "ace": PACKET_VERSION,
            "messageId": self.message_id,
            "from": self.from_id,
            "to": self.to_id,
            "timestamp": self.timestamp,
            "encryption": {
                "prekey": self.prekey_id,
                "kemCiphertext": to_base64(self.kem_ciphertext),
                "payload": to_base64(self.payload),
            },
            "signature": dict(self.signature),
        }

    @property
    def header(self) -> bytes:
        return packet_header(
            self.from_id,
            self.to_id,
            self.message_id,
            self.timestamp,
            self.prekey_id,
            self.kem_ciphertext,
        )

    def sign_payload(self) -> bytes:
        return packet_sign_payload(
            self.to_id, self.message_id, self.prekey_id, self.kem_ciphertext, self.payload
        )


@dataclass(frozen=True)
class PrivateMessage:
    """A verified, decrypted message: the packet metadata plus the private content."""

    message_id: str
    from_id: str
    to_id: str
    timestamp: int
    type: str
    schema_digest: str
    thread_id: str | None
    body: dict

    @classmethod
    def of(cls, packet: Packet, content: dict) -> PrivateMessage:
        """``packet``'s metadata with its decoded private ``content``."""
        return cls(
            packet.message_id,
            packet.from_id,
            packet.to_id,
            packet.timestamp,
            content["type"],
            content["schemaDigest"],
            content.get("threadId"),
            content["body"],
        )

    @property
    def conversation(self) -> str:
        return conversation_key(self.from_id, self.to_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "messageId": self.message_id,
            "from": self.from_id,
            "to": self.to_id,
            "timestamp": self.timestamp,
            "type": self.type,
            "schemaDigest": self.schema_digest,
            "threadId": self.thread_id,
            "body": self.body,
        }

    @staticmethod
    def from_dict(d: dict) -> "PrivateMessage":
        return PrivateMessage(
            d["messageId"],
            d["from"],
            d["to"],
            d["timestamp"],
            d["type"],
            d["schemaDigest"],
            d.get("threadId"),
            d["body"],
        )


def packet_header(
    from_id: str, to_id: str, message_id: str, timestamp: int, prekey_id: str, kem: bytes
) -> bytes:
    return encode_payload(_LABEL, from_id, to_id, message_id, str(timestamp), prekey_id, kem)


def packet_sign_payload(
    to_id: str, message_id: str, prekey_id: str, kem: bytes, payload: bytes
) -> bytes:
    """The ``packet`` action payload; signed with ``aceId = from`` at ``timestamp``."""
    return encode_payload(to_id, message_id, prekey_id, kem, payload)


def aead_key(ss: bytes, header: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=header).derive(ss)


# --- padding (03 § Encryption) -------------------------------------------------


def plaintext_bucket(content_len: int) -> int:
    """The padded plaintext length for ``content_len`` content bytes: the smallest power of two
    >= ``MIN_PLAINTEXT_BUCKET`` holding ``content_len + 4``; above 2^20, ``MAX_PLAINTEXT_BYTES +
    4``."""
    n = content_len + _LENGTH_PREFIX
    if n > 1 << 20:
        return _LARGEST_BUCKET
    b = MIN_PLAINTEXT_BUCKET
    while b < n:
        b *= 2
    return b


PLAINTEXT_BUCKETS: frozenset[int] = frozenset(
    [MIN_PLAINTEXT_BUCKET << i for i in range(((1 << 20) // MIN_PLAINTEXT_BUCKET).bit_length())]
    + [_LARGEST_BUCKET]
)


def pad_plaintext(content: bytes) -> bytes:
    """``u32be(len(content)) || content || zeros`` to ``plaintext_bucket(len(content))``."""
    n = len(content)
    return (
        n.to_bytes(_LENGTH_PREFIX, "big")
        + bytes(content)
        + bytes(plaintext_bucket(n) - n - _LENGTH_PREFIX)
    )


def unpad_plaintext(plaintext: bytes) -> bytes:
    """The content inside a padded plaintext, or ``invalid_body`` unless the length is a bucket,
    the prefix fits, the bucket is the one the prefix implies and the padding is all zero."""
    size = len(plaintext)
    n = int.from_bytes(plaintext[:_LENGTH_PREFIX], "big")
    if (
        size not in PLAINTEXT_BUCKETS
        or n > MAX_PLAINTEXT_BYTES
        or _LENGTH_PREFIX + n > size
        or plaintext_bucket(n) != size
        or any(plaintext[_LENGTH_PREFIX + n :])
    ):
        raise ACEError("invalid_body", "plaintext padding is invalid")
    return bytes(plaintext[_LENGTH_PREFIX : _LENGTH_PREFIX + n])


# --- private content ------------------------------------------------------------


def _is_admission(value: object) -> bool:
    """The closed object ``{proof, permit, source}`` of three JSON objects (03 § Private
    content); the permits and the PublishedAgent are checked by the receiver (05 § Admission
    recovery)."""
    return (
        type(value) is dict
        and set(value) == {"proof", "permit", "source"}
        and all(type(v) is dict for v in value.values())
    )


def encode_content(
    type_: str,
    schema_digest: str,
    body: dict,
    thread_id: str | None = None,
    *,
    prekey: bytes,
    admission: dict | None = None,
) -> bytes:
    """Canonical JSON of ``{type, schemaDigest, threadId?, body, prekey, admission?}``.
    ``prekey``: the 1216-byte public key the sender offers the receiver for its replies (04 §
    Peer prekeys). ``admission``: the ``{proof, permit, source}`` of an Outbox retry (05 §
    Admission recovery)."""
    if not is_namespaced_id(type_):
        raise ACEError("invalid_argument", "type must be a namespaced identifier")
    if not is_sha256_hex(schema_digest):
        raise ACEError("invalid_argument", "schemaDigest must be 64 lowercase hex")
    if thread_id is not None and not is_thread_id(thread_id):
        raise ACEError("invalid_argument", "threadId must be 1..256 characters without controls")
    if not isinstance(prekey, (bytes, bytearray)) or len(prekey) != KEM_PUBLIC_KEY_SIZE:
        raise ACEError("invalid_argument", f"prekey must be {KEM_PUBLIC_KEY_SIZE} bytes")
    if admission is not None and (
        not _is_admission(admission) or type_ in (RECEIPT_TYPE, CONTACT_TYPE)
    ):
        raise ACEError(
            "invalid_argument",
            "admission must be {proof, permit, source} of three objects, never on a receipt or "
            "contact",
        )
    if type(body) is not dict:
        raise ACEError("invalid_body", "body must be a JSON object")
    check_json_value({"body": body})  # depth counted from the content root, as receivers do
    content = {
        "type": type_,
        "schemaDigest": schema_digest,
        "body": body,
        "prekey": to_base64(bytes(prekey)),
    }
    if thread_id is not None:
        content["threadId"] = thread_id
    if admission is not None:
        content["admission"] = admission
    raw = canonical_state_bytes(content)
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise ACEError("limit_exceeded", f"private content exceeds {MAX_PLAINTEXT_BYTES} bytes")
    return raw


def decode_content(raw: bytes) -> dict:
    """``{type, schemaDigest, threadId?, body, prekey, admission?}`` from decrypted bytes, with
    ``prekey`` decoded to its 1216 bytes, or ``invalid_body`` (also for ``admission`` on a receipt
    or contact). The receiver strips ``prekey`` and ``admission`` before anything reaches the
    host."""
    c = loads_object(raw, "invalid_body", "private content")
    if (
        not {"type", "schemaDigest", "body", "prekey"}
        <= set(c)
        <= {"type", "schemaDigest", "threadId", "body", "prekey", "admission"}
        or not is_namespaced_id(c["type"])
        or not is_sha256_hex(c["schemaDigest"])
        or type(c["body"]) is not dict
        or ("threadId" in c and not is_thread_id(c["threadId"]))
        or (
            "admission" in c
            and (not _is_admission(c["admission"]) or c["type"] in (RECEIPT_TYPE, CONTACT_TYPE))
        )
    ):
        raise ACEError("invalid_body", "invalid private content")
    c["prekey"] = decode_prekey_public_key(c["prekey"])
    return c


# --- create ------------------------------------------------------------------


def create_packet(
    identity: ACEIdentity,
    to: str,
    prekey: Prekey | dict,
    plaintext: bytes,
    *,
    timestamp: int,
    message_id: str | None = None,
    _kem: tuple[bytes, bytes] | None = None,
    _nonce: bytes | None = None,
) -> dict:
    """Encrypt ``plaintext`` (encoded private content) to ``prekey`` and sign. Returns the wire
    dict. ``_kem`` = ``(ss, kemCiphertext)`` and ``_nonce`` are deterministic-vector hooks."""
    if isinstance(prekey, dict):
        public = decode_fixed_b64(
            prekey.get("publicKey"), KEM_PUBLIC_KEY_SIZE, "invalid_argument", "prekey.publicKey"
        )
        prekey = Prekey(prekey.get("id"), public)  # type: ignore[arg-type]
    if not is_ace_id(to) or to == identity.get_ace_id():
        raise ACEError("invalid_argument", "to must be another ACE ID")
    if prekey_id(prekey.public_key) != prekey.id:
        raise ACEError("invalid_argument", "prekey id does not match its public key")
    check_wire_int(timestamp, "timestamp")
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ACEError("limit_exceeded", f"plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes")
    from_id = identity.get_ace_id()
    mid = str(uuid.uuid4()) if message_id is None else message_id
    if not is_message_id(mid):
        raise ACEError("invalid_argument", "message_id must be a lowercase UUIDv4")
    ss, kem = _xwing.encapsulate(prekey.public_key) if _kem is None else _kem
    header = packet_header(from_id, to, mid, timestamp, prekey.id, kem)
    nonce = os.urandom(_NONCE) if _nonce is None else _nonce
    payload = nonce + AESGCM(aead_key(ss, header)).encrypt(nonce, pad_plaintext(plaintext), header)
    sign_payload = packet_sign_payload(to, mid, prekey.id, kem, payload)
    signature = sign_operational(identity, timestamp, sign_payload, "packet")
    out = Packet(mid, from_id, to, timestamp, prekey.id, kem, payload, signature).to_dict()
    if len(canonical_state_bytes(out)) > MAX_PACKET_BYTES:
        raise ACEError("limit_exceeded", f"packet exceeds {MAX_PACKET_BYTES} bytes")
    return out


# --- open --------------------------------------------------------------------


def decode_packet(obj: object) -> Packet:
    """The closed packet shape; ``invalid_packet`` or ``unsupported_version``."""
    if type(obj) is not dict:
        raise ACEError("invalid_packet", "packet must be a JSON object")
    if isinstance(obj.get("ace"), str) and obj["ace"] != PACKET_VERSION:
        raise ACEError("unsupported_version", 'packet version must be "1"')
    try:
        too_big = len(canonical_state_bytes(obj)) > MAX_PACKET_BYTES
    except (TypeError, ValueError):
        raise ACEError("invalid_packet", "packet is not canonical JSON") from None
    if too_big:
        raise ACEError("invalid_packet", "packet exceeds MAX_PACKET_BYTES")
    if set(obj) != _KEYS or obj["ace"] != PACKET_VERSION:
        raise ACEError("invalid_packet", "packet has unknown or missing members")
    ts = wire_int(obj["timestamp"])
    if (
        not is_message_id(obj["messageId"])
        or not is_ace_id(obj["from"])
        or not is_ace_id(obj["to"])
        or obj["from"] == obj["to"]
        or ts is None
    ):
        raise ACEError("invalid_packet", "invalid packet metadata")
    enc, sig = obj["encryption"], obj["signature"]
    if type(enc) is not dict or set(enc) != {"prekey", "kemCiphertext", "payload"}:
        raise ACEError("invalid_packet", "encryption must be {prekey, kemCiphertext, payload}")
    if not is_sha256_hex(enc["prekey"]):
        raise ACEError("invalid_packet", "encryption.prekey must be 64 lowercase hex")
    kem = decode_fixed_b64(
        enc["kemCiphertext"], KEM_CIPHERTEXT_SIZE, "invalid_packet", "kemCiphertext"
    )
    payload = decode_b64(enc["payload"], "invalid_packet", "payload", max_bytes=_MAX_PAYLOAD)
    if len(payload) - _MIN_PAYLOAD not in PLAINTEXT_BUCKETS:
        raise ACEError("invalid_packet", "encryption.payload is not a padded bucket")
    if (
        type(sig) is not dict
        or set(sig) != {"scheme", "seq", "value"}
        or sig["scheme"] != SCHEME
        or wire_int(sig["seq"]) is None
    ):
        raise ACEError("invalid_packet", "signature must be {scheme: ml-dsa-65, seq, value}")
    decode_fixed_b64(sig["value"], SIGNATURE_SIZE, "invalid_packet", "signature.value")
    # Wire integers: the lexical form does not matter (1000, 1000.0 and 1e3 are equal).
    sig = {**sig, "seq": wire_int(sig["seq"])}
    return Packet(obj["messageId"], obj["from"], obj["to"], ts, enc["prekey"], kem, payload, sig)


def parse_packet(raw: bytes) -> Packet:
    """Raw wire bytes -> ``Packet`` (size, JSON and shape checks)."""
    if len(raw) > MAX_PACKET_BYTES + 4096:
        raise ACEError("invalid_packet", "packet exceeds MAX_PACKET_BYTES")
    return decode_packet(loads_object(raw, "invalid_packet", "packet"))


def verify_packet(packet: Packet, sender: KelState, now: int) -> None:
    """Sender binding and operational signature at ``now`` (06 step 4):
    ``invalid_signature`` / ``stale_peer_binding``."""
    if sender.ace_id != packet.from_id:
        raise ACEError("invalid_signature", "packet sender does not match the verified identity")
    verify_operational_signature(
        sender, packet.signature, packet.sign_payload(), "packet", packet.timestamp, now
    )


def check_window(packet: Packet, now: int) -> None:
    """``now - OFFLINE_WINDOW_SECONDS <= timestamp <= now + TIMESTAMP_WINDOW_SECONDS``, else
    ``stale_timestamp`` (06 step 5)."""
    if not now - OFFLINE_WINDOW_SECONDS <= packet.timestamp <= now + TIMESTAMP_WINDOW_SECONDS:
        raise ACEError("stale_timestamp", "packet timestamp is outside the acceptance window")


def decrypt_packet(packet: Packet, vault: PrekeyVault, now: int | None = None) -> bytes:
    """The unpadded plaintext; ``unknown_prekey``, ``decryption_failed`` or ``invalid_body`` (bad
    padding). ``now`` lets the vault refuse prekeys whose retention ended (04 § Prekey); a peer
    prekey opens only a packet from the peer it was offered to (04 § Peer prekeys)."""
    key = vault.open(packet.prekey_id, now, sender=packet.from_id)
    try:
        ss = key.decapsulate(packet.kem_ciphertext)
        p = packet.payload
        padded = AESGCM(aead_key(ss, packet.header)).decrypt(p[:_NONCE], p[_NONCE:], packet.header)
    except InvalidTag:
        raise ACEError("decryption_failed", "AEAD authentication failed") from None
    except Exception as exc:
        raise ACEError("decryption_failed", f"decryption failed: {type(exc).__name__}") from None
    return unpad_plaintext(padded)
