"""Tests for all security hardening fixes — edge cases, input validation, and attack prevention."""

from __future__ import annotations

import threading
import pytest

from ace import SoftwareIdentity, ReplayDetector, create_message, parse_message, ThreadStateMachine
from ace.encryption import (
    encrypt, decrypt, compute_conversation_id,
    _MIN_PAYLOAD_LEN, MAX_PAYLOAD_SIZE,
)
from ace.signing import build_sign_data, encode_payload, verify_signature, decode_signature


# ============================================================================
# C1: Payload length validation in decrypt
# ============================================================================

class TestDecryptPayloadValidation:
    def setup_method(self):
        self.sender = SoftwareIdentity.generate("ed25519")
        self.receiver = SoftwareIdentity.generate("ed25519")
        self.conv_id = compute_conversation_id(
            self.sender.get_encryption_public_key(),
            self.receiver.get_encryption_public_key(),
        )

    def test_empty_payload_rejected(self):
        eph_pub, _ = encrypt(b"x", self.receiver.get_encryption_public_key(), self.conv_id)
        with pytest.raises(ValueError, match="too short"):
            decrypt(eph_pub, b"", self.receiver.get_encryption_private_key(), self.conv_id)

    def test_short_payload_rejected(self):
        eph_pub, _ = encrypt(b"x", self.receiver.get_encryption_public_key(), self.conv_id)
        with pytest.raises(ValueError, match="too short"):
            decrypt(eph_pub, b"\x00" * 27, self.receiver.get_encryption_private_key(), self.conv_id)

    def test_minimum_valid_payload_length(self):
        """28 bytes (nonce + tag) should not trigger the length error."""
        eph_pub, _ = encrypt(b"x", self.receiver.get_encryption_public_key(), self.conv_id)
        # 28 bytes will fail GCM auth (wrong data), but should NOT raise "too short"
        with pytest.raises(Exception) as exc_info:
            decrypt(eph_pub, b"\x00" * 28, self.receiver.get_encryption_private_key(), self.conv_id)
        assert "too short" not in str(exc_info.value)

    def test_empty_plaintext_roundtrip(self):
        """Empty plaintext should encrypt and decrypt correctly."""
        eph_pub, payload = encrypt(b"", self.receiver.get_encryption_public_key(), self.conv_id)
        decrypted = decrypt(eph_pub, payload, self.receiver.get_encryption_private_key(), self.conv_id)
        assert decrypted == b""


# ============================================================================
# C2: ReplayDetector thread safety
# ============================================================================

class TestReplayDetectorThreadSafety:
    def test_concurrent_replay_detection(self):
        """Concurrent check_and_reserve for the same ID must accept exactly once."""
        detector = ReplayDetector(100_000)
        results: list[bool] = []
        barrier = threading.Barrier(50)

        def try_reserve():
            barrier.wait()
            results.append(detector.check_and_reserve("msg-race"))

        threads = [threading.Thread(target=try_reserve) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 1
        assert results.count(False) == 49


# ============================================================================
# C3: ReplayDetector integrated into parse_message
# ============================================================================

class TestParseMessageReplayIntegration:
    def test_replay_detected_in_parse(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        detector = ReplayDetector()
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "hello"},
            state_machine=sm,
        )

        # First parse should succeed
        parse_message(
            msg, receiver,
            sender.get_signing_public_key(),
            state_machine=sm,
            replay_detector=detector,
        )

        # Second parse of same message should raise replay
        with pytest.raises(ValueError, match="Replay detected"):
            parse_message(
                msg, receiver,
                sender.get_signing_public_key(),
                state_machine=sm,
                replay_detector=detector,
            )

    def test_parse_without_detector_still_works(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "hello"},
            state_machine=sm,
        )

        # Should work without replay_detector
        parsed = parse_message(
            msg, receiver,
            sender.get_signing_public_key(),
            state_machine=sm,
        )
        assert parsed.body["message"] == "hello"


# ============================================================================
# I1: Signing scheme validation
# ============================================================================

class TestSchemeValidation:
    def test_invalid_scheme_init(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        enc_priv = X25519PrivateKey.generate()
        with pytest.raises(ValueError, match="Unsupported signing scheme"):
            SoftwareIdentity("none", b"\x00" * 32, enc_priv)

    def test_invalid_scheme_generate(self):
        with pytest.raises(ValueError, match="Unsupported signing scheme"):
            SoftwareIdentity.generate("rsa")

    def test_empty_scheme_rejected(self):
        with pytest.raises(ValueError, match="Unsupported signing scheme"):
            SoftwareIdentity.generate("")

    def test_verify_unknown_scheme_raises(self):
        with pytest.raises(ValueError, match="Unsupported signing scheme"):
            verify_signature(b"\x00" * 32, b"\x00" * 64, "rsa", b"\x00" * 32)


# ============================================================================
# I2: Precise exception handling in verify_signature
# ============================================================================

class TestVerifySignaturePrecision:
    def test_ed25519_wrong_length_sig(self):
        id_ = SoftwareIdentity.generate("ed25519")
        payload = encode_payload("rfq", "ace:sha256:recipient", "conv", "msg-001", "thread-1", b"\x01")
        sign_data = build_sign_data("message", id_.get_ace_id(), 1741000000, payload)
        # Wrong signature length
        assert verify_signature(sign_data, b"\x00" * 10, "ed25519", id_.get_signing_public_key()) is False

    def test_secp256k1_wrong_length_sig(self):
        id_ = SoftwareIdentity.generate("secp256k1")
        payload = encode_payload("rfq", "ace:sha256:recipient", "conv", "msg-001", "thread-1", b"\x01")
        sign_data = build_sign_data("message", id_.get_ace_id(), 1741000000, payload)
        # Wrong signature length should be explicitly rejected
        assert verify_signature(sign_data, b"\x00" * 64, "secp256k1", id_.get_signing_public_key()) is False


# ============================================================================
# I3: X25519 public key validation
# ============================================================================

class TestPublicKeyValidation:
    def test_zero_key_rejected_encrypt(self):
        with pytest.raises(ValueError, match="all-zeros"):
            encrypt(b"test", b"\x00" * 32, "a" * 64)

    def test_wrong_length_key_rejected_encrypt(self):
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            encrypt(b"test", b"\x00" * 16, "a" * 64)

    def test_zero_key_rejected_decrypt(self):
        receiver = SoftwareIdentity.generate("ed25519")
        with pytest.raises(ValueError, match="all-zeros"):
            decrypt(b"\x00" * 32, b"\x00" * 28, receiver.get_encryption_private_key(), "a" * 64)

    def test_wrong_length_key_rejected_decrypt(self):
        receiver = SoftwareIdentity.generate("ed25519")
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            decrypt(b"\x00" * 10, b"\x00" * 28, receiver.get_encryption_private_key(), "a" * 64)


# ============================================================================
# I5: Private key export safeguard
# ============================================================================

class TestPrivateKeyExportGuard:
    def test_to_dict_without_flag_raises(self):
        id_ = SoftwareIdentity.generate("ed25519")
        with pytest.raises(ValueError, match="include_private_keys"):
            id_.to_dict()

    def test_to_dict_with_flag_works(self):
        id_ = SoftwareIdentity.generate("ed25519")
        d = id_.to_dict(include_private_keys=True)
        assert "signingPrivateKey" in d
        assert "encryptionPrivateKey" in d

    def test_roundtrip_with_flag(self):
        id_ = SoftwareIdentity.generate("secp256k1")
        d = id_.to_dict(include_private_keys=True)
        restored = SoftwareIdentity.from_dict(d)
        assert restored.get_ace_id() == id_.get_ace_id()


# ============================================================================
# S2: ACEMessage.from_dict input validation
# ============================================================================

class TestACEMessageFromDictValidation:
    def test_missing_required_fields(self):
        from ace.types import ACEMessage
        with pytest.raises(ValueError, match="missing required fields"):
            ACEMessage.from_dict({"ace": "1.0"})

    def test_missing_encryption_fields(self):
        from ace.types import ACEMessage
        d = {
            "ace": "1.0", "messageId": "m", "from": "f", "to": "t",
            "conversationId": "c", "type": "text", "timestamp": 0,
            "encryption": {"payload": "x"},  # missing ephemeralPubKey
            "signature": {"scheme": "ed25519", "value": "v"},
        }
        with pytest.raises(ValueError, match="ephemeralPubKey"):
            ACEMessage.from_dict(d)

    def test_missing_signature_fields(self):
        from ace.types import ACEMessage
        d = {
            "ace": "1.0", "messageId": "m", "from": "f", "to": "t",
            "conversationId": "c", "type": "text", "timestamp": 0,
            "encryption": {"ephemeralPubKey": "k", "payload": "p"},
            "signature": {"scheme": "ed25519"},  # missing value
        }
        with pytest.raises(ValueError, match="value"):
            ACEMessage.from_dict(d)

    def test_encryption_not_dict(self):
        from ace.types import ACEMessage
        d = {
            "ace": "1.0", "messageId": "m", "from": "f", "to": "t",
            "conversationId": "c", "type": "text", "timestamp": 0,
            "encryption": "not-a-dict",
            "signature": {"scheme": "ed25519", "value": "v"},
        }
        with pytest.raises(ValueError, match="encryption"):
            ACEMessage.from_dict(d)


# ============================================================================
# S4: Timestamp range validation in build_sign_data
# ============================================================================

class TestTimestampRangeValidation:
    def test_negative_timestamp_rejected(self):
        with pytest.raises(ValueError, match="Timestamp"):
            build_sign_data("message", "f", -1)

    def test_overflow_timestamp_rejected(self):
        with pytest.raises(ValueError, match="Timestamp"):
            build_sign_data("message", "f", (1 << 53))

    def test_zero_timestamp_accepted(self):
        result = build_sign_data("message", "f", 0)
        assert len(result) == 32

    def test_valid_timestamp_accepted(self):
        result = build_sign_data("message", "f", 1741000000)
        assert len(result) == 32
