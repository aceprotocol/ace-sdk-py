import re
import time
import pytest
from ace import SoftwareIdentity, ThreadStateMachine
from ace.messages import create_message, validate_body, parse_message, parse_message_from_registration
from ace._utils import to_base64
from ace.encryption import encrypt
from ace.signing import build_sign_data, encode_payload, encode_signature
from ace.types import ACEMessage, EncryptionEnvelope, SignatureEnvelope


class TestValidateBody:
    def test_rfq(self):
        validate_body("rfq", {"need": "GPU rental"})
        with pytest.raises(ValueError, match="need"):
            validate_body("rfq", {})

    def test_offer(self):
        validate_body("offer", {"price": "10", "currency": "USD"})
        with pytest.raises(ValueError, match="currency"):
            validate_body("offer", {"price": "10"})

    def test_accept(self):
        validate_body("accept", {"offerId": "abc"})
        with pytest.raises(ValueError, match="offerId"):
            validate_body("accept", {})

    def test_invoice(self):
        validate_body("invoice", {
            "offerId": "abc", "amount": "10", "currency": "USD",
            "settlementMethod": "crypto/instant",
        })
        with pytest.raises(ValueError, match="offerId"):
            validate_body("invoice", {"amount": "10"})

    def test_deliver_inline(self):
        validate_body("deliver", {"type": "inline", "content": "data"})
        with pytest.raises(ValueError, match="content"):
            validate_body("deliver", {"type": "inline"})

    def test_deliver_reference(self):
        validate_body("deliver", {"type": "reference", "uri": "https://example.com"})
        with pytest.raises(ValueError, match="uri"):
            validate_body("deliver", {"type": "reference"})

    def test_confirm(self):
        validate_body("confirm", {"deliverId": "abc"})
        with pytest.raises(ValueError, match="deliverId"):
            validate_body("confirm", {})

    def test_text(self):
        validate_body("text", {"message": "hello"})
        with pytest.raises(ValueError, match="message"):
            validate_body("text", {})

    def test_info(self):
        validate_body("info", {"message": "ok"})

    def test_rejects_wrong_required_field_types(self):
        with pytest.raises(ValueError, match="amount must be a string"):
            validate_body("invoice", {
                "offerId": "550e8400-e29b-41d4-a716-446655440000",
                "amount": ["3.50"],
                "currency": "USD",
                "settlementMethod": "crypto/instant",
            })

    def test_rejects_wrong_optional_field_types(self):
        with pytest.raises(ValueError, match="ttl must be a number"):
            validate_body("offer", {
                "price": "3.50",
                "currency": "USD",
                "ttl": True,
            })

    def test_rejects_wrong_system_message_type(self):
        with pytest.raises(ValueError, match="message must be a string"):
            validate_body("text", {
                "message": {"hello": "world"},
            })


class TestCreateMessage:
    def test_creates_envelope(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="rfq",
            body={"need": "GPU rental", "maxPrice": "50", "currency": "USD"},
            state_machine=ThreadStateMachine(),
            thread_id="test-001",
        )
        assert msg.ace == "1.0"
        assert msg.type == "rfq"
        assert msg.from_id == sender.get_ace_id()
        assert msg.to_id == receiver.get_ace_id()
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            msg.message_id,
        )

    def test_thread_id(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="rfq",
            body={"need": "test"},
            state_machine=ThreadStateMachine(),
            thread_id="deal-001",
        )
        assert msg.thread_id == "deal-001"


class TestParseMessage:
    def test_roundtrip(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "Hello from ACE!"},
            state_machine=sm,
        )

        parsed = parse_message(
            msg, receiver,
            sender.get_signing_public_key(),
            state_machine=sm,
        )
        assert parsed.type == "text"
        assert parsed.body == {"message": "Hello from ACE!"}
        assert parsed.from_id == sender.get_ace_id()

    def test_rejects_mismatched_sender_identity(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        other = SoftwareIdentity.generate("ed25519")
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "test"},
            state_machine=sm,
        )

        with pytest.raises(ValueError, match="does not match"):
            parse_message(msg, receiver, other.get_signing_public_key(), state_machine=sm)

    def test_rejects_non_uuid_message_id(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "test"},
            state_machine=sm,
        )
        msg.message_id = "../evil"

        with pytest.raises(ValueError, match="UUID v4"):
            parse_message(msg, receiver, sender.get_signing_public_key(), state_machine=sm)

    def test_rejects_conversation_id_not_bound_to_encryption_keys(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        bogus_conversation_id = "b" * 64
        body_bytes = b'{"message":"bound check"}'
        ephemeral_pub_key, payload = encrypt(
            body_bytes,
            receiver.get_encryption_public_key(),
            bogus_conversation_id,
        )
        message_id = "550e8400-e29b-41d4-a716-446655440000"
        timestamp = int(time.time())
        message_payload = encode_payload("text", receiver.get_ace_id(), bogus_conversation_id, message_id, "", payload)
        sign_data = build_sign_data("message", sender.get_ace_id(), timestamp, message_payload)
        signature, scheme = sender.sign(sign_data)
        msg = ACEMessage(
            ace="1.0",
            message_id=message_id,
            from_id=sender.get_ace_id(),
            to_id=receiver.get_ace_id(),
            conversation_id=bogus_conversation_id,
            type="text",
            timestamp=timestamp,
            encryption=EncryptionEnvelope(
                ephemeral_pub_key=to_base64(ephemeral_pub_key),
                payload=to_base64(payload),
            ),
            signature=SignatureEnvelope(
                scheme=scheme,
                value=encode_signature(signature, scheme),
            ),
        )

        with pytest.raises(ValueError, match="conversation_id does not match"):
            parse_message(
                msg,
                receiver,
                sender.get_signing_public_key(),
                state_machine=ThreadStateMachine(),
                sender_encryption_pub_key=sender.get_encryption_public_key(),
            )

    def test_parses_strictly_from_sender_registration(self):
        sender = SoftwareIdentity.generate("secp256k1")
        receiver = SoftwareIdentity.generate("ed25519")
        reg = sender.to_registration_file(name="Seller", endpoint="https://seller.example.com/ace")
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "strict registration path"},
            state_machine=sm,
        )

        parsed = parse_message_from_registration(msg, receiver, reg, state_machine=sm)
        assert parsed.body == {"message": "strict registration path"}

    def test_rejects_invalid_base64_payload(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        sm = ThreadStateMachine()

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="text",
            body={"message": "test"},
            state_machine=sm,
        )
        msg.encryption.payload = "!!!not-base64!!!"

        with pytest.raises(ValueError, match="Base64"):
            parse_message(msg, receiver, sender.get_signing_public_key(), state_machine=sm)

    def test_rejects_oversized_payload_before_base64_decode(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        oversized_payload = "A" * (((10 * 1024 * 1024 + 1 + 2) // 3) * 4)

        msg = ACEMessage(
            ace="1.0",
            message_id="550e8400-e29b-41d4-a716-446655440000",
            from_id=sender.get_ace_id(),
            to_id=receiver.get_ace_id(),
            conversation_id="a" * 64,
            type="text",
            timestamp=int(time.time()),
            encryption=EncryptionEnvelope(
                ephemeral_pub_key="AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                payload=oversized_payload,
            ),
            signature=SignatureEnvelope(
                scheme="ed25519",
                value="AQ==",
            ),
        )

        with pytest.raises(ValueError, match="Payload too large"):
            parse_message(msg, receiver, sender.get_signing_public_key(), state_machine=ThreadStateMachine())

    def test_rejects_tampered_thread_id(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")

        msg = create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="rfq",
            body={"need": "gpu rental"},
            state_machine=ThreadStateMachine(),
            thread_id="deal-a",
        )
        msg.thread_id = "deal-b"

        with pytest.raises(ValueError, match="Signature verification failed"):
            parse_message(msg, receiver, sender.get_signing_public_key(), state_machine=ThreadStateMachine())

    def test_rejects_cross_thread_reference_on_create(self):
        sender = SoftwareIdentity.generate("ed25519")
        receiver = SoftwareIdentity.generate("ed25519")
        sm = ThreadStateMachine()

        create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="rfq",
            body={"need": "gpu rental"},
            state_machine=sm,
            thread_id="deal-a",
        )
        offer_a = create_message(
            sender=receiver,
            recipient_pub_key=sender.get_encryption_public_key(),
            recipient_ace_id=sender.get_ace_id(),
            type_="offer",
            body={"price": "10", "currency": "USD"},
            state_machine=sm,
            thread_id="deal-a",
        )
        create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="accept",
            body={"offerId": offer_a.message_id},
            state_machine=sm,
            thread_id="deal-a",
        )
        create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="rfq",
            body={"need": "design review"},
            state_machine=sm,
            thread_id="deal-b",
        )
        offer_b = create_message(
            sender=receiver,
            recipient_pub_key=sender.get_encryption_public_key(),
            recipient_ace_id=sender.get_ace_id(),
            type_="offer",
            body={"price": "20", "currency": "USD"},
            state_machine=sm,
            thread_id="deal-b",
        )
        create_message(
            sender=sender,
            recipient_pub_key=receiver.get_encryption_public_key(),
            recipient_ace_id=receiver.get_ace_id(),
            type_="accept",
            body={"offerId": offer_b.message_id},
            state_machine=sm,
            thread_id="deal-b",
        )

        with pytest.raises(ValueError, match="same thread"):
            create_message(
                sender=receiver,
                recipient_pub_key=sender.get_encryption_public_key(),
                recipient_ace_id=sender.get_ace_id(),
                type_="invoice",
                body={
                    "offerId": offer_a.message_id,
                    "amount": "20",
                    "currency": "USD",
                    "settlementMethod": "crypto/instant",
                },
                state_machine=sm,
                thread_id="deal-b",
            )
