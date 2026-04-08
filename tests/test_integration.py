import pytest
from ace import (
    SoftwareIdentity, create_message, parse_message,
    ReplayDetector, ThreadStateMachine,
)


def test_buyer_seller_flow():
    """Full RFQ → Offer → Accept flow between ed25519 and secp256k1 agents."""
    buyer = SoftwareIdentity.generate("ed25519")
    seller = SoftwareIdentity.generate("secp256k1")
    thread_id = "deal-gpu-001"
    sm_buyer = ThreadStateMachine()
    sm_seller = ThreadStateMachine()
    rd_buyer = ReplayDetector()
    rd_seller = ReplayDetector()

    # Buyer sends RFQ
    rfq = create_message(
        sender=buyer,
        recipient_pub_key=seller.get_encryption_public_key(),
        recipient_ace_id=seller.get_ace_id(),
        type_="rfq",
        body={"need": "4x A100 GPU for 2 hours", "maxPrice": "50.00", "currency": "USD"},
        state_machine=sm_buyer,
        thread_id=thread_id,
    )
    assert rfq.ace == "1.0"
    assert rfq.thread_id == thread_id

    # Seller parses RFQ
    parsed_rfq = parse_message(rfq, seller, buyer.get_signing_public_key(), state_machine=sm_seller, replay_detector=rd_seller)
    assert parsed_rfq.body == {"need": "4x A100 GPU for 2 hours", "maxPrice": "50.00", "currency": "USD"}

    # Seller sends Offer
    offer = create_message(
        sender=seller,
        recipient_pub_key=buyer.get_encryption_public_key(),
        recipient_ace_id=buyer.get_ace_id(),
        type_="offer",
        body={"price": "40.00", "currency": "USD", "terms": "4x A100, 2h", "ttl": 300},
        state_machine=sm_seller,
        thread_id=thread_id,
    )
    parsed_offer = parse_message(offer, buyer, seller.get_signing_public_key(), state_machine=sm_buyer, replay_detector=rd_buyer)
    assert parsed_offer.body["price"] == "40.00"

    # Buyer sends Accept
    accept = create_message(
        sender=buyer,
        recipient_pub_key=seller.get_encryption_public_key(),
        recipient_ace_id=seller.get_ace_id(),
        type_="accept",
        body={"offerId": offer.message_id},
        state_machine=sm_buyer,
        thread_id=thread_id,
    )
    parsed_accept = parse_message(accept, seller, buyer.get_signing_public_key(), state_machine=sm_seller, replay_detector=rd_seller)
    assert parsed_accept.body["offerId"] == offer.message_id


def test_reject_invalid_signature():
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")
    impersonator = SoftwareIdentity.generate("ed25519")
    sm = ThreadStateMachine()

    msg = create_message(
        sender=sender,
        recipient_pub_key=receiver.get_encryption_public_key(),
        recipient_ace_id=receiver.get_ace_id(),
        type_="text",
        body={"message": "Trust me"},
        state_machine=sm,
    )

    with pytest.raises(ValueError, match="does not match|Signature"):
        parse_message(msg, receiver, impersonator.get_signing_public_key(), state_machine=sm)


def test_replay_detection():
    detector = ReplayDetector()
    sender = SoftwareIdentity.generate("ed25519")
    receiver = SoftwareIdentity.generate("ed25519")

    msg = create_message(
        sender=sender,
        recipient_pub_key=receiver.get_encryption_public_key(),
        recipient_ace_id=receiver.get_ace_id(),
        type_="info",
        body={"message": "hello"},
        state_machine=ThreadStateMachine(),
    )

    assert detector.check_and_reserve(msg.message_id) is True
    assert detector.check_and_reserve(msg.message_id) is False


def test_cross_scheme_communication():
    """ed25519 ↔ secp256k1 bidirectional communication."""
    agent_ed = SoftwareIdentity.generate("ed25519")
    agent_sec = SoftwareIdentity.generate("secp256k1")
    sm = ThreadStateMachine()

    # ed25519 → secp256k1
    msg1 = create_message(
        sender=agent_ed,
        recipient_pub_key=agent_sec.get_encryption_public_key(),
        recipient_ace_id=agent_sec.get_ace_id(),
        type_="text",
        body={"message": "Ed25519 → secp256k1"},
        state_machine=sm,
    )
    parsed1 = parse_message(msg1, agent_sec, agent_ed.get_signing_public_key(), state_machine=sm)
    assert parsed1.body == {"message": "Ed25519 → secp256k1"}

    # secp256k1 → ed25519
    msg2 = create_message(
        sender=agent_sec,
        recipient_pub_key=agent_ed.get_encryption_public_key(),
        recipient_ace_id=agent_ed.get_ace_id(),
        type_="text",
        body={"message": "secp256k1 → Ed25519"},
        state_machine=sm,
    )
    parsed2 = parse_message(msg2, agent_ed, agent_sec.get_signing_public_key(), state_machine=sm)
    assert parsed2.body == {"message": "secp256k1 → Ed25519"}
