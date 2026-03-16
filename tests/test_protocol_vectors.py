from ace.encryption import compute_conversation_id
from ace.identity import compute_ace_id
from ace.signing import build_sign_data, encode_payload
from ace._utils import secp_pubkey_to_address
from coincurve import PublicKey


def test_ace_id_golden_vector():
    signing_pub = bytes(range(33))
    assert compute_ace_id(signing_pub) == (
        "ace:sha256:5d8fcfefa9aeeb711fb8ed1e4b7d5c8a9bafa46e8e76e68aa18adce5a10df6ab"
    )


def test_conversation_id_golden_vector():
    pub_a = bytes(range(1, 33))
    pub_b = bytes(255 - i for i in range(32))
    assert compute_conversation_id(pub_a, pub_b) == (
        "fcdad8d0e1cbe6726f86938e504f6a7290c6d458181ced3e199cd25bf694cb40"
    )


def test_sign_data_golden_vector():
    """Golden vector for the unified build_sign_data format."""
    payload_bytes = bytes([1, 2, 3, 4, 5, 6])
    message_payload = encode_payload(
        "offer",
        "ace:sha256:bbb",
        "conv123",
        "550e8400-e29b-41d4-a716-446655440000",
        "thread-1",
        payload_bytes,
    )
    result = build_sign_data(
        "message",
        "ace:sha256:aaa",
        1741000000,
        message_payload,
    )
    # New golden hash for the unified V1 signing format
    assert result.hex() == "34bc0519278ebfd7ed8c97cbb348eac253a016c97710d69c8feb01afa2405c47"
    assert len(result) == 32

    # Verify determinism
    result2 = build_sign_data(
        "message",
        "ace:sha256:aaa",
        1741000000,
        message_payload,
    )
    assert result == result2


def test_secp256k1_address_golden_vector():
    compressed_pub = bytes.fromhex(
        "0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0"
    )
    uncompressed = PublicKey(compressed_pub).format(compressed=False)
    assert secp_pubkey_to_address(uncompressed) == "0x6370eF2f4Db3611D657b90667De398a2Cc2a370C"
