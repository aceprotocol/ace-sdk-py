from ace.types import (
    is_economic_type, is_system_type, is_social_type,
    ACEMessage, EncryptionEnvelope, SignatureEnvelope,
    RegistrationFile, SigningConfig, Capability, PricingInfo, ChainInfo,
    AgentProfile, ProfilePricing, DiscoverAgent, DiscoverResult,
)


def test_economic_types():
    assert is_economic_type("rfq") is True
    assert is_economic_type("offer") is True
    assert is_economic_type("confirm") is True
    assert is_economic_type("info") is False
    assert is_economic_type("text") is False


def test_system_types():
    assert is_system_type("info") is True
    assert is_system_type("rfq") is False


def test_social_types():
    assert is_social_type("text") is True
    assert is_social_type("info") is False


def test_ace_message_to_dict_no_plaintext_body():
    """Wire format must NOT contain plaintext body — only encrypted payload."""
    msg = ACEMessage(
        ace="1.0",
        message_id="msg-001",
        from_id="ace:sha256:" + "a" * 64,
        to_id="ace:sha256:" + "b" * 64,
        conversation_id="c" * 64,
        type="text",
        timestamp=1741000000,
        encryption=EncryptionEnvelope(ephemeral_pub_key="AAAA", payload="BBBB"),
        signature=SignatureEnvelope(scheme="ed25519", value="CCCC"),
    )
    d = msg.to_dict()
    assert "body" not in d
    assert "encryption" in d
    assert d["encryption"]["payload"] == "BBBB"


def test_ace_message_roundtrip():
    """to_dict → from_dict preserves all envelope fields."""
    msg = ACEMessage(
        ace="1.0",
        message_id="msg-001",
        from_id="ace:sha256:" + "a" * 64,
        to_id="ace:sha256:" + "b" * 64,
        conversation_id="c" * 64,
        type="rfq",
        timestamp=1741000000,
        encryption=EncryptionEnvelope(ephemeral_pub_key="AAAA", payload="BBBB"),
        signature=SignatureEnvelope(scheme="ed25519", value="CCCC"),
        thread_id="deal-001",
    )
    d = msg.to_dict()
    restored = ACEMessage.from_dict(d)
    assert restored.message_id == msg.message_id
    assert restored.from_id == msg.from_id
    assert restored.to_id == msg.to_id
    assert restored.conversation_id == msg.conversation_id
    assert restored.type == msg.type
    assert restored.timestamp == msg.timestamp
    assert restored.encryption.ephemeral_pub_key == msg.encryption.ephemeral_pub_key
    assert restored.encryption.payload == msg.encryption.payload
    assert restored.signature.scheme == msg.signature.scheme
    assert restored.signature.value == msg.signature.value
    assert restored.thread_id == msg.thread_id


def test_registration_file_to_dict_with_capabilities_and_pricing():
    """Capabilities with pricing must serialize completely."""
    reg = RegistrationFile(
        ace="1.0",
        id="ace:sha256:" + "a" * 64,
        name="TestAgent",
        endpoint="https://test.example.com/ace",
        tier=0,
        signing=SigningConfig(
            scheme="ed25519",
            address="5Ht7RkVSupHeNbGWiHfwJ3RYn4RZfpAv5tk2UrQKbkWR",
            encryption_public_key="AAAA",
        ),
        capabilities=[
            Capability(
                id="translate",
                description="Translation service",
                input="text",
                output="text",
                pricing=PricingInfo(model="per-call", amount="0.01", currency="USD"),
            ),
            Capability(id="summarize", description="Summarization"),
        ],
        chains=[ChainInfo(network="eip155:1", address="0x1234")],
        settlement=["crypto/instant"],
    )
    d = reg.to_dict()
    caps = d["capabilities"]
    assert len(caps) == 2
    assert caps[0]["pricing"] == {"model": "per-call", "amount": "0.01", "currency": "USD"}
    assert "pricing" not in caps[1]
    assert caps[0]["input"] == "text"
    assert caps[0]["output"] == "text"
    assert d["chains"] == [{"network": "eip155:1", "address": "0x1234"}]
    assert d["settlement"] == ["crypto/instant"]


def test_agent_profile_from_dict_with_wire_pricing():
    profile = AgentProfile.from_dict({
        "name": "RelayBot",
        "pricing": {"currency": "USD", "maxAmount": "10"},
    })
    assert profile.name == "RelayBot"
    assert isinstance(profile.pricing, ProfilePricing)
    assert profile.pricing.max_amount == "10"
    assert profile.to_dict() == {
        "name": "RelayBot",
        "pricing": {"currency": "USD", "maxAmount": "10"},
    }


def test_discover_agent_from_dict_matches_relay_wire_format():
    agent = DiscoverAgent.from_dict({
        "aceId": "ace:sha256:" + "a" * 64,
        "encryptionPublicKey": "enc",
        "signingPublicKey": "sig",
        "scheme": "ed25519",
        "profile": {
            "name": "RelayBot",
            "pricing": {"currency": "USD", "maxAmount": "10"},
        },
    })
    assert agent.ace_id == "ace:sha256:" + "a" * 64
    assert agent.encryption_public_key == "enc"
    assert agent.profile.pricing.max_amount == "10"
    assert agent.to_dict()["profile"]["pricing"]["maxAmount"] == "10"


def test_discover_result_from_dict_normalizes_agents():
    result = DiscoverResult.from_dict({
        "agents": [
            {
                "aceId": "ace:sha256:" + "b" * 64,
                "encryptionPublicKey": "enc2",
                "signingPublicKey": "sig2",
                "scheme": "secp256k1",
                "profile": {"name": "Seller"},
            }
        ],
        "cursor": "next-page",
    })
    assert len(result.agents) == 1
    assert isinstance(result.agents[0], DiscoverAgent)
    assert result.agents[0].profile.name == "Seller"
    assert result.to_dict()["cursor"] == "next-page"
