"""Tests for AgentProfile types and validate_profile."""

import pytest

from ace.types import AgentProfile, ProfilePricing
from ace.discovery import validate_profile


class TestValidateProfileValid:
    """Tests that valid profiles pass validation."""

    def test_full_profile(self):
        profile = AgentProfile(
            name="My Agent",
            description="A helpful agent",
            image="https://example.com/avatar.png",
            tags=["ai", "assistant"],
            capabilities=["chat", "search"],
            chains=["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"],
            endpoint="https://example.com/agent",
            pricing=ProfilePricing(currency="USD", max_amount="10.00"),
        )
        validate_profile(profile)

    def test_empty_profile(self):
        profile = AgentProfile()
        validate_profile(profile)

    def test_minimal_profile_name_only(self):
        profile = AgentProfile(name="x")
        validate_profile(profile)

    def test_pricing_without_max_amount(self):
        profile = AgentProfile(pricing=ProfilePricing(currency="USD"))
        validate_profile(profile)


class TestValidateProfileName:
    """Tests for name validation."""

    def test_name_max_length(self):
        profile = AgentProfile(name="a" * 64)
        validate_profile(profile)

    def test_name_too_long(self):
        profile = AgentProfile(name="a" * 65)
        with pytest.raises(ValueError, match="name must be 1-64 characters"):
            validate_profile(profile)

    def test_name_empty_string(self):
        profile = AgentProfile(name="")
        with pytest.raises(ValueError, match="name must be 1-64 characters"):
            validate_profile(profile)


class TestValidateProfileDescription:
    """Tests for description validation."""

    def test_description_max_length(self):
        profile = AgentProfile(description="a" * 256)
        validate_profile(profile)

    def test_description_too_long(self):
        profile = AgentProfile(description="a" * 257)
        with pytest.raises(ValueError, match="description must be at most 256 characters"):
            validate_profile(profile)

    def test_description_control_chars(self):
        profile = AgentProfile(description="hello\x00world")
        with pytest.raises(ValueError, match="description must not contain control characters"):
            validate_profile(profile)

    def test_description_newline_rejected(self):
        profile = AgentProfile(description="hello\nworld")
        with pytest.raises(ValueError, match="description must not contain control characters"):
            validate_profile(profile)

    def test_description_tab_rejected(self):
        profile = AgentProfile(description="hello\tworld")
        with pytest.raises(ValueError, match="description must not contain control characters"):
            validate_profile(profile)


class TestValidateProfileImage:
    """Tests for image validation."""

    def test_image_valid_https(self):
        profile = AgentProfile(image="https://example.com/avatar.png")
        validate_profile(profile)

    def test_image_max_length(self):
        profile = AgentProfile(image="https://example.com/" + "a" * 491)
        validate_profile(profile)

    def test_image_too_long(self):
        profile = AgentProfile(image="https://example.com/" + "a" * 493)
        with pytest.raises(ValueError, match="image must be at most 512 characters"):
            validate_profile(profile)

    def test_image_http_rejected(self):
        profile = AgentProfile(image="http://example.com/avatar.png")
        with pytest.raises(ValueError, match="image must be a valid HTTPS URL"):
            validate_profile(profile)

    def test_image_no_scheme_rejected(self):
        profile = AgentProfile(image="example.com/avatar.png")
        with pytest.raises(ValueError, match="image must be a valid HTTPS URL"):
            validate_profile(profile)

    def test_image_none_accepted(self):
        profile = AgentProfile(image=None)
        validate_profile(profile)


class TestValidateProfileTags:
    """Tests for tags validation."""

    def test_tags_max_count(self):
        profile = AgentProfile(tags=[f"tag{i}" for i in range(10)])
        validate_profile(profile)

    def test_tags_too_many(self):
        profile = AgentProfile(tags=[f"tag{i}" for i in range(11)])
        with pytest.raises(ValueError, match="tags must be a list of at most 10 items"):
            validate_profile(profile)

    def test_tag_max_length(self):
        profile = AgentProfile(tags=["a" * 32])
        validate_profile(profile)

    def test_tag_too_long(self):
        profile = AgentProfile(tags=["a" * 33])
        with pytest.raises(ValueError, match="lowercase alphanumeric.*tags"):
            validate_profile(profile)

    def test_tag_uppercase_rejected(self):
        profile = AgentProfile(tags=["Hello"])
        with pytest.raises(ValueError, match="lowercase alphanumeric.*tags"):
            validate_profile(profile)

    def test_tag_with_spaces_rejected(self):
        profile = AgentProfile(tags=["hello world"])
        with pytest.raises(ValueError, match="lowercase alphanumeric.*tags"):
            validate_profile(profile)

    def test_tag_with_hyphen_valid(self):
        profile = AgentProfile(tags=["my-tag"])
        validate_profile(profile)

    def test_tag_starting_with_hyphen_rejected(self):
        profile = AgentProfile(tags=["-invalid"])
        with pytest.raises(ValueError, match="lowercase alphanumeric.*tags"):
            validate_profile(profile)


class TestValidateProfileCapabilities:
    """Tests for capabilities validation."""

    def test_capabilities_max_count(self):
        profile = AgentProfile(capabilities=[f"cap{i}" for i in range(20)])
        validate_profile(profile)

    def test_capabilities_too_many(self):
        profile = AgentProfile(capabilities=[f"cap{i}" for i in range(21)])
        with pytest.raises(ValueError, match="capabilities must be a list of at most 20 items"):
            validate_profile(profile)

    def test_capability_uppercase_rejected(self):
        profile = AgentProfile(capabilities=["Chat"])
        with pytest.raises(ValueError, match="lowercase alphanumeric.*capabilities"):
            validate_profile(profile)

    def test_capability_with_hyphen_valid(self):
        profile = AgentProfile(capabilities=["web-search"])
        validate_profile(profile)


class TestValidateProfileChains:
    """Tests for chains validation."""

    def test_chains_max_count(self):
        profile = AgentProfile(chains=[f"eip155:{i}" for i in range(10)])
        validate_profile(profile)

    def test_chains_too_many(self):
        profile = AgentProfile(chains=[f"eip155:{i}" for i in range(11)])
        with pytest.raises(ValueError, match="chains must be a list of at most 10 items"):
            validate_profile(profile)

    def test_chain_missing_colon_rejected(self):
        profile = AgentProfile(chains=["ethereum"])
        with pytest.raises(ValueError, match="CAIP-2 identifier"):
            validate_profile(profile)

    def test_chain_valid_caip2(self):
        profile = AgentProfile(chains=["eip155:1"])
        validate_profile(profile)


class TestValidateProfileEndpoint:
    """Tests for endpoint validation."""

    def test_endpoint_https_valid(self):
        profile = AgentProfile(endpoint="https://example.com")
        validate_profile(profile)

    def test_endpoint_http_rejected(self):
        profile = AgentProfile(endpoint="http://example.com")
        with pytest.raises(ValueError, match="valid HTTPS URL with host"):
            validate_profile(profile)

    def test_endpoint_no_scheme_rejected(self):
        profile = AgentProfile(endpoint="example.com")
        with pytest.raises(ValueError, match="valid HTTPS URL with host"):
            validate_profile(profile)

    def test_endpoint_missing_host_rejected(self):
        profile = AgentProfile(endpoint="https:///nohost")
        with pytest.raises(ValueError, match="valid HTTPS URL with host"):
            validate_profile(profile)

    def test_endpoint_empty_host_rejected(self):
        profile = AgentProfile(endpoint="https://")
        with pytest.raises(ValueError, match="valid HTTPS URL with host"):
            validate_profile(profile)


class TestValidateProfilePricing:
    """Tests for pricing validation."""

    def test_pricing_valid(self):
        profile = AgentProfile(pricing=ProfilePricing(currency="USD", max_amount="100"))
        validate_profile(profile)

    def test_pricing_missing_currency(self):
        profile = AgentProfile(pricing=ProfilePricing(currency=""))
        with pytest.raises(ValueError, match="pricing.currency is required"):
            validate_profile(profile)

    def test_pricing_dict_normalized(self):
        profile = AgentProfile(pricing={"currency": "USD", "maxAmount": "100"})
        validate_profile(profile)
        assert isinstance(profile.pricing, ProfilePricing)
        assert profile.pricing.max_amount == "100"
