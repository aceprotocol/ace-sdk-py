import copy

import pytest

from ace import COMMERCE, CORE, TEXT, ProfileManifest, Profiles
from tests.helpers import raises

# 08-profiles § Official manifests
OFFICIAL = {
    "ace:core:1": "66f46d4b8951b75f98abae24a72ceffa173c4e27748d09be78b8d6382ddc8222",
    "ace:text:1": "48619350eaea46b2d60f7ce71fe55867e00c8dd081796b408fb6a95692b8b307",
    "ace:commerce:1": "30583f0a1acd86ac5a217d706df1c27dc7caea5d4f2deed6112807679afab053",
}
MESSAGES = {
    "ace:receipt:1": "a79fea8c61d30c484fdc9ba71fee310c612da84f84827fe2c4b2e99e5708d3e3",
    "ace:contact:1": "29fc76bbaa5a437aa068f823b1f2b2466c89fed6b2ea4b9cfa7c31cc80df15e9",
    "ace:text:1": "e91541145d670369cf651d062e6bb8a94ce2605d4a9f2261ceef1d8a29c2e7da",
    "ace:commerce:rfq:1": "7b3fc71d8e538ff2f5ca0189d81feb237aa31e1f49787e951b90e9e17c1207d5",
    "ace:commerce:payment:1": "33a1fde87d16bf5ad5d4387d73e0823ed14ccd15149f51bee938b54be8d95ff5",
    "ace:commerce:confirm:1": "876f22d60311651917fb7aee630368b885b8378fa1d0ac9dd91b17a65d8800d7",
}
TRANSLATION = {
    "id": "urn:example:translation:1",
    "messages": [
        {
            "type": "urn:example:translation:request:1",
            "schema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "maxLength": 10},
                    "lang": {"type": "string", "enum": ["en", "fr"]},
                    "n": {"type": "integer", "minimum": 1, "maximum": 3},
                },
                "required": ["text"],
                "additionalProperties": False,
            },
        }
    ],
}


def test_official_digests_match_the_spec():
    for m in (CORE, TEXT, COMMERCE):
        assert m.digest == OFFICIAL[m.id]
    every = {t: s.digest for m in (CORE, TEXT, COMMERCE) for t, s in m.messages.items()}
    for t, d in MESSAGES.items():
        assert every[t] == d
    assert len(COMMERCE.messages) == 8


def test_installed_set_and_body_validation():
    custom = ProfileManifest(TRANSLATION)
    profiles = Profiles([TEXT, custom])
    assert profiles.entries() == [TEXT.descriptor(), custom.descriptor()]  # core never announced
    t = "urn:example:translation:request:1"
    d = profiles.message_digest(t)
    profiles.validate(t, d, {"text": "hello", "lang": "fr", "n": 2})
    for body in (
        {},
        {"text": "x" * 11},
        {"text": "a", "lang": "de"},
        {"text": "a", "n": 4},
        {"text": "a", "extra": 1},
        {"text": None},
    ):
        with raises("invalid_body"):
            profiles.validate(t, d, body)
    with raises("unsupported_schema"):
        profiles.validate(t, "0" * 64, {"text": "a"})
    with raises("unsupported_schema"):
        Profiles([TEXT]).message_digest("ace:commerce:rfq:1")
    assert Profiles().supports(TEXT.descriptor())
    assert not Profiles().supports({"id": "ace:text:1", "schemaDigest": "0" * 64})


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
            "$ref": "x",
        },
        {"type": "object", "properties": {}, "required": ["a"], "additionalProperties": False},
        {
            "type": "object",
            "properties": {"a": {"type": "number"}},
            "required": [],
            "additionalProperties": True,
        },
        {
            "type": "object",
            "properties": {"a": {"type": "integer", "minimum": 5, "maximum": 1}},
            "required": [],
            "additionalProperties": True,
        },
        {"type": "string"},
    ],
)
def test_invalid_schemas(schema):
    m = copy.deepcopy(TRANSLATION)
    m["messages"][0]["schema"] = schema
    with raises("invalid_argument"):
        ProfileManifest(m)


def test_reserved_prefix_and_conflicts():
    with raises("invalid_argument"):
        ProfileManifest({**TRANSLATION, "id": "ace:text:1"})
    ProfileManifest({**TRANSLATION, "id": "urn:ace:x:1"})  # only ace: is reserved
    with raises("invalid_argument"):
        ProfileManifest(COMMERCE.to_dict())  # official content still needs the bundled path
    with raises("invalid_argument"):
        Profiles([TEXT, ProfileManifest(TRANSLATION), ProfileManifest(TRANSLATION)])
    # 08: an endpoint MUST reject a manifest defining a message type already installed
    clash = {**TRANSLATION, "id": "urn:example:other:1"}
    with raises("invalid_argument"):
        Profiles([TEXT, ProfileManifest(TRANSLATION), ProfileManifest(clash)])
