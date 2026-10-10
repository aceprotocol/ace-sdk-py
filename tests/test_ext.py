"""Namespaced extensions (02 § Profile Fields) and urn:ace:commerce:1 (04 § Commerce extension)."""

import pytest

from ace import (
    COMMERCE_EXT,
    MAX_EXT_BYTES,
    MAX_EXT_DEPTH,
    MAX_EXT_KEY_BYTES,
    MAX_EXT_KEYS,
    ext_canonical,
    validate_commerce_ext,
    validate_ext,
)

from .helpers import raises

PROFILE_COMMERCE = {
    "chains": ["eip155:8453", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"],
    "pricing": {"currency": "USDC", "maxAmount": "12.50"},
    "settlement": ["crypto/instant"],
    "accounts": [{"network": "eip155:8453", "address": "0x7a3b"}],
}


def test_limits():
    assert (MAX_EXT_KEYS, MAX_EXT_KEY_BYTES, MAX_EXT_BYTES, MAX_EXT_DEPTH) == (8, 256, 4096, 8)


def test_absent_and_canonical_form():
    for v in (None, {}):
        assert validate_ext(v, "profile") is None and validate_ext(v, "intent") is None
        assert ext_canonical(v) == ""
    out = validate_ext({"urn:x:1": {"z": [1, {"y": None}], "é": "/ü", "a": True}}, "profile")
    assert out == {"urn:x:1": {"a": True, "z": [1, {"y": None}], "é": "/ü"}}
    assert list(out["urn:x:1"]) == ["a", "z", "é"]  # key order is the canonical (sorted) one
    assert ext_canonical(out) == '{"urn:x:1":{"a":true,"z":[1,{"y":null}],"é":"/ü"}}'
    assert ext_canonical({"b:1": {}, "a:1": {}}) == '{"a:1":{},"b:1":{}}'
    # the returned object is a fresh canonical copy, not the input
    src = {"urn:x:1": {"b": 1, "a": 2}}
    out = validate_ext(src, "intent")
    assert out == src and out is not src and list(out["urn:x:1"]) == ["a", "b"]


@pytest.mark.parametrize(
    "carrier,code", [("profile", "invalid_profile"), ("intent", "invalid_argument")]
)
def test_shape_rules(carrier, code):
    # root = depth 0, the namespace value = depth 1, ... the eighth nested object = depth 8
    deep_ok = {"urn:x:1": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": "leaf"}}}}}}}}}
    assert validate_ext(deep_ok, carrier) == deep_ok
    key_max = "urn:" + "a" * (MAX_EXT_KEY_BYTES - 4)
    assert validate_ext({key_max: {}}, carrier) == {key_max: {}}
    eight = {f"urn:x:{i}": {} for i in range(MAX_EXT_KEYS)}
    assert validate_ext(eight, carrier) == eight
    big_ok = {"urn:x:1": {"a": "x" * (MAX_EXT_BYTES - len('{"urn:x:1":{"a":""}}'))}}
    assert len(ext_canonical(validate_ext(big_ok, carrier))) == MAX_EXT_BYTES
    bad = [
        [],
        "x",
        5,
        {"x": {}},  # no namespace separator
        {"Urn:x": {}},  # uppercase scheme
        {"urn:": {}},  # empty identifier part
        {"urn:x y": {}},  # space
        {key_max + "a": {}},
        {"urn:" + "é" * 127: {}},  # 258 bytes
        {f"urn:x:{i}": {} for i in range(MAX_EXT_KEYS + 1)},
        {"urn:x:1": "s"},
        {"urn:x:1": None},
        {"urn:x:1": []},
        {"urn:x:1": 1},
        # depth 9
        {"urn:x:1": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": "leaf"}}}}}}}}}},
        {"urn:x:1": {"a": [[[[[[[[1]]]]]]]]}},  # arrays count too (depth 9)
        {"urn:x:1": {"a": "x" * (MAX_EXT_BYTES - len('{"urn:x:1":{"a":""}}') + 1)}},
        {"urn:x:1": {"a": float("inf")}},
        {"urn:x:1": {"a": b"bytes"}},
        {"urn:x:1": {1: "non-string key"}},
    ]
    for value in bad:
        with raises(code):
            validate_ext(value, carrier)


def test_commerce_profile_members():
    assert validate_commerce_ext(PROFILE_COMMERCE, "profile") == PROFILE_COMMERCE
    assert validate_commerce_ext({}, "profile") == {}
    euro = {"pricing": {"currency": "€"}}
    assert validate_commerce_ext(euro, "profile") == euro
    wrapped = {COMMERCE_EXT: PROFILE_COMMERCE}
    assert validate_ext(wrapped, "profile") == wrapped
    bad = [
        [],
        {"maxPrice": "1", "currency": "USDC"},  # intent members on a profile
        {"unknown": 1},
        {"chains": "eip155:1"},
        {"chains": None},
        {"chains": ["eip155"]},
        {"chains": ["EIP155:1"]},
        {"chains": ["eip155:1"] * 11},
        {"pricing": None},
        {"pricing": "USDC"},
        {"pricing": {}},
        {"pricing": {"currency": None}},
        {"pricing": {"currency": ""}},
        {"pricing": {"currency": "x" * 17}},
        {"pricing": {"currency": "US\nD"}},
        {"pricing": {"currency": "USDC", "maxAmount": None}},
        {"pricing": {"currency": "USDC", "maxAmount": "1."}},
        {"pricing": {"currency": "USDC", "maxAmount": "-1"}},
        {"pricing": {"currency": "USDC", "maxAmount": ""}},
        {"pricing": {"currency": "USDC", "maxAmount": "1" * 33}},
        {"pricing": {"currency": "USDC", "max_amount": "1"}},
        {"settlement": [1]},
        {"settlement": ["x"] * 11},
        {"accounts": {}},
        {"accounts": [{"network": "eip155:1"}]},
        {"accounts": [{"network": "eip155", "address": "x"}]},
        {"accounts": [{"network": "eip155:1", "address": 1}]},
        {"accounts": [{"network": "eip155:1", "address": "x", "extra": 1}]},
        {"accounts": [{"network": "eip155:1", "address": "x"}] * 11},
    ]
    for value in bad:
        with raises("invalid_profile"):
            validate_commerce_ext(value, "profile")
        with raises("invalid_profile"):
            validate_ext(_wrap(value), "profile")
    # the commerce check applies only to its namespace: other namespaces are opaque
    assert validate_ext({"urn:x:1": {"unknown": 1, "maxPrice": 5}}, "profile")


def test_commerce_intent_members():
    both = {"maxPrice": "50.00", "currency": "USDC"}
    assert validate_commerce_ext(both, "intent") == both
    assert validate_commerce_ext({}, "intent") == {}
    long_ok = {"maxPrice": "é" * 64, "currency": "\x01" * 16}  # code points; no control-char rule
    assert validate_commerce_ext(long_ok, "intent") == long_ok
    assert validate_ext({COMMERCE_EXT: both}, "intent") == {COMMERCE_EXT: both}
    bad = [
        [],
        {"maxPrice": "1"},
        {"currency": "USDC"},
        {"maxPrice": "1", "currency": None},
        {"maxPrice": None, "currency": "USDC"},
        {"maxPrice": 1, "currency": "USDC"},
        {"maxPrice": "", "currency": "USDC"},
        {"maxPrice": "1" * 65, "currency": "USDC"},
        {"maxPrice": "1", "currency": ""},
        {"maxPrice": "1", "currency": "x" * 17},
        {**both, "chains": ["eip155:1"]},  # profile members on an intent
        {**both, "unknown": 1},
    ]
    for value in bad:
        with raises("invalid_argument"):
            validate_commerce_ext(value, "intent")
        with raises("invalid_argument"):
            validate_ext(_wrap(value), "intent")


def _wrap(value) -> dict:
    """``value`` as the commerce namespace of an ext (a non-object value cannot be a namespace
    value, so it is nested one level down where the commerce validator still rejects it)."""
    return {COMMERCE_EXT: value} if isinstance(value, dict) else {COMMERCE_EXT: {"x": value}}
