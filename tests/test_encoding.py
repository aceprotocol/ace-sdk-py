import pytest

from ace import canonical_state_bytes, conversation_key, sha256_hex
from ace.errors import ACEError


def test_canonical_json_rules():
    assert canonical_state_bytes({"b": 1, "a": [True, None, 1.5, 1e21, -0.0]}) == (
        b'{"a":[true,null,1.5,1e+21,0],"b":1}'
    )
    s = '"\\/\b\t\n\f\r\x01\x7fé'
    assert canonical_state_bytes(s) == ('"\\"\\\\/\\b\\t\\n\\f\\r\\u0001\x7fé"').encode()
    # code point order equals UTF-8 byte order (not UTF-16)
    keys = {"\U0001f600": 1, "｡": 2, "a": 3}
    assert canonical_state_bytes(keys) == '{"a":3,"｡":2,"\U0001f600":1}'.encode()
    with pytest.raises(ValueError):
        canonical_state_bytes("\ud800")


def test_pair_key_is_symmetric():
    a, b = "ace:sha256:" + "1" * 64, "ace:sha256:" + "2" * 64
    assert conversation_key(a, b) == conversation_key(b, a) == sha256_hex(a, b)


def test_rule_codes_follow_the_outcome_grammar():
    assert ACEError("custom_rule_code").category == "permanent"
    assert ACEError("receiver_capacity").category == "local"
    with pytest.raises(ValueError):
        ACEError("Bad-Code")  # type: ignore[arg-type]
