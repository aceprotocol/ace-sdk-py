import pytest

from ace._intent import intent_digest

from .helpers import raises


def test_operation_identity_matches_typescript_and_swift():
    value = {
        "z": [None, True, False, -0.0, 1.0, 1e-7, 1e21, "1"],
        "\ue000": "private",
        "😀": "中文/\n",
    }
    assert (
        intent_digest(value) == "5755ebae76cfdbfc522994dc18b9bba626d19aef7c98638c44a0ba8c852de634"
    )
    assert (
        intent_digest({"a": 1})
        == "2317a230dd89e93a9aee06850327e78f32a0e7ccbca1771fcf4d3ae16478eb2c"
    )
    assert intent_digest(
        {
            "😀": "中文/\n",
            "\ue000": "private",
            "z": [None, True, False, 0, 1, 0.0000001, 10**21, "1"],
        }
    ) == intent_digest(value)


def test_operation_identity_preserves_types():
    assert (
        len(
            {
                intent_digest(v)
                for v in [None, False, 0, "0", [], {}, ["number", "0000000000000000"]]
            }
        )
        == 7
    )


@pytest.mark.parametrize("value", [2**53 + 1, 10**400, {"\ud800": "x"}, {"value": "\ud800"}])
def test_operation_identity_rejects_lossy_numbers_and_unicode(value):
    with raises("invalid_body"):
        intent_digest(value)
