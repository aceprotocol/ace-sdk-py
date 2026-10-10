import hashlib

import pytest

from ace import (
    EXECUTION_REQUEST_SCHEMA,
    EXECUTION_REQUEST_SCHEMA_DIGEST,
    EXECUTION_REQUEST_TYPE,
    parse_execution_request,
)
from tests.helpers import VECTORS, raises


def test_generic_execution_wrapper_is_data_not_authority():
    case = VECTORS["vectors"]["grants"]["cases"][0]
    body = {"intent": case["intent"], "grants": case["chain"]}
    parsed = parse_execution_request(body)
    assert parsed == body and parsed is not body and parsed["intent"] is not body["intent"]
    assert EXECUTION_REQUEST_TYPE == "urn:ace:execute:1"
    assert (
        EXECUTION_REQUEST_SCHEMA_DIGEST
        == "5acd227e6886b0d327ed34be5ff2a89debbc08a1cbcd87ba582f9eed6e42cf32"
    )
    assert (
        EXECUTION_REQUEST_SCHEMA_DIGEST
        == hashlib.sha256(EXECUTION_REQUEST_SCHEMA.encode()).hexdigest()
    )


@pytest.mark.parametrize(
    "change",
    [{"condition": "unrecognized"}, {"grants": []}, {"grants": [None]}, {"grants": [{}] * 9}],
)
def test_closed_framing(change):
    case = VECTORS["vectors"]["grants"]["cases"][0]
    with raises("invalid_authorization"):
        parse_execution_request({"intent": case["intent"], "grants": case["chain"], **change})
