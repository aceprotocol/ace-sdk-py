"""Principal binding (09-principal): types, bodies, records, rules, pipeline."""

# ruff: noqa: E501

from __future__ import annotations

import pytest

from ace import ECONOMIC_TYPES, MESSAGE_TYPES, ACEError, validate_body
from ace.errors import _category
from ace.types import PRINCIPAL_TYPES, is_economic_type, is_principal_type

from .helpers import raises

CONV = "ab" * 32
MID = "00000000-0000-4000-8000-000000000001"


def test_type_lists():
    assert MESSAGE_TYPES[-3:] == ("request", "decision", "report") and len(MESSAGE_TYPES) == 13
    assert len(ECONOMIC_TYPES) == 8 and PRINCIPAL_TYPES == ("request", "decision", "report")
    assert all(is_principal_type(t) and not is_economic_type(t) for t in PRINCIPAL_TYPES)
    assert not is_principal_type("text") and not is_principal_type(3)


def test_error_codes_permanent():
    assert _category("invalid_principal") == "permanent" and _category("wrong_principal") == "permanent"
    assert ACEError("wrong_principal").category == "permanent"


@pytest.mark.parametrize("type_,body", [
    ("request", {"action": "pay", "summary": "Pay 1 USDC"}),
    ("request", {"action": "x402.pay", "summary": "s", "amount": "1", "currency": "USDC", "ttl": 60,
                 "details": {"payTo": "x"}, "ref": {"conversationId": CONV, "messageId": MID, "threadId": "t"}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV, "messageId": MID, "threadId": None}}),
    ("decision", {"requestId": MID, "outcome": "approve"}),
    ("decision", {"requestId": MID, "outcome": "deny", "reason": "no", "result": {"x": 1}}),
    ("report", {"action": "pay", "summary": "paid", "outcome": "skipped", "proof": {}, "requestId": MID}),
])
def test_valid_bodies(type_, body):
    validate_body(type_, body)


@pytest.mark.parametrize("type_,body", [
    ("request", {"action": "a"}),
    ("request", {"action": "a", "summary": "s", "details": "x"}),
    ("request", {"action": "a", "summary": "s", "ttl": 1.5}),
    ("request", {"action": "a", "summary": "s", "ref": []}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV.upper(), "messageId": MID}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV, "messageId": "AAAAAAAA-0000-4000-8000-000000000001"}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV}}),
    ("request", {"action": "a", "summary": "s", "ref": {"conversationId": CONV, "messageId": MID, "threadId": ""}}),
    ("decision", {"requestId": MID, "outcome": "maybe"}),
    ("decision", {"requestId": MID, "outcome": "APPROVE"}),
    ("decision", {"requestId": MID, "outcome": "approve", "result": []}),
    ("report", {"action": "a", "summary": "s", "outcome": "done"}),
    ("report", {"action": "a", "summary": "s", "outcome": "ok", "proof": "x"}),
])
def test_invalid_bodies(type_, body):
    with raises("invalid_body"):
        validate_body(type_, body)
