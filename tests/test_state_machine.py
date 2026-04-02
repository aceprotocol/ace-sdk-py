"""Tests for the ACE Protocol thread state machine."""

from __future__ import annotations

import uuid

import pytest

from ace.state_machine import (
    ThreadStateMachine,
    InvalidTransitionError,
    validate_thread_id,
    TRANSITIONS,
)
from ace.types import ECONOMIC_TYPES


def _uuid() -> str:
    return str(uuid.uuid4())


NOW = 1_700_000_000
CONV_A = 'a' * 64
CONV_B = 'b' * 64


# ============================================================
# Standard Flow
# ============================================================

class TestStandardFlow:
    def test_full_7_step_flow(self):
        sm = ThreadStateMachine()
        assert sm.transition(CONV_A, 'deal-001', 'rfq', _uuid(), NOW) == 'rfq'
        assert sm.transition(CONV_A, 'deal-001', 'offer', _uuid(), NOW) == 'offered'
        assert sm.transition(CONV_A, 'deal-001', 'accept', _uuid(), NOW) == 'accepted'
        assert sm.transition(CONV_A, 'deal-001', 'invoice', _uuid(), NOW) == 'invoiced'
        assert sm.transition(CONV_A, 'deal-001', 'receipt', _uuid(), NOW) == 'paid'
        assert sm.transition(CONV_A, 'deal-001', 'deliver', _uuid(), NOW) == 'delivered'
        assert sm.transition(CONV_A, 'deal-001', 'confirm', _uuid(), NOW) == 'confirmed'


# ============================================================
# Valid Variations
# ============================================================

class TestValidVariations:
    def test_counter_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'offer', _uuid(), NOW) == 'offered'
        assert sm.transition(CONV_A, 't', 'offer', _uuid(), NOW) == 'offered'
        assert sm.transition(CONV_A, 't', 'accept', _uuid(), NOW) == 'accepted'

    def test_reject_after_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'reject', _uuid(), NOW) == 'rejected'
        assert sm.is_terminal(CONV_A, 't') is True

    def test_deliver_first(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW) == 'delivered'
        assert sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW) == 'confirmed'

    def test_pre_paid(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW) == 'paid'
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW)


# ============================================================
# Real-World Commerce Scenarios
# ============================================================

class TestRealWorldScenarios:
    def test_free_service(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW) == 'confirmed'

    def test_pre_paid_api_service(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW) == 'confirmed'

    def test_counter_offer_negotiation(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'invoice', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW) == 'confirmed'


# ============================================================
# Invalid Transitions
# ============================================================

class TestInvalidTransitions:
    def test_offer_before_rfq(self):
        sm = ThreadStateMachine()
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)

    def test_accept_before_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)

    def test_reject_before_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)

    def test_invoice_before_accept(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'invoice', _uuid(), NOW)

    def test_deliver_before_accept(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)

    def test_confirm_before_deliver(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW)

    def test_no_double_rfq(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)

    def test_no_double_accept(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)

    def test_receipt_before_invoice_or_accept(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW)

    def test_no_offer_after_accept(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)

    def test_no_rfq_after_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)

    def test_no_renegotiation_after_accept(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)

        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)


# ============================================================
# Terminal State Enforcement
# ============================================================

class TestTerminalStateEnforcement:
    def test_rejected_blocks_all_economic(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)

        for msg_type in ECONOMIC_TYPES:
            with pytest.raises(InvalidTransitionError):
                sm.transition(CONV_A, 't', msg_type, _uuid(), NOW)

    def test_confirmed_is_terminal(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW)

        assert sm.is_terminal(CONV_A, 't') is True

        for msg_type in ECONOMIC_TYPES:
            with pytest.raises(InvalidTransitionError):
                sm.transition(CONV_A, 't', msg_type, _uuid(), NOW)

    def test_text_info_allowed_after_rejected(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)

        assert sm.transition(CONV_A, 't', 'text', _uuid(), NOW) == 'rejected'
        assert sm.transition(CONV_A, 't', 'info', _uuid(), NOW) == 'rejected'

    def test_text_info_allowed_after_confirmed(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW)

        assert sm.transition(CONV_A, 't', 'text', _uuid(), NOW) == 'confirmed'
        assert sm.transition(CONV_A, 't', 'info', _uuid(), NOW) == 'confirmed'


# ============================================================
# Non-Economic Messages
# ============================================================

class TestNonEconomicMessages:
    def test_text_always_allowed_no_state_change(self):
        sm = ThreadStateMachine()
        assert sm.transition(CONV_A, 't', 'text', _uuid(), NOW) == 'idle'
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'text', _uuid(), NOW) == 'rfq'
        assert sm.get_state(CONV_A, 't') == 'rfq'

    def test_info_always_allowed_no_state_change(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        assert sm.transition(CONV_A, 't', 'info', _uuid(), NOW) == 'offered'

    def test_text_info_do_not_require_valid_thread_id(self):
        sm = ThreadStateMachine()
        assert sm.transition(CONV_A, '', 'text', _uuid(), NOW) == 'idle'


# ============================================================
# Conversation Isolation
# ============================================================

class TestConversationIsolation:
    def test_same_thread_id_different_conversations(self):
        sm = ThreadStateMachine()
        thread_id = 'deal-001'

        sm.transition(CONV_A, thread_id, 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, thread_id, 'offer', _uuid(), NOW)

        assert sm.get_state(CONV_B, thread_id) == 'idle'
        sm.transition(CONV_B, thread_id, 'rfq', _uuid(), NOW)

        assert sm.get_state(CONV_A, thread_id) == 'offered'
        assert sm.get_state(CONV_B, thread_id) == 'rfq'

    def test_different_thread_ids_same_conversation(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 'deal-a', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 'deal-a', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 'deal-b', 'rfq', _uuid(), NOW)

        assert sm.get_state(CONV_A, 'deal-a') == 'offered'
        assert sm.get_state(CONV_A, 'deal-b') == 'rfq'
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 'deal-b', 'accept', _uuid(), NOW)


# ============================================================
# ThreadId Validation
# ============================================================

class TestThreadIdValidation:
    def test_empty_thread_id_for_economic(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="must not be empty"):
            sm.transition(CONV_A, '', 'rfq', _uuid(), NOW)

    def test_too_long_thread_id(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="exceeds max length"):
            sm.transition(CONV_A, 'x' * 257, 'rfq', _uuid(), NOW)

    def test_max_length_accepted(self):
        sm = ThreadStateMachine()
        assert sm.transition(CONV_A, 'x' * 256, 'rfq', _uuid(), NOW) == 'rfq'

    def test_null_byte_rejected(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="control characters"):
            sm.transition(CONV_A, 'deal\x00evil', 'rfq', _uuid(), NOW)

    def test_newline_rejected(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="control characters"):
            sm.transition(CONV_A, 'deal\nevil', 'rfq', _uuid(), NOW)

    def test_tab_rejected(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="control characters"):
            sm.transition(CONV_A, 'deal\tevil', 'rfq', _uuid(), NOW)

    def test_del_rejected(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="control characters"):
            sm.transition(CONV_A, 'deal\x7fevil', 'rfq', _uuid(), NOW)

    def test_unicode_accepted(self):
        sm = ThreadStateMachine()
        assert sm.transition(CONV_A, 'deal-\u4ea4\u6613-\U0001f916', 'rfq', _uuid(), NOW) == 'rfq'

    def test_special_printable_accepted(self):
        sm = ThreadStateMachine()
        assert sm.transition(CONV_A, 'deal-001/sub.task@2026', 'rfq', _uuid(), NOW) == 'rfq'


class TestValidateThreadIdExported:
    def test_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_thread_id('')

    def test_control_chars(self):
        with pytest.raises(ValueError, match="control characters"):
            validate_thread_id('a\x00b')

    def test_valid(self):
        validate_thread_id('deal-001')  # Should not raise


# ============================================================
# Composite Key Safety
# ============================================================

class TestCompositeKeySafety:
    def test_no_collision_colon_in_conv_id(self):
        sm = ThreadStateMachine()
        sm.transition('a:b', 'c', 'rfq', _uuid(), NOW)
        assert sm.get_state('a:b', 'c') == 'rfq'
        assert sm.get_state('a', 'b:c') == 'idle'

    def test_no_collision_at_length_prefix_boundaries(self):
        sm = ThreadStateMachine()
        sm.transition('ab', 'cd', 'rfq', _uuid(), NOW)
        assert sm.get_state('a', 'b:cd') == 'idle'
        assert sm.get_state('ab:c', 'd') == 'idle'


# ============================================================
# canTransition
# ============================================================

class TestCanTransition:
    def test_valid(self):
        sm = ThreadStateMachine()
        assert sm.can_transition(CONV_A, 'new', 'rfq') is True

    def test_invalid(self):
        sm = ThreadStateMachine()
        assert sm.can_transition(CONV_A, 'new', 'offer') is False

    def test_always_true_for_non_economic(self):
        sm = ThreadStateMachine()
        assert sm.can_transition(CONV_A, 'any', 'text') is True
        assert sm.can_transition(CONV_A, 'any', 'info') is True

    def test_false_for_invalid_thread_id(self):
        sm = ThreadStateMachine()
        assert sm.can_transition(CONV_A, '', 'rfq') is False

    def test_false_for_terminal(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)
        assert sm.can_transition(CONV_A, 't', 'rfq') is False

    def test_does_not_mutate_state(self):
        sm = ThreadStateMachine()
        sm.can_transition(CONV_A, 'new', 'rfq')
        assert sm.get_state(CONV_A, 'new') == 'idle'


# ============================================================
# allowedTypes
# ============================================================

class TestAllowedTypes:
    def test_idle_returns_rfq(self):
        sm = ThreadStateMachine()
        assert sm.allowed_types(CONV_A, 'new') == ['rfq']

    def test_rfq_returns_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        assert sm.allowed_types(CONV_A, 't') == ['offer']

    def test_offered_returns_accept_reject_offer(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        allowed = sm.allowed_types(CONV_A, 't')
        assert 'accept' in allowed
        assert 'reject' in allowed
        assert 'offer' in allowed

    def test_accepted_returns_invoice_receipt_deliver(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        allowed = sm.allowed_types(CONV_A, 't')
        assert 'invoice' in allowed
        assert 'receipt' in allowed
        assert 'deliver' in allowed

    def test_confirmed_returns_empty(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW)
        assert sm.allowed_types(CONV_A, 't') == []

    def test_rejected_returns_empty(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)
        assert sm.allowed_types(CONV_A, 't') == []


# ============================================================
# Snapshot & History
# ============================================================

class TestSnapshotAndHistory:
    def test_records_history(self):
        sm = ThreadStateMachine()
        id1, id2 = _uuid(), _uuid()
        sm.transition(CONV_A, 't', 'rfq', id1, 1000)
        sm.transition(CONV_A, 't', 'offer', id2, 1001)

        snap = sm.get_snapshot(CONV_A, 't')
        assert snap.conversation_id == CONV_A
        assert snap.thread_id == 't'
        assert snap.state == 'offered'
        assert len(snap.history) == 2
        assert snap.history[0] == {'type': 'rfq', 'messageId': id1, 'timestamp': 1000}
        assert snap.history[1] == {'type': 'offer', 'messageId': id2, 'timestamp': 1001}

    def test_idle_snapshot_for_unknown(self):
        sm = ThreadStateMachine()
        snap = sm.get_snapshot(CONV_A, 'unknown')
        assert snap.state == 'idle'
        assert snap.history == []


# ============================================================
# Export / Import
# ============================================================

class TestExportImport:
    def test_roundtrip(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't1', 'rfq', _uuid(), 1000)
        sm.transition(CONV_A, 't1', 'offer', _uuid(), 1001)
        sm.transition(CONV_B, 't2', 'rfq', _uuid(), 1002)

        restored = ThreadStateMachine.from_export(sm.export_state())

        assert restored.get_state(CONV_A, 't1') == 'offered'
        assert restored.get_state(CONV_B, 't2') == 'rfq'
        assert len(restored.get_snapshot(CONV_A, 't1').history) == 2

        with pytest.raises(InvalidTransitionError):
            restored.transition(CONV_A, 't1', 'rfq', _uuid(), NOW)
        assert restored.transition(CONV_A, 't1', 'accept', _uuid(), NOW) == 'accepted'

    def test_empty_export(self):
        assert ThreadStateMachine().export_state() == []

    def test_import_empty(self):
        sm = ThreadStateMachine.from_export([])
        assert sm.get_state(CONV_A, 'any') == 'idle'


# ============================================================
# Remove
# ============================================================

class TestRemove:
    def test_remove_resets_to_idle(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        assert sm.remove(CONV_A, 't') is True
        assert sm.get_state(CONV_A, 't') == 'idle'
        assert sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW) == 'rfq'

    def test_remove_nonexistent(self):
        sm = ThreadStateMachine()
        assert sm.remove(CONV_A, 'x') is False

    def test_remove_only_targeted(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 'keep', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 'remove', 'rfq', _uuid(), NOW)
        sm.remove(CONV_A, 'remove')
        assert sm.get_state(CONV_A, 'keep') == 'rfq'
        assert sm.get_state(CONV_A, 'remove') == 'idle'


# ============================================================
# Attack Scenarios
# ============================================================

class TestAttackScenarios:
    def test_state_skip_idle_to_invoice(self):
        sm = ThreadStateMachine()
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'invoice', _uuid(), NOW)

    def test_state_skip_idle_to_accept(self):
        sm = ThreadStateMachine()
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)

    def test_state_skip_idle_to_deliver(self):
        sm = ThreadStateMachine()
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'deliver', _uuid(), NOW)

    def test_state_skip_idle_to_confirm(self):
        sm = ThreadStateMachine()
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'confirm', _uuid(), NOW)

    def test_state_skip_rfq_to_receipt(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW)

    def test_double_receipt_in_single_cycle(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'invoice', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'receipt', _uuid(), NOW)

    def test_terminal_bypass_rejected(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'reject', _uuid(), NOW)

        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'invoice', _uuid(), NOW)

    def test_cross_conversation_hijack(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 'deal-001', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 'deal-001', 'offer', _uuid(), NOW)

        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_B, 'deal-001', 'accept', _uuid(), NOW)

    def test_null_byte_injection(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="control characters"):
            sm.transition(CONV_A, 'deal\x00-001', 'rfq', _uuid(), NOW)

    def test_oversized_thread_id(self):
        sm = ThreadStateMachine()
        with pytest.raises(ValueError, match="exceeds max length"):
            sm.transition(CONV_A, 'A' * 10000, 'rfq', _uuid(), NOW)

    def test_renegotiate_after_execution(self):
        sm = ThreadStateMachine()
        sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'accept', _uuid(), NOW)
        sm.transition(CONV_A, 't', 'invoice', _uuid(), NOW)

        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'rfq', _uuid(), NOW)
        with pytest.raises(InvalidTransitionError):
            sm.transition(CONV_A, 't', 'offer', _uuid(), NOW)


# ============================================================
# InvalidTransitionError properties
# ============================================================

class TestInvalidTransitionErrorProperties:
    def test_exposes_properties(self):
        sm = ThreadStateMachine()
        with pytest.raises(InvalidTransitionError) as exc_info:
            sm.transition(CONV_A, 'my-thread', 'offer', _uuid(), NOW)
        err = exc_info.value
        assert err.thread_id == 'my-thread'
        assert err.current_state == 'idle'
        assert err.message_type == 'offer'


# ============================================================
# Exhaustive: every MessageType x every state
# ============================================================

ALL_ECONOMIC_TYPES = [
    'rfq', 'offer', 'accept', 'reject',
    'invoice', 'receipt',
    'deliver', 'confirm',
]

ALL_STATES = [
    'idle', 'rfq', 'offered', 'accepted',
    'invoiced', 'paid', 'delivered',
    'confirmed', 'rejected',
]

PATHS_TO_STATE: dict[str, list[str]] = {
    'idle': [],
    'rfq': ['rfq'],
    'offered': ['rfq', 'offer'],
    'accepted': ['rfq', 'offer', 'accept'],
    'invoiced': ['rfq', 'offer', 'accept', 'invoice'],
    'paid': ['rfq', 'offer', 'accept', 'invoice', 'receipt'],
    'delivered': ['rfq', 'offer', 'accept', 'invoice', 'receipt', 'deliver'],
    'confirmed': ['rfq', 'offer', 'accept', 'invoice', 'receipt', 'deliver', 'confirm'],
    'rejected': ['rfq', 'offer', 'reject'],
}


def _build_to_state(sm: ThreadStateMachine, conv: str, thread: str, target: str) -> None:
    for msg_type in PATHS_TO_STATE[target]:
        sm.transition(conv, thread, msg_type, _uuid(), NOW)


@pytest.mark.parametrize(
    "state,msg_type",
    [(s, m) for s in ALL_STATES for m in ALL_ECONOMIC_TYPES],
)
def test_exhaustive_transition(state: str, msg_type: str):
    sm = ThreadStateMachine()
    thread = f"{state}-{msg_type}"
    _build_to_state(sm, CONV_A, thread, state)

    try:
        result = sm.transition(CONV_A, thread, msg_type, _uuid(), NOW)
        assert isinstance(result, str)
    except InvalidTransitionError:
        pass  # Expected for invalid transitions


# ============================================================
# Capacity Eviction
# ============================================================

class TestCapacityEviction:
    def test_invalid_capacity_rejected(self):
        with pytest.raises(ValueError, match="capacity"):
            ThreadStateMachine(capacity=0)
        with pytest.raises(ValueError, match="capacity"):
            ThreadStateMachine(capacity=-1)

    def test_none_capacity_means_unlimited(self):
        sm = ThreadStateMachine(capacity=None)
        for i in range(100):
            sm.transition(CONV_A, f"t-{i}", 'rfq', _uuid(), NOW)
        # All 100 threads should exist
        assert len(sm.export_state()) == 100

    def test_evicts_terminal_threads_first(self):
        sm = ThreadStateMachine(capacity=2)
        # Thread t1: drive to terminal (rejected)
        sm.transition(CONV_A, 't1', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't1', 'offer', _uuid(), NOW)
        sm.transition(CONV_A, 't1', 'reject', _uuid(), NOW)
        assert sm.is_terminal(CONV_A, 't1')

        # Thread t2: active
        sm.transition(CONV_A, 't2', 'rfq', _uuid(), NOW)

        # Thread t3: adding this exceeds capacity=2, should evict terminal t1
        sm.transition(CONV_A, 't3', 'rfq', _uuid(), NOW)

        states = sm.export_state()
        thread_ids = {s['threadId'] for s in states}
        assert 't1' not in thread_ids  # terminal thread evicted
        assert 't2' in thread_ids
        assert 't3' in thread_ids

    def test_evicts_oldest_when_no_terminal(self):
        sm = ThreadStateMachine(capacity=2)
        sm.transition(CONV_A, 't1', 'rfq', _uuid(), NOW)
        sm.transition(CONV_A, 't2', 'rfq', _uuid(), NOW)
        # t3 forces eviction; no terminal threads, so oldest (t1) is evicted
        sm.transition(CONV_A, 't3', 'rfq', _uuid(), NOW)

        states = sm.export_state()
        thread_ids = {s['threadId'] for s in states}
        assert 't1' not in thread_ids
        assert 't2' in thread_ids
        assert 't3' in thread_ids

    def test_from_export_preserves_capacity(self):
        sm = ThreadStateMachine(capacity=2)
        sm.transition(CONV_A, 't1', 'rfq', _uuid(), NOW)
        exported = sm.export_state()
        restored = ThreadStateMachine.from_export(exported, capacity=2)
        restored.transition(CONV_A, 't2', 'rfq', _uuid(), NOW)
        restored.transition(CONV_A, 't3', 'rfq', _uuid(), NOW)
        states = restored.export_state()
        assert len(states) == 2
