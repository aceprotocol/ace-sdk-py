"""ACE Protocol thread state machine."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from .types import MessageType, is_economic_type
from ._utils import CONTROL_CHAR_RE

# === Thread States ===

ThreadState = Literal[
    'idle', 'rfq', 'offered', 'accepted', 'rejected',
    'invoiced', 'paid', 'delivered', 'confirmed',
]

# === Transition Table ===

TRANSITIONS: dict[tuple[str, str], str] = {
    # Phase 1: Negotiation (linear)
    ('idle', 'rfq'): 'rfq',
    ('rfq', 'offer'): 'offered',
    ('offered', 'accept'): 'accepted',
    ('offered', 'reject'): 'rejected',
    ('offered', 'offer'): 'offered',       # Counter-offer

    # Phase 2: Execution (linear from accepted)
    ('accepted', 'invoice'): 'invoiced',
    ('accepted', 'receipt'): 'paid',       # Pre-paid
    ('invoiced', 'receipt'): 'paid',

    ('accepted', 'deliver'): 'delivered',  # Deliver-first
    ('paid', 'deliver'): 'delivered',
    ('delivered', 'confirm'): 'confirmed',
}

# Rejected and confirmed are terminal — no outgoing economic transitions.
TERMINAL_STATES: frozenset[str] = frozenset({'rejected', 'confirmed'})

# === Validation ===

MAX_THREAD_ID_LENGTH = 256


def validate_thread_id(thread_id: str) -> None:
    """Validate thread_id format."""
    if len(thread_id) == 0:
        raise ValueError('threadId must not be empty')
    if len(thread_id) > MAX_THREAD_ID_LENGTH:
        raise ValueError(f'threadId exceeds max length of {MAX_THREAD_ID_LENGTH} characters')
    if CONTROL_CHAR_RE.search(thread_id):
        raise ValueError('threadId must not contain control characters')


# === Error ===

class InvalidTransitionError(Exception):
    """Raised when a state transition is not allowed."""

    def __init__(self, thread_id: str, current_state: str, message_type: str) -> None:
        self.thread_id = thread_id
        self.current_state = current_state
        self.message_type = message_type
        super().__init__(
            f"Invalid transition: cannot process '{message_type}' in state "
            f"'{current_state}' (thread: {thread_id})"
        )


# === State Machine ===

@dataclass
class _ThreadEntry:
    conversation_id: str
    thread_id: str
    state: str
    history: list[dict[str, Any]]


@dataclass
class ThreadSnapshot:
    conversation_id: str
    thread_id: str
    state: str
    history: list[dict[str, Any]]


class ThreadStateMachine:
    """Tracks economic message flow per (conversationId, threadId) pair."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: dict[str, _ThreadEntry] = {}

    def _composite_key(self, conversation_id: str, thread_id: str) -> str:
        """Length-prefixed composite key prevents collision."""
        return f"{len(conversation_id)}:{conversation_id}:{thread_id}"

    def transition(
        self,
        conversation_id: str,
        thread_id: str,
        message_type: str,
        message_id: str,
        timestamp: int,
    ) -> str:
        """Validate and apply a state transition.

        Non-economic messages (text, info) are always allowed and do not change state.
        Returns the new state after transition.

        Raises:
            InvalidTransitionError: if the transition is not allowed
            ValueError: if threadId is invalid
        """
        if not is_economic_type(message_type):
            with self._lock:
                return self._get_state_unlocked(conversation_id, thread_id)

        validate_thread_id(thread_id)

        with self._lock:
            key = self._composite_key(conversation_id, thread_id)
            thread = self._threads.get(key)
            current_state: str = thread.state if thread else 'idle'

            if current_state in TERMINAL_STATES:
                raise InvalidTransitionError(thread_id, current_state, message_type)

            next_state = TRANSITIONS.get((current_state, message_type))

            if next_state is None:
                raise InvalidTransitionError(thread_id, current_state, message_type)

            history_entry = {'type': message_type, 'messageId': message_id, 'timestamp': timestamp}

            if thread is None:
                self._threads[key] = _ThreadEntry(
                    conversation_id=conversation_id,
                    thread_id=thread_id,
                    state=next_state,
                    history=[history_entry],
                )
            else:
                thread.state = next_state
                thread.history.append(history_entry)

            return next_state

    def can_transition(self, conversation_id: str, thread_id: str, message_type: str) -> bool:
        """Check if a transition would be valid without applying it."""
        if not is_economic_type(message_type):
            return True

        try:
            validate_thread_id(thread_id)
        except ValueError:
            return False

        with self._lock:
            current_state = self._get_state_unlocked(conversation_id, thread_id)

        if current_state in TERMINAL_STATES:
            return False

        return (current_state, message_type) in TRANSITIONS

    def _get_state_unlocked(self, conversation_id: str, thread_id: str) -> str:
        """Get current state (caller must hold self._lock)."""
        thread = self._threads.get(self._composite_key(conversation_id, thread_id))
        return thread.state if thread else 'idle'

    def get_state(self, conversation_id: str, thread_id: str) -> str:
        """Get current state for a thread."""
        with self._lock:
            return self._get_state_unlocked(conversation_id, thread_id)

    def get_snapshot(self, conversation_id: str, thread_id: str) -> ThreadSnapshot:
        """Get a snapshot of a thread's state and history."""
        with self._lock:
            thread = self._threads.get(self._composite_key(conversation_id, thread_id))
            return ThreadSnapshot(
                conversation_id=conversation_id,
                thread_id=thread_id,
                state=thread.state if thread else 'idle',
                history=list(thread.history) if thread else [],
            )

    def allowed_types(self, conversation_id: str, thread_id: str) -> list[str]:
        """Get list of message types allowed from current state."""
        with self._lock:
            current_state = self._get_state_unlocked(conversation_id, thread_id)

        if current_state in TERMINAL_STATES:
            return []

        allowed: list[str] = []
        for (state, msg_type) in TRANSITIONS:
            if state == current_state:
                allowed.append(msg_type)
        return allowed

    def is_terminal(self, conversation_id: str, thread_id: str) -> bool:
        """Check if thread is in a terminal state."""
        return self.get_state(conversation_id, thread_id) in TERMINAL_STATES

    def remove(self, conversation_id: str, thread_id: str) -> bool:
        """Remove a thread. Returns True if it existed."""
        with self._lock:
            key = self._composite_key(conversation_id, thread_id)
            if key in self._threads:
                del self._threads[key]
                return True
            return False

    def export_state(self) -> list[dict[str, Any]]:
        """Export all thread states as a list of snapshots."""
        with self._lock:
            snapshots: list[dict[str, Any]] = []
            for thread in self._threads.values():
                snapshots.append({
                    'conversationId': thread.conversation_id,
                    'threadId': thread.thread_id,
                    'state': thread.state,
                    'history': list(thread.history),
                })
            return snapshots

    @staticmethod
    def from_export(snapshots: list[dict[str, Any]]) -> 'ThreadStateMachine':
        """Restore a state machine from exported snapshots."""
        sm = ThreadStateMachine()
        # No lock needed: sm is not yet shared with other threads.
        for snap in snapshots:
            key = sm._composite_key(snap['conversationId'], snap['threadId'])
            sm._threads[key] = _ThreadEntry(
                conversation_id=snap['conversationId'],
                thread_id=snap['threadId'],
                state=snap['state'],
                history=list(snap['history']),
            )
        return sm
