"""ACE Protocol thread state machine."""

from __future__ import annotations

import threading
from collections import OrderedDict
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

    def __init__(self, capacity: int | None = None) -> None:
        if capacity is not None and capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        self._capacity = capacity
        self._lock = threading.Lock()
        self._threads: OrderedDict[str, _ThreadEntry] = OrderedDict()

    def _composite_key(self, conversation_id: str, thread_id: str) -> str:
        """Length-prefixed composite key prevents collision."""
        return f"{len(conversation_id)}:{conversation_id}:{thread_id}"

    def _evict_if_over_capacity(self) -> None:
        """Evict oldest terminal threads when over capacity. Caller must hold lock."""
        if self._capacity is None or len(self._threads) <= self._capacity:
            return
        # First pass: evict oldest terminal threads
        to_remove = []
        for key, entry in self._threads.items():
            if entry.state in TERMINAL_STATES:
                to_remove.append(key)
                if len(self._threads) - len(to_remove) <= self._capacity:
                    break
        for key in to_remove:
            del self._threads[key]
        # If still over capacity, evict oldest regardless of state
        while len(self._threads) > self._capacity:
            self._threads.popitem(last=False)

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
                self._evict_if_over_capacity()
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

    # Derived from TRANSITIONS + TERMINAL_STATES — no manual sync needed
    _VALID_STATES: frozenset[str] = frozenset(
        {'idle'} | TERMINAL_STATES | {v for v in TRANSITIONS.values()}
    )

    _MAX_IMPORT_HISTORY = 1000
    _MAX_IMPORT_THREADS = 100_000

    @staticmethod
    def from_export(snapshots: list[dict[str, Any]], capacity: int | None = None) -> 'ThreadStateMachine':
        """Restore a state machine from exported snapshots.

        Validates that each snapshot's history represents a legal walk through
        the transition table from 'idle'. Rejects snapshots with invalid
        transition sequences to prevent state injection.
        """
        if len(snapshots) > ThreadStateMachine._MAX_IMPORT_THREADS:
            raise ValueError(
                f"fromExport: too many threads ({len(snapshots)}), "
                f"max is {ThreadStateMachine._MAX_IMPORT_THREADS}"
            )
        sm = ThreadStateMachine(capacity=capacity)
        for snap in snapshots:
            conv_id = snap['conversationId']
            thread_id = snap['threadId']

            # Validate threadId format (same rules as live messages)
            validate_thread_id(thread_id)
            if not conv_id or len(conv_id) > 256:
                raise ValueError("fromExport: invalid conversationId")

            # Validate state is a known value
            if snap['state'] not in ThreadStateMachine._VALID_STATES:
                raise ValueError(f"fromExport: invalid state '{str(snap['state'])[:32]}'")

            history = snap['history']
            if not isinstance(history, list):
                raise ValueError("fromExport: history must be a list")
            if len(history) > ThreadStateMachine._MAX_IMPORT_HISTORY:
                raise ValueError(f"fromExport: history too large ({len(history)})")

            # Replay the history to verify it represents a valid transition sequence
            replay_state: str = 'idle'
            for entry in history:
                msg_type = entry.get('type')
                if not isinstance(msg_type, str) or not is_economic_type(msg_type):
                    raise ValueError(f"fromExport: unknown message type '{str(msg_type)[:32]}' in thread history")
                if not isinstance(entry.get('messageId'), str):
                    raise ValueError("fromExport: invalid history entry")
                if not isinstance(entry.get('timestamp'), int):
                    raise ValueError("fromExport: invalid history entry timestamp")

                next_state = TRANSITIONS.get((replay_state, msg_type))
                if next_state is None:
                    raise ValueError(
                        f"fromExport: invalid transition '{msg_type}' from state '{replay_state}'"
                    )
                replay_state = next_state

            # Final replayed state must match the declared state
            if replay_state != snap['state']:
                raise ValueError(
                    f"fromExport: declared state '{snap['state']}' does not match "
                    f"history replay '{replay_state}'"
                )

            key = sm._composite_key(conv_id, thread_id)
            sm._threads[key] = _ThreadEntry(
                conversation_id=conv_id,
                thread_id=thread_id,
                state=snap['state'],
                history=list(history),
            )
        return sm
