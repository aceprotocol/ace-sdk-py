"""ACE Protocol thread state machine."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Literal

from ._utils import CONTROL_CHAR_RE
from .types import is_economic_type

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
MAX_CONVERSATION_ID_LENGTH = 256
DEFAULT_MAX_THREADS = 100_000
DEFAULT_MAX_HISTORY_PER_THREAD = 1_000


def validate_thread_id(thread_id: str) -> None:
    """Validate thread_id format (lengths count Unicode code points)."""
    if not isinstance(thread_id, str):
        raise ValueError('threadId must be a string')
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


def _is_positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _is_timestamp(value: object) -> bool:
    return type(value) is int and value >= 0


class ThreadStateMachine:
    """Tracks economic message flow per (conversationId, threadId) pair.

    Resource limits reject new work rather than evict: forgetting a thread
    would let a finished (terminal) deal be reopened. Use ``remove()`` to
    drop a thread explicitly.
    """

    def __init__(
        self,
        *,
        max_threads: int = DEFAULT_MAX_THREADS,
        max_history_per_thread: int = DEFAULT_MAX_HISTORY_PER_THREAD,
    ) -> None:
        if not _is_positive_int(max_threads):
            raise ValueError(f"max_threads must be a positive integer, got {max_threads!r}")
        if not _is_positive_int(max_history_per_thread):
            raise ValueError(
                f"max_history_per_thread must be a positive integer, got {max_history_per_thread!r}"
            )
        self._max_threads = max_threads
        self._max_history_per_thread = max_history_per_thread
        self._lock = threading.Lock()
        self._threads: dict[str, _ThreadEntry] = {}

    def _composite_key(self, conversation_id: str, thread_id: str) -> str:
        """Length-prefixed composite key prevents collision."""
        return f"{len(conversation_id)}:{conversation_id}:{thread_id}"

    def _limit_error(self, thread: _ThreadEntry | None) -> str | None:
        """Resource-limit error for adding one entry, or None. Caller must hold lock."""
        if thread is None:
            if len(self._threads) >= self._max_threads:
                return f"Thread limit reached ({self._max_threads})"
        elif len(thread.history) >= self._max_history_per_thread:
            return f"Thread history exceeds maximum of {self._max_history_per_thread} entries"
        return None

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
            ValueError: if threadId is invalid or a resource limit is reached
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

            limit_error = self._limit_error(thread)
            if limit_error is not None:
                raise ValueError(limit_error)

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
            thread = self._threads.get(self._composite_key(conversation_id, thread_id))
            current_state = thread.state if thread else 'idle'
            if current_state in TERMINAL_STATES or (current_state, message_type) not in TRANSITIONS:
                return False
            # Must agree with transition(): a limit that would reject also fails here.
            return self._limit_error(thread) is None

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
    def from_export(
        snapshots: list[dict[str, Any]],
        *,
        max_threads: int = DEFAULT_MAX_THREADS,
        max_history_per_thread: int = DEFAULT_MAX_HISTORY_PER_THREAD,
    ) -> 'ThreadStateMachine':
        """Restore a state machine from exported snapshots.

        Validates that each snapshot's history represents a legal walk through
        the transition table from 'idle'. Rejects snapshots with invalid
        transition sequences to prevent state injection.
        """
        sm = ThreadStateMachine(max_threads=max_threads, max_history_per_thread=max_history_per_thread)
        if len(snapshots) > max_threads:
            raise ValueError(f"fromExport: too many threads ({len(snapshots)}), max is {max_threads}")
        for snap in snapshots:
            conv_id = snap['conversationId']
            thread_id = snap['threadId']

            # Validate threadId format (same rules as live messages)
            validate_thread_id(thread_id)
            if not isinstance(conv_id, str) or not conv_id or len(conv_id) > MAX_CONVERSATION_ID_LENGTH:
                raise ValueError("fromExport: invalid conversationId")

            history = snap['history']
            if not isinstance(history, list) or not history:
                raise ValueError("fromExport: history must be a non-empty list")
            if len(history) > max_history_per_thread:
                raise ValueError(f"fromExport: history too large ({len(history)})")

            # Replay the history to verify it represents a valid transition sequence
            replay_state: str = 'idle'
            for entry in history:
                if not isinstance(entry, dict):
                    raise ValueError("fromExport: invalid history entry")
                msg_type = entry.get('type')
                if not isinstance(msg_type, str) or not is_economic_type(msg_type):
                    raise ValueError(f"fromExport: unknown message type '{str(msg_type)[:32]}' in thread history")
                if not isinstance(entry.get('messageId'), str):
                    raise ValueError("fromExport: invalid history entry")
                if not _is_timestamp(entry.get('timestamp')):
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
                    f"fromExport: declared state '{str(snap['state'])[:32]}' does not match "
                    f"history replay '{replay_state}'"
                )

            key = sm._composite_key(conv_id, thread_id)
            if key in sm._threads:
                raise ValueError("fromExport: duplicate thread")
            sm._threads[key] = _ThreadEntry(
                conversation_id=conv_id,
                thread_id=thread_id,
                state=replay_state,
                history=list(history),
            )
        return sm
