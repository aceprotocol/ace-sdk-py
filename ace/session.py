"""Pairwise MLS primitives backed by the common Rust engine.

Enrollment inputs MUST come from an authenticated, fresh ACE handshake. This module
does not enroll peers, deliver packets, persist secrets, or fall back to static encryption.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Callable, Protocol, TypeVar

from ._encoding import MAX_SAFE_INTEGER, canonical_state_bytes, is_ace_id
from .limits import (
    MLS_MAX_ENGINE_IO_BYTES,
    MLS_MAX_KEY_PACKAGE_CHARS,
    MLS_MAX_MESSAGE_CHARS,
    MLS_MAX_PLAINTEXT_BYTES,
)
from .store import ACEStore

_NATIVE_PROCESSES: dict[str, int] = {}


#: Codes that describe the frame or the attempt, not this host: retrying the same input
#: cannot succeed. Every other code (engine, storage, receipt) is a local failure.
_PERMANENT_CODES = frozenset(
    {
        "invalid_delivery_frame",
        "invalid_session_input",
        "invalid_session_message",
        "invalid_session_members",
        "secure_delivery_required",
        "delivery_expired",
        "delivery_peer_disabled",
        "session_closed",
        "session_limit",
    }
)


class MLSError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)

    @property
    def is_permanent(self) -> bool:
        return self.code in _PERMANENT_CODES


class MLSEngine(Protocol):
    def execute(self, command: bytes) -> bytes: ...


class NativeMLSEngine:
    """Load an explicit trusted library path. No PATH/environment search or fallback.

    The caller must verify the source/build artifact before loading native code. Close
    this engine after all its sessions. Use as a context manager for deterministic cleanup.
    Live sessions must not be shared through fork().
    """
    def __init__(self, library: str | Path):
        path = Path(library)
        if not path.is_absolute() or not path.is_file():
            raise MLSError("invalid_engine_path")
        path = path.resolve()
        if _NATIVE_PROCESSES.get(str(path), os.getpid()) != os.getpid():
            raise MLSError("engine_after_fork_requires_exec")
        _NATIVE_PROCESSES[str(path)] = os.getpid()
        self._lock = threading.RLock()
        self._pid = os.getpid()
        self._id = 0
        self._lib = ctypes.CDLL(str(path))
        self._lib.ace_session_engine_new.argtypes = []
        self._lib.ace_session_engine_new.restype = ctypes.c_uint64
        self._lib.ace_session_engine_free.argtypes = [ctypes.c_uint64]
        self._lib.ace_session_engine_free.restype = None
        self._lib.ace_session_engine_call.argtypes = [
            ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self._lib.ace_session_engine_call.restype = ctypes.POINTER(ctypes.c_uint8)
        self._lib.ace_session_buffer_free.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ]
        self._lib.ace_session_buffer_free.restype = None
        self._lib.ace_session_abi_version.argtypes = []
        self._lib.ace_session_abi_version.restype = ctypes.c_uint32
        if self._lib.ace_session_abi_version() != 1:
            raise MLSError("unsupported_engine_abi")
        self._id = self._lib.ace_session_engine_new()
        if not self._id:
            raise MLSError("engine_unavailable")

    def execute(self, command: bytes) -> bytes:
        if not isinstance(command, bytes) or len(command) > MLS_MAX_ENGINE_IO_BYTES:
            raise MLSError("session_limit")
        # Check before taking a mutex that could have been held by another thread at fork.
        if self._pid != os.getpid():
            raise MLSError("engine_closed")
        with self._lock:
            if not self._id:
                raise MLSError("engine_closed")
            data = (ctypes.c_uint8 * max(1, len(command)))()
            ctypes.memmove(data, command, len(command))
            size = ctypes.c_size_t()
            try:
                result = self._lib.ace_session_engine_call(
                    self._id, data, len(command), ctypes.byref(size),
                )
            finally:
                ctypes.memset(data, 0, len(data))
            if not result:
                raise MLSError("engine_unavailable")
            try:
                if size.value > MLS_MAX_ENGINE_IO_BYTES:
                    raise MLSError("invalid_engine_response")
                return ctypes.string_at(result, size.value)
            finally:
                self._lib.ace_session_buffer_free(result, size.value)

    def close(self) -> None:
        if self._pid != os.getpid():
            return
        with self._lock:
            if self._id and self._pid == os.getpid():
                self._lib.ace_session_engine_free(self._id)
            self._id = 0

    def __enter__(self) -> NativeMLSEngine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except (AttributeError, TypeError):
            pass  # Partially initialized object or interpreter shutdown.


T = TypeVar("T")


class CoordinatedMLSStore(Protocol):
    """Same scoped callback contract as the TS/Swift CoordinatedStore.

    For host rollback protection the implementation must use a trusted external
    monotonic backend. The callback's handle must not escape its live lock scope.
    """
    def coordinate(self, name: str, body: Callable[[ACEStore], T]) -> T: ...


class PairwiseMLS:
    """Process-local MLS state with a durable generation barrier before every transition.

    The store holds only public metadata. There is no export/import/resume method.
    MemoryStore/FileStore cannot protect against rollback of the entire host. Returned
    ciphertext still needs the application's durable delivery journal.
    """
    def __init__(self, engine: MLSEngine, store: ACEStore | CoordinatedMLSStore,
                 local: str, peer: str):
        if not is_ace_id(local) or not is_ace_id(peer) or local == peer:
            raise MLSError("invalid_session_input")
        self._lock = threading.RLock()
        self._engine, self._store = engine, store
        self._pid = os.getpid()
        self._closed = False
        self._state = self._result(self._call({"op": "new", "local": local, "peer": peer}))
        context = secrets.token_hex(32)
        self._gate = {
            "version": 1, "context": context, "local": local, "peer": peer,
            "signatureKey": self._state["signatureKey"], "generation": 0, "closed": False,
        }
        self._key, self._name = f"mls/gates/{context}.json", f"mls-{context[:48]}"
        try:
            self._check_state(self._state, 0)
            if self._state["ready"]:
                raise MLSError("invalid_engine_state")

            def register(data: ACEStore) -> None:
                if data.read(self._key) is not None:
                    raise MLSError("session_context_conflict")
                data.write(self._key, canonical_state_bytes(self._gate))
            self._coordinate(register)
        except BaseException:
            self._destroy()
            raise

    @property
    def state(self) -> dict:
        self._check_process()
        with self._lock:
            return self._state.copy()

    def create(self, key_package: str) -> dict:
        """The peer package must come from a fresh, authenticated ACE handshake."""
        return self._wire_step("create", "key_package", key_package, MLS_MAX_KEY_PACKAGE_CHARS)

    def join(self, welcome: str) -> dict:
        """The Welcome must be bound to the same authenticated handshake."""
        return self._wire_step("join", "welcome", welcome, MLS_MAX_MESSAGE_CHARS)

    def send(self, plaintext: bytes) -> dict:
        if not isinstance(plaintext, bytes) or len(plaintext) > MLS_MAX_PLAINTEXT_BYTES:
            raise MLSError("session_limit")
        return self._step({"op": "send", "plaintext": base64.b64encode(plaintext).decode()})

    def receive(self, message: str) -> dict:
        return self._wire_step("receive", "message", message, MLS_MAX_MESSAGE_CHARS)

    def update(self) -> dict:
        """Past epochs are erased immediately. Coordinate updates with delivery."""
        return self._step({"op": "update"})

    def close(self) -> None:
        self._check_process()
        with self._lock:
            if self._closed:
                return
            try:
                def mark(data: ACEStore) -> None:
                    self._check_gate(data)
                    data.delete(self._key)
                self._coordinate(mark)
            finally:
                self._destroy()

    def _coordinate(self, body: Callable[[ACEStore], T]) -> T:
        if callable(getattr(self._store, "coordinate", None)):
            return self._store.coordinate(self._name, body)
        with self._store.lock(self._name):
            return body(self._store)

    def _check_gate(self, data: ACEStore) -> None:
        if data.read(self._key) != canonical_state_bytes(self._gate):
            raise MLSError("session_generation_mismatch")

    def _check_state(self, state: dict, generation: int) -> None:
        if (type(state.get("handle")) is not int or state["handle"] < 1
                or state["handle"] != self._state["handle"]
                or any(state.get(k) != self._gate[k] for k in ("local", "peer", "signatureKey"))
                or state.get("generation") != generation):
            raise MLSError("invalid_engine_state")

    def _step(self, command: dict) -> dict:
        self._check_process()
        with self._lock:
            if self._closed:
                raise MLSError("session_closed")
            try:
                def transition(data: ACEStore) -> dict:
                    self._check_gate(data)
                    handle, generation = self._state["handle"], self._gate["generation"]
                    self._check_state(self._result(self._call({"op": "info", "handle": handle})),
                                      generation)
                    if generation >= MAX_SAFE_INTEGER:
                        raise MLSError("session_limit")
                    next_gate = {**self._gate, "generation": generation + 1}
                    data.write(self._key, canonical_state_bytes(next_gate))
                    self._gate = next_gate
                    result = self._call({**command, "handle": handle, "generation": generation})
                    if not result["ok"] and result["error"] in {
                        "session_failed", "session_closed", "session_generation_mismatch",
                    }:
                        raise MLSError(result["error"])
                    if result["ok"] and result["result"].get("event", {}).get("kind") not in {
                        "welcome", "joined", "application", "commit",
                    }:
                        raise MLSError("invalid_engine_response")
                    state = self._result(self._call({"op": "info", "handle": handle}))
                    self._check_state(state, generation + 1)
                    self._state = state
                    return result
                response = self._coordinate(transition)
            except BaseException:
                self._destroy()
                raise
            return self._result(response)["event"]

    def _wire_step(self, op: str, field: str, value: str, limit: int) -> dict:
        if not isinstance(value, str) or len(value) > limit:
            raise MLSError("session_limit")
        return self._step({"op": op, field: value})

    def _check_process(self) -> None:
        if self._pid != os.getpid():
            self._closed = True
            raise MLSError("session_closed")

    def _destroy(self) -> None:
        self._closed = True
        try:
            self._call({"op": "close", "handle": self._state["handle"]})
        except Exception:
            pass  # The instance never resumes even if its engine is already unavailable.

    def _call(self, command: dict) -> dict:
        raw = self._engine.execute(json.dumps(command, separators=(",", ":")).encode())
        if not isinstance(raw, bytes) or len(raw) > MLS_MAX_ENGINE_IO_BYTES:
            raise MLSError("invalid_engine_response")
        result = json.loads(raw)
        if (not isinstance(result, dict) or type(result.get("ok")) is not bool
                or "result" not in result
                or not (result.get("error") is None or isinstance(result["error"], str))):
            raise MLSError("invalid_engine_response")
        return result

    @staticmethod
    def _result(response: dict) -> dict:
        if not response["ok"]:
            raise MLSError(response["error"] or "session_failed")
        return response["result"]
