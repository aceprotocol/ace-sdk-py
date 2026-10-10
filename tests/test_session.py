import base64
import json
import os
import subprocess
import sys

import pytest

from ace.session import MLSError, NativeMLSEngine, PairwiseMLS
from ace.store import MemoryStore

ALICE, BOB = "ace:sha256:" + "a" * 64, "ace:sha256:" + "b" * 64
LIBRARY = os.environ.get("ACE_MLS_LIBRARY")
pytestmark = pytest.mark.skipif(
    not LIBRARY, reason="explicit native MLS integration build required",
)


@pytest.fixture
def engine():
    with NativeMLSEngine(LIBRARY) as value:
        yield value


def pair(engine, store=None):
    a = PairwiseMLS(engine, store or MemoryStore(), ALICE, BOB)
    b = PairwiseMLS(engine, MemoryStore(), BOB, ALICE)
    b.join(a.create(b.state["keyPackage"])["message"])
    return a, b


def test_native_roundtrip_replay_and_update(engine):
    a, b = pair(engine)
    packet = a.send(b"private")["message"]
    assert base64.b64decode(b.receive(packet)["plaintext"]) == b"private"
    with pytest.raises(MLSError, match="invalid_session_message"):
        b.receive(packet)
    a.receive(b.update()["message"])
    assert base64.b64decode(a.receive(b.send(b"reply")["message"])["plaintext"]) == b"reply"
    a.close()
    b.close()


def test_rejected_ciphertext_keeps_valid_ratchet(engine):
    a, b = pair(engine)
    packet = a.send(b"valid")["message"]
    generation = b.state["generation"]
    with pytest.raises(MLSError):
        b.receive("garbage")
    assert b.state["generation"] == generation + 1
    assert base64.b64decode(b.receive(packet)["plaintext"]) == b"valid"


def test_rollback_closes_without_reinitializing(engine):
    store = MemoryStore()
    a, _ = pair(engine, store)
    key, = store.list("mls/gates/")
    snapshot = store.read(key)
    a.send(b"advance")
    store.write(key, snapshot)
    with pytest.raises(MLSError, match="session_generation_mismatch"):
        a.send(b"old")
    with pytest.raises(MLSError, match="session_closed"):
        a.update()


def test_missing_gate_closes(engine):
    store = MemoryStore()
    a, _ = pair(engine, store)
    key, = store.list("mls/gates/")
    store.delete(key)
    with pytest.raises(MLSError, match="session_generation_mismatch"):
        a.send(b"old")


def test_lost_ack_never_releases_output_or_resumes(engine):
    class FaultStore:
        def __init__(self):
            self.data, self.fail = MemoryStore(), False

        def coordinate(self, name, body):
            with self.data.lock(name):
                result = body(self.data)
                if self.fail:
                    raise OSError("lost acknowledgement")
                return result
    store = FaultStore()
    a, _ = pair(engine, store)
    store.fail = True
    with pytest.raises(OSError, match="lost acknowledgement"):
        a.send(b"not released")
    store.fail = False
    with pytest.raises(MLSError, match="session_closed"):
        a.send(b"retry")


def test_out_of_band_engine_mutation_is_refused(engine):
    a, _ = pair(engine)
    engine.execute(json.dumps({"op": "update", "handle": a.state["handle"],
                               "generation": a.state["generation"]}).encode())
    with pytest.raises(MLSError, match="invalid_engine_state"):
        a.send(b"not released")


def test_native_engine_closed_and_empty_input(engine):
    assert json.loads(engine.execute(b""))["error"] == "invalid_session_input"
    engine.close()
    engine.close()
    with pytest.raises(MLSError, match="engine_closed"):
        engine.execute(b"{}")


def test_only_public_gate_metadata_is_stored(engine):
    store = MemoryStore()
    a, _ = pair(engine, store)
    a.send(b"super secret plaintext")
    key, = store.list("mls/gates/")
    assert set(json.loads(store.read(key))) == {
        "version", "context", "local", "peer", "signatureKey", "generation", "closed",
    }


def test_unexpected_core_failure_destroys_context(engine):
    class Faulty:
        def execute(self, command):
            result = engine.execute(command)
            if json.loads(command)["op"] == "send":
                return b'{"ok":false,"result":null,"error":"session_failed"}'
            return result
    a, _ = pair(Faulty())
    with pytest.raises(MLSError, match="session_failed"):
        a.send(b"not released")
    with pytest.raises(MLSError, match="session_closed"):
        a.update()


def test_forked_process_cannot_inherit_native_engine():
    # A fresh subprocess avoids forking pytest's own threads and plugins. The parent takes
    # the binding mutex deliberately: the child must reject before waiting on that mutex.
    script = '''
import os, signal, threading
from ace.session import MLSError, NativeMLSEngine, PairwiseMLS
from ace.store import MemoryStore
engine = NativeMLSEngine(os.environ["ACE_MLS_LIBRARY"])
session = PairwiseMLS(engine, MemoryStore(), "ace:sha256:"+"a"*64, "ace:sha256:"+"b"*64)
held, release = threading.Event(), threading.Event()
def hold():
    with engine._lock, session._lock:
        held.set()
        release.wait()
worker = threading.Thread(target=hold)
worker.start()
held.wait()
try:
    pid = os.fork()
    if pid == 0:
        signal.alarm(3)
        try:
            session.update()
        except MLSError as error:
            if error.code != "session_closed": os._exit(6)
        else: os._exit(7)
        try:
            engine.execute(b"{}")
        except MLSError as error:
            if error.code != "engine_closed": os._exit(2)
        else: os._exit(3)
        try:
            NativeMLSEngine(os.environ["ACE_MLS_LIBRARY"])
        except MLSError as error:
            os._exit(0 if error.code == "engine_after_fork_requires_exec" else 4)
        os._exit(5)
    _, status = os.waitpid(pid, 0)
    assert status == 0
finally:
    release.set()
    worker.join()
engine.close()
'''
    subprocess.run([sys.executable, "-c", script], check=True, timeout=10)
