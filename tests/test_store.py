"""MemoryStore / FileStore: contract, atomic writes, symlinks, locks across processes."""

from __future__ import annotations

import json
import multiprocessing
import os
import socket
import stat
import threading
import time

import pytest

from ace import ACEStore, FileStore, MemoryStore

from .helpers import raises


@pytest.fixture(params=["memory", "file"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else FileStore(tmp_path / "state")


def test_protocol(store):
    assert isinstance(store, ACEStore)


def test_read_write_delete_list(store):
    assert store.read("a.json") is None
    store.write("a.json", b"1")
    store.write("threads/x.json", b"2")
    store.write("threads/y.json", "é".encode())
    store.write("threadsz", b"3")
    assert store.read("a.json") == b"1"
    store.write("a.json", b"replaced")
    assert store.read("a.json") == b"replaced"
    assert store.list("threads/") == ["threads/x.json", "threads/y.json"]
    assert store.list("threads") == ["threads/x.json", "threads/y.json", "threadsz"]
    assert store.list("") == ["a.json", "threads/x.json", "threads/y.json", "threadsz"]
    assert store.list("nope/") == []
    store.delete("threads/x.json")
    store.delete("threads/x.json")  # missing is ok
    store.delete("missing/deep.json")
    assert store.list("threads/") == ["threads/y.json"]


@pytest.mark.parametrize("key", ["", "/a", "a/", "A", "a//b", ".tmp", "a/.b", "x" * 201, "a b", None, "ä"])
def test_key_grammar(store, key):
    with raises("invalid_argument"):
        store.write(key, b"x")
    with raises("invalid_argument"):
        store.read(key)


def test_lock_exclusive_and_timeout(store):
    with store.lock("threads"):
        with raises("storage_failed"):
            store.lock("threads", timeout=0.1)
        with raises("storage_failed"):
            store.lock("threads", timeout=0)  # non-reentrant
        with store.lock("peers", timeout=0):
            pass
    with store.lock("threads", timeout=0):
        pass


def test_receive_lock_busy(store):
    held = store.lock("receive", 0)
    with held:
        with raises("receiver_busy"):
            store.lock("receive", 0)
    with store.lock("receive", 0):
        pass


def test_lock_across_threads(store):
    order = []
    held = store.lock("threads")
    held.__enter__()

    def worker():
        with store.lock("threads", timeout=5):
            order.append("worker")

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(0.15)
    order.append("main")
    held.__exit__(None, None, None)
    t.join()
    assert order == ["main", "worker"]


# --- FileStore specifics ------------------------------------------------------------------

def test_file_permissions_and_layout(tmp_path):
    fs = FileStore(tmp_path / "s")
    fs.write("deliveries/abc.json", b"{}")
    root = tmp_path / "s"
    assert stat.S_IMODE(os.stat(root / "deliveries").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(root / "deliveries" / "abc.json").st_mode) == 0o600
    assert not [p for p in (root / "deliveries").iterdir() if p.name.startswith(".tmp-")]
    with fs.lock("threads"):
        info = json.loads((root / "locks" / "threads.lock").read_text())
        assert info["pid"] == os.getpid() and info["host"] == socket.gethostname()
        assert isinstance(info["createdAt"], int)
        assert fs.list("") == ["deliveries/abc.json"]  # lock files are not keys
    assert not (root / "locks" / "threads.lock").exists()
    with raises("invalid_argument"):
        fs.write("locks/x.lock", b"")


def test_file_refuses_symlinks(tmp_path):
    fs = FileStore(tmp_path / "s")
    target = tmp_path / "secret"
    target.write_bytes(b"secret")
    os.symlink(target, tmp_path / "s" / "link.json")
    with raises("storage_failed"):
        fs.read("link.json")
    os.symlink(tmp_path, tmp_path / "s" / "dir")
    with raises("storage_failed"):
        fs.read("dir/secret")
    with raises("storage_failed"):
        fs.write("dir/new.json", b"x")
    assert not (tmp_path / "new.json").exists()
    # write replaces the link itself, never the target
    fs.write("link.json", b"mine")
    assert target.read_bytes() == b"secret" and fs.read("link.json") == b"mine"


def test_file_rejects_large(tmp_path, monkeypatch):
    import ace.store as st

    fs = FileStore(tmp_path / "s")
    fs.write("big.json", b"x" * 100)
    monkeypatch.setattr(st, "MAX_VALUE_BYTES", 10)
    with raises("storage_failed"):
        fs.read("big.json")


def test_file_persists_across_instances(tmp_path):
    FileStore(tmp_path / "s").write("replay.json", b"{}")
    assert FileStore(tmp_path / "s").read("replay.json") == b"{}"


def test_stale_lock_dead_pid(tmp_path):
    fs = FileStore(tmp_path / "s")
    p = multiprocessing.get_context("spawn").Process(target=_noop)
    p.start()
    p.join()
    (tmp_path / "s" / "locks").mkdir(mode=0o700)
    (tmp_path / "s" / "locks" / "peers.lock").write_text(
        json.dumps({"createdAt": 1, "host": socket.gethostname(), "pid": p.pid}))
    with fs.lock("peers", timeout=0):
        pass


def test_stale_lock_other_host_or_live_pid_is_respected(tmp_path):
    fs = FileStore(tmp_path / "s")
    (tmp_path / "s" / "locks").mkdir(mode=0o700)
    lock = tmp_path / "s" / "locks" / "peers.lock"
    lock.write_text(json.dumps({"createdAt": 1, "host": "elsewhere", "pid": 999999}))
    with raises("storage_failed"):
        fs.lock("peers", timeout=0.1)
    lock.write_text(json.dumps({"createdAt": 1, "host": socket.gethostname(), "pid": os.getppid()}))
    with raises("storage_failed"):
        fs.lock("peers", timeout=0.1)


def test_unparseable_lock(tmp_path):
    fs = FileStore(tmp_path / "s")
    (tmp_path / "s" / "locks").mkdir(mode=0o700)
    lock = tmp_path / "s" / "locks" / "threads.lock"
    lock.write_text("garbage")
    with raises("storage_failed"):
        fs.lock("threads", timeout=0.1)  # fresh: respected
    old = time.time() - 120
    os.utime(lock, (old, old))
    with fs.lock("threads", timeout=0):
        pass


def test_release_only_own_content(tmp_path):
    fs = FileStore(tmp_path / "s")
    held = fs.lock("threads")
    lock = tmp_path / "s" / "locks" / "threads.lock"
    lock.write_text(json.dumps({"createdAt": 2, "host": "other", "pid": 1}))
    held.release()
    assert lock.exists()


# --- two processes -------------------------------------------------------------------------

def _noop():
    pass


def _hold_lock(root, name, ready, release):
    fs = FileStore(root)
    with fs.lock(name):
        ready.set()
        release.wait(10)


def _try_lock(root, name, timeout, result):
    from ace import ACEError

    try:
        with FileStore(root).lock(name, timeout=timeout):
            result.put("acquired")
    except ACEError as exc:
        result.put(exc.code)


def test_lock_contention_two_processes(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    root = str(tmp_path / "s")
    FileStore(root)
    for name, busy in (("receive", "receiver_busy"), ("threads", "storage_failed")):
        ready, release, result = ctx.Event(), ctx.Event(), ctx.Queue()
        holder = ctx.Process(target=_hold_lock, args=(root, name, ready, release))
        holder.start()
        assert ready.wait(20)
        # another process
        other = ctx.Process(target=_try_lock, args=(root, name, 0.2, result))
        other.start()
        other.join(20)
        assert result.get(timeout=5) == busy
        # this process
        with raises(busy):
            FileStore(root).lock(name, timeout=0.2)
        # a waiter succeeds once the holder releases
        waiter = ctx.Process(target=_try_lock, args=(root, name, 10, result))
        waiter.start()
        time.sleep(0.3)
        release.set()
        holder.join(20)
        waiter.join(20)
        assert result.get(timeout=5) == "acquired"


def _crash_holding(root):
    fs = FileStore(root)
    fs.lock("receive")
    os._exit(0)  # dies without releasing


def test_lock_left_by_crashed_process(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    root = str(tmp_path / "s")
    p = ctx.Process(target=_crash_holding, args=(root,))
    p.start()
    p.join(20)
    assert os.path.exists(os.path.join(root, "locks", "receive.lock"))
    with FileStore(root).lock("receive", timeout=0):
        pass
