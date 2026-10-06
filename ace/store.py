"""Key-value persistence for the pipeline: ``ACEStore``, ``MemoryStore``, ``FileStore``."""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import stat
import threading
import time
from typing import Any, Callable, ContextManager, Protocol, runtime_checkable

from ._encoding import canonical_state_bytes, wire_int
from .errors import ACEError

KEY_RE = re.compile(r"[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*")
LOCK_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
MAX_KEY_LENGTH = 200
MAX_VALUE_BYTES = 64 * 1024 * 1024
_STALE_LOCK_SECONDS = 60
_POLL_SECONDS = 0.05


@runtime_checkable
class ACEStore(Protocol):
    """Synchronous key-value store used by PeerStore, ThreadStore, Inbox and Outbox.

    - ``read`` returns ``None`` for a missing key.
    - ``write`` atomically replaces the value and is durable when it returns.
    - ``delete`` of a missing key is not an error.
    - ``list(prefix)`` returns the keys starting with ``prefix``, sorted ascending.
    - ``lock(name, timeout)`` returns a context manager holding an exclusive,
      non-reentrant lock from ``__enter__`` (or earlier) until ``__exit__``. A timeout is
      ``receiver_busy`` for the ``receive`` lock and ``storage_failed`` otherwise.

    Keys match ``^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`` (at most 200 characters).
    Every I/O failure is ``ACEError(storage_failed)``.
    """

    def read(self, key: str) -> bytes | None: ...
    def write(self, key: str, value: bytes) -> None: ...
    def delete(self, key: str) -> None: ...
    def list(self, prefix: str) -> list[str]: ...
    def lock(self, name: str, timeout: float = 10.0) -> ContextManager[Any]: ...


def check_key(key: object) -> str:
    if not isinstance(key, str) or len(key) > MAX_KEY_LENGTH or KEY_RE.fullmatch(key) is None:
        raise ACEError("invalid_argument", f"invalid store key {str(key)[:64]!r}")
    return key


def _check_lock_args(name: object, timeout: object) -> tuple[str, float]:
    if not isinstance(name, str) or LOCK_NAME_RE.fullmatch(name) is None or len(name) > 64:
        raise ACEError("invalid_argument", f"invalid lock name {str(name)[:64]!r}")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout >= 0:
        raise ACEError("invalid_argument", "timeout must be a non-negative number")
    return name, float(timeout)


def _busy(name: str) -> ACEError:
    if name == "receive":
        return ACEError("receiver_busy", "another receiver holds the receive lock")
    return ACEError("storage_failed", f"timed out waiting for lock {name!r}")


def _check_value(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ACEError("invalid_argument", "store values must be bytes")
    data = bytes(value)
    if len(data) > MAX_VALUE_BYTES:
        raise ACEError("storage_failed", "value exceeds 64 MiB")
    return data


class _Held:
    """A lock handle that is already acquired; ``release()`` / ``__exit__`` free it once."""

    def __init__(self, release: Callable[[], None]) -> None:
        self._release: Callable[[], None] | None = release
        self._mutex = threading.Lock()

    def release(self) -> None:
        with self._mutex:
            fn, self._release = self._release, None
        if fn is not None:
            fn()

    def __enter__(self) -> "_Held":
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def _acquire_mutex(m: threading.Lock, name: str, timeout: float) -> None:
    ok = m.acquire(blocking=False) if timeout == 0 else m.acquire(timeout=timeout)
    if not ok:
        raise _busy(name)


# --- MemoryStore ------------------------------------------------------------------------

class MemoryStore:
    """In-memory ``ACEStore``: a dict plus one in-process mutex per lock name."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}
        self._mutex = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def read(self, key: str) -> bytes | None:
        check_key(key)
        with self._mutex:
            return self._data.get(key)

    def write(self, key: str, value: bytes) -> None:
        check_key(key)
        data = _check_value(value)
        with self._mutex:
            self._data[key] = data

    def delete(self, key: str) -> None:
        check_key(key)
        with self._mutex:
            self._data.pop(key, None)

    def list(self, prefix: str) -> list[str]:
        if not isinstance(prefix, str):
            raise ACEError("invalid_argument", "prefix must be a string")
        with self._mutex:
            return sorted(k for k in self._data if k.startswith(prefix))

    def lock(self, name: str, timeout: float = 10.0) -> _Held:
        name, timeout = _check_lock_args(name, timeout)
        with self._mutex:
            m = self._locks.setdefault(name, threading.Lock())
        _acquire_mutex(m, name, timeout)
        return _Held(m.release)


# --- FileStore --------------------------------------------------------------------------

_PROCESS_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _io_error(what: str, exc: BaseException) -> ACEError:
    return ACEError("storage_failed", f"{what}: {type(exc).__name__}: {exc}")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


class FileStore:
    """``ACEStore`` over a directory (``root/<key>``).

    Directories are created 0700 and files 0600. Reads refuse symlinks and files over
    64 MiB. Writes go to ``.tmp-<16 hex>`` (``O_CREAT|O_EXCL|O_NOFOLLOW``), are fsynced,
    renamed over the key and the directory is fsynced. Locks are ``root/locks/<name>.lock``
    files holding ``{"createdAt","host","pid"}``; a lock left by a dead process on this host,
    or an unparseable lock file older than 60 s, is taken over. Concurrent access to one
    root by different SDK languages is unsupported; the files at rest are portable.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        try:
            os.makedirs(root, mode=0o700, exist_ok=True)
            self._root = os.path.realpath(os.fspath(root))
            st = os.stat(self._root)
        except OSError as exc:
            raise _io_error("cannot create store root", exc) from None
        if not stat.S_ISDIR(st.st_mode):
            raise ACEError("storage_failed", "store root is not a directory")
        self._host = socket.gethostname()

    @property
    def root(self) -> str:
        return self._root

    # --- paths ---

    def _path(self, key: str) -> str:
        check_key(key)
        if key == "locks" or key.startswith("locks/"):
            raise ACEError("invalid_argument", "the locks/ prefix is reserved by FileStore")
        return os.path.join(self._root, *key.split("/"))

    def _check_parents(self, key: str) -> bool:
        """True if every parent directory exists as a real directory; refuses symlinks."""
        path = self._root
        for part in key.split("/")[:-1]:
            path = os.path.join(path, part)
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                return False
            if not stat.S_ISDIR(st.st_mode):
                raise ACEError("storage_failed", f"{part!r} is not a directory (symlinks are refused)")
        return True

    def _ensure_dir(self, rel_parts: list[str]) -> str:
        path = self._root
        for part in rel_parts:
            path = os.path.join(path, part)
            try:
                os.mkdir(path, 0o700)
                self._fsync_dir(os.path.dirname(path))
            except FileExistsError:
                pass
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode):
                raise ACEError("storage_failed", f"{part!r} is not a directory (symlinks are refused)")
        return path

    @staticmethod
    def _fsync_dir(path: str) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _read_file(path: str) -> bytes | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ACEError("storage_failed", "refusing to read a symlink") from None
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ACEError("storage_failed", "not a regular file")
            if st.st_size > MAX_VALUE_BYTES:
                raise ACEError("storage_failed", "file exceeds 64 MiB")
            chunks = []
            remaining = MAX_VALUE_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_VALUE_BYTES:
                raise ACEError("storage_failed", "file exceeds 64 MiB")
            return data
        finally:
            os.close(fd)

    # --- ACEStore ---

    def read(self, key: str) -> bytes | None:
        path = self._path(key)
        try:
            if not self._check_parents(key):
                return None
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                raise ACEError("storage_failed", "refusing to read a symlink")
            return self._read_file(path)
        except FileNotFoundError:
            return None
        except ACEError:
            raise
        except OSError as exc:
            raise _io_error(f"read {key}", exc) from None

    def write(self, key: str, value: bytes) -> None:
        path = self._path(key)
        data = _check_value(value)
        tmp = None
        try:
            directory = self._ensure_dir(key.split("/")[:-1])
            tmp = os.path.join(directory, ".tmp-" + os.urandom(8).hex())
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    view = view[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, path)
            tmp = None
            self._fsync_dir(directory)
        except ACEError:
            raise
        except OSError as exc:
            raise _io_error(f"write {key}", exc) from None
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def delete(self, key: str) -> None:
        path = self._path(key)
        try:
            if not self._check_parents(key):
                return
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                raise ACEError("storage_failed", f"{key} is a directory")
            os.unlink(path)
            self._fsync_dir(os.path.dirname(path))
        except FileNotFoundError:
            return
        except ACEError:
            raise
        except OSError as exc:
            raise _io_error(f"delete {key}", exc) from None

    def list(self, prefix: str) -> list[str]:
        if not isinstance(prefix, str):
            raise ACEError("invalid_argument", "prefix must be a string")
        base_parts = prefix.split("/")[:-1]
        out: list[str] = []
        try:
            start = os.path.join(self._root, *base_parts)
            try:
                st = os.lstat(start)
            except FileNotFoundError:
                return []
            if not stat.S_ISDIR(st.st_mode):
                return []
            stack = [(start, base_parts)]
            while stack:
                directory, parts = stack.pop()
                with os.scandir(directory) as it:
                    for entry in it:
                        rel = parts + [entry.name]
                        if not rel or (len(rel) == 1 and entry.name == "locks"):
                            continue
                        key = "/".join(rel)
                        if entry.is_dir(follow_symlinks=False):
                            if (key + "/").startswith(prefix) or prefix.startswith(key + "/"):
                                stack.append((entry.path, rel))
                        elif entry.is_file(follow_symlinks=False):
                            if key.startswith(prefix) and len(key) <= MAX_KEY_LENGTH and KEY_RE.fullmatch(key):
                                out.append(key)
        except OSError as exc:
            raise _io_error(f"list {prefix}", exc) from None
        return sorted(out)

    # --- locks ---

    def lock(self, name: str, timeout: float = 10.0) -> _Held:
        name, timeout = _check_lock_args(name, timeout)
        deadline = time.monotonic() + timeout
        with _PROCESS_LOCKS_GUARD:
            m = _PROCESS_LOCKS.setdefault((self._root, name), threading.Lock())
        _acquire_mutex(m, name, timeout)
        try:
            content = self._acquire_file(name, deadline)
        except BaseException:
            m.release()
            raise

        def release() -> None:
            try:
                self._release_file(name, content)
            finally:
                m.release()

        return _Held(release)

    def _lock_path(self, name: str) -> str:
        return os.path.join(self._root, "locks", name + ".lock")

    def _acquire_file(self, name: str, deadline: float) -> bytes:
        try:
            self._ensure_dir(["locks"])
        except OSError as exc:
            raise _io_error("create locks directory", exc) from None
        path = self._lock_path(name)
        content = canonical_state_bytes({"createdAt": int(time.time()), "host": self._host, "pid": os.getpid()})
        while True:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                if self._take_over_stale(path):
                    continue
                if time.monotonic() >= deadline:
                    raise _busy(name) from None
                time.sleep(min(_POLL_SECONDS, max(0.0, deadline - time.monotonic())) or _POLL_SECONDS)
                continue
            except OSError as exc:
                raise _io_error(f"create lock {name}", exc) from None
            try:
                try:
                    os.write(fd, content)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._fsync_dir(os.path.dirname(path))
            except OSError as exc:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                raise _io_error(f"write lock {name}", exc) from None
            return content

    def _take_over_stale(self, path: str) -> bool:
        """Unlink a stale lock file; True means retry immediately."""
        try:
            raw = self._read_file(path)
            st = os.lstat(path)
        except FileNotFoundError:
            return True
        except (OSError, ACEError):
            return False
        if raw is None:
            return True
        stale = False
        try:
            info = json.loads(raw.decode("utf-8"))
            pid = wire_int(info.get("pid")) if isinstance(info, dict) else None
            host = info.get("host") if isinstance(info, dict) else None
            if pid is None or not isinstance(host, str):
                raise ValueError("lock file fields")
            stale = host == self._host and pid > 0 and not _pid_alive(pid)
        except (ValueError, UnicodeDecodeError, AttributeError):
            stale = time.time() - st.st_mtime > _STALE_LOCK_SECONDS
        if not stale:
            return False
        try:
            # Narrow the race with another taker: unlink only if the content is unchanged.
            if self._read_file(path) == raw:
                os.unlink(path)
        except FileNotFoundError:
            pass
        except (OSError, ACEError):
            return False
        return True

    def _release_file(self, name: str, content: bytes) -> None:
        path = self._lock_path(name)
        try:
            if self._read_file(path) == content:
                os.unlink(path)
                self._fsync_dir(os.path.dirname(path))
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise _io_error(f"release lock {name}", exc) from None


# --- JSON records -----------------------------------------------------------------------

def dump_record(obj: object) -> bytes:
    """Persisted-JSON writer: compact UTF-8, sorted keys, non-ASCII and '/' unescaped."""
    return canonical_state_bytes(obj)


def load_record(store: ACEStore, key: str) -> dict | None:
    """Read a ``version: 1`` JSON object; anything else is ``storage_failed``."""
    raw = store.read(key)
    if raw is None:
        return None
    try:
        obj = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ACEError("storage_failed", f"{key} is not valid JSON") from None
    if not isinstance(obj, dict):
        raise ACEError("storage_failed", f"{key} is not a JSON object")
    version = obj.get("version")
    if isinstance(version, bool) or version != 1:
        raise ACEError("storage_failed", f"{key} has an unknown version")
    return obj
