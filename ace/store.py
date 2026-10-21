"""Key-value persistence for the pipeline: ``ACEStore``, ``MemoryStore``, ``FileStore``."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import stat
import sys
import threading
import time
from typing import Any, Callable, ContextManager, Protocol, runtime_checkable

from ._encoding import canonical_state_bytes
from .errors import ACEError

KEY_RE = re.compile(r"[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*")
LOCK_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")  # ACEStore lock names
MAX_KEY_LENGTH = 200
MAX_VALUE_BYTES = 64 * 1024 * 1024
_POLL_SECONDS = 0.05


def fsync(fd: int) -> None:
    """``fsync``; on macOS ``F_FULLFSYNC``, since its ``fsync`` does not flush the drive cache
    (``fsync`` when the filesystem does not support it)."""
    if sys.platform == "darwin" and hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        fsync(fd)
    finally:
        os.close(fd)


def write_file_atomic(path: str, data: bytes, tmp_name: str) -> None:
    """Write ``data`` to ``tmp_name`` beside ``path`` (0600, ``O_EXCL|O_NOFOLLOW``), fsync,
    rename over ``path`` and fsync the directory. Raises ``OSError``; the temp file never
    outlives a failure."""
    directory = os.path.dirname(path)
    tmp = os.path.join(directory, tmp_name)
    renamed = False
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, path)
        renamed = True
        fsync_dir(directory)
    finally:
        if not renamed:
            try:
                os.unlink(tmp)
            except OSError:
                pass


@runtime_checkable
class ACEStore(Protocol):
    """Synchronous key-value store used by PeerStore, ThreadStore, Inbox and Outbox.

    - ``read`` returns ``None`` for a missing key.
    - ``write`` atomically replaces the value and is durable when it returns.
    - ``delete`` of a missing key is not an error.
    - ``list(prefix)`` returns the keys starting with ``prefix``, sorted ascending; ``prefix``
      is empty, a key, or a key followed by ``/`` (else ``invalid_argument``).
    - ``lock(name, timeout)`` returns a context manager holding an exclusive,
      non-reentrant lock from ``__enter__`` (or earlier) until ``__exit__``. A timeout is
      ``lock_busy``.

    Keys match ``^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`` (at most 200 characters),
    lock names ``^[a-z0-9][a-z0-9_-]{0,63}$``. A value over 64 MiB is ``invalid_argument``.
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


def check_prefix(prefix: object) -> str:
    """A ``list`` prefix: empty, a key, or a key followed by ``/``."""
    if not isinstance(prefix, str):
        raise ACEError("invalid_argument", "prefix must be a string")
    if prefix:
        check_key(prefix[:-1] if prefix.endswith("/") else prefix)
    return prefix


def check_lock_name(name: object) -> str:
    if not isinstance(name, str) or LOCK_NAME_RE.fullmatch(name) is None:
        raise ACEError("invalid_argument", f"invalid lock name {str(name)[:64]!r}")
    return name


def _check_lock_args(name: object, timeout: object) -> tuple[str, float]:
    check_lock_name(name)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout >= 0:
        raise ACEError("invalid_argument", "timeout must be a non-negative number")
    return name, float(timeout)


def _busy(name: str) -> ACEError:
    if name == "receive":
        return ACEError("lock_busy", "another receiver holds the receive lock")
    return ACEError("lock_busy", f"timed out waiting for lock {name!r}")


def _check_value(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ACEError("invalid_argument", "store values must be bytes")
    data = bytes(value)
    if len(data) > MAX_VALUE_BYTES:
        raise ACEError("invalid_argument", "value exceeds 64 MiB")
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
        check_prefix(prefix)
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


def _check_private(st: os.stat_result, path: str) -> None:
    """Fail closed on a store directory or file another user owns or could access; the
    refusal names ``path`` and the fix."""
    uid = os.geteuid()
    if st.st_uid != uid:
        raise ACEError(
            "storage_failed",
            f"{path} is owned by another user (uid {st.st_uid}); "
            f"use a store root this user (uid {uid}) owns",
        )
    if st.st_mode & 0o077:
        mode = "700" if stat.S_ISDIR(st.st_mode) else "600"
        raise ACEError(
            "storage_failed", f"{path} is accessible to group or others; run: chmod {mode} {path}"
        )


class FileStore:
    """``ACEStore`` over a directory (``root/<key>``).

    Directories are created 0700 and files 0600; a directory or file read that another
    user owns or that grants group/other access is refused. Reads refuse symlinks and files over
    64 MiB. Writes go to ``.tmp-<16 hex>`` (``O_CREAT|O_EXCL|O_NOFOLLOW``), are fsynced,
    renamed over the key and the directory is fsynced. Locks are ``root/locks/<name>.lock``
    permanent files with POSIX flock. The kernel releases locks on process exit; never
    unlink or replace lock files. A local filesystem is required (network mounts unsupported).
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        try:
            missing = []
            cursor = os.path.abspath(os.fspath(root))
            while not os.path.lexists(cursor):
                missing.append(cursor)
                cursor = os.path.dirname(cursor)
            for path in reversed(missing):
                try:
                    os.mkdir(path, 0o700)
                except FileExistsError:
                    continue
                fsync_dir(os.path.dirname(path))
            self._root = os.path.realpath(os.fspath(root))
            st = os.stat(self._root)
        except OSError as exc:
            raise _io_error("cannot create store root", exc) from None
        if not stat.S_ISDIR(st.st_mode):
            raise ACEError("storage_failed", "store root is not a directory")
        _check_private(st, self._root)

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
                raise ACEError(
                    "storage_failed", f"{part!r} is not a directory (symlinks are refused)"
                )
            _check_private(st, path)
        return True

    def _ensure_dir(self, rel_parts: list[str]) -> str:
        path = self._root
        for part in rel_parts:
            path = os.path.join(path, part)
            try:
                os.mkdir(path, 0o700)
                fsync_dir(os.path.dirname(path))
            except FileExistsError:
                pass
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode):
                raise ACEError(
                    "storage_failed", f"{part!r} is not a directory (symlinks are refused)"
                )
            _check_private(st, path)
        return path

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
            _check_private(st, path)
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
        except OSError as exc:
            raise _io_error(f"read {key}", exc) from None

    def write(self, key: str, value: bytes) -> None:
        path = self._path(key)
        data = _check_value(value)
        try:
            self._ensure_dir(key.split("/")[:-1])
            write_file_atomic(path, data, ".tmp-" + os.urandom(8).hex())
        except OSError as exc:
            raise _io_error(f"write {key}", exc) from None

    def delete(self, key: str) -> None:
        path = self._path(key)
        try:
            if not self._check_parents(key):
                return
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                raise ACEError("storage_failed", f"{key} is a directory")
            os.unlink(path)
            fsync_dir(os.path.dirname(path))
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _io_error(f"delete {key}", exc) from None

    def list(self, prefix: str) -> list[str]:
        check_prefix(prefix)
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
                            if (
                                key.startswith(prefix)
                                and len(key) <= MAX_KEY_LENGTH
                                and KEY_RE.fullmatch(key)
                            ):
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
            fd = self._acquire_file(name, deadline)
        except BaseException:
            m.release()
            raise

        def release() -> None:
            try:
                os.close(fd)
            finally:
                m.release()

        return _Held(release)

    def _lock_path(self, name: str) -> str:
        return os.path.join(self._root, "locks", name + ".lock")

    def _acquire_file(self, name: str, deadline: float) -> int:
        try:
            self._ensure_dir(["locks"])
        except OSError as exc:
            raise _io_error(f"acquire lock {name}", exc) from None
        return flock_file(self._lock_path(name), name, deadline)


def flock_file(path: str, name: str, deadline: float) -> int:
    """Open (0600, ``O_NOFOLLOW``; refused unless ours and owner-only) and exclusively ``flock``
    the permanent lock file ``path``, polling until ``deadline`` (``time.monotonic``); returns
    the fd, whose close releases it. A timeout is ``lock_busy``; any I/O failure
    ``storage_failed``."""
    fd = None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ACEError("storage_failed", "lock is not a regular file")
        _check_private(st, path)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                    raise
                if time.monotonic() >= deadline:
                    raise _busy(name) from None
                time.sleep(min(_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
    except BaseException as exc:
        if fd is not None:
            os.close(fd)
        if isinstance(exc, OSError):
            raise _io_error(f"acquire lock {name}", exc) from None
        raise


# --- JSON records -----------------------------------------------------------------------


def write_record(store: ACEStore, key: str, obj: dict) -> None:
    """Write ``obj`` as a ``version: 1`` record (compact UTF-8, sorted keys, non-ASCII and
    '/' unescaped); the counterpart of ``load_record``."""
    store.write(key, canonical_state_bytes({**obj, "version": 1}))


def load_record(store: ACEStore, key: str) -> dict | None:
    """Read a ``version: 1`` JSON object; anything else is ``storage_failed``."""
    raw = store.read(key)
    return None if raw is None else parse_record(raw, key)


def parse_record(raw: bytes, key: str) -> dict:
    """``load_record`` on bytes already read from ``key``."""
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
