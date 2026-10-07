"""Descriptor-rooted, bounded state for operator-approved supervision."""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any

from .supervision_config import SupervisionError


_MAX_RECORD = 65_536
_MAX_RECORDS = 1_000
_MAX_AUDIT = 1_048_576
_AUDIT_NAMES = ("audit.current", "audit.previous")
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_STAGING = re.compile(r"\.write-[0-9a-f]{32}\Z")
_TARGET_ID = re.compile(r"[0-9a-f]{32}\Z")
_GENERATION = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9_-]{1,64}:[A-Za-z0-9_-]{1,64}\Z")
_CATEGORIES = ("receipts", "targets", "approvals")
_SENSITIVE = ("secret", "credential", "password", "token", "screen", "terminal", "prompt", "input", "output", "stdout", "stderr", "authorization", "api_key", "private")


def _unsafe() -> SupervisionError:
    return SupervisionError("state_unsafe")


def _full() -> SupervisionError:
    return SupervisionError("state_full")


def _invalid(reason: str) -> SupervisionError:
    return SupervisionError("invalid_request", reason=reason)


def _json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _invalid("value_not_json_serializable") from None


def _decode_json(raw: bytes) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        raise _unsafe() from None

def _absolute(path: Path | str) -> Path:
    result = Path(path)
    if not result.is_absolute() or ".." in result.parts:
        raise _unsafe()
    return result


def _directory_info(info: os.stat_result, *, final: bool) -> None:
    uid = os.getuid()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
        raise _unsafe()
    if final:
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise _unsafe()
    elif info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0):
        raise _unsafe()


def _open_directory(path: Path, *, create_missing: bool = False, private_final: bool = True) -> int:
    """Walk an absolute path using no-follow directory descriptors."""
    if not path.is_absolute() or ".." in path.parts:
        raise _unsafe()
    fd = -1
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        _directory_info(os.fstat(fd), final=False)
        parts = path.parts[1:]
        for index, component in enumerate(parts):
            final = index == len(parts) - 1 and private_final
            created = False
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not create_missing:
                    raise _unsafe() from None
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
                except OSError:
                    raise _unsafe() from None
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=fd,
                    )
                except OSError:
                    raise _unsafe() from None
            except OSError:
                raise _unsafe() from None
            try:
                if created:
                    os.fchmod(child, 0o700)
                _directory_info(os.fstat(child), final=final)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        if not parts:
            _directory_info(os.fstat(fd), final=False)
        result = fd
        fd = -1
        return result
    except SupervisionError:
        raise
    except OSError:
        raise _unsafe() from None
    finally:
        if fd >= 0:
            os.close(fd)


def _parent_and_name(path: Path, *, create_missing: bool = False) -> tuple[int, str]:
    name = path.name
    if not name or name in (".", ".."):
        raise _unsafe()
    parent = _open_directory(path.parent, create_missing=create_missing, private_final=False)
    return parent, name

def _remove_initialized_state(path: Path) -> None:
    parent_fd, name = _parent_and_name(path)
    root_fd = -1
    try:
        root_fd = _open_directory(path)
        names = set(os.listdir(root_fd))
        required = {"epoch.json", "key", "lock", *_CATEGORIES}
        allowed = required | set(_AUDIT_NAMES)
        if not required <= names or names - allowed:
            raise _unsafe()
        for fixed in ("epoch.json", "key", "lock"):
            _read_file(root_fd, fixed, maximum=_MAX_RECORD)
        for audit_name in _AUDIT_NAMES:
            _read_file(root_fd, audit_name, maximum=_MAX_AUDIT, required=False)
        for category in _CATEGORIES:
            category_fd = os.open(
                category,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                info = os.fstat(category_fd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise _unsafe()
                entries = os.listdir(category_fd)
                if len(entries) > _MAX_RECORDS:
                    raise _unsafe()
                for entry in entries:
                    if not entry.endswith(".json") or not _HASH.fullmatch(entry[:-5]):
                        raise _unsafe()
                    _read_file(category_fd, entry, maximum=_MAX_RECORD)
                    os.unlink(entry, dir_fd=category_fd)
                os.fsync(category_fd)
            finally:
                os.close(category_fd)
            os.rmdir(category, dir_fd=root_fd)
        for fixed in ("epoch.json", "key", "lock", *_AUDIT_NAMES):
            maximum = _MAX_AUDIT if fixed in _AUDIT_NAMES else _MAX_RECORD
            if _read_file(root_fd, fixed, maximum=maximum, required=False) is not None:
                os.unlink(fixed, dir_fd=root_fd)
        os.fsync(root_fd)
        os.close(root_fd)
        root_fd = -1
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except SupervisionError:
        raise
    except OSError:
        raise _unsafe() from None
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)


def _check_regular(info: os.stat_result, *, maximum: int) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > maximum
    ):
        raise _unsafe()


def _read_file(directory_fd: int, name: str, *, maximum: int, required: bool = True) -> bytes | None:
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        if required:
            raise _unsafe() from None
        return None
    except OSError:
        raise _unsafe() from None
    try:
        info = os.fstat(fd)
        _check_regular(info, maximum=maximum)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise _unsafe()
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise _unsafe() from None
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise _unsafe()
        return raw
    finally:
        os.close(fd)

def _list_names_bounded(directory_fd: int, *, maximum: int) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    raise _unsafe()
    except OSError:
        raise _unsafe() from None
    return names


def _validate_archivable_namespace(root_fd: int) -> None:
    required = {"lock", *_CATEGORIES}
    allowed = required | {"epoch.json", "key", *_AUDIT_NAMES}
    names = set(_list_names_bounded(root_fd, maximum=len(allowed) + 1))
    if not required <= names or any(name not in allowed and not _STAGING.fullmatch(name) for name in names):
        raise _unsafe()
    staged = [name for name in names if _STAGING.fullmatch(name)]
    if len(staged) > 1:
        raise _unsafe()
    staged_total = len(staged)
    _read_file(root_fd, "lock", maximum=_MAX_RECORD)
    for name in ("epoch.json", "key"):
        _read_file(root_fd, name, maximum=_MAX_RECORD, required=False)
    for name in _AUDIT_NAMES:
        _read_file(root_fd, name, maximum=_MAX_AUDIT, required=False)
    for name in staged:
        _read_file(root_fd, name, maximum=_MAX_RECORD)
    for category in _CATEGORIES:
        try:
            directory_fd = os.open(
                category,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
        except OSError:
            raise _unsafe() from None
        try:
            info = os.fstat(directory_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _unsafe()
            entries = _list_names_bounded(directory_fd, maximum=_MAX_RECORDS + 1)
            published_count = 0
            category_staged_count = 0
            for entry in entries:
                if entry.endswith(".json") and _HASH.fullmatch(entry[:-5]):
                    published_count += 1
                    if published_count > _MAX_RECORDS:
                        raise _unsafe()
                    _read_file(directory_fd, entry, maximum=_MAX_RECORD)
                elif _STAGING.fullmatch(entry):
                    category_staged_count += 1
                    if category_staged_count > 1:
                        raise _unsafe()
                    _read_file(directory_fd, entry, maximum=_MAX_RECORD)
                else:
                    raise _unsafe()
            staged_total += category_staged_count
            if staged_total > 1:
                raise _unsafe()
        finally:
            os.close(directory_fd)








def _write_all(fd: int, raw: bytes) -> None:
    position = 0
    while position < len(raw):
        written = os.write(fd, raw[position:])
        if written <= 0:
            raise OSError("short write")
        position += written


def _atomic_write(directory_fd: int, name: str, raw: bytes, *, replace: bool = True, maximum: int = _MAX_RECORD) -> None:
    if len(raw) > maximum:
        raise _full()
    try:
        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise _unsafe() from None
        if existing is not None:
            _check_regular(existing, maximum=maximum)
            if not replace:
                raise SupervisionError("operation_conflict")
        temporary = ".write-" + secrets.token_hex(16)
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            try:
                os.fchmod(fd, 0o600)
                _write_all(fd, raw)
                os.fsync(fd)
                _check_regular(os.fstat(fd), maximum=maximum)
            finally:
                os.close(fd)
            if not replace:
                try:
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise SupervisionError("operation_conflict")
            os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
            raise
    except SupervisionError:
        raise
    except OSError:
        raise _unsafe() from None


def _hash_name(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() + ".json"


def _record_copy(record: dict[str, Any]) -> dict[str, Any]:
    return _decode_json(_json_bytes(record))


class _AsyncLock:
    def __init__(self, state: "SupervisionState", timeout: float):
        self.state = state
        self.timeout = timeout
        self.fd = -1

    async def __aenter__(self) -> "SupervisionState":
        state = self.state
        state._verify_path()
        self.fd = state._open_lock_file()
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.timeout
            while True:
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    state._active_locks += 1
                    return state
                except BlockingIOError:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        raise SupervisionError("busy")
                    await asyncio.sleep(min(0.01, remaining))
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    async def __aexit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self.fd >= 0:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = -1
                self.state._active_locks -= 1


class SupervisionState:
    """Opened private state; operations are bounded and durable across restarts."""

    def __init__(self, path: Path | str):
        self.path = _absolute(path)
        self._dir_fd = -1
        self._closed = False
        self._active_locks = 0
        self._epoch: str = ""
        self._key: bytes = b""
        self._next_sequence: int = 1
        self._metadata_loaded = False
        self._recovered_allocating: set[str] = set()
        try:
            self._dir_fd = _open_directory(self.path)
            self._verify_path()
            self._validate_root()
            self._load_metadata()
            self._validate_contents()
        except SupervisionError:
            self.close()
            raise
        except OSError:
            self.close()
            raise _unsafe() from None

    @classmethod
    def initialize(cls, path: Path | str) -> "SupervisionState":
        state_path = _absolute(path)
        parent_fd, name = _parent_and_name(state_path, create_missing=True)
        created = False
        owns_empty_directory = False
        root_fd = -1
        initialized_state: SupervisionState | None = None

        def verify_path() -> None:
            opened = os.fstat(root_fd)
            _directory_info(opened, final=True)
            visible_parent_fd = _open_directory(state_path.parent, private_final=False)
            try:
                parent_info = os.fstat(parent_fd)
                visible_parent = os.fstat(visible_parent_fd)
                if (parent_info.st_dev, parent_info.st_ino) != (visible_parent.st_dev, visible_parent.st_ino):
                    raise _unsafe()
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                _directory_info(current, final=True)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise _unsafe()
            finally:
                os.close(visible_parent_fd)

        try:
            try:
                root_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                    created = True
                    root_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent_fd,
                    )
                except OSError:
                    raise _unsafe() from None
            except OSError:
                raise _unsafe() from None
            if created:
                os.fchmod(root_fd, 0o700)
            _directory_info(os.fstat(root_fd), final=True)
            verify_path()
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SupervisionError("busy") from None
            verify_path()
            if os.listdir(root_fd):
                raise SupervisionError("state_unsafe", reason="state_already_initialized")
            owns_empty_directory = True
            for category in _CATEGORIES:
                os.mkdir(category, 0o700, dir_fd=root_fd)
                child = os.open(category, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
                try:
                    os.fchmod(child, 0o700)
                    os.fsync(child)
                finally:
                    os.close(child)
            key = secrets.token_bytes(32)
            metadata = {
                "version": 1,
                "epoch": secrets.token_hex(16),
                "next_sequence": 1,
                "key_sha256": hashlib.sha256(key).hexdigest(),
            }
            _atomic_write(root_fd, "key", key, replace=False)
            _atomic_write(root_fd, "epoch.json", _json_bytes(metadata), replace=False)
            lock_fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
            try:
                os.fchmod(lock_fd, 0o600)
                os.fsync(lock_fd)
            finally:
                os.close(lock_fd)
            verify_path()
            os.fsync(root_fd)
            verify_path()
            initialized_state = cls(state_path)
            opened = os.fstat(root_fd)
            returned = os.fstat(initialized_state._dir_fd)
            if (opened.st_dev, opened.st_ino) != (returned.st_dev, returned.st_ino):
                raise _unsafe()
            verify_path()
        except BaseException as error:
            if initialized_state is not None:
                initialized_state.close()
            if owns_empty_directory and root_fd >= 0:
                for category in _CATEGORIES:
                    try:
                        child = os.open(category, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
                    except OSError:
                        continue
                    try:
                        for entry in os.listdir(child):
                            info = os.stat(entry, dir_fd=child, follow_symlinks=False)
                            if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1:
                                os.unlink(entry, dir_fd=child)
                    except OSError:
                        pass
                    finally:
                        os.close(child)
                    try:
                        os.rmdir(category, dir_fd=root_fd)
                    except OSError:
                        pass
                for entry in ("key", "epoch.json", "lock"):
                    try:
                        info = os.stat(entry, dir_fd=root_fd, follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1:
                            os.unlink(entry, dir_fd=root_fd)
                    except OSError:
                        pass
                try:
                    os.fsync(root_fd)
                except OSError:
                    pass
                if created:
                    try:
                        verify_path()
                        os.rmdir(name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    except (OSError, SupervisionError):
                        pass
            if root_fd >= 0:
                os.close(root_fd)
            os.close(parent_fd)
            if isinstance(error, SupervisionError):
                raise
            if isinstance(error, OSError):
                raise _unsafe() from None
            raise
        os.close(root_fd)
        os.close(parent_fd)
        assert initialized_state is not None
        return initialized_state

    @classmethod
    def reinitialize(cls, path: Path | str) -> "SupervisionState":
        state_path = _absolute(path)
        lock_fd = -1
        parent_fd = -1
        root_fd = -1
        staging_path: Path | None = None
        staging_ready = False
        reservation_created = False
        reservation_inode: tuple[int, int] | None = None
        moved_old = False
        moved_new = False
        try:
            parent_fd, name = _parent_and_name(state_path)
            root_fd = _open_directory(state_path)
            # Rotation and initialization share directory ownership; acquire it
            # before the mutation-file lock so an initializer cannot erase an archive.
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SupervisionError("busy") from None

            def verify_path() -> None:
                opened = os.fstat(root_fd)
                _directory_info(opened, final=True)
                visible_parent_fd = _open_directory(state_path.parent, private_final=False)
                try:
                    parent_info = os.fstat(parent_fd)
                    visible_parent = os.fstat(visible_parent_fd)
                    if (parent_info.st_dev, parent_info.st_ino) != (visible_parent.st_dev, visible_parent.st_ino):
                        raise _unsafe()
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    _directory_info(current, final=True)
                    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                        raise _unsafe()
                    visible_root_fd = _open_directory(state_path)
                    try:
                        visible_root = os.fstat(visible_root_fd)
                        if (visible_root.st_dev, visible_root.st_ino) != (opened.st_dev, opened.st_ino):
                            raise _unsafe()
                    finally:
                        os.close(visible_root_fd)
                finally:
                    os.close(visible_parent_fd)

            def verify_lock_path() -> None:
                opened = os.fstat(lock_fd)
                current = os.stat("lock", dir_fd=root_fd, follow_symlinks=False)
                _check_regular(current, maximum=_MAX_RECORD)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise _unsafe()

            verify_path()
            try:
                lock_fd = os.open(
                    "lock",
                    os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=root_fd,
                )
            except OSError:
                raise _unsafe() from None
            _check_regular(os.fstat(lock_fd), maximum=_MAX_RECORD)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SupervisionError("busy") from None
            verify_path()
            verify_lock_path()
            _validate_archivable_namespace(root_fd)

            previous_name = name + ".previous"
            stage_name = ".dotunnel-state-" + hashlib.sha256(os.fsencode(str(state_path))).hexdigest()[:16] + ".new"
            try:
                os.stat(previous_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise _unsafe() from None
            else:
                raise SupervisionError("state_full", reason="previous_namespace_requires_reconciliation")
            try:
                os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise _unsafe() from None
            else:
                raise SupervisionError("state_full", reason="staging_namespace_requires_reconciliation")

            staging_path = state_path.with_name(stage_name)
            staged = cls.initialize(staging_path)
            staged.close()
            staging_ready = True
            os.fsync(parent_fd)

            try:
                os.mkdir(previous_name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                raise SupervisionError("state_full", reason="previous_namespace_requires_reconciliation") from None
            except OSError:
                raise _unsafe() from None
            reservation_created = True
            reservation = os.stat(previous_name, dir_fd=parent_fd, follow_symlinks=False)
            reservation_inode = (reservation.st_dev, reservation.st_ino)
            reservation_fd = os.open(
                previous_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            try:
                os.fchmod(reservation_fd, 0o700)
                info = os.fstat(reservation_fd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise _unsafe()
            finally:
                os.close(reservation_fd)

            verify_path()
            verify_lock_path()
            _validate_archivable_namespace(root_fd)
            opened = os.fstat(root_fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise _unsafe()
            os.rename(name, previous_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_old = True
            reservation_created = False
            os.fsync(parent_fd)
            os.rename(stage_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_new = True
            staging_ready = False
            os.fsync(parent_fd)
        except BaseException as error:
            if parent_fd >= 0 and root_fd >= 0 and moved_old and not moved_new:
                try:
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        archived = os.stat(name + ".previous", dir_fd=parent_fd, follow_symlinks=False)
                        opened = os.fstat(root_fd)
                        if (archived.st_dev, archived.st_ino) == (opened.st_dev, opened.st_ino):
                            os.rename(name + ".previous", name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                            os.fsync(parent_fd)
                            moved_old = False
                except OSError:
                    pass
            if parent_fd >= 0 and reservation_created and reservation_inode is not None:
                try:
                    reservation = os.stat(name + ".previous", dir_fd=parent_fd, follow_symlinks=False)
                    if (reservation.st_dev, reservation.st_ino) == reservation_inode:
                        os.rmdir(name + ".previous", dir_fd=parent_fd)
                        os.fsync(parent_fd)
                except OSError:
                    pass
            if staging_ready and staging_path is not None and not moved_old and not moved_new:
                try:
                    _remove_initialized_state(staging_path)
                except (OSError, SupervisionError):
                    pass
            if isinstance(error, OSError):
                raise _unsafe() from None
            raise
        finally:
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)
            if root_fd >= 0:
                os.close(root_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
        return cls(state_path)

    @property
    def epoch(self) -> str:
        self._verify_path()
        return self._epoch

    @property
    def key(self) -> bytes:
        self._verify_path()
        return self._key

    def close(self) -> None:
        if not self._closed:
            if self._dir_fd >= 0:
                os.close(self._dir_fd)
                self._dir_fd = -1
            self._closed = True

    def lock(self, timeout: float = 1.0) -> _AsyncLock:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
            raise _invalid("invalid_lock_timeout")
        return _AsyncLock(self, float(timeout))

    def _verify_path(self) -> None:
        if self._closed or self._dir_fd < 0:
            raise _unsafe()
        current_fd = _open_directory(self.path)
        try:
            before = os.fstat(self._dir_fd)
            current = os.fstat(current_fd)
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise _unsafe()
            if self._metadata_loaded:
                marker = _read_file(current_fd, "reinit.marker", maximum=_MAX_RECORD, required=False)
                metadata_raw = _read_file(current_fd, "epoch.json", maximum=_MAX_RECORD)
                key = _read_file(current_fd, "key", maximum=_MAX_RECORD)
                if marker is not None:
                    raise _unsafe()
                assert metadata_raw is not None and key is not None
                metadata = _decode_json(metadata_raw)
                if (
                    not isinstance(metadata, dict)
                    or set(metadata) != {"version", "epoch", "next_sequence", "key_sha256"}
                    or metadata.get("version") != 1
                    or isinstance(metadata.get("version"), bool)
                    or metadata.get("epoch") != self._epoch
                    or isinstance(metadata.get("next_sequence"), bool)
                    or not isinstance(metadata.get("next_sequence"), int)
                    or metadata.get("next_sequence") < 1
                    or key != self._key
                    or metadata.get("key_sha256") != hashlib.sha256(key).hexdigest()
                ):
                    raise _unsafe()
                self._next_sequence = metadata["next_sequence"]
        finally:
            os.close(current_fd)
    def _open_lock_file(self) -> int:
        self._verify_path()
        try:
            fd = os.open(
                "lock",
                os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._dir_fd,
            )
        except OSError:
            raise _unsafe() from None
        try:
            _check_regular(os.fstat(fd), maximum=_MAX_RECORD)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _open_category(self, category: str) -> int:
        self._verify_path()
        try:
            fd = os.open(
                category,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._dir_fd,
            )
        except OSError:
            raise _unsafe() from None
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _unsafe()
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _load_metadata(self) -> None:
        metadata_raw = _read_file(self._dir_fd, "epoch.json", maximum=_MAX_RECORD)
        key = _read_file(self._dir_fd, "key", maximum=_MAX_RECORD)
        assert metadata_raw is not None and key is not None
        metadata = _decode_json(metadata_raw)
        if (
            not isinstance(metadata, dict)
            or set(metadata) != {"version", "epoch", "next_sequence", "key_sha256"}
            or metadata.get("version") != 1
            or isinstance(metadata.get("version"), bool)
            or not isinstance(metadata.get("epoch"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", metadata["epoch"])
            or isinstance(metadata.get("next_sequence"), bool)
            or not isinstance(metadata.get("next_sequence"), int)
            or metadata["next_sequence"] < 1
            or not isinstance(metadata.get("key_sha256"), str)
            or not _HASH.fullmatch(metadata["key_sha256"])
            or len(key) != 32
            or hashlib.sha256(key).hexdigest() != metadata["key_sha256"]
        ):
            raise _unsafe()
        self._epoch = metadata["epoch"]
        self._next_sequence = metadata["next_sequence"]
        self._key = key
        self._metadata_loaded = True

    def _validate_root(self) -> None:
        names = set(os.listdir(self._dir_fd))
        required = {"epoch.json", "key", "lock", *_CATEGORIES}
        allowed = required | set(_AUDIT_NAMES)
        if not required <= names or names - allowed:
            raise _unsafe()
        for category in _CATEGORIES:
            category_fd = self._open_category(category)
            os.close(category_fd)
        lock_fd = self._open_lock_file()
        os.close(lock_fd)

    def _read_category_file(self, directory_fd: int, name: str, category: str) -> dict[str, Any]:
        if not name.endswith(".json") or not _HASH.fullmatch(name[:-5]):
            raise _unsafe()
        raw = _read_file(directory_fd, name, maximum=_MAX_RECORD)
        assert raw is not None
        record = _decode_json(raw)
        if not isinstance(record, dict) or record.get("epoch") != self._epoch:
            raise _unsafe()
        if category == "receipts":
            operation_id = record.get("operation_id")
            if (
                not isinstance(operation_id, str)
                or not _ID.fullmatch(operation_id)
                or _hash_name(operation_id) != name
                or not isinstance(record.get("fingerprint"), str)
                or not _HASH.fullmatch(record["fingerprint"])
                or isinstance(record.get("sequence"), bool)
                or not isinstance(record.get("sequence"), int)
                or record["sequence"] < 1
                or not isinstance(record.get("binding"), dict)
                or record.get("state") not in ("prepared", "finished")
            ):
                raise _unsafe()
            if record["state"] == "finished" and not isinstance(record.get("result"), dict):
                raise _unsafe()
            if record["state"] == "prepared" and "result" in record:
                raise _unsafe()
        elif category == "targets":
            target_id = record.get("target_id")
            if (
                not isinstance(target_id, str)
                or not _TARGET_ID.fullmatch(target_id)
                or _hash_name(target_id) != name
                or not isinstance(record.get("operation_id"), str)
                or not _ID.fullmatch(record["operation_id"])
                or not isinstance(record.get("nonce"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["nonce"])
                or not isinstance(record.get("binding"), dict)
                or record.get("state") not in ("allocating", "active", "unknown", "refused")
            ):
                raise _unsafe()
            if record["state"] == "active" and not isinstance(record.get("native"), dict):
                raise _unsafe()
            if "native" in record and not isinstance(record["native"], dict):
                raise _unsafe()
        else:
            scope = record.get("scope")
            generation = record.get("generation")
            if (
                not isinstance(scope, str)
                or not _SCOPE.fullmatch(scope)
                or not isinstance(generation, str)
                or not _GENERATION.fullmatch(generation)
                or _hash_name(scope + "\0" + generation) != name
                or not isinstance(record.get("approved"), bool)
            ):
                raise _unsafe()
        return record

    def _validate_contents(self) -> None:
        marker = _read_file(self._dir_fd, "reinit.marker", maximum=_MAX_RECORD, required=False)
        if marker is not None:
            parsed = _decode_json(marker)
            if parsed != {"version": 1, "state": "reinitializing"}:
                raise _unsafe()
            raise _unsafe()
        sequences: set[int] = set()
        for category in _CATEGORIES:
            category_fd = self._open_category(category)
            try:
                names = os.listdir(category_fd)
                if len(names) > _MAX_RECORDS:
                    raise _unsafe()
                for name in names:
                    record = self._read_category_file(category_fd, name, category)
                    if category == "receipts":
                        sequence = record["sequence"]
                        if sequence >= self._next_sequence or sequence in sequences:
                            raise _unsafe()
                        sequences.add(sequence)
                    elif category == "targets" and record["state"] == "allocating":
                        self._recovered_allocating.add(record["target_id"])
            finally:
                os.close(category_fd)
        for name in _AUDIT_NAMES:
            _read_file(self._dir_fd, name, maximum=_MAX_AUDIT, required=False)

    def _write_metadata(self) -> None:
        metadata = {
            "version": 1,
            "epoch": self._epoch,
            "next_sequence": self._next_sequence,
            "key_sha256": hashlib.sha256(self._key).hexdigest(),
        }
        _atomic_write(self._dir_fd, "epoch.json", _json_bytes(metadata))

    def _category_count(self, category: str) -> int:
        directory_fd = self._open_category(category)
        try:
            names = os.listdir(directory_fd)
            if len(names) > _MAX_RECORDS:
                raise _unsafe()
            for name in names:
                if not name.endswith(".json") or not _HASH.fullmatch(name[:-5]):
                    raise _unsafe()
            return len(names)
        finally:
            os.close(directory_fd)

    def _ensure_target_capacity(self) -> None:
        if self._category_count("targets") >= _MAX_RECORDS:
            raise _full()

    def check_target_capacity(self) -> None:
        """Fail before receipt admission if the bounded target store is full."""
        self._verify_path()
        self._ensure_target_capacity()


    def _read_record(self, category: str, key: str) -> dict[str, Any] | None:
        directory_fd = self._open_category(category)
        try:
            name = _hash_name(key)
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError:
                raise _unsafe() from None
            return self._read_category_file(directory_fd, name, category)
        finally:
            os.close(directory_fd)

    def _save_record(self, category: str, key: str, record: dict[str, Any], *, replace: bool) -> None:
        raw = _json_bytes(record)
        if len(raw) > _MAX_RECORD:
            raise _full()
        directory_fd = self._open_category(category)
        try:
            _atomic_write(directory_fd, _hash_name(key), raw, replace=replace)
        finally:
            os.close(directory_fd)

    def _iter_records(self, category: str) -> list[dict[str, Any]]:
        directory_fd = self._open_category(category)
        try:
            names = os.listdir(directory_fd)
            if len(names) > _MAX_RECORDS:
                raise _unsafe()
            return [self._read_category_file(directory_fd, name, category) for name in names]
        finally:
            os.close(directory_fd)

    def _operation(self, operation_id: object, fingerprint: object | None = None) -> str:
        if not isinstance(operation_id, str) or not _ID.fullmatch(operation_id):
            raise _invalid("invalid_operation_id")
        if fingerprint is not None and (not isinstance(fingerprint, str) or not _HASH.fullmatch(fingerprint)):
            raise _invalid("invalid_fingerprint")
        return operation_id

    def _lookup_receipt(self, operation_id: str) -> dict[str, Any] | None:
        return self._read_record("receipts", operation_id)

    def lookup_receipt(self, operation_id: str, fingerprint: str) -> dict[str, Any] | None:
        self._verify_path()
        operation_id = self._operation(operation_id, fingerprint)
        receipt = self._lookup_receipt(operation_id)
        if receipt is None:
            return None
        if receipt["fingerprint"] != fingerprint:
            raise SupervisionError("operation_conflict")
        if receipt["state"] == "finished":
            result = _record_copy(receipt["result"])
            result["historical"] = True
            return result
        return {
            "delivery": "unknown",
            "error": {"code": "delivery_unknown", "message": "The backend effect may have occurred; delivery is unknown."},
            "operation_id": operation_id,
            "historical": True,
        }

    def prepare(self, operation_id: str, fingerprint: str, binding: dict[str, Any]) -> dict[str, Any]:
        self._verify_path()
        operation_id = self._operation(operation_id, fingerprint)
        if not isinstance(binding, dict):
            raise _invalid("invalid_operation_binding")
        existing = self._lookup_receipt(operation_id)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise SupervisionError("operation_conflict")
            return _record_copy(existing)
        if self._category_count("receipts") >= _MAX_RECORDS:
            raise _full()
        record = {
            "epoch": self._epoch,
            "operation_id": operation_id,
            "fingerprint": fingerprint,
            "sequence": self._next_sequence,
            "binding": binding,
            "state": "prepared",
        }
        encoded = _json_bytes(record)
        if len(encoded) > _MAX_RECORD:
            raise _full()
        self._next_sequence += 1
        self._write_metadata()
        self._save_record("receipts", operation_id, record, replace=False)
        return _record_copy(record)

    def finish(self, operation_id: str, result: dict[str, Any]) -> None:
        self._verify_path()
        operation_id = self._operation(operation_id)
        if not isinstance(result, dict):
            raise _invalid("invalid_operation_result")
        receipt = self._lookup_receipt(operation_id)
        if receipt is None or receipt["state"] != "prepared":
            raise SupervisionError("operation_conflict")
        receipt["state"] = "finished"
        receipt["result"] = result
        if len(_json_bytes(receipt)) > _MAX_RECORD:
            raise _full()
        self._save_record("receipts", operation_id, receipt, replace=True)

    def allocate_target(self, operation_id: str, binding: dict[str, Any]) -> dict[str, Any]:
        self._verify_path()
        operation_id = self._operation(operation_id)
        if not isinstance(binding, dict):
            raise _invalid("invalid_target_binding")
        self._ensure_target_capacity()
        target_id = secrets.token_hex(16)
        nonce = secrets.token_hex(32)
        record = {
            "epoch": self._epoch,
            "target_id": target_id,
            "nonce": nonce,
            "operation_id": operation_id,
            "binding": binding,
            "state": "allocating",
        }
        if len(_json_bytes(record)) > _MAX_RECORD:
            raise _full()
        self._save_record("targets", target_id, record, replace=False)
        return _record_copy(record)

    def activate_target(self, target_id: str, native: dict[str, Any]) -> dict[str, Any]:
        self._verify_path()
        if not isinstance(target_id, str) or not _TARGET_ID.fullmatch(target_id):
            raise _invalid("invalid_target_id")
        if not isinstance(native, dict):
            raise _invalid("invalid_native_identity")
        record = self._read_record("targets", target_id)
        if record is None or record["state"] not in ("allocating", "unknown"):
            raise SupervisionError("stale_target")
        record["state"] = "active"
        record["native"] = native
        if len(_json_bytes(record)) > _MAX_RECORD:
            raise _full()
        self._save_record("targets", target_id, record, replace=True)
        return _record_copy(record)

    def update_target(self, target_id: str, state: str, native: dict[str, Any] | None = None) -> dict[str, Any]:
        self._verify_path()
        if not isinstance(target_id, str) or not _TARGET_ID.fullmatch(target_id):
            raise _invalid("invalid_target_id")
        if state not in ("unknown", "refused"):
            raise _invalid("invalid_target_state")
        if native is not None and not isinstance(native, dict):
            raise _invalid("invalid_native_identity")
        record = self._read_record("targets", target_id)
        if record is None:
            raise SupervisionError("stale_target")
        record["state"] = state
        if state == "refused":
            record.pop("native", None)
        elif native is not None:
            record["native"] = native
        if len(_json_bytes(record)) > _MAX_RECORD:
            raise _full()
        self._save_record("targets", target_id, record, replace=True)
        return _record_copy(record)

    def list_targets(self) -> list[dict[str, Any]]:
        self._verify_path()
        records = self._iter_records("targets")
        for record in records:
            if record["state"] == "allocating" and record["target_id"] in self._recovered_allocating:
                record["state"] = "unknown"
        records.sort(key=lambda record: record["target_id"])
        return [_record_copy(record) for record in records]

    def set_approval(self, scope: str, generation: str, approved: bool) -> None:
        self._verify_path()
        if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
            raise _invalid("invalid_approval_scope")
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise _invalid("invalid_approval_generation")
        if not isinstance(approved, bool):
            raise _invalid("invalid_approval_value")
        key = scope + "\0" + generation
        existing = self._read_record("approvals", key)
        if existing is None and self._category_count("approvals") >= _MAX_RECORDS:
            raise _full()
        record = {"epoch": self._epoch, "scope": scope, "generation": generation, "approved": approved}
        self._save_record("approvals", key, record, replace=existing is not None)

    def approved(self, scope: str, generation: str) -> bool:
        self._verify_path()
        if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
            raise _invalid("invalid_approval_scope")
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise _invalid("invalid_approval_generation")
        record = self._read_record("approvals", scope + "\0" + generation)
        return bool(record and record["approved"])

    def unresolved_predecessors(self) -> dict[str, Any]:
        self._verify_path()
        unresolved: list[dict[str, Any]] = []
        for receipt in self._iter_records("receipts"):
            is_unknown = receipt["state"] == "prepared"
            if receipt["state"] == "finished":
                result = receipt["result"]
                error = result.get("error")
                is_unknown = result.get("delivery") == "unknown" or (
                    isinstance(error, dict) and error.get("code") == "delivery_unknown"
                )
            if is_unknown:
                unresolved.append(receipt)
        unresolved.sort(key=lambda receipt: (receipt["sequence"], receipt["operation_id"]))
        ids = [receipt["operation_id"] for receipt in unresolved[:32]]
        return {
            "unresolved_predecessor_count": len(unresolved),
            "unresolved_predecessor_ids": ids,
            "unresolved_predecessors_truncated": len(unresolved) > len(ids),
        }

    def _sanitize_audit(self, value: object, *, depth: int = 0) -> Any:
        if depth > 4:
            return None
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, str):
            return value if len(value) <= 60_000 and "\x00" not in value else None
        if isinstance(value, list):
            return [self._sanitize_audit(item, depth=depth + 1) for item in value[:128]]
        if isinstance(value, dict):
            cleaned: dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index == 128:
                    break
                if not isinstance(key, str) or not key or any(sensitive in key.lower() for sensitive in _SENSITIVE):
                    continue
                sanitized = self._sanitize_audit(item, depth=depth + 1)
                if sanitized is not None:
                    cleaned[key[:128]] = sanitized
            return cleaned
        return None

    def audit(self, event: dict[str, Any]) -> None:
        self._verify_path()
        if not isinstance(event, dict):
            raise _invalid("invalid_audit_event")
        sanitized = self._sanitize_audit(event)
        if not isinstance(sanitized, dict):
            raise _invalid("invalid_audit_event")
        sanitized["timestamp"] = time.time()
        line = _json_bytes(sanitized) + b"\n"
        if len(line) > _MAX_RECORD:
            raise _full()
        try:
            current = _read_file(self._dir_fd, "audit.current", maximum=_MAX_AUDIT, required=False)
            if current is not None and (not current.endswith(b"\n") or len(current) + len(line) > _MAX_AUDIT):
                previous = _read_file(self._dir_fd, "audit.previous", maximum=_MAX_AUDIT, required=False)
                if previous is not None:
                    os.unlink("audit.previous", dir_fd=self._dir_fd)
                os.replace("audit.current", "audit.previous", src_dir_fd=self._dir_fd, dst_dir_fd=self._dir_fd)
                os.fsync(self._dir_fd)
                current = None
            if current is None:
                fd = os.open(
                    "audit.current",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=self._dir_fd,
                )
                try:
                    os.fchmod(fd, 0o600)
                    _check_regular(os.fstat(fd), maximum=_MAX_AUDIT)
                    _write_all(fd, line)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(self._dir_fd)
                return
            fd = os.open(
                "audit.current",
                os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._dir_fd,
            )
            try:
                _check_regular(os.fstat(fd), maximum=_MAX_AUDIT)
                _write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self._dir_fd)
        except SupervisionError:
            raise
        except OSError:
            raise _unsafe() from None
