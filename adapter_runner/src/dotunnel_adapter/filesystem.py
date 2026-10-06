"""Descriptor-rooted request claiming and create-only report publication."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import pwd
import re
import secrets
import stat
import threading
from pathlib import Path
from typing import Any, NoReturn

from .protocol import RunnerError, canonical_json


_FILE_LIMIT = 65536
_PATH_LIMIT = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | os.O_CLOEXEC
    | os.O_NOCTTY
)
_PROTECTED_NAMES = frozenset(
    {
        "credential",
        "credentials",
        "secret",
        "secrets",
        "token",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_xmss",
        "identity",
        "private",
        "private_key",
        "private-key",
        "privatekey",
        "privkey",
        "authorized_keys",
        "known_hosts",
        "agent.db",
        "auth.json",
        "client.json",
        "config.local",
        "config.local.json",
        "profile.json",
    }
)
_PROTECTED_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".p8",
    ".ppk",
    ".der",
    ".jks",
    ".keystore",
    ".gpg",
    ".pgp",
    ".asc",
)
try:
    _RENAMEAT2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2")
    _RENAMEAT2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    _RENAMEAT2.restype = ctypes.c_int
except (AttributeError, OSError):
    _RENAMEAT2 = None


def _rename_noreplace(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
    if _RENAMEAT2 is None:
        _fail()
    result = _RENAMEAT2(
        source_fd,
        os.fsencode(source),
        destination_fd,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, "claim destination exists", destination)
    raise OSError(error, "atomic claim move failed")


def _fail(code: str = "request_conflict") -> NoReturn:
    raise RunnerError(code)


def _protected(component: str) -> bool:
    lowered = component.casefold()
    return (
        component.startswith(".")
        or lowered in _PROTECTED_NAMES
        or lowered.split(".", 1)[0] in _PROTECTED_NAMES
        or lowered.endswith(_PROTECTED_SUFFIXES)
    )


def _components(relative: object) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\x00" in relative or relative.startswith("/"):
        _fail("invalid_request")
    try:
        encoded = relative.encode("utf-8", "strict")
    except UnicodeError:
        _fail("invalid_request")
    if len(encoded) > _PATH_LIMIT:
        _fail("invalid_request")
    components = tuple(relative.split("/"))
    if any(component in ("", ".", "..") or _protected(component) for component in components):
        _fail("invalid_request")
    return components


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def _stable_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _identity(before) == _identity(after)
        and stat.S_ISREG(after.st_mode)
        and after.st_nlink == 1
        and after.st_uid == os.getuid()
        and not after.st_mode & 0o077
    )


def _same_entry(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_nlink == second.st_nlink == 1
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
        and stat.S_ISREG(first.st_mode)
        and stat.S_ISREG(second.st_mode)
    )


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            _fail()
        offset += written



class Workspace:
    """A workspace root pinned by descriptor; client paths never escape it."""

    def _open_claim_directory(self) -> int:
        self._ensure_open()
        name = ".dotunnel-claims"
        fd = -1
        try:
            try:
                os.mkdir(name, 0o700, dir_fd=self._root_fd)
            except FileExistsError:
                pass
            fd = os.open(name, _DIR_FLAGS, dir_fd=self._root_fd)
            info = os.fstat(fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                _fail()
            return fd
        except RunnerError:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        except OSError:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            _fail()

    @staticmethod
    def _move_to_claim(parent_fd: int, name: str, claim_fd: int) -> str:
        for _attempt in range(8):
            claim_name = "claim-" + secrets.token_hex(16)
            try:
                _rename_noreplace(parent_fd, name, claim_fd, claim_name)
                return claim_name
            except FileExistsError:
                continue
        _fail()

    @staticmethod
    def _restore_claim(claim_fd: int, claim_name: str, parent_fd: int, name: str) -> None:
        try:
            _rename_noreplace(claim_fd, claim_name, parent_fd, name)
            os.fsync(claim_fd)
            os.fsync(parent_fd)
        except OSError:
            return

    def __init__(self, root: Path):
        self._root_fd = -1
        self._closed = True
        self._claim_lock = threading.Lock()
        self._snapshots: dict[str, tuple[tuple[int, int, int, int, int, int], bytes, str]] = {}
        try:
            raw = os.fspath(root)
            if not isinstance(raw, str) or not raw or "\x00" in raw:
                _fail("invalid_config")
            requested = Path(raw)
            if not requested.is_absolute() or ".." in requested.parts:
                _fail("invalid_config")
            absolute = Path(os.path.normpath(raw))
            account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
            if absolute == Path("/") or absolute == account_home:
                _fail("invalid_config")
            current = os.open("/", _DIR_FLAGS)
            try:
                for component in absolute.parts[1:]:
                    child = os.open(component, _DIR_FLAGS, dir_fd=current)
                    os.close(current)
                    current = child
                info = os.fstat(current)
                if not stat.S_ISDIR(info.st_mode):
                    _fail("invalid_config")
                self._root_fd = current
                self._closed = False
                current = -1
            finally:
                if current >= 0:
                    os.close(current)
        except RunnerError:
            raise
        except (OSError, KeyError, TypeError, ValueError, UnicodeError):
            _fail("invalid_config")

    def close(self) -> None:
        if self._closed:
            return
        fd = self._root_fd
        self._root_fd = -1
        self._closed = True
        self._snapshots.clear()
        try:
            os.close(fd)
        except OSError:
            _fail()

    def _ensure_open(self) -> None:
        if self._closed or self._root_fd < 0:
            _fail()

    def _open_directory(self, components: tuple[str, ...]) -> int:
        self._ensure_open()
        current = os.dup(self._root_fd)
        try:
            for component in components:
                child = os.open(component, _DIR_FLAGS, dir_fd=current)
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    os.close(child)
                    _fail()
                os.close(current)
                current = child
            return current
        except RunnerError:
            os.close(current)
            raise
        except OSError:
            os.close(current)
            _fail()

    def _open_parent(self, components: tuple[str, ...]) -> tuple[int, str]:
        if not components:
            _fail("invalid_request")
        return self._open_directory(components[:-1]), components[-1]

    @staticmethod
    def _open_regular_at(parent_fd: int, name: str) -> int:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or before.st_mode & 0o077
            ):
                _fail()
            fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
            try:
                after = os.fstat(fd)
                if not _same_entry(before, after) or after.st_uid != os.getuid() or after.st_mode & 0o077:
                    _fail()
                return fd
            except BaseException:
                os.close(fd)
                raise
        except RunnerError:
            raise
        except OSError:
            _fail()

    @staticmethod
    def _read_fd(fd: int) -> tuple[bytes, os.stat_result]:
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or before.st_mode & 0o077
            ):
                _fail()
            if before.st_size > _FILE_LIMIT:
                _fail("resource_limit")
            chunks = bytearray()
            offset = 0
            while len(chunks) <= _FILE_LIMIT:
                block = os.pread(fd, min(8192, _FILE_LIMIT + 1 - len(chunks)), offset)
                if not block:
                    break
                chunks.extend(block)
                offset += len(block)
            after = os.fstat(fd)
            if len(chunks) > _FILE_LIMIT:
                _fail("resource_limit")
            if not _stable_file(before, after) or len(chunks) != after.st_size:
                _fail()
            return bytes(chunks), after
        except RunnerError:
            raise
        except OSError:
            _fail()

    def _open_snapshot(self, relative: str):
        components = _components(relative)
        parent_fd, name = self._open_parent(components)
        try:
            fd = self._open_regular_at(parent_fd, name)
            try:
                data, info = self._read_fd(fd)
                return parent_fd, name, fd, data, info
            except BaseException:
                os.close(fd)
                raise
        except BaseException:
            os.close(parent_fd)
            raise

    def read_request(self, relative: str) -> tuple[bytes, str]:
        self._ensure_open()
        parent_fd = -1
        fd = -1
        try:
            parent_fd, name, fd, data, info = self._open_snapshot(relative)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not _same_entry(info, current):
                _fail()
            digest = hashlib.sha256(data).hexdigest()
            self._snapshots.clear()
            self._snapshots[relative] = (_identity(info), data, digest)
            return data, digest
        except RunnerError:
            raise
        except OSError:
            _fail()
        finally:
            if fd >= 0:
                os.close(fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def claim_request(self, relative: str, expected_sha256: str) -> bytes:
        self._ensure_open()
        _components(relative)
        if not isinstance(expected_sha256, str) or _SHA256.fullmatch(expected_sha256) is None:
            _fail("invalid_request")
        # The atomic no-replace rename is the cross-process one-shot claim.
        # A mismatch is restored to the pending path or retained privately if
        # another request has already occupied that path.
        with self._claim_lock:
            parent_fd = -1
            fd = -1
            claim_dir_fd = -1
            claimed_fd = -1
            claim_name = None
            try:
                parent_fd, name, fd, data, info = self._open_snapshot(relative)
                snapshot = self._snapshots.get(relative)
                digest = hashlib.sha256(data).hexdigest()
                if digest != expected_sha256:
                    _fail()
                if snapshot is not None and (
                    snapshot[0] != _identity(info)
                    or snapshot[1] != data
                    or snapshot[2] != expected_sha256
                ):
                    _fail()
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_entry(info, current):
                    _fail()
                claim_dir_fd = self._open_claim_directory()
                claim_name = self._move_to_claim(parent_fd, name, claim_dir_fd)
                os.fsync(parent_fd)
                os.fsync(claim_dir_fd)
                moved = os.stat(claim_name, dir_fd=claim_dir_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(moved.st_mode)
                    or moved.st_nlink != 1
                    or moved.st_uid != os.getuid()
                    or moved.st_mode & 0o077
                    or not _same_inode(info, moved)
                ):
                    _fail()
                claimed_fd = self._open_regular_at(claim_dir_fd, claim_name)
                claimed_data, claimed_info = self._read_fd(claimed_fd)
                if (
                    not _same_inode(info, claimed_info)
                    or claimed_data != data
                    or hashlib.sha256(claimed_data).hexdigest() != expected_sha256
                ):
                    _fail()
                current_claim = os.stat(claim_name, dir_fd=claim_dir_fd, follow_symlinks=False)
                if not _same_entry(claimed_info, current_claim):
                    _fail()
                os.unlink(claim_name, dir_fd=claim_dir_fd)
                claim_name = None
                self._snapshots.pop(relative, None)
                os.fsync(claim_dir_fd)
                os.fsync(parent_fd)
                return data
            except RunnerError:
                if claim_name is not None and claim_dir_fd >= 0 and parent_fd >= 0:
                    self._restore_claim(claim_dir_fd, claim_name, parent_fd, name)
                raise
            except OSError:
                if claim_name is not None and claim_dir_fd >= 0 and parent_fd >= 0:
                    self._restore_claim(claim_dir_fd, claim_name, parent_fd, name)
                _fail()
            finally:
                if claimed_fd >= 0:
                    os.close(claimed_fd)
                if fd >= 0:
                    os.close(fd)
                if parent_fd >= 0:
                    os.close(parent_fd)
                if claim_dir_fd >= 0:
                    os.close(claim_dir_fd)

    def _mkdir_chain(self, components: tuple[str, ...]) -> int:
        current = os.dup(self._root_fd)
        try:
            for component in components:
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, _DIR_FLAGS, dir_fd=current)
                info = os.fstat(child)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                ):
                    os.close(child)
                    _fail()
                os.close(current)
                current = child
            return current
        except RunnerError:
            os.close(current)
            raise
        except OSError:
            os.close(current)
            _fail()

    def ensure_report_available(self, reports: str, request_id: str) -> None:
        """Validate the destination before consuming a request or admitting effects."""
        self._ensure_open()
        components = _components(reports)
        if not isinstance(request_id, str) or _IDENTIFIER.fullmatch(request_id) is None:
            _fail("invalid_request")
        directory_fd = self._mkdir_chain(components)
        try:
            try:
                os.stat(request_id + ".json", dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            _fail()
        except RunnerError:
            raise
        except OSError:
            _fail()
        finally:
            os.close(directory_fd)

    def write_report(self, reports: str, request_id: str, report: dict[str, Any]) -> tuple[str, str]:
        self._ensure_open()
        report_components = _components(reports)
        if not isinstance(request_id, str) or _IDENTIFIER.fullmatch(request_id) is None:
            _fail("invalid_request")
        if not isinstance(report, dict):
            _fail("invalid_request")
        content = canonical_json(report)
        if len(content) > _FILE_LIMIT:
            _fail("resource_limit")
        directory_fd = -1
        fd = -1
        name = request_id + ".json"
        temporary: str | None = ".report-" + secrets.token_hex(16)
        try:
            directory_fd = self._mkdir_chain(report_components)
            fd = os.open(temporary, _CREATE_FLAGS, 0o600, dir_fd=directory_fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                _fail()
            os.fchmod(fd, 0o600)
            _write_all(fd, content)
            os.fsync(fd)
            final = os.fstat(fd)
            staged = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(final.st_mode)
                or final.st_nlink != 1
                or final.st_uid != os.getuid()
                or stat.S_IMODE(final.st_mode) != 0o600
                or final.st_size != len(content)
                or not _same_entry(final, staged)
            ):
                _fail()
            _rename_noreplace(directory_fd, temporary, directory_fd, name)
            temporary = None
            published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not _same_entry(os.fstat(fd), published):
                _fail()
            os.fsync(directory_fd)
            relative = "/".join((*report_components, name))
            return relative, hashlib.sha256(content).hexdigest()
        except RunnerError:
            raise
        except OSError:
            _fail()
        finally:
            if fd >= 0:
                os.close(fd)
            if directory_fd >= 0:
                if temporary is not None:
                    try:
                        os.unlink(temporary, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                os.close(directory_fd)
