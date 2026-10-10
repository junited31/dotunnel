"""Fixed runner authority and independently managed receipt lifecycle.

Root invocation is restricted to reviewed disposable-runner workflows. Importing
this module performs no privileged operation; filesystem fixtures exercise the
same descriptor/identity checks without claiming root or kernel acceptance.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from types import ModuleType
from pathlib import Path
from collections.abc import Iterator
from typing import Any

_ROOT_UID = 0
_MAX_RECORD_BYTES = 64 * 1024
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_policy_module: ModuleType | None = None


def _policy():
    global _policy_module
    if _policy_module is None:
        _policy_module = load_root_sibling("runner_policy")
    return _policy_module


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))


def _file_identity(value):
    return (*_identity(value), value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory(fd: int, *, private: bool = True):
    value = os.fstat(fd)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != _ROOT_UID:
        raise ValueError("authority-directory-owner-or-type")
    if (private and stat.S_IMODE(value.st_mode) != 0o700) or (not private and value.st_mode & 0o022):
        raise ValueError("authority-directory-mode")
    return value


def _regular(value, *, source: bool = False):
    permitted = {0o400, 0o444} if source else {0o600}
    maximum = 1024 * 1024 if source else _MAX_RECORD_BYTES
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != _ROOT_UID
            or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) not in permitted
            or not 0 <= value.st_size <= maximum):
        raise ValueError("authority-record-owner-type-mode-or-size")


def _read_at(directory: int, name: str, *, source: bool = False):
    try:
        fd = os.open(name, os.O_RDONLY | _FILE, dir_fd=directory)
        try:
            before = os.fstat(fd)
            _regular(before, source=source)
            chunks = bytearray()
            maximum = 1024 * 1024 if source else _MAX_RECORD_BYTES
            while True:
                block = os.read(fd, min(4096, maximum + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
                if len(chunks) > maximum:
                    raise ValueError("authority-record-size")
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if _file_identity(before) != _file_identity(os.fstat(fd)) or _file_identity(before) != _file_identity(named):
                raise ValueError("authority-record-changed")
            return bytes(chunks), _file_identity(before)
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError("authority-record-unavailable") from error


def _json(raw: bytes):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("authority-duplicate-field")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("authority-nonfinite-number")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("authority-invalid-json") from error


def _encode(value) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError("authority-invalid-value") from error
    if len(raw) > _MAX_RECORD_BYTES:
        raise ValueError("authority-record-size")
    return raw


def _source(value):
    if (type(value) is not dict or set(value) != {"commit", "closure_sha256"}
            or type(value["commit"]) is not str or re.fullmatch(r"[0-9a-f]{40}", value["commit"]) is None
            or type(value["closure_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", value["closure_sha256"]) is None):
        raise ValueError("authority-invalid-source")
    return dict(value)


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is None:
        raise ValueError("boot-identity-unavailable")
    return value


def _pid_birth(pid: int) -> int:
    if type(pid) is not int or pid <= 0:
        raise ValueError("invalid-process-identity")
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    fields = raw[raw.rfind(b")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("process-identity-unavailable")
    return int(fields[19])


class AuthorityStore:
    """Owned generation, immutable identity, journaled intent/effect/commit.

    No root side-effect is hidden inside an intent or receipt write. The caller
    must observe the exact external resource before committing it, and resolve
    every uncertain intent before claiming complete cleanup.
    """
    def __init__(self, parent, directory, lock, names, context, source):
        self.parent_fd = parent
        self.directory_fd = directory
        self.lock_fd = lock
        self.names = names
        self.context = context
        self.source = source
        self._closed = False
        self._local_lock = threading.Lock()
        self._parent_identity = _identity(_directory(parent, private=False))
        self._directory_identity = _identity(_directory(directory))
        self._lock_identity = _file_identity(os.fstat(lock))
        _regular(os.fstat(lock))
        if os.fstat(lock).st_size:
            raise ValueError("authority-lock-content")
        raw, self._authority_identity = _read_at(directory, "authority.json")
        self._authority_digest = hashlib.sha256(raw).digest()
        authority = _json(raw)
        if (type(authority) is not dict or set(authority) != {"schema", "context", "source", "boot_id", "nonce"}
                or type(authority["schema"]) is not int or authority["schema"] != 1
                or authority["context"] != context or authority["source"] != source
                or authority["boot_id"] != _boot_id() or type(authority["nonce"]) is not str
                or re.fullmatch(r"[0-9a-f]{32}", authority["nonce"]) is None):
            raise ValueError("authority-binding-mismatch")
        _policy().validate_context(authority["context"])
        self.nonce = authority["nonce"]
        with self._locked():
            self._load()

    @classmethod
    def create(cls, parent_fd: int, context: dict[str, Any], source: dict[str, str]):
        names = _policy().validate_context(context)
        source = _source(source)
        context = _json(_encode(context))
        _directory(parent_fd, private=False)
        parent = os.dup(parent_fd)
        directory = lock = None
        try:
            os.mkdir(names.prefix, mode=0o700, dir_fd=parent)
            directory = os.open(names.prefix, _DIRECTORY, dir_fd=parent)
            os.fchmod(directory, 0o700)
            lock = os.open("authority.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | _FILE, 0o600, dir_fd=directory)
            os.fchmod(lock, 0o600)
            os.fsync(lock)
            nonce = secrets.token_hex(16)
            cls._new(directory, "authority.json", {
                "schema": 1, "context": context, "source": source,
                "boot_id": _boot_id(), "nonce": nonce,
            })
            cls._new(directory, "journal.json", {
                "schema": 1, "nonce": nonce, "phase": "OPEN", "effects": [],
                "cleanup_owner": None, "terminal": None, "credential": None,
                "runtime_state": None, "snapshots": {"readiness": None, "terminal": None},
            })
            os.fsync(directory)
            os.fsync(parent)
            return cls(parent, directory, lock, names, context, source)
        except BaseException:
            for fd in (lock, directory, parent):
                if fd is not None:
                    os.close(fd)
            # A partially created owned generation is recovery evidence, not
            # permission to remove a colliding/replaced path or replay effects.
            raise

    @classmethod
    def open(cls, parent_fd: int, context: dict[str, Any], source: dict[str, str]):
        names = _policy().validate_context(context)
        source = _source(source)
        context = _json(_encode(context))
        parent = os.dup(parent_fd)
        directory = lock = None
        try:
            directory = os.open(names.prefix, _DIRECTORY, dir_fd=parent)
            lock = os.open("authority.lock", os.O_RDWR | _FILE, dir_fd=directory)
            return cls(parent, directory, lock, names, context, source)
        except (OSError, ValueError):
            for fd in (lock, directory, parent):
                if fd is not None:
                    os.close(fd)
            raise ValueError("authority-open-refused") from None

    @staticmethod
    def _new(directory: int, name: str, value):
        raw = _encode(value)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE, 0o600, dir_fd=directory)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise ValueError("authority-short-write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self):
        if not self._closed:
            self._closed = True
            for fd in (self.lock_fd, self.directory_fd, self.parent_fd):
                os.close(fd)

    def _check(self):
        if self._closed:
            raise ValueError("authority-closed")
        try:
            named = os.stat(self.names.prefix, dir_fd=self.parent_fd, follow_symlinks=False)
            lock = os.stat("authority.lock", dir_fd=self.directory_fd, follow_symlinks=False)
            if (_identity(_directory(self.parent_fd, private=False)) != self._parent_identity
                    or _identity(_directory(self.directory_fd)) != self._directory_identity
                    or _identity(named) != self._directory_identity
                    or _file_identity(os.fstat(self.lock_fd)) != self._lock_identity
                    or _file_identity(lock) != self._lock_identity):
                raise ValueError("authority-generation-changed")
            raw, identity = _read_at(self.directory_fd, "authority.json")
            if identity != self._authority_identity or hashlib.sha256(raw).digest() != self._authority_digest:
                raise ValueError("authority-record-changed")
        except OSError as error:
            raise ValueError("authority-generation-unavailable") from error

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        deadline = time.monotonic() + 0.5
        if not self._local_lock.acquire(timeout=0.5):
            raise ValueError("authority-busy")
        try:
            self._check()
            while True:
                try:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise ValueError("authority-busy") from error
                    time.sleep(0.002)
                except OSError as error:
                    raise ValueError("authority-lock-unavailable") from error
            try:
                self._check()
                yield
            finally:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        finally:
            self._local_lock.release()

    def _load(self):
        value = _json(_read_at(self.directory_fd, "journal.json")[0])
        if (type(value) is not dict or set(value) != {"schema", "nonce", "phase", "effects", "cleanup_owner", "terminal", "credential", "runtime_state", "snapshots"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["nonce"] != self.nonce
                or type(value["phase"]) is not str or value["phase"] not in {"OPEN", "RECOVERING", "CLEANUP_TERMINAL"}
                or type(value["effects"]) is not list or len(value["effects"]) > 32):
            raise ValueError("authority-journal-invalid")
        seen = set()
        for row in value["effects"]:
            if (type(row) is not dict or set(row) != {"id", "role", "desired", "observed"}
                    or type(row["id"]) is not str or re.fullmatch(r"[0-9a-f]{32}", row["id"]) is None
                    or row["id"] in seen):
                raise ValueError("authority-effect-invalid")
            seen.add(row["id"])
            self._desired(row["role"], row["desired"])
            if row["observed"] is not None:
                self._observed(row, row["observed"])
        owner = value["cleanup_owner"]
        if owner is not None and (type(owner) is not dict or set(owner) != {"pid", "birth"}
                                  or any(type(owner[k]) is not int or owner[k] <= 0 for k in owner)):
            raise ValueError("authority-cleanup-owner-invalid")
        if value["phase"] == "CLEANUP_TERMINAL":
            self._receipt(value["terminal"])
        elif value["terminal"] is not None:
            raise ValueError("authority-premature-terminal")
        if value["runtime_state"] is not None and type(value["runtime_state"]) is not dict:
            raise ValueError("authority-runtime-state-invalid")
        self._fingerprint(value["credential"])
        if type(value["snapshots"]) is not dict or set(value["snapshots"]) != {"readiness", "terminal"}:
            raise ValueError("authority-snapshots-invalid")
        for fingerprint in value["snapshots"].values():
            self._fingerprint(fingerprint)
        return value

    def _save(self, value):
        self._check()
        # Exclusive temporary names are never deleted/replaced after a failed
        # write. Interrupted next-record evidence blocks further mutations.
        self._new(self.directory_fd, "journal.next", value)
        self._check()
        os.replace("journal.next", "journal.json", src_dir_fd=self.directory_fd, dst_dir_fd=self.directory_fd)
        os.fsync(self.directory_fd)
        self._check()

    def _desired(self, role, desired):
        if type(desired) is not dict or set(desired) != {"unit"} or desired["unit"] != self.names.unit(role):
            raise ValueError("authority-effect-target-mismatch")

    def _observed(self, row, observed):
        if type(observed) is not dict or observed.get("unit") != row["desired"]["unit"]:
            raise ValueError("authority-effect-observation-mismatch")
        if set(observed) == {"unit", "invocation_id", "absence"}:
            if observed["invocation_id"] is not None:
                raise ValueError("authority-effect-observation-mismatch")
            AuthorityStore._absence(row, observed["absence"])
            return
        if set(observed) == {"unit", "invocation_id", "never_started"}:
            idle = observed["never_started"]
            fields = {
                "load_state", "active_state", "sub_state", "main_pid", "control_pid",
                "fragment_path", "definition_sha256", "device", "inode", "nonce",
                "control_group", "cgroup_absent",
            }
            if (row["role"] not in {
                    "recovery", "recovery-probe", "reaper", "harmless",
                    "publisher-readiness", "publisher-terminal",
                }
                    or observed["invocation_id"] is not None
                    or type(idle) is not dict or set(idle) != fields
                    or idle["load_state"] != "loaded" or idle["active_state"] != "inactive"
                    or idle["sub_state"] != "dead"
                    or type(idle["main_pid"]) is not int or idle["main_pid"] != 0
                    or type(idle["control_pid"]) is not int or idle["control_pid"] != 0
                    or idle["fragment_path"] != "/run/systemd/system/" + row["desired"]["unit"]
                    or type(idle["definition_sha256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", idle["definition_sha256"]) is None
                    or type(idle["device"]) is not int or idle["device"] < 0
                    or type(idle["inode"]) is not int or idle["inode"] <= 0
                    or idle["nonce"] != self.nonce
                    or idle["control_group"] != "" or idle["cgroup_absent"] is not True):
                raise ValueError("authority-effect-observation-mismatch")
            return
        if (set(observed) != {"unit", "invocation_id"}
                or type(observed["invocation_id"]) is not str
                or re.fullmatch(r"[0-9a-f]{32}", observed["invocation_id"]) is None):
            raise ValueError("authority-effect-observation-mismatch")

    def intent(self, role: str, desired: dict[str, str]) -> str:
        self._desired(role, desired)
        with self._locked():
            value = self._load()
            allowed = value["phase"] == "OPEN" and role != "publisher-terminal"
            if role == "publisher-terminal":
                allowed = (
                    value["phase"] == "RECOVERING"
                    and self._can_commit(value)
                    and value["snapshots"]["terminal"] is not None
                )
                if allowed:
                    self._matched_record("terminal.json", value["snapshots"]["terminal"])
            if not allowed or len(value["effects"]) >= 32 or any(row["role"] == role for row in value["effects"]):
                raise ValueError("authority-effect-replay-or-closed")
            identifier = secrets.token_hex(16)
            value["effects"].append({"id": identifier, "role": role, "desired": dict(desired), "observed": None})
            self._save(value)
            return identifier

    def commit(self, identifier: str, observed: dict[str, Any]):
        with self._locked():
            value = self._load()
            row = next((row for row in value["effects"] if row["id"] == identifier), None)
            if row is None or row["observed"] is not None or not self._can_commit(value):
                raise ValueError("authority-effect-commit-refused")
            self._observed(row, observed)
            row["observed"] = dict(observed)
            self._save(value)

    def uncommitted_effects(self):
        with self._locked():
            return tuple(row for row in self._load()["effects"] if row["observed"] is None)

    def begin_cleanup(self) -> bool:
        with self._locked():
            value = self._load()
            if value["phase"] == "CLEANUP_TERMINAL":
                return False
            owner = value["cleanup_owner"]
            if owner is not None:
                try:
                    if _pid_birth(owner["pid"]) == owner["birth"]:
                        return False
                except (FileNotFoundError, ProcessLookupError):
                    pass
            value["phase"] = "RECOVERING"
            value["cleanup_owner"] = {"pid": os.getpid(), "birth": _pid_birth(os.getpid())}
            self._save(value)
            return True

    @staticmethod
    def _receipt(value):
        if (type(value) is not dict or set(value) != {"scenario_result", "cleanup_state", "original_cause", "work_populated", "container_record_state"}
                or type(value["scenario_result"]) is not str or value["scenario_result"] not in {"PASS", "FAIL", "NOT_VERIFIED"}
                or type(value["cleanup_state"]) is not str or value["cleanup_state"] not in {"COMPLETE", "UNKNOWN"}
                or value["original_cause"] is not None and (type(value["original_cause"]) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", value["original_cause"]) is None)
                or type(value["work_populated"]) is not bool
                or type(value["container_record_state"]) is not str or value["container_record_state"] not in {"NOT_CREATED", "ABSENT", "UNKNOWN"}):
            raise ValueError("authority-terminal-invalid")
        if value["scenario_result"] == "PASS" and (value["cleanup_state"] != "COMPLETE" or value["original_cause"] is not None):
            raise ValueError("authority-false-pass")
        if value["cleanup_state"] == "COMPLETE" and (value["work_populated"] or value["container_record_state"] == "UNKNOWN"):
            raise ValueError("authority-false-complete")

    def finish_cleanup(self, receipt: dict[str, Any]):
        self._receipt(receipt)
        with self._locked():
            value = self._load()
            owner = {"pid": os.getpid(), "birth": _pid_birth(os.getpid())}
            if value["phase"] != "RECOVERING" or value["cleanup_owner"] != owner:
                raise ValueError("authority-cleanup-not-owned")
            if receipt["cleanup_state"] == "COMPLETE" and any(row["observed"] is None for row in value["effects"]):
                raise ValueError("authority-unresolved-effects")
            value["terminal"] = _json(_encode(receipt))
            value["phase"] = "CLEANUP_TERMINAL"
            self._save(value)

    def terminal_receipt(self):
        with self._locked():
            return self._load()["terminal"]

    @staticmethod
    def _fingerprint(value):
        if value is not None and (
                type(value) is not dict or set(value) != {"identity", "sha256"}
                or type(value["identity"]) is not list or len(value["identity"]) != 9
                or any(type(item) is not int or item < 0 for item in value["identity"])
                or type(value["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None):
            raise ValueError("authority-file-fingerprint-invalid")

    @staticmethod
    def _absence(row, value):
        if (type(value) is not dict or set(value) != {"unit", "load_state", "active_state", "main_pid", "control_pid"}
                or value["unit"] != row["desired"]["unit"] or value["load_state"] != "not-found"
                or value["active_state"] != "inactive"
                or type(value["main_pid"]) is not int or value["main_pid"] != 0
                or type(value["control_pid"]) is not int or value["control_pid"] != 0):
            raise ValueError("authority-absence-not-observed")

    @staticmethod
    def _can_commit(value):
        return value["phase"] == "OPEN" or (
            value["phase"] == "RECOVERING"
            and value["cleanup_owner"] == {"pid": os.getpid(), "birth": _pid_birth(os.getpid())}
        )

    def commit_absence(self, identifier: str, observation: dict[str, Any]):
        """Record explicit fresh absence supplied by the trusted kernel observer."""
        with self._locked():
            value = self._load()
            row = next((row for row in value["effects"] if row["id"] == identifier), None)
            if row is None or row["observed"] is not None or not self._can_commit(value):
                raise ValueError("authority-absence-commit-refused")
            self._absence(row, observation)
            row["observed"] = {"unit": row["desired"]["unit"], "invocation_id": None, "absence": dict(observation)}
            self._save(value)

    def effects(self):
        with self._locked():
            return tuple(self._load()["effects"])

    def read_runtime_state(self):
        with self._locked():
            return self._load()["runtime_state"]

    def save_runtime_state(self, state: dict[str, Any], *, initial: bool = False):
        if type(state) is not dict or type(initial) is not bool:
            raise ValueError("authority-runtime-state-invalid")
        copied = _json(_encode(state))
        with self._locked():
            value = self._load()
            if initial != (value["runtime_state"] is None):
                raise ValueError("authority-runtime-state-initialization")
            value["runtime_state"] = copied
            self._save(value)

    def update_runtime_state(self, transform):
        """Atomically preserve concurrent cancellation/publication transitions.

        The trusted transform receives a detached JSON dict and must not call
        another store method or perform external effects while holding the lock.
        """
        with self._locked():
            value = self._load()
            if value["runtime_state"] is None:
                raise ValueError("authority-runtime-state-uninitialized")
            state = transform(value["runtime_state"])
            if type(state) is not dict:
                raise ValueError("authority-runtime-state-invalid")
            value["runtime_state"] = _json(_encode(state))
            self._save(value)

    @staticmethod
    def _credentials(value):
        if (type(value) is not dict
                or set(value) != {"ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL", "ACTIONS_RUNTIME_URL"}
                or any(type(item) is not str or not item or len(item) > 8192
                       or not item.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in item)
                       for item in value.values())):
            raise ValueError("authority-runtime-credentials-invalid")
        return value

    def write_credentials(self, runtime: dict[str, str]):
        self._credentials(runtime)
        with self._locked():
            value = self._load()
            if value["credential"] is not None:
                raise ValueError("authority-credentials-already-created")
            self._new(self.directory_fd, "runtime.json", runtime)
            raw, identity = _read_at(self.directory_fd, "runtime.json")
            value["credential"] = {"identity": list(identity), "sha256": hashlib.sha256(raw).hexdigest()}
            self._save(value)

    def _matched_record(self, name: str, fingerprint):
        if fingerprint is None:
            raise ValueError("authority-record-not-committed")
        raw, identity = _read_at(self.directory_fd, name)
        if list(identity) != fingerprint["identity"] or hashlib.sha256(raw).hexdigest() != fingerprint["sha256"]:
            raise ValueError("authority-record-generation-mismatch")
        return raw, identity

    def read_credentials(self):
        with self._locked():
            value = self._load()
            return self._credentials(_json(self._matched_record("runtime.json", value["credential"])[0]))

    def remove_credentials(self):
        with self._locked():
            value = self._load()
            _, identity = self._matched_record("runtime.json", value["credential"])
            self._check()
            if _file_identity(os.stat("runtime.json", dir_fd=self.directory_fd, follow_symlinks=False)) != identity:
                raise ValueError("authority-credential-generation-mismatch")
            os.unlink("runtime.json", dir_fd=self.directory_fd)
            os.fsync(self.directory_fd)
            value["credential"] = None
            self._save(value)

    @staticmethod
    def _snapshot_name(kind: str):
        if type(kind) is not str or kind not in {"readiness", "terminal"}:
            raise ValueError("authority-snapshot-kind")
        return kind + ".json"

    def write_snapshot(self, kind: str, snapshot: dict[str, Any]):
        name = self._snapshot_name(kind)
        if type(snapshot) is not dict:
            raise ValueError("authority-snapshot-invalid")
        with self._locked():
            value = self._load()
            if value["snapshots"][kind] is not None:
                raise ValueError("authority-snapshot-already-frozen")
            self._new(self.directory_fd, name, snapshot)
            raw, identity = _read_at(self.directory_fd, name)
            value["snapshots"][kind] = {"identity": list(identity), "sha256": hashlib.sha256(raw).hexdigest()}
            self._save(value)

    def read_snapshot(self, kind: str):
        name = self._snapshot_name(kind)
        with self._locked():
            value = self._load()
            return _json(self._matched_record(name, value["snapshots"][kind])[0])


class AdmissionPipe:
    """One root-retained writer and a single transferable read capability.

    Birth/fd checks are necessary, not sufficient, GO authority. The root broker
    must also validate its registered unit, client executable and container.
    Admission closure and the three-byte write share one lock; no caller ever
    receives or duplicates a writer.
    """
    def __init__(self, *, deadline_ns: int):
        if type(deadline_ns) is not int or deadline_ns <= time.monotonic_ns():
            raise ValueError("admission-deadline-expired")
        self._lock = threading.Lock()
        self._reader, self._writer = os.pipe2(os.O_CLOEXEC)
        value = os.fstat(self._reader)
        self._identity = (value.st_dev, value.st_ino)
        self._deadline_ns = deadline_ns
        self._sent = False
        self._closed = False

    def take_reader(self) -> int:
        with self._lock:
            if self._reader is None or self._closed:
                raise ValueError("admission-reader-unavailable")
            reader = self._reader
            self._reader = None
            return reader

    def admit_go(self, pid: int, birth: int):
        with self._lock:
            if self._closed or self._sent or time.monotonic_ns() >= self._deadline_ns:
                raise ValueError("admission-closed-or-used")
            if type(birth) is not int or birth <= 0:
                raise ValueError("admission-client-birth")
            try:
                if _pid_birth(pid) != birth:
                    raise ValueError("admission-client-birth")
                reader = os.stat(f"/proc/{pid}/fd/0")
                flags = Path(f"/proc/{pid}/fdinfo/0").read_text(encoding="ascii")
                access = next(line.split(":", 1)[1].strip() for line in flags.splitlines() if line.startswith("flags:"))
                if (not stat.S_ISFIFO(reader.st_mode) or (reader.st_dev, reader.st_ino) != self._identity
                        or int(access, 8) & os.O_ACCMODE != os.O_RDONLY or _pid_birth(pid) != birth):
                    raise ValueError("admission-client-reader-mismatch")
            except (OSError, StopIteration) as error:
                raise ValueError("admission-client-unavailable") from error
            if os.write(self._writer, b"GO\n") != 3:
                self._close_locked()
                raise ValueError("admission-short-write")
            self._sent = True

    def _close_locked(self):
        if not self._closed:
            self._closed = True
            for fd in (self._reader, self._writer):
                if fd is not None:
                    os.close(fd)
            self._reader = self._writer = None

    def close(self):
        with self._lock:
            self._close_locked()


def load_root_sibling(name: str) -> ModuleType:
    """Load a fixed sealed sibling, never checkout code or a caller module path."""
    if name not in {"runner_policy", "runner_artifact", "runner_runtime"}:
        raise ValueError("root-module-not-allowlisted")
    if __package__:
        return importlib.import_module(__package__ + "." + name)
    if os.geteuid() != 0:
        raise ValueError("trusted-root-required")
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    directory = os.open(str(Path(__file__).parent), _DIRECTORY)
    try:
        _directory(directory, private=False)
        raw, _ = _read_at(directory, name + ".py", source=True)
    finally:
        os.close(directory)
    module = ModuleType(name)
    module.__file__ = str(Path(__file__).parent / (name + ".py"))
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def _main() -> int:
    if os.geteuid() != 0:
        print('{"status":"BLOCKED","reason":"trusted-root-required"}')
        return 2
    operations = {"receipt-start", "reap", "recover", "publish-readiness", "publish-terminal"}
    if (len(sys.argv) != 4 or sys.argv[1] not in operations
            or any(re.fullmatch(r"[1-9][0-9]{0,19}", value) is None for value in sys.argv[2:])):
        print('{"status":"BLOCKED","reason":"fixed-root-invocation-required"}')
        return 2
    run, attempt = sys.argv[2:]
    expected = f"/run/dotunnelpilot{run}a{attempt}-source"
    try:
        if str(Path(__file__).parent) != expected:
            raise ValueError("root-source-path-mismatch")
        directory = os.open(expected, _DIRECTORY)
        try:
            value = _directory(directory, private=False)
            if stat.S_IMODE(value.st_mode) != 0o500:
                raise ValueError("root-source-directory-unsealed")
            _read_at(directory, "runner_prepare.py", source=True)
        finally:
            os.close(directory)
        sys.modules["runner_prepare"] = sys.modules[__name__]
        load_root_sibling("runner_policy")
        load_root_sibling("runner_artifact")
        runtime = load_root_sibling("runner_runtime")
        return runtime.main(sys.argv[1], run, attempt)
    except (OSError, ValueError, ImportError):
        print('{"status":"BLOCKED","reason":"sealed-root-source-unavailable"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
