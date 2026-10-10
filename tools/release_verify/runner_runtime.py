"""Fixed, independently fenced Task2 receipt runtime for a disposable runner.

The only root entrypoints are receipt-start, reap, recover,
publish-readiness, and publish-terminal. All persistent identity comes from
RunNames and a root-promoted immutable source manifest; no operation accepts a
filesystem path, executable, limit, or arbitrary system command from its caller.
"""
from __future__ import annotations

import ctypes
import errno
import base64
import contextlib
import copy
import hashlib
import http.client
import json
import ipaddress
import os
import platform
import pwd
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

if __package__:
    from . import runner_artifact, runner_policy, runner_prepare
else:  # root loader installs only the verified sibling modules in sys.modules
    import runner_artifact  # type: ignore[no-redef]
    import runner_policy  # type: ignore[no-redef]
    import runner_prepare  # type: ignore[no-redef]


_ROOT = "/"
_RUN_DIR = "/run"
_SYSTEMD_DIR = "/run/systemd/system"
_CGROUP_DIR = "/sys/fs/cgroup"
_SYSTEMCTL = "/usr/bin/systemctl"
_PYTHON = "/usr/bin/python3"
_NODE_SET_PRIV = "/usr/bin/setpriv"
_OPENSSL = "/usr/bin/openssl"
_UPLOAD_ACTION_COMMIT = "ea165f8d65b6e75b540449e92b4886f43607fa02"
_REQUIRED_SOURCE_FILES = frozenset({
    "runner_prepare.py", "runner_policy.py", "runner_runtime.py",
    "runner_artifact.py", "runner_dispatch.mjs", "upload-index.js",
})
_OPTIONAL_SOURCE_FILES = frozenset({"upload-action.yml", "package-lock.json"})
_REQUIRED_CHECKS = frozenset({"Secret scan", "Python 3.11", "Python 3.13"})
_CHECKS_APP_ID = 15368
_MAX_HANDOFF = 16 * 1024
_MAX_METADATA = 64 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_RECORD = 64 * 1024
_MAX_FDS = 256
_MAX_CMD_BYTES = 64 * 1024
_MAX_CTRL_REQUEST = 4 * 1024
_MAX_CTRL_REPLY = 64 * 1024
_HARMLESS_CODE = "import os,time;\nif os.read(0,3)!=b'GO\\n': raise SystemExit(71)\ntime.sleep(20)"
_NS = 1_000_000_000

_STATE_FIELDS = frozenset({
    "schema", "boot_id", "nonce", "context", "source", "source_directory", "scenario",
    "outer_deadline_ns", "dispatcher", "phase", "timestamps", "deadlines",
    "definitions", "units", "child", "cancel_notice", "original_cause",
    "publication", "readiness_sha256", "terminal_sha256", "control_directory",
    "publisher_directory", "prepared_terminal",
})
_IDENTITY_FIELDS = frozenset({
    "pid", "birth", "uid", "gid", "exe_path", "exe_device", "exe_inode",
    "exe_uid", "exe_gid", "exe_mode", "cgroup", "cap_eff", "cap_prm",
    "cap_bnd", "cap_amb", "no_new_privs", "held_fds",
})
_UNIT_FIELDS = frozenset({
    "unit", "role", "invocation_id", "fragment_path", "definition_sha256",
    "control_group", "slice", "main_pid", "control_pid", "manager",
    "cgroup", "process",
})
_MANAGER_FIELDS = frozenset({
    "load_state", "active_state", "sub_state", "result", "user", "group",
    "memory_max", "memory_swap_max", "cpu_quota_usec", "tasks_max",
    "runtime_max_usec", "kill_mode", "timeout_stop_usec", "restart",
    "oom_policy", "standard_output", "standard_error",
    "log_rate_interval_usec", "log_rate_burst", "private_network",
    "invocation_id", "fragment_path", "control_group", "slice", "main_pid",
    "control_pid", "exec_main_status", "exec_main_start_usec",
    "exec_main_exit_usec", "active_enter_usec", "drop_in_paths",
})
_PUBLICATION_FIELDS = frozenset({
    "state", "exit_code", "artifact_id", "digest", "url", "updated_ns",
})


class RuntimeFailure(ValueError):
    """An internal refusal whose public diagnostic never contains input data."""

    def __init__(self, code: str):
        self.code = code if re.fullmatch(r"[a-z][a-z0-9-]{0,79}", code) else "runtime-refused"
        super().__init__(self.code)

    def __str__(self) -> str:
        return "runner receipt operation refused"

    def __repr__(self) -> str:
        return "RuntimeFailure()"


def _fail(code: str) -> None:
    raise RuntimeFailure(code)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-json-key")
        result[key] = value
    return result


def _constant(_value: str) -> object:
    _fail("nonfinite-json-number")


def _strict_json(raw: bytes, maximum: int) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _fail("invalid-json-size")
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except RuntimeFailure:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError):
        _fail("invalid-json")


def _canonical(value: object, maximum: int = _MAX_RECORD) -> bytes:
    try:
        raw = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        _fail("invalid-record")
    if len(raw) > maximum:
        _fail("record-too-large")
    return raw


def _ascii_text(value: object, maximum: int, *, allow_empty: bool = False) -> bool:
    return (
        type(value) is str and len(value) <= maximum and (allow_empty or bool(value))
        and value.isascii() and all(0x20 <= ord(char) <= 0x7e for char in value)
    )


def boot_id() -> str:
    try:
        fd = os.open("/proc/sys/kernel/random/boot_id", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 128)
            if os.read(fd, 1):
                _fail("boot-id-too-large")
        finally:
            os.close(fd)
    except OSError:
        _fail("boot-id-unavailable")
    value = raw.decode("ascii", "strict").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is None:
        _fail("boot-id-invalid")
    return value


def _pid_stat(pid: int) -> tuple[int, int]:
    if type(pid) is not int or pid <= 0:
        _fail("process-identity-invalid")
    try:
        fd = os.open(f"/proc/{pid}/stat", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 8192)
            if os.read(fd, 1):
                _fail("process-stat-too-large")
        finally:
            os.close(fd)
    except OSError as error:
        raise ProcessLookupError("process identity unavailable") from error
    close = raw.rfind(b")")
    if close < 0:
        _fail("process-stat-invalid")
    fields = raw[close + 2 :].split()
    if len(fields) < 20:
        _fail("process-stat-invalid")
    try:
        ppid = int(fields[1])
        birth = int(fields[19])
    except ValueError:
        _fail("process-stat-invalid")
    if ppid < 0 or birth <= 0:
        _fail("process-stat-invalid")
    return ppid, birth


def _proc_status(pid: int) -> dict[str, str]:
    try:
        fd = os.open(f"/proc/{pid}/status", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 64 * 1024)
            if os.read(fd, 1):
                _fail("process-status-too-large")
        finally:
            os.close(fd)
    except OSError as error:
        raise ProcessLookupError("process identity unavailable") from error
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        _fail("process-status-invalid")
    fields: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep and key in {
            "Uid", "Gid", "CapEff", "CapPrm", "CapBnd", "CapAmb", "NoNewPrivs",
        }:
            if key in fields:
                _fail("process-status-duplicate")
            fields[key] = value.strip()
    if not {"Uid", "Gid", "CapEff", "CapPrm", "CapBnd", "CapAmb", "NoNewPrivs"} <= set(fields):
        _fail("process-status-incomplete")
    return fields


def _process_fds(pid: int) -> tuple[tuple[int, int, int, int, int, int, str], ...]:
    directory = f"/proc/{pid}/fd"
    try:
        names = os.listdir(directory)
    except OSError as error:
        raise ProcessLookupError("process descriptors unavailable") from error
    numeric: list[int] = []
    for name in names:
        if not name.isascii() or not name.isdecimal():
            _fail("process-descriptor-name-invalid")
        numeric.append(int(name))
    if len(numeric) > _MAX_FDS:
        _fail("process-descriptor-limit")
    values: list[tuple[int, int, int, int, int, int, str]] = []
    for number in sorted(numeric):
        try:
            descriptor = os.stat(f"{directory}/{number}", follow_symlinks=True)
            target = os.readlink(f"{directory}/{number}")
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ProcessLookupError("process descriptor changed") from error
        if len(target) > 512 or "\x00" in target:
            _fail("process-descriptor-target-invalid")
        values.append((
            number, descriptor.st_dev, descriptor.st_ino, descriptor.st_uid,
            descriptor.st_gid, stat.S_IMODE(descriptor.st_mode), target,
        ))
    return tuple(values)


def _process_cgroup(pid: int) -> str:
    try:
        fd = os.open(f"/proc/{pid}/cgroup", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 8192)
            if os.read(fd, 1):
                _fail("process-cgroup-too-large")
        finally:
            os.close(fd)
        lines = raw.decode("ascii", "strict").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ProcessLookupError("process cgroup unavailable") from error
    unified = [line[3:] for line in lines if line.startswith("0::")]
    if len(unified) != 1 or not unified[0].startswith("/") or ".." in unified[0].split("/"):
        _fail("process-cgroup-not-unified")
    return unified[0]


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    birth: int
    uid: int
    gid: int
    exe_path: str
    exe_device: int
    exe_inode: int
    exe_uid: int
    exe_gid: int
    exe_mode: int
    cgroup: str
    cap_eff: str
    cap_prm: str
    cap_bnd: str
    cap_amb: str
    no_new_privs: int
    held_fds: tuple[tuple[int, int, int, int, int, int, str], ...] = field(repr=False)

    def to_record(self) -> dict[str, object]:
        return {
            "pid": self.pid, "birth": self.birth, "uid": self.uid, "gid": self.gid,
            "exe_path": self.exe_path, "exe_device": self.exe_device, "exe_inode": self.exe_inode,
            "exe_uid": self.exe_uid, "exe_gid": self.exe_gid, "exe_mode": self.exe_mode,
            "cgroup": self.cgroup, "cap_eff": self.cap_eff, "cap_prm": self.cap_prm,
            "cap_bnd": self.cap_bnd, "cap_amb": self.cap_amb,
            "no_new_privs": self.no_new_privs,
            "held_fds": [list(row) for row in self.held_fds],
        }

    def public_record(self) -> dict[str, object]:
        return {
            "pid": self.pid, "birth": self.birth, "uid": self.uid, "gid": self.gid,
            "exe_device": self.exe_device, "exe_inode": self.exe_inode,
            "exe_owner": self.exe_uid, "exe_mode": self.exe_mode,
            "cgroup": self.cgroup, "held_fd_count": len(self.held_fds),
            "held_fd_sha256": hashlib.sha256(_canonical([list(row) for row in self.held_fds])).hexdigest(),
        }

    def __repr__(self) -> str:
        return "ProcessIdentity()"

    def __str__(self) -> str:
        return "ProcessIdentity()"


def observe_process(pid: int) -> ProcessIdentity:
    """Capture a PID, start ticks, credentials, executable and held-FD identity."""
    _ppid, before = _pid_stat(pid)
    status = _proc_status(pid)
    uid_values = status["Uid"].split()
    gid_values = status["Gid"].split()
    if len(uid_values) != 4 or len(gid_values) != 4:
        _fail("process-credentials-invalid")
    try:
        uids = tuple(int(value) for value in uid_values)
        gids = tuple(int(value) for value in gid_values)
        no_new_privs = int(status["NoNewPrivs"])
    except ValueError:
        _fail("process-credentials-invalid")
    if len(set(uids)) != 1 or len(set(gids)) != 1 or no_new_privs not in {0, 1}:
        _fail("process-credentials-diverged")
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        exe = os.stat(f"/proc/{pid}/exe")
        if not stat.S_ISREG(exe.st_mode) or exe_path.endswith(" (deleted)"):
            _fail("process-executable-invalid")
        held_fds = _process_fds(pid)
        cgroup = _process_cgroup(pid)
    except OSError as error:
        raise ProcessLookupError("process identity unavailable") from error
    _ppid, after = _pid_stat(pid)
    if before != after:
        _fail("process-generation-changed")
    return ProcessIdentity(
        pid=pid, birth=before, uid=uids[0], gid=gids[0], exe_path=exe_path,
        exe_device=exe.st_dev, exe_inode=exe.st_ino, exe_uid=exe.st_uid,
        exe_gid=exe.st_gid, exe_mode=stat.S_IMODE(exe.st_mode), cgroup=cgroup,
        cap_eff=status["CapEff"], cap_prm=status["CapPrm"], cap_bnd=status["CapBnd"],
        cap_amb=status["CapAmb"], no_new_privs=no_new_privs, held_fds=held_fds,
    )


def require_same_process(expected: ProcessIdentity) -> ProcessIdentity:
    """Reobserve without ever treating a missing or reused PID as the owner."""
    if type(expected) is not ProcessIdentity:
        _fail("process-identity-invalid")
    current = observe_process(expected.pid)
    fields = (
        "pid", "birth", "uid", "gid", "exe_path", "exe_device", "exe_inode",
        "exe_uid", "exe_gid", "exe_mode", "cgroup", "cap_eff", "cap_prm",
        "cap_bnd", "cap_amb", "no_new_privs",
    )
    if any(getattr(current, name) != getattr(expected, name) for name in fields):
        _fail("process-identity-changed")
    return current


def _process_identity_live(expected: ProcessIdentity) -> bool:
    try:
        require_same_process(expected)
    except (ProcessLookupError, RuntimeFailure):
        return False
    return True




def _secure_root_binary(path: str) -> str:
    if type(path) is not str or not path.startswith("/"):
        _fail("fixed-binary-path-invalid")
    try:
        lexical = Path(path)
        value = lexical.lstat()
        resolved = str(lexical.resolve(strict=True))
        target = os.stat(resolved, follow_symlinks=False)
    except OSError:
        _fail("fixed-binary-unavailable")
    if not stat.S_ISREG(target.st_mode) or target.st_uid != 0 or target.st_mode & 0o022 or not target.st_mode & 0o111:
        _fail("fixed-binary-owner-mode")
    if value.st_uid != 0 or (not stat.S_ISLNK(value.st_mode) and value.st_mode & 0o022):
        _fail("fixed-binary-owner-mode")
    current = Path(resolved).parent
    while current != current.parent:
        try:
            info = current.lstat()
        except OSError:
            _fail("fixed-binary-ancestor")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail("fixed-binary-ancestor")
        current = current.parent
    return resolved


def _trust_dispatcher(identity: ProcessIdentity) -> None:
    if (identity.uid <= 0 or identity.gid <= 0 or identity.exe_uid != 0
            or identity.exe_mode & 0o022 or not identity.exe_mode & 0o111
            or not identity.exe_path.startswith("/")):
        _fail("dispatcher-owner-or-executable")
    try:
        resolved = str(Path(identity.exe_path).resolve(strict=True))
        info = os.stat(f"/proc/{identity.pid}/exe")
        target = os.stat(resolved, follow_symlinks=False)
    except OSError:
        _fail("dispatcher-executable-unavailable")
    if ((info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
            != (identity.exe_device, identity.exe_inode, identity.exe_uid, identity.exe_mode)
            or (target.st_dev, target.st_ino) != (identity.exe_device, identity.exe_inode)):
        _fail("dispatcher-executable-changed")
    _secure_root_binary(resolved)


@dataclass(frozen=True)
class Handoff:
    context: dict[str, object]
    dispatcher: ProcessIdentity
    scenario: str
    outer_deadline_ns: int
    runtime: dict[str, str] = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "Handoff()"

    def __str__(self) -> str:
        return "Handoff()"


def _runtime_values(value: object) -> dict[str, str]:
    fields = {"ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL", "ACTIONS_RUNTIME_URL"}
    if type(value) is not dict or set(value) != fields:
        _fail("runtime-capabilities-invalid")
    result: dict[str, str] = {}
    for name in fields:
        item = value[name]
        if not _ascii_text(item, 8192):
            _fail("runtime-capability-invalid")
        result[name] = item
    results = urlsplit(result["ACTIONS_RESULTS_URL"])
    runtime = urlsplit(result["ACTIONS_RUNTIME_URL"])
    results_host = results.hostname or ""
    labels = results_host.split(".")
    public_actions_host = (
        results_host == results_host.lower()
        and results_host.endswith(".actions.githubusercontent.com")
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    )
    if (results.scheme != "https" or not public_actions_host
            or results.port not in (None, 443) or results.username is not None or results.password is not None
            or results.query or results.fragment or results.path not in {"", "/"}
            or runtime.scheme != "https" or runtime.hostname != "pipelines.actions.githubusercontent.com"
            or runtime.port not in (None, 443) or runtime.username is not None
            or runtime.password is not None or runtime.query or runtime.fragment or runtime.path not in {"", "/"}):
        _fail("runtime-endpoint-invalid")
    if re.fullmatch(r"[A-Za-z0-9._~+/=-]{8,8192}", result["ACTIONS_RUNTIME_TOKEN"]) is None:
        _fail("runtime-token-invalid")
    return result


def parse_handoff(raw: bytes, *, now_ns: int | None = None) -> Handoff:
    """Parse the exact anonymous-pipe payload and bind its live dispatcher."""
    value = _strict_json(raw, _MAX_HANDOFF)
    fields = {"context", "dispatcher_pid", "scenario", "outer_deadline_ns", "runtime"}
    if type(value) is not dict or set(value) != fields:
        _fail("handoff-fields-invalid")
    context = value["context"]
    names = runner_policy.validate_context(context)
    if type(value["dispatcher_pid"]) is not int or value["dispatcher_pid"] <= 0:
        _fail("dispatcher-pid-invalid")
    if type(value["scenario"]) is not str or value["scenario"] not in {"normal", "workflow-cancel"}:
        _fail("scenario-invalid")
    text_deadline = value["outer_deadline_ns"]
    if type(text_deadline) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", text_deadline) is None:
        _fail("outer-deadline-invalid")
    deadline = int(text_deadline)
    now = time.monotonic_ns() if now_ns is None else now_ns
    if type(now) is not int or deadline - now < 540 * _NS or deadline - now > 600 * _NS:
        _fail("outer-deadline-window")
    try:
        identity = observe_process(value["dispatcher_pid"])
    except ProcessLookupError:
        _fail("dispatcher-identity-unavailable")
    _trust_dispatcher(identity)
    if identity.uid == 0:
        _fail("dispatcher-must-be-nonroot")
    return Handoff(
        context=copy.deepcopy(context), dispatcher=identity, scenario=value["scenario"],
        outer_deadline_ns=deadline, runtime=_runtime_values(value["runtime"]),
    )


def _read_fd(fd: int, maximum: int) -> bytes:
    value = bytearray()
    while len(value) <= maximum:
        part = os.read(fd, min(64 * 1024, maximum + 1 - len(value)))
        if not part:
            break
        value.extend(part)
    if len(value) > maximum:
        _fail("input-too-large")
    return bytes(value)


def _read_handoff_stdin() -> bytes:
    try:
        info = os.fstat(0)
        if not stat.S_ISFIFO(info.st_mode):
            _fail("handoff-not-anonymous-pipe")
        raw = _read_fd(0, _MAX_HANDOFF)
    except OSError:
        _fail("handoff-unavailable")
    return raw


def _secure_dir(path: str, *, owner: int = 0, exact_mode: int | None = None,
                forbid_write_mask: int = 0o022) -> os.stat_result:
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        _fail("directory-unavailable")
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
            or exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode
            or exact_mode is None and stat.S_IMODE(info.st_mode) & forbid_write_mask):
        _fail("directory-owner-mode")
    return info


def _secure_record_at(directory_fd: int, name: str, *, maximum: int, mode: int,
                      owner: int = 0, links: int = 1) -> tuple[bytes, os.stat_result]:
    if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name)
            or name in {".", ".."}):
        _fail("record-name-invalid")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError:
        _fail("record-unavailable")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != links
                or info.st_size < 0 or info.st_size > maximum):
            _fail("record-owner-mode-size")
        raw = _read_fd(fd, maximum)
        if len(raw) != info.st_size:
            _fail("record-size-changed")
        after = os.fstat(fd)
        if ((after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode,
             after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
            _fail("record-changed-during-read")
        return raw, info
    finally:
        os.close(fd)


def _source_directory_record(source_fd: int, source_path: str) -> dict[str, int]:
    held = os.fstat(source_fd)
    try:
        named = os.stat(source_path, follow_symlinks=False)
    except OSError:
        _fail("source-directory-replaced")
    if ((not stat.S_ISDIR(held.st_mode) or held.st_uid != 0 or held.st_gid != 0
            or stat.S_IMODE(held.st_mode) != 0o500 or held.st_nlink != 2)
            or (held.st_dev, held.st_ino, held.st_uid, held.st_gid, held.st_mode, held.st_nlink)
            != (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode, named.st_nlink)):
        _fail("source-directory-identity")
    return {
        "device": held.st_dev, "inode": held.st_ino, "uid": held.st_uid,
        "gid": held.st_gid, "mode": stat.S_IMODE(held.st_mode), "nlink": held.st_nlink,
    }


def validate_source_manifest(
    names: runner_policy.RunNames,
    *,
    expected_directory: dict[str, int] | None = None,
) -> dict[str, object]:
    """Rehash the root-promoted source closure and bind its held directory inode."""
    _secure_dir(_RUN_DIR, owner=0)
    source_fd = os.open(names.source, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        _secure_dir(names.source, owner=0, exact_mode=0o500)
        directory_identity = _source_directory_record(source_fd, names.source)
        if expected_directory is None:
            device = os.environ.get("DOTUNNEL_SOURCE_DEV", "")
            inode = os.environ.get("DOTUNNEL_SOURCE_INO", "")
            if (re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", device) is None
                    or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", inode) is None
                    or int(device) != directory_identity["device"]
                    or int(inode) != directory_identity["inode"]):
                _fail("source-handoff-identity-mismatch")
        elif directory_identity != expected_directory:
            _fail("source-generation-changed")
        raw, _manifest_info = _secure_record_at(source_fd, "manifest.json", maximum=4096, mode=0o400)
        manifest = _strict_json(raw, 4096)
        if (type(manifest) is not dict
                or set(manifest) != {"schema", "commit", "files", "upload_action_commit", "closure_sha256"}
                or type(manifest["schema"]) is not int or manifest["schema"] != 1
                or type(manifest["commit"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]) is None
                or manifest["upload_action_commit"] != _UPLOAD_ACTION_COMMIT
                or type(manifest["files"]) is not dict
                or not _REQUIRED_SOURCE_FILES <= set(manifest["files"])
                or not set(manifest["files"]) <= _REQUIRED_SOURCE_FILES | _OPTIONAL_SOURCE_FILES
                or type(manifest["closure_sha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", manifest["closure_sha256"]) is None):
            _fail("source-manifest-invalid")
        for name, digest in manifest["files"].items():
            if (type(name) is not str or type(digest) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
                _fail("source-manifest-file-invalid")
        closure = {
            "commit": manifest["commit"], "files": manifest["files"],
            "upload_action_commit": manifest["upload_action_commit"],
        }
        expected_closure = hashlib.sha256(_canonical(closure, maximum=4096)).hexdigest()
        if expected_closure != manifest["closure_sha256"]:
            _fail("source-closure-digest-mismatch")
        total = 0
        for name in sorted(manifest["files"]):
            raw_file, _info = _secure_record_at(source_fd, name, maximum=_MAX_SOURCE_BYTES, mode=0o400)
            total += len(raw_file)
            if total > _MAX_SOURCE_BYTES or hashlib.sha256(raw_file).hexdigest() != manifest["files"][name]:
                _fail("source-file-digest-mismatch")
        if _source_directory_record(source_fd, names.source) != directory_identity:
            _fail("source-directory-changed-during-read")
        return {
            "commit": manifest["commit"], "closure_sha256": manifest["closure_sha256"],
            "files": dict(manifest["files"]), "upload_action_commit": _UPLOAD_ACTION_COMMIT,
            "source_path": names.source, "source_directory": directory_identity,
        }
    finally:
        os.close(source_fd)


def _resolve_bounded(host: str, deadline_ns: int) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    done = threading.Event()
    result: list[Any] = []

    def lookup() -> None:
        try:
            result.append(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP))
        except BaseException:
            result.append(None)
        finally:
            done.set()

    threading.Thread(target=lookup, name="github-metadata-dns", daemon=True).start()
    remain = deadline_ns - time.monotonic_ns()
    if remain <= 0 or not done.wait(remain / _NS) or not result or result[0] is None:
        _fail("metadata-dns-timeout")
    endpoints: list[tuple[int, int, int, tuple[Any, ...]]] = []
    for family, kind, proto, _canon, sockaddr in result[0]:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            _fail("metadata-dns-private-address")
        if family in {socket.AF_INET, socket.AF_INET6} and (family, kind, proto, sockaddr) not in endpoints:
            endpoints.append((family, kind, proto, sockaddr))
    if not endpoints:
        _fail("metadata-dns-empty")
    return endpoints[:8]


def _https_json(path: str, deadline_ns: int) -> dict[str, object]:
    if (type(path) is not str
            or path != "/repos/junited31/dotunnel"
            and not path.startswith("/repos/junited31/dotunnel/")
            or "\r" in path or "\n" in path):
        _fail("metadata-path-invalid")
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    endpoints = _resolve_bounded("api.github.com", deadline_ns)
    last_error = False
    for family, kind, proto, sockaddr in endpoints:
        raw: socket.socket | None = None
        tls: ssl.SSLSocket | None = None
        try:
            remain = deadline_ns - time.monotonic_ns()
            if remain <= 0:
                _fail("metadata-deadline")
            raw = socket.socket(family, kind, proto)
            raw.settimeout(min(2.0, remain / _NS))
            raw.connect(sockaddr)
            remain = deadline_ns - time.monotonic_ns()
            if remain <= 0:
                _fail("metadata-deadline")
            tls = context.wrap_socket(raw, server_hostname="api.github.com")
            raw = None
            tls.settimeout(min(2.0, max(0.001, (deadline_ns - time.monotonic_ns()) / _NS)))
            request = (
                f"GET {path} HTTP/1.1\r\nHost: api.github.com\r\n"
                "User-Agent: dotunnel-runner-receipt/1\r\nAccept: application/vnd.github+json\r\n"
                "Accept-Encoding: identity\r\nX-GitHub-Api-Version: 2022-11-28\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(request)
            response = http.client.HTTPResponse(tls, method="GET")
            response.begin()
            if response.status != 200 or response.getheader("Location") is not None:
                _fail("metadata-http-refused")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > _MAX_METADATA):
                _fail("metadata-body-size")
            raw_body = bytearray()
            while len(raw_body) <= _MAX_METADATA:
                remain = deadline_ns - time.monotonic_ns()
                if remain <= 0:
                    _fail("metadata-deadline")
                tls.settimeout(min(2.0, remain / _NS))
                chunk = response.read(min(8192, _MAX_METADATA + 1 - len(raw_body)))
                if not chunk:
                    break
                raw_body.extend(chunk)
            if len(raw_body) > _MAX_METADATA or length is not None and len(raw_body) != int(length):
                _fail("metadata-body-size")
            value = _strict_json(bytes(raw_body), _MAX_METADATA)
            if type(value) is not dict:
                _fail("metadata-schema")
            return value
        except RuntimeFailure:
            raise
        except Exception:
            last_error = True
        finally:
            for item in (tls, raw):
                if item is not None:
                    try:
                        item.close()
                    except OSError:
                        pass
    _fail("metadata-https-failed" if last_error else "metadata-unavailable")


def _verify_public_github(context: dict[str, object], source: dict[str, object],
                          deadline_ns: int) -> str:
    run = context["run"]
    attempt = context["attempt"]
    helper_commit = source["commit"]
    repository = _https_json("/repos/junited31/dotunnel", deadline_ns)
    if repository.get("full_name") != "junited31/dotunnel" or repository.get("default_branch") != "main":
        _fail("github-repository-mismatch")
    ref = _https_json("/repos/junited31/dotunnel/git/ref/heads/main", deadline_ns)
    ref_object = ref.get("object")
    if (type(ref_object) is not dict or type(ref_object.get("sha")) is not str
            or re.fullmatch(r"[0-9a-f]{40}", ref_object["sha"]) is None):
        _fail("github-main-ref-invalid")
    workflow_commit = ref_object["sha"]
    branch = _https_json("/repos/junited31/dotunnel/branches/main", deadline_ns)
    branch_commit = branch.get("commit")
    if (branch.get("protected") is not True or type(branch_commit) is not dict
            or branch_commit.get("sha") != workflow_commit):
        _fail("github-main-not-protected-head")
    comparison = _https_json(
        f"/repos/junited31/dotunnel/compare/{helper_commit}...{workflow_commit}?per_page=1",
        deadline_ns,
    )
    merge_base = comparison.get("merge_base_commit")
    base_commit = comparison.get("base_commit")
    if (comparison.get("status") not in {"ahead", "identical"}
            or type(merge_base) is not dict or merge_base.get("sha") != helper_commit
            or type(base_commit) is not dict or base_commit.get("sha") != helper_commit):
        _fail("github-helper-not-on-main")
    checks = _https_json(
        f"/repos/junited31/dotunnel/commits/{helper_commit}/check-runs?per_page=100",
        deadline_ns,
    )
    check_rows = checks.get("check_runs")
    total = checks.get("total_count")
    if type(check_rows) is not list or type(total) is not int or total != len(check_rows) or total > 100:
        _fail("github-checks-incomplete")
    by_name: dict[str, list[dict[str, object]]] = {name: [] for name in _REQUIRED_CHECKS}
    for row in check_rows:
        if type(row) is dict and row.get("name") in by_name:
            by_name[row["name"]].append(row)
    for name, rows in by_name.items():
        if len(rows) != 1:
            _fail("github-required-check-ambiguous")
        row = rows[0]
        app = row.get("app")
        if (type(app) is not dict or type(app.get("id")) is not int
                or app["id"] != _CHECKS_APP_ID or row.get("status") != "completed"
                or row.get("conclusion") != "success"):
            _fail("github-required-checks-missing")
    run_info = _https_json(
        f"/repos/junited31/dotunnel/actions/runs/{run}/attempts/{attempt}", deadline_ns,
    )
    repo_info = run_info.get("head_repository")
    actor = run_info.get("actor")
    triggering_actor = run_info.get("triggering_actor")
    if (type(repo_info) is not dict or repo_info.get("full_name") != "junited31/dotunnel"
            or run_info.get("repository") is not None and (
                type(run_info.get("repository")) is not dict
                or run_info["repository"].get("full_name") != "junited31/dotunnel")
            or type(run_info.get("run_attempt")) is not int or run_info["run_attempt"] != int(attempt)
            or run_info.get("event") != "workflow_dispatch"
            or run_info.get("ref") != "refs/heads/main"
            or run_info.get("path") != ".github/workflows/release-verification.yml@refs/heads/main"
            or run_info.get("head_branch") != "main" or run_info.get("head_sha") != workflow_commit
            or run_info.get("status") != "in_progress"
            or type(actor) is not dict or actor.get("login") != "junited31"
            or type(triggering_actor) is not dict or triggering_actor.get("login") != "junited31"):
        _fail("github-run-metadata-mismatch")
    return workflow_commit


def _require_platform(deadline_ns: int) -> None:
    if (os.geteuid() != 0 or os.getuid() != 0 or platform.system() != "Linux"
            or platform.machine().lower() not in {"x86_64", "amd64"}
            or sys.version_info < (3, 11)):
        _fail("runner-platform-unsupported")
    try:
        comm = Path("/proc/1/comm").read_text(encoding="ascii").strip()
        controllers = Path(_CGROUP_DIR, "cgroup.controllers").read_text(encoding="ascii").split()
        cgroup_info = os.stat(_CGROUP_DIR, follow_symlinks=False)
    except OSError:
        _fail("runner-cgroup-unavailable")
    if comm != "systemd" or not stat.S_ISDIR(cgroup_info.st_mode) or not {"cpu", "memory", "pids"} <= set(controllers):
        _fail("runner-cgroup-unsupported")
    for path in ("/run/systemd/system", _SYSTEMD_DIR):
        _secure_dir(path, owner=0)
    status = _systemctl(["is-system-running"], deadline_ns, allow_nonzero=True)
    if status.strip() != b"running":
        _fail("systemd-not-running")


def _systemctl(args: list[str], deadline_ns: int, *, allow_nonzero: bool = False) -> bytes:
    if not args or any(type(value) is not str or "\x00" in value or "\n" in value for value in args):
        _fail("systemctl-arguments-invalid")
    _secure_root_binary(_SYSTEMCTL)
    returncode, stdout, _stderr = _bounded_command(
        [_SYSTEMCTL, *args], deadline_ns, allowed={_SYSTEMCTL}, allow_nonzero=allow_nonzero,
    )
    if returncode != 0 and not allow_nonzero:
        _fail("systemctl-command-failed")
    return stdout


def _bounded_command(argv: list[str], deadline_ns: int, *, allowed: set[str],
                     allow_nonzero: bool = False, output_limit: int = _MAX_CMD_BYTES) -> tuple[int, bytes, bytes]:
    if (not argv or argv[0] not in allowed or type(deadline_ns) is not int
            or deadline_ns <= time.monotonic_ns() or not 0 < output_limit <= _MAX_CMD_BYTES):
        _fail("fixed-command-refused")
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "SYSTEMD_PAGER": "cat",
        "SYSTEMD_COLORS": "0", "SYSTEMD_URLIFY": "0",
    }
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, close_fds=True, start_new_session=True,
        )
    except OSError:
        _fail("fixed-command-unavailable")
    assert process.stdout is not None and process.stderr is not None
    out_fd = process.stdout.fileno()
    err_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    output: dict[int, bytearray] = {out_fd: bytearray(), err_fd: bytearray()}
    streams = {out_fd: process.stdout, err_fd: process.stderr}
    overflow = False
    timed_out = False
    try:
        while selector.get_map() or process.poll() is None:
            remain = deadline_ns - time.monotonic_ns()
            if remain <= 0:
                timed_out = True
                break
            for key, _mask in selector.select(min(0.1, remain / _NS)):
                fd = key.fd
                try:
                    block = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(fd)
                    streams[fd].close()
                    continue
                output[fd].extend(block)
                if len(output[fd]) > output_limit:
                    overflow = True
                    break
            if overflow:
                break
        if timed_out or overflow:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1.0)
    finally:
        selector.close()
        for stream in streams.values():
            if not stream.closed:
                stream.close()
    if timed_out:
        _fail("fixed-command-timeout")
    if overflow:
        _fail("fixed-command-output-limit")
    result = (int(process.returncode), bytes(output[out_fd]), bytes(output[err_fd]))
    if result[0] != 0 and not allow_nonzero:
        _fail("fixed-command-failed")
    return result


def _parse_properties(raw: bytes, expected: frozenset[str]) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        _fail("systemd-properties-invalid")
    result: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or key not in expected or key in result or len(value) > 4096:
            _fail("systemd-properties-invalid")
        result[key] = value
    if set(result) != expected:
        _fail("systemd-properties-incomplete")
    return result


_UNIT_PROPERTY_NAMES = frozenset({
    "Id", "LoadState", "ActiveState", "SubState", "Result", "InvocationID",
    "FragmentPath", "DropInPaths", "ControlGroup", "Slice", "MainPID", "ControlPID",
    "User", "Group", "MemoryMax", "MemorySwapMax", "CPUQuotaPerSecUSec", "TasksMax",
    "RuntimeMaxUSec", "KillMode", "TimeoutStopUSec", "Restart", "OOMPolicy",
    "StandardOutput", "StandardError", "LogRateLimitIntervalUSec", "LogRateLimitBurst",
    "PrivateNetwork", "ExecMainStatus", "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic", "ActiveEnterTimestampMonotonic",
    "WorkingDirectory", "Environment", "NoNewPrivileges",
})


def _unit_name(names: runner_policy.RunNames, role: str) -> str:
    return names.unit(role)


def _slice_name(names: runner_policy.RunNames, role: str) -> str:
    if role == "work":
        return names.work_slice
    if role == "reaper":
        return f"dotunnelreaper{names.run}a{names.attempt}.slice"
    if role in {"recovery", "recovery-probe"}:
        prefix = "dotunnelrecovery" if role == "recovery" else "dotunnelrecoveryprobe"
        return f"{prefix}{names.run}a{names.attempt}.slice"
    if role in {"publisher-readiness", "publisher-terminal"}:
        return f"dotunnelpublisher{names.run}a{names.attempt}.slice"
    _fail("unknown-slice-role")
def _definition_unit(names: runner_policy.RunNames, role: str) -> str:
    if role in {"recovery", "recovery-probe", "reaper", "harmless", "publisher-readiness", "publisher-terminal"}:
        return _unit_name(names, role)
    if role == "work-slice":
        return _slice_name(names, "work")
    if role == "reaper-slice":
        return _slice_name(names, "reaper")
    if role == "recovery-slice":
        return _slice_name(names, "recovery")
    if role == "publisher-slice":
        return _slice_name(names, "publisher-readiness")
    _fail("unit-definition-role-invalid")


def _show_unit(name: str, deadline_ns: int) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}\.(?:service|slice)", name):
        _fail("systemd-unit-name-invalid")
    properties = ",".join(sorted(_UNIT_PROPERTY_NAMES))
    raw = _systemctl(["show", "--no-pager", f"--property={properties}", name], deadline_ns, allow_nonzero=True)
    return _parse_properties(raw, _UNIT_PROPERTY_NAMES)


def _parse_unsigned(value: str, code: str, *, allow_zero: bool = True) -> int:
    if type(value) is not str or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value) is None:
        _fail(code)
    result = int(value)
    if not allow_zero and result <= 0:
        _fail(code)
    return result


def _unit_absence(name: str, properties: dict[str, str]) -> dict[str, object]:
    if (properties["LoadState"] != "not-found" or properties["ActiveState"] != "inactive"
            or _parse_unsigned(properties["MainPID"], "unit-absence-invalid") != 0
            or _parse_unsigned(properties["ControlPID"], "unit-absence-invalid") != 0):
        _fail("unit-collision")
    return {
        "unit": name, "load_state": "not-found", "active_state": "inactive",
        "main_pid": 0, "control_pid": 0,
    }


def _unit_file_name(name: str) -> str:
    if "/" in name or ".." in name or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}\.(?:service|slice)", name):
        _fail("unit-file-name-invalid")
    return os.path.join(_SYSTEMD_DIR, name)


def _unit_directory_fd() -> int:
    _secure_dir("/run", owner=0)
    _secure_dir("/run/systemd", owner=0)
    _secure_dir(_SYSTEMD_DIR, owner=0)
    try:
        return os.open(_SYSTEMD_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        _fail("systemd-unit-directory-unavailable")


def _write_unit(name: str, content: bytes) -> dict[str, object]:
    if not content or len(content) > 16 * 1024 or not content.endswith(b"\n"):
        _fail("unit-definition-size")
    directory = _unit_directory_fd()
    try:
        try:
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o444, dir_fd=directory,
            )
        except FileExistsError:
            _fail("unit-definition-collision")
        try:
            os.fchmod(fd, 0o444)
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    _fail("unit-definition-short-write")
                view = view[written:]
            os.fsync(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                    or info.st_size != len(content)):
                _fail("unit-definition-identity")
        finally:
            os.close(fd)
        os.fsync(directory)
        return {
            "unit": name, "sha256": hashlib.sha256(content).hexdigest(),
            "device": info.st_dev, "inode": info.st_ino,
        }
    finally:
        os.close(directory)


def _read_unit_definition(name: str, expected: dict[str, object]) -> bytes:
    directory = _unit_directory_fd()
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        except OSError:
            _fail("unit-definition-unavailable")
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                    or info.st_dev != expected.get("device") or info.st_ino != expected.get("inode")):
                _fail("unit-definition-changed")
            content = _read_fd(fd, 16 * 1024)
            if (hashlib.sha256(content).hexdigest() != expected.get("sha256")
                    or len(content) != info.st_size):
                _fail("unit-definition-digest-changed")
            return content
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _slice_content(names: runner_policy.RunNames, role: str, nonce: str) -> bytes:
    budget_role = "aggregate" if role == "work" else "publisher" if role.startswith("publisher") else role
    memory, cpu, tasks, _runtime = runner_policy.BUDGETS[budget_role]
    name = _slice_name(names, role)
    rows = [
        "[Unit]", f"Description=dotunnel receipt {role} {names.run}a{names.attempt}", "",
        "[Slice]", f"MemoryMax={memory}", "MemorySwapMax=0", f"CPUQuota={cpu}%",
        f"TasksMax={tasks}", "",
    ]
    if role == "work":
        rows[1] = f"Description=dotunnel receipt work {names.run}a{names.attempt}"
    if not name.endswith(".slice") or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        _fail("slice-definition-invalid")
    return ("\n".join(rows)).encode("ascii")


def _unit_content(names: runner_policy.RunNames, role: str, nonce: str,
                  source_path: str, dispatcher: ProcessIdentity,
                  *, reader_fd: int | None = None) -> bytes:
    unit = _unit_name(names, role)
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        _fail("unit-generation-invalid")
    memory, cpu, tasks, runtime = runner_policy.BUDGETS["harmless" if role == "harmless" else (
        "publisher" if role.startswith("publisher") else role
    )]
    lines = [
        "[Unit]", f"Description=dotunnel receipt {role} {names.run}a{names.attempt}",
        "StartLimitIntervalSec=0",
    ]
    if role == "reaper":
        recovery = _unit_name(names, "recovery")
        lines.append(f"OnFailure={recovery}")
    if role == "harmless":
        slice_name = names.work_slice
    elif role in {"publisher-readiness", "publisher-terminal"}:
        slice_name = _slice_name(names, "publisher-readiness")
    else:
        slice_name = _slice_name(names, role)
    lines.extend([
        "", "[Service]", "Type=exec", f"Slice={slice_name}",
        "MemoryMax=" + str(memory), "MemorySwapMax=0", f"CPUQuota={cpu}%",
        f"TasksMax={tasks}", f"RuntimeMaxSec={runtime}s", "KillMode=control-group",
        "TimeoutStopSec=2s", "Restart=no", "OOMPolicy=kill", "UMask=0077",
        "StandardOutput=null", "StandardError=null", "LogRateLimitIntervalSec=1s",
        "LogRateLimitBurst=1", "NoNewPrivileges=yes",
        f"Environment=DOTUNNEL_GENERATION={nonce}",
        f"Environment=DOTUNNEL_RUN={names.run}", f"Environment=DOTUNNEL_ATTEMPT={names.attempt}",
        "Environment=LANG=C.UTF-8", "Environment=LC_ALL=C.UTF-8",
    ])
    if role == "reaper":
        lines.append(f"ExecStopPost={_SYSTEMCTL} --no-block start {recovery}")
    if role == "harmless":
        if type(reader_fd) is not int or reader_fd < 0:
            _fail("admission-reader-unavailable")
        reader = os.fstat(reader_fd)
        if not stat.S_ISFIFO(reader.st_mode) or os.get_inheritable(reader_fd):
            _fail("admission-reader-identity")
        code = _HARMLESS_CODE
        # systemd opens this held root read end as the child service's stdin.
        quoted = json.dumps(code, ensure_ascii=True)
        lines.extend([
            f"User={dispatcher.uid}", f"Group={dispatcher.gid}", "WorkingDirectory=/",
            f"StandardInput=file:/proc/{os.getpid()}/fd/{reader_fd}",
            "PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes",
            "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
            "RestrictSUIDSGID=yes", "RestrictAddressFamilies=AF_UNIX",
            "CapabilityBoundingSet=", "AmbientCapabilities=", "IPAddressDeny=any",
            "ExecStart=" + _secure_root_binary(_PYTHON) + " -I -S -c " + quoted,
        ])
    else:
        if role in {"reaper", "recovery", "recovery-probe", "publisher-readiness", "publisher-terminal"}:
            operation = {
                "reaper": "reap", "recovery": "recover", "recovery-probe": "recover",
                "publisher-readiness": "publish-readiness", "publisher-terminal": "publish-terminal",
            }[role]
            lines.extend([
                "User=0", "Group=0", "WorkingDirectory=/",
                f"ExecStart={_secure_root_binary(_PYTHON)} -I -S {source_path}/runner_prepare.py {operation} {names.run} {names.attempt}",
            ])
        else:
            _fail("unit-role-invalid")
        writable_paths = [names.root]
        if role in {"reaper", "recovery", "recovery-probe"}:
            writable_paths.append(names.control)
        if role in {"reaper", "recovery"}:
            writable_paths.append(_SYSTEMD_DIR)
        publisher_directory = names.root + "-publisher"
        if role in {"recovery", "recovery-probe"}:
            publisher_directory = "-" + publisher_directory
        writable_paths.append(publisher_directory)
        lines.extend([
            "PrivateNetwork=yes", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes",
            "ReadWritePaths=" + " ".join(writable_paths),
        ])
    lines.append("")
    return "\n".join(lines).encode("ascii")


def _verify_no_preexisting_units(names: runner_policy.RunNames, deadline_ns: int) -> None:
    candidates = [
        names.work_slice, _slice_name(names, "reaper"), _slice_name(names, "recovery"),
        _slice_name(names, "recovery-probe"), _slice_name(names, "publisher-readiness"),
        *(_unit_name(names, role) for role in (
            "reaper", "recovery", "recovery-probe", "harmless",
            "publisher-readiness", "publisher-terminal",
        )),
    ]
    for name in candidates:
        props = _show_unit(name, deadline_ns)
        _unit_absence(name, props)
        path = _unit_file_name(name)
        try:
            os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            _fail("unit-path-unavailable")
        else:
            _fail("unit-file-collision")
        for parent in ("/etc/systemd/system", "/usr/lib/systemd/system"):
            candidate = os.path.join(parent, name)
            try:
                os.stat(candidate, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                _fail("unit-path-unavailable")
            _fail("unit-file-collision")
        if props["DropInPaths"]:
            _fail("unit-dropin-collision")
    for directory in (names.root, names.control, names.root + "-publisher"):
        try:
            os.stat(directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _fail("run-path-unavailable")
        _fail("run-path-collision")


def _manager_duration(value: str, code: str) -> int:
    if re.fullmatch(r"[0-9]+(?:us|ms|s|min)", value) is None:
        _fail(code)
    amount_text = re.match(r"[0-9]+", value)
    assert amount_text is not None
    amount = int(amount_text.group(0))
    unit = value[len(amount_text.group(0)) :]
    return amount * {"us": 1, "ms": 1000, "s": 1_000_000, "min": 60_000_000}[unit]


def _manager_values(properties: dict[str, str]) -> dict[str, object]:
    keys = {
        "LoadState": "load_state", "ActiveState": "active_state", "SubState": "sub_state",
        "Result": "result", "User": "user", "Group": "group", "MemoryMax": "memory_max",
        "MemorySwapMax": "memory_swap_max", "CPUQuotaPerSecUSec": "cpu_quota_usec",
        "TasksMax": "tasks_max", "RuntimeMaxUSec": "runtime_max_usec", "KillMode": "kill_mode",
        "TimeoutStopUSec": "timeout_stop_usec", "Restart": "restart", "OOMPolicy": "oom_policy",
        "StandardOutput": "standard_output", "StandardError": "standard_error",
        "LogRateLimitIntervalUSec": "log_rate_interval_usec", "LogRateLimitBurst": "log_rate_burst",
        "PrivateNetwork": "private_network", "InvocationID": "invocation_id",
        "FragmentPath": "fragment_path", "ControlGroup": "control_group", "Slice": "slice",
        "MainPID": "main_pid", "ControlPID": "control_pid", "ExecMainStatus": "exec_main_status",
        "ExecMainStartTimestampMonotonic": "exec_main_start_usec",
        "ExecMainExitTimestampMonotonic": "exec_main_exit_usec",
        "ActiveEnterTimestampMonotonic": "active_enter_usec", "DropInPaths": "drop_in_paths",
    }
    result: dict[str, object] = {}
    for key, target in keys.items():
        value = properties[key]
        if target in {"memory_max", "memory_swap_max", "tasks_max", "log_rate_burst", "main_pid", "control_pid", "exec_main_status", "exec_main_start_usec", "exec_main_exit_usec", "active_enter_usec"}:
            result[target] = _parse_unsigned(value, "systemd-property-invalid")
        elif target in {"cpu_quota_usec", "runtime_max_usec", "timeout_stop_usec", "log_rate_interval_usec"}:
            result[target] = _manager_duration(value, "systemd-property-invalid")
        else:
            result[target] = value
    return result


def _open_cgroup(control_group: str) -> tuple[int, os.stat_result]:
    if (type(control_group) is not str or not control_group.startswith("/")
            or ".." in control_group.split("/") or "\x00" in control_group):
        _fail("cgroup-path-invalid")
    try:
        fd = os.open(_CGROUP_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        for component in control_group.split("/"):
            if not component:
                continue
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            os.close(fd)
            _fail("cgroup-not-directory")
        return fd, info
    except FileNotFoundError:
        _fail("cgroup-removed")
    except OSError:
        _fail("cgroup-unavailable")


def _cgroup_read(fd: int, name: str, maximum: int = 64 * 1024) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_.]+", name):
        _fail("cgroup-file-invalid")
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                _fail("cgroup-file-type")
            return _read_fd(file_fd, maximum)
        finally:
            os.close(file_fd)
    except OSError:
        _fail("cgroup-file-unavailable")


def _cgroup_value(fd: int, name: str) -> str:
    try:
        value = _cgroup_read(fd, name, 4096).decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        _fail("cgroup-value-invalid")
    if not value or "\x00" in value:
        _fail("cgroup-value-invalid")
    return value


def _cgroup_events(fd: int) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in _cgroup_value(fd, "memory.events").splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in values:
            _fail("cgroup-memory-events-invalid")
        values[fields[0]] = _parse_unsigned(fields[1], "cgroup-memory-events-invalid")
    if not {"low", "high", "max", "oom", "oom_kill"} <= set(values):
        _fail("cgroup-memory-events-incomplete")
    return values


def _cgroup_snapshot(control_group: str, budget: tuple[int, int, int, int], *,
                     require_populated: bool | None = None) -> dict[str, object]:
    fd, info = _open_cgroup(control_group)
    try:
        memory_max = _parse_unsigned(_cgroup_value(fd, "memory.max"), "cgroup-memory-limit")
        swap_max = _parse_unsigned(_cgroup_value(fd, "memory.swap.max"), "cgroup-swap-limit")
        cpu = _cgroup_value(fd, "cpu.max").split()
        if len(cpu) != 2 or cpu[0] == "max":
            _fail("cgroup-cpu-limit")
        quota = _parse_unsigned(cpu[0], "cgroup-cpu-limit", allow_zero=False)
        period = _parse_unsigned(cpu[1], "cgroup-cpu-period", allow_zero=False)
        tasks_max = _parse_unsigned(_cgroup_value(fd, "pids.max"), "cgroup-task-limit")
        memory_current = _parse_unsigned(_cgroup_value(fd, "memory.current"), "cgroup-memory-current")
        swap_current = _parse_unsigned(_cgroup_value(fd, "memory.swap.current"), "cgroup-swap-current")
        pids_current = _parse_unsigned(_cgroup_value(fd, "pids.current"), "cgroup-pids-current")
        oom_group = _parse_unsigned(_cgroup_value(fd, "memory.oom.group"), "cgroup-oom-group")
        events = _cgroup_events(fd)
        cgroup_events = {}
        for line in _cgroup_value(fd, "cgroup.events").splitlines():
            pieces = line.split()
            if len(pieces) != 2 or pieces[0] in cgroup_events:
                _fail("cgroup-events-invalid")
            cgroup_events[pieces[0]] = _parse_unsigned(pieces[1], "cgroup-events-invalid")
        if "populated" not in cgroup_events:
            _fail("cgroup-populated-unavailable")
        populated = cgroup_events["populated"]
        memory_limit, cpu_percent, tasks_limit, _runtime = budget
        if (memory_max <= 0 or memory_max > memory_limit or swap_max != 0
                or quota * 100 > cpu_percent * period or tasks_max <= 0 or tasks_max > tasks_limit
                or memory_current > memory_max or swap_current != 0 or pids_current > tasks_max
                or oom_group != 1 or events["oom"] or events["oom_kill"]
                or populated not in {0, 1}
                or require_populated is not None and bool(populated) != require_populated):
            _fail("cgroup-effective-limit-mismatch")
        processes = _cgroup_pids(fd)
        if len(processes) > tasks_max or require_populated is False and processes:
            _fail("cgroup-process-set-mismatch")
        return {
            "device": info.st_dev, "inode": info.st_ino, "control_group": control_group,
            "present": True, "memory_max": memory_max, "memory_swap_max": swap_max,
            "cpu_max": [quota, period], "tasks_max": tasks_max,
            "memory_current": memory_current, "memory_swap_current": swap_current,
            "pids_current": pids_current, "memory_oom_group": oom_group,
            "memory_events": events, "populated": bool(populated),
            "pids": processes,
        }
    finally:
        os.close(fd)


def _cgroup_pids(fd: int) -> list[dict[str, int]]:
    raw = _cgroup_read(fd, "cgroup.procs", 64 * 1024)
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        _fail("cgroup-pid-list-invalid")
    if len(lines) > 384:
        _fail("cgroup-pid-list-limit")
    values: list[dict[str, int]] = []
    seen: set[int] = set()
    for line in lines:
        pid = _parse_unsigned(line, "cgroup-pid-invalid", allow_zero=False)
        if pid in seen:
            _fail("cgroup-pid-duplicate")
        seen.add(pid)
        try:
            _ppid, birth = _pid_stat(pid)
        except ProcessLookupError:
            # A cgroup.procs read can race a process exit; re-read the kernel list.
            _fail("cgroup-pid-raced")
        values.append({"pid": pid, "birth": birth})
    return values


def _check_unit_budget(properties: dict[str, str], role: str,
                       expected_slice: str | None, *, active: bool) -> dict[str, object]:
    manager = _manager_values(properties)
    if (manager["load_state"] != "loaded" or manager["fragment_path"] != _unit_file_name(properties["Id"])
            or manager["drop_in_paths"] or manager["memory_max"] in {0, 2**64 - 1}
            or manager["memory_swap_max"] != 0 or manager["tasks_max"] == 0
            or manager["kill_mode"] != "control-group" or manager["restart"] != "no"
            or manager["oom_policy"] != "kill" or manager["standard_output"] != "null"
            or manager["standard_error"] != "null" or manager["log_rate_interval_usec"] != 1_000_000
            or manager["log_rate_burst"] != 1 or manager["timeout_stop_usec"] != 2_000_000
            or manager["slice"] != expected_slice):
        _fail("systemd-unit-budget-mismatch")
    memory, cpu, tasks, runtime = runner_policy.BUDGETS["harmless" if role == "harmless" else (
        "publisher" if role.startswith("publisher") else role
    )]
    if (manager["memory_max"] > memory or manager["tasks_max"] > tasks
            or manager["cpu_quota_usec"] > cpu * 10_000
            or manager["runtime_max_usec"] > runtime * 1_000_000):
        _fail("systemd-unit-limit-increased")
    expected_uid = 0 if role != "harmless" else None
    if role == "harmless":
        user = str(manager["user"])
        group = str(manager["group"])
        try:
            actual_uid = pwd.getpwnam(user).pw_uid if not user.isdecimal() else int(user)
            actual_gid = pwd.getgrnam(group).gr_gid if not group.isdecimal() else int(group)
        except (KeyError, OverflowError):
            _fail("systemd-child-user-invalid")
        if actual_uid <= 0 or actual_gid <= 0:
            _fail("systemd-child-user-invalid")
    elif manager["user"] not in {"root", "0"} or manager["group"] not in {"root", "0"}:
        _fail("systemd-root-user-invalid")
    if role != "harmless" and manager["private_network"] != "yes":
        _fail("root-network-namespace-required")
    if active and manager["active_state"] != "active":
        _fail("systemd-unit-not-active")
    invocation = manager["invocation_id"]
    if active and (type(invocation) is not str or re.fullmatch(r"[0-9a-f]{32}", invocation) is None):
        _fail("systemd-invocation-id-unavailable")
    return manager


def _process_file(pid: int, name: str, maximum: int) -> bytes:
    try:
        fd = os.open(f"/proc/{pid}/{name}", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            return _read_fd(fd, maximum)
        finally:
            os.close(fd)
    except OSError as error:
        raise ProcessLookupError("process evidence unavailable") from error


def _process_argv(pid: int) -> tuple[bytes, list[str]]:
    raw = _process_file(pid, "cmdline", 16 * 1024)
    if not raw.endswith(b"\0") or b"\0\0" in raw:
        _fail("process-command-invalid")
    try:
        argv = [item.decode("utf-8", "strict") for item in raw[:-1].split(b"\0")]
    except UnicodeDecodeError:
        _fail("process-command-invalid")
    if not argv or any(not item for item in argv):
        _fail("process-command-invalid")
    return raw, argv


def _check_no_process_secrets(pid: int) -> None:
    raw = _process_file(pid, "environ", 64 * 1024)
    forbidden = {
        b"ACTIONS_RUNTIME_TOKEN", b"GITHUB_TOKEN", b"GH_TOKEN",
        b"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    }
    for item in raw.split(b"\0"):
        name, _sep, _value = item.partition(b"=")
        if name in forbidden:
            _fail("root-service-secret-environment")


def _require_process_in_unit_cgroup(process: ProcessIdentity, manager_path: str,
                                    cgroup: dict[str, object], expected_path: str) -> None:
    if (manager_path != expected_path or process.cgroup != manager_path
            or type(cgroup) is not dict or cgroup.get("control_group") != manager_path
            or cgroup.get("present") is not True):
        _fail("unit-process-cgroup-identity")
    pids = cgroup.get("pids")
    if (type(pids) is not list or not any(
            type(row) is dict and type(row.get("pid")) is int
            and type(row.get("birth")) is int
            and row["pid"] == process.pid and row["birth"] == process.birth
            for row in pids)):
        _fail("unit-process-cgroup-identity")


def _observe_unit(names: runner_policy.RunNames, role: str, deadline_ns: int,
                  *, expected_definition: dict[str, object] | None = None,
                  active: bool = True) -> dict[str, object]:
    unit = _unit_name(names, role)
    properties = _show_unit(unit, deadline_ns)
    if properties["Id"] != unit:
        _fail("systemd-unit-id-mismatch")
    expected_slice = names.work_slice if role == "harmless" else _slice_name(names, role)
    manager = _check_unit_budget(properties, role, expected_slice, active=active)
    invocation = manager["invocation_id"]
    if type(invocation) is not str or re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        _fail("systemd-invocation-id-unavailable")
    state = _load_state_from_names(names)
    definition = expected_definition
    if definition is None:
        definition = state["definitions"].get(role)
    if type(definition) is not dict:
        _fail("unit-definition-record-missing")
    _read_unit_definition(unit, definition)
    fragment = manager["fragment_path"]
    unit_info = os.stat(fragment, follow_symlinks=False)
    if unit_info.st_dev != definition["device"] or unit_info.st_ino != definition["inode"]:
        _fail("unit-fragment-identity-changed")
    cgroup = manager["control_group"]
    if type(cgroup) is not str or not cgroup.startswith("/"):
        _fail("unit-cgroup-unavailable")
    expected_cgroup = f"/{expected_slice}/{unit}"
    if cgroup != expected_cgroup:
        _fail("unit-cgroup-path-mismatch")
    if properties["WorkingDirectory"] != "/" or properties["NoNewPrivileges"] != "yes":
        _fail("unit-process-boundary-mismatch")
    required_environment = {
        f"DOTUNNEL_GENERATION={state['nonce']}",
        f"DOTUNNEL_RUN={names.run}",
        f"DOTUNNEL_ATTEMPT={names.attempt}",
        "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
    }
    if not required_environment <= set(properties["Environment"].split()):
        _fail("unit-environment-mismatch")
    budget = runner_policy.BUDGETS["harmless" if role == "harmless" else (
        "publisher" if role.startswith("publisher") else role
    )]
    pid = manager["main_pid"]
    if active and (type(pid) is not int or pid <= 0):
        _fail("systemd-main-pid-unavailable")
    process = observe_process(pid) if type(pid) is int and pid > 0 else None
    if process is not None:
        _check_no_process_secrets(process.pid)
        executable = _secure_root_binary(_PYTHON)
        executable_info = os.stat(executable, follow_symlinks=False)
        if ((process.exe_device, process.exe_inode) != (executable_info.st_dev, executable_info.st_ino)
                or process.no_new_privs != 1):
            _fail("unit-process-executable-mismatch")
        _raw_cmdline, argv = _process_argv(process.pid)
        if role == "harmless":
            dispatcher = _identity_from_record(state["dispatcher"])
            if process.uid != dispatcher.uid or process.gid != dispatcher.gid:
                _fail("child-credentials-mismatch")
            if (argv != [executable, "-I", "-S", "-c", _HARMLESS_CODE]
                    or any(cap.strip("0") for cap in (
                        process.cap_eff, process.cap_prm, process.cap_bnd, process.cap_amb,
                    ))):
                _fail("harmless-child-command-mismatch")
        else:
            if process.uid != 0 or process.gid != 0:
                _fail("root-service-credentials-mismatch")
            operation = {
                "reaper": "reap", "recovery": "recover", "recovery-probe": "recover",
                "publisher-readiness": "publish-readiness",
                "publisher-terminal": "publish-terminal",
            }[role]
            expected_argv = [
                executable, "-I", "-S", os.path.join(names.source, "runner_prepare.py"),
                operation, names.run, names.attempt,
            ]
            if argv != expected_argv:
                _fail("root-service-command-mismatch")
            if role.startswith("publisher") and (
                    os.readlink(f"/proc/{process.pid}/ns/net") == os.readlink("/proc/1/ns/net")):
                _fail("publisher-network-namespace-required")
    elif (manager["active_state"] not in {"inactive", "failed"}
            or manager["main_pid"] != 0 or manager["control_pid"] != 0):
        _fail("unit-process-absence-unproved")
    try:
        cg = _cgroup_snapshot(cgroup, budget, require_populated=True if active else None)
    except RuntimeFailure as error:
        if (error.code != "cgroup-removed" or active or process is not None
                or manager["active_state"] not in {"inactive", "failed"}
                or manager["main_pid"] != 0 or manager["control_pid"] != 0):
            raise
        cg = {
            "control_group": cgroup, "present": False, "observed_absent": True,
            "populated": False, "pids": [],
        }
    if process is not None:
        _require_process_in_unit_cgroup(process, cgroup, cg, expected_cgroup)
    return {
        "unit": unit, "role": role, "invocation_id": invocation,
        "fragment_path": fragment, "definition_sha256": definition["sha256"],
        "control_group": cgroup, "slice": expected_slice, "main_pid": manager["main_pid"],
        "control_pid": manager["control_pid"], "manager": manager, "cgroup": cg,
        "process": process.to_record() if process is not None else None,
    }


def _identity_from_record(value: object) -> ProcessIdentity:
    if type(value) is not dict or set(value) != _IDENTITY_FIELDS:
        _fail("process-record-invalid")
    try:
        fds = tuple(tuple(row) for row in value["held_fds"])
        identity = ProcessIdentity(
            pid=value["pid"], birth=value["birth"], uid=value["uid"], gid=value["gid"],
            exe_path=value["exe_path"], exe_device=value["exe_device"], exe_inode=value["exe_inode"],
            exe_uid=value["exe_uid"], exe_gid=value["exe_gid"], exe_mode=value["exe_mode"],
            cgroup=value["cgroup"], cap_eff=value["cap_eff"], cap_prm=value["cap_prm"],
            cap_bnd=value["cap_bnd"], cap_amb=value["cap_amb"], no_new_privs=value["no_new_privs"],
            held_fds=fds,
        )
    except (KeyError, TypeError, ValueError):
        _fail("process-record-invalid")
    if (type(identity.pid) is not int or identity.pid <= 0 or type(identity.birth) is not int
            or identity.birth <= 0 or any(type(number) is not int or number < 0 for number in (
                identity.uid, identity.gid, identity.exe_device, identity.exe_inode,
                identity.exe_uid, identity.exe_gid, identity.exe_mode, identity.no_new_privs,
            )) or type(identity.exe_path) is not str or type(identity.cgroup) is not str
            or any(type(value) is not str for value in (
                identity.cap_eff, identity.cap_prm, identity.cap_bnd, identity.cap_amb,
            ))):
        _fail("process-record-invalid")
    return identity


def _validate_state(state: object, names: runner_policy.RunNames) -> dict[str, Any]:
    if type(state) is not dict or set(state) != _STATE_FIELDS or type(state.get("schema")) is not int or state["schema"] != 1:
        _fail("runtime-state-schema")
    if (state["boot_id"] != boot_id() or type(state["nonce"]) is not str
            or re.fullmatch(r"[0-9a-f]{32}", state["nonce"]) is None
            or runner_policy.validate_context(state["context"]).run != names.run
            or runner_policy.validate_context(state["context"]).attempt != names.attempt
            or state["scenario"] not in {"normal", "workflow-cancel"}
            or type(state["outer_deadline_ns"]) is not str
            or re.fullmatch(r"[1-9][0-9]{0,19}", state["outer_deadline_ns"]) is None
            or state["phase"] not in {"ARMING", "RUNNING", "CLEANING", "CLEANUP_TERMINAL"}):
        _fail("runtime-state-binding")
    _identity_from_record(state["dispatcher"])
    if type(state["source"]) is not dict or set(state["source"]) != {"commit", "closure_sha256", "files", "upload_action_commit", "source_path"}:
        _fail("runtime-state-source")
    if type(state["timestamps"]) is not dict or set(state["timestamps"]) != {
            "reaper_started_ns", "ready_ns", "cancel_received_ns", "cleanup_started_ns",
            "cleanup_finished_ns", "terminal_ns"}:
        _fail("runtime-state-timestamps")
    if type(state["deadlines"]) is not dict or set(state["deadlines"]) not in ({}, {"work_ns", "cleanup_ns", "publish_ns", "outer_ns"}):
        _fail("runtime-state-deadlines")
    if type(state["definitions"]) is not dict or type(state["units"]) is not dict:
        _fail("runtime-state-units")
    source_directory = state["source_directory"]
    source_directory_fields = {"device", "inode", "uid", "gid", "mode", "nlink"}
    if (type(source_directory) is not dict or set(source_directory) != source_directory_fields
            or any(type(value) is not int or value < 0 for value in source_directory.values())
            or source_directory["uid"] != 0 or source_directory["gid"] != 0
            or source_directory["mode"] != 0o500 or source_directory["nlink"] != 2):
        _fail("runtime-state-source-directory")
    for role, definition in state["definitions"].items():
        if (type(definition) is not dict
                or set(definition) != {"unit", "sha256", "device", "inode"}
                or definition["unit"] != _definition_unit(names, role)
                or type(definition["sha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", definition["sha256"]) is None
                or any(type(definition[field]) is not int or definition[field] < 0 for field in ("device", "inode"))):
            _fail("runtime-state-definition")
    for role, observation in state["units"].items():
        if role not in state["definitions"] or type(observation) is not dict or set(observation) != _UNIT_FIELDS:
            _fail("runtime-state-unit-observation")
        if (observation["unit"] != _unit_name(names, role)
                or observation["invocation_id"] is not None and (
                    type(observation["invocation_id"]) is not str
                    or re.fullmatch(r"[0-9a-f]{32}", observation["invocation_id"]) is None)
                or type(observation["manager"]) is not dict
                or set(observation["manager"]) != _MANAGER_FIELDS
                or type(observation["cgroup"]) is not dict
                or type(observation["control_group"]) is not str):
            _fail("runtime-state-unit-observation")
    if state["child"] is not None and (type(state["child"]) is not dict
            or set(state["child"]) != {"process", "pipe", "unit"}
            or type(state["child"]["process"]) is not dict
            or state["child"]["unit"] != _unit_name(names, "harmless")):
        _fail("runtime-state-child")
    if state["cancel_notice"] is not None:
        notice = state["cancel_notice"]
        if (type(notice) is not dict or set(notice) != {
                "notice_ns", "received_ns", "live_at_notice", "child"}
                or type(notice["notice_ns"]) is not str
                or re.fullmatch(r"[1-9][0-9]{0,19}", notice["notice_ns"]) is None
                or type(notice["received_ns"]) is not int or notice["received_ns"] <= 0
                or type(notice["live_at_notice"]) is not bool
                or notice["child"] is not None and type(notice["child"]) is not dict):
            _fail("runtime-state-cancel")
    if state["original_cause"] is not None and (
            type(state["original_cause"]) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", state["original_cause"]) is None):
        _fail("runtime-state-cause")
    if type(state["publication"]) is not dict or set(state["publication"]) != {"readiness", "terminal"}:
        _fail("runtime-state-publication")
    for publication in state["publication"].values():
        if (type(publication) is not dict or set(publication) != _PUBLICATION_FIELDS
                or publication["state"] not in {"PENDING", "LOCAL_PUBLISHED", "FAILED", "UNKNOWN"}
                or publication["exit_code"] is not None and type(publication["exit_code"]) is not int
                or publication["artifact_id"] is not None and type(publication["artifact_id"]) is not int
                or publication["digest"] is not None and (
                    type(publication["digest"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", publication["digest"]) is None)
                or publication["url"] is not None and type(publication["url"]) is not str
                or type(publication["updated_ns"]) is not int):
            _fail("runtime-state-publication")
    for field_name in ("readiness_sha256", "terminal_sha256"):
        value = state[field_name]
        if value is not None and (type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None):
            _fail("runtime-state-snapshot-digest")
    for field_name in ("control_directory", "publisher_directory"):
        value = state[field_name]
        if value is not None and type(value) is not dict:
            _fail("runtime-state-directory")
    if state["prepared_terminal"] is not None and type(state["prepared_terminal"]) is not dict:
        _fail("runtime-state-terminal")
    return state


def _load_state(store: Any, names: runner_policy.RunNames) -> dict[str, Any]:
    value = store.read_runtime_state()
    return _validate_state(value, names)


def _load_state_from_names(names: runner_policy.RunNames) -> dict[str, Any]:
    store, parent = _open_store(names)
    try:
        return _load_state(store, names)
    finally:
        store.close()
        os.close(parent)

def _update_state(store: Any, names: runner_policy.RunNames,
                  transform: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    def checked(value: dict[str, Any]) -> dict[str, Any]:
        state = _validate_state(value, names)
        updated = transform(copy.deepcopy(state))
        return _validate_state(updated, names)
    try:
        return store.update_runtime_state(checked)
    except RuntimeFailure:
        raise
    except Exception:
        _fail("runtime-state-update-refused")


def _read_authority_header(names: runner_policy.RunNames) -> tuple[int, dict[str, object], dict[str, object]]:
    _secure_dir(_RUN_DIR, owner=0)
    parent = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        root_fd = os.open(names.prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        _secure_dir(os.path.join(_RUN_DIR, names.prefix), owner=0, exact_mode=0o700)
        try:
            raw, _info = _secure_record_at(root_fd, "authority.json", maximum=_MAX_RECORD, mode=0o600)
            authority = _strict_json(raw, _MAX_RECORD)
            if (type(authority) is not dict or set(authority) != {"schema", "context", "source", "boot_id", "nonce"}
                    or type(authority["schema"]) is not int or authority["schema"] != 1
                    or type(authority["context"]) is not dict or type(authority["source"]) is not dict
                    or authority["boot_id"] != boot_id()):
                _fail("authority-header-invalid")
            context = authority["context"]
            if runner_policy.validate_context(context).run != names.run or runner_policy.validate_context(context).attempt != names.attempt:
                _fail("authority-run-mismatch")
            source = authority["source"]
            if (set(source) != {"commit", "closure_sha256"}
                    or type(source["commit"]) is not str or re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is None
                    or type(source["closure_sha256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", source["closure_sha256"]) is None):
                _fail("authority-source-invalid")
            os.close(root_fd)
            return parent, context, source
        except BaseException:
            os.close(root_fd)
            raise
    except BaseException:
        os.close(parent)
        raise


def _open_store(names: runner_policy.RunNames) -> tuple[Any, int]:
    parent, context, source = _read_authority_header(names)
    try:
        store = runner_prepare.AuthorityStore.open(parent, context, source)
        return store, parent
    except BaseException:
        os.close(parent)
        raise


def _make_initial_state(names: runner_policy.RunNames, handoff: Handoff,
                        source: dict[str, object], nonce: str) -> dict[str, object]:
    persisted_source = {
        key: source[key] for key in (
            "commit", "closure_sha256", "files", "upload_action_commit", "source_path",
        )
    }
    return {
        "schema": 1, "boot_id": boot_id(), "nonce": nonce,
        "context": copy.deepcopy(handoff.context), "source": persisted_source,
        "source_directory": copy.deepcopy(source["source_directory"]),
        "scenario": handoff.scenario, "outer_deadline_ns": str(handoff.outer_deadline_ns),
        "dispatcher": handoff.dispatcher.to_record(), "phase": "ARMING",
        "timestamps": {
            "reaper_started_ns": None, "ready_ns": None, "cancel_received_ns": None,
            "cleanup_started_ns": None, "cleanup_finished_ns": None, "terminal_ns": None,
        },
        "deadlines": {}, "definitions": {}, "units": {}, "child": None,
        "cancel_notice": None, "original_cause": None,
        "publication": {
            "readiness": {"state": "PENDING", "exit_code": None, "artifact_id": None,
                           "digest": None, "url": None, "updated_ns": time.monotonic_ns()},
            "terminal": {"state": "PENDING", "exit_code": None, "artifact_id": None,
                          "digest": None, "url": None, "updated_ns": time.monotonic_ns()},
        },
        "readiness_sha256": None, "terminal_sha256": None,
        "control_directory": None, "publisher_directory": None,
        "prepared_terminal": None,
    }


def _record_definition(store: Any, names: runner_policy.RunNames, role: str,
                       definition: dict[str, object]) -> None:
    def transform(state: dict[str, Any]) -> dict[str, Any]:
        if role in state["definitions"]:
            _fail("unit-definition-replay")
        state["definitions"][role] = {
            "unit": _definition_unit(names, role), "sha256": definition["sha256"],
            "device": definition["device"], "inode": definition["inode"],
        }
        return state
    _update_state(store, names, transform)
def _ensure_slice_definition(store: Any, names: runner_policy.RunNames,
                             role: str, content: bytes) -> dict[str, object]:
    key = "work-slice" if role == "work" else "publisher-slice" if role.startswith("publisher") else f"{role}-slice"
    unit = _slice_name(names, role)
    state = _load_state(store, names)
    existing = state["definitions"].get(key)
    if existing is not None:
        if _read_unit_definition(unit, existing) != content:
            _fail("slice-definition-content-changed")
        return existing
    definition = _write_unit(unit, content)
    _record_definition(store, names, key, definition)
    return {
        "unit": unit, "sha256": definition["sha256"],
        "device": definition["device"], "inode": definition["inode"],
    }


def _record_unit(store: Any, names: runner_policy.RunNames,
                 observation: dict[str, object], *, replace_existing: bool = False) -> None:
    role = observation["role"]
    def transform(state: dict[str, Any]) -> dict[str, Any]:
        if role in state["units"] and not replace_existing:
            old = state["units"][role]
            if old != observation:
                _fail("unit-observation-replay")
        state["units"][role] = copy.deepcopy(observation)
        return state
    _update_state(store, names, transform)


def _set_cause(store: Any, names: runner_policy.RunNames, cause: str) -> str | None:
    if type(cause) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", cause) is None:
        _fail("original-cause-invalid")
    def transform(state: dict[str, Any]) -> dict[str, Any]:
        if state["original_cause"] is None:
            state["original_cause"] = cause
        return state
    state = _update_state(store, names, transform)
    return state["original_cause"]


def _check_bootstrap_caller(
    names: runner_policy.RunNames,
    handoff: Handoff,
    deadline_ns: int,
    source_directory: dict[str, int],
) -> dict[str, object]:
    if any(name in os.environ for name in ("ACTIONS_RUNTIME_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")):
        _fail("root-caller-binding")
    for name, field in (("DOTUNNEL_SOURCE_DEV", "device"), ("DOTUNNEL_SOURCE_INO", "inode")):
        value = os.environ.get(name, "")
        if re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value) is None or int(value) != source_directory[field]:
            _fail("source-handoff-identity-mismatch")
    native_name = f"{names.prefix}-bootstrap.service"
    props = _show_unit(native_name, deadline_ns)
    nonce = os.environ.get("DOTUNNEL_BOOTSTRAP_NONCE", "")
    if (props["Id"] != native_name or props["LoadState"] != "loaded"
            or props["ActiveState"] != "active" or props["SubState"] not in {"running", "start"}
            or props["FragmentPath"] != f"/run/systemd/transient/{native_name}"
            or props["DropInPaths"] or props["MainPID"] != str(os.getpid())
            or props["ControlPID"] != "0"
            or props["WorkingDirectory"] != f"/proc/{handoff.dispatcher.pid}/cwd"
            or f"DOTUNNEL_BOOTSTRAP_NONCE={nonce}" not in props["Environment"]
            or "DOTUNNEL_SOURCE_DEV=" in props["Environment"]
            or "DOTUNNEL_SOURCE_INO=" in props["Environment"]
            or re.fullmatch(r"[0-9a-f]{32}", nonce) is None):
        _fail("bootstrap-unit-identity")
    invocation = props["InvocationID"]
    if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        _fail("bootstrap-invocation-unavailable")
    _secure_dir("/run/systemd/transient", owner=0)
    fragment = os.stat(props["FragmentPath"], follow_symlinks=False)
    if (not stat.S_ISREG(fragment.st_mode) or fragment.st_uid != 0
            or fragment.st_mode & 0o022 or fragment.st_nlink != 1):
        _fail("bootstrap-unit-owner")
    active_ns = _parse_unsigned(props["ActiveEnterTimestampMonotonic"], "bootstrap-start-time") * 1000
    if active_ns <= 0 or time.monotonic_ns() - active_ns > 90 * _NS:
        _fail("bootstrap-runtime-expired")
    main_pid = _parse_unsigned(props["MainPID"], "bootstrap-main-pid", allow_zero=False)
    if main_pid != os.getpid():
        _fail("bootstrap-entry-mismatch")
    bootstrap_cgroup = props["ControlGroup"]
    group = _cgroup_snapshot(bootstrap_cgroup, runner_policy.BUDGETS["preparation"], require_populated=True)
    if [row["pid"] for row in group["pids"]] != [os.getpid()]:
        _fail("bootstrap-cgroup-identity")
    if (props["KillMode"] != "control-group" or props["Restart"] != "no"
            or props["OOMPolicy"] != "kill" or props["StandardOutput"] != "null"
            or props["StandardError"] != "null" or props["TimeoutStopUSec"] not in {"2s", "2000000", "2000000us"}
            or props["MemorySwapMax"] != "0" or props["TasksMax"] != "128"
            or props["MemoryMax"] not in {str(768 * runner_policy.MIB), "805306368"}
            or props["CPUQuotaPerSecUSec"] not in {"1s", "1000000", "1000000us"}
            or props["RuntimeMaxUSec"] not in {"90s", "90000000", "90000000us"}
            or props["LogRateLimitIntervalUSec"] not in {"1s", "1000000", "1000000us"}
            or props["LogRateLimitBurst"] != "1"
            or props["User"] not in {"root", "0"} or props["Group"] not in {"root", "0"}):
        _fail("bootstrap-unit-budget")
    return {
        "unit": native_name, "invocation_id": invocation,
        "fragment_path": props["FragmentPath"], "fragment_device": fragment.st_dev,
        "fragment_inode": fragment.st_ino, "control_group": bootstrap_cgroup,
        "cgroup": group,
    }




def _check_name_collisions(names: runner_policy.RunNames, deadline_ns: int) -> None:
    _verify_no_preexisting_units(names, deadline_ns)
    parent_fd = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            os.stat(names.prefix, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            _fail("authority-path-unavailable")
        _fail("authority-path-collision")
    finally:
        os.close(parent_fd)


def _create_control_directory(names: runner_policy.RunNames) -> dict[str, object]:
    parent_fd = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.mkdir(names.control.removeprefix(_RUN_DIR + "/"), 0o711, dir_fd=parent_fd)
        fd = os.open(names.control.removeprefix(_RUN_DIR + "/"), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o711)
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711:
                _fail("control-directory-identity")
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "mode": 0o711}
    except FileExistsError:
        _fail("control-directory-collision")
    finally:
        os.close(parent_fd)


def _create_publisher_directory(names: runner_policy.RunNames) -> dict[str, object]:
    parent_fd = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    basename = names.prefix + "-publisher"
    try:
        os.mkdir(basename, 0o700, dir_fd=parent_fd)
        fd = os.open(basename, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                _fail("publisher-directory-identity")
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "mode": 0o700}
    except FileExistsError:
        _fail("publisher-directory-collision")
    finally:
        os.close(parent_fd)


def _service_unit_setup(store: Any, names: runner_policy.RunNames, role: str,
                        deadline_ns: int, *, source_path: str, dispatcher: ProcessIdentity,
                        start_async: bool) -> dict[str, object]:
    unit = _unit_name(names, role)
    effect = store.intent(role, {"unit": unit})
    slice_role = "work" if role == "harmless" else "publisher-readiness" if role.startswith("publisher") else role
    slice_name = _slice_name(names, slice_role)
    slice_content = _slice_content(names, slice_role, _load_state(store, names)["nonce"])
    slice_file = _unit_file_name(slice_name)
    try:
        os.stat(slice_file, follow_symlinks=False)
    except FileNotFoundError:
        _write_unit(slice_name, slice_content)
    else:
        _fail("slice-definition-collision")
    definition = _unit_content(names, role, _load_state(store, names)["nonce"], source_path, dispatcher)
    definition_info = _write_unit(unit, definition)
    _record_definition(store, names, role, {
        "unit": unit, "sha256": definition_info["sha256"],
        "device": definition_info["device"], "inode": definition_info["inode"],
    })
    _systemctl(["daemon-reload"], deadline_ns)
    if start_async:
        _systemctl(["--no-block", "start", unit], deadline_ns)
    else:
        _systemctl(["start", unit], deadline_ns)
    observation = _wait_unit_active(names, role, deadline_ns, definition={
        "unit": unit, "sha256": definition_info["sha256"],
        "device": definition_info["device"], "inode": definition_info["inode"],
    })
    _record_unit(store, names, observation)
    if role != "recovery":
        store.commit(effect, {"unit": unit, "invocation_id": observation["invocation_id"]})
    return observation


def _wait_unit_active(names: runner_policy.RunNames, role: str, deadline_ns: int,
                      *, definition: dict[str, object] | None = None,
                      allow_inactive: bool = False) -> dict[str, object]:
    last: dict[str, object] | None = None
    while time.monotonic_ns() < deadline_ns:
        try:
            last = _observe_unit(names, role, min(deadline_ns, time.monotonic_ns() + 2 * _NS),
                                 expected_definition=definition, active=not allow_inactive)
        except RuntimeFailure:
            time.sleep(0.05)
            continue
        manager = last["manager"]
        if manager["active_state"] == "active" or allow_inactive and manager["active_state"] in {"inactive", "failed"}:
            return last
        time.sleep(0.05)
    _fail("systemd-unit-start-timeout")


def _bootstrap_sources(source: dict[str, object], names: runner_policy.RunNames,
                       source_directory: dict[str, int]) -> dict[str, object]:
    if source.get("source_path") != names.source:
        _fail("source-path-binding")
    checked = validate_source_manifest(names, expected_directory=source_directory)
    if (checked["commit"] != source["commit"] or checked["closure_sha256"] != source["closure_sha256"]
            or checked["source_directory"] != source_directory):
        _fail("source-authority-mismatch")
    return checked


def _ensure_operation_source(names: runner_policy.RunNames, state: dict[str, Any]) -> None:
    source = _bootstrap_sources(state["source"], names, state["source_directory"])
    if source["commit"] != state["source"]["commit"] or source["closure_sha256"] != state["source"]["closure_sha256"]:
        _fail("source-generation-changed")
    this_file = os.path.realpath(__file__)
    if this_file != os.path.join(names.source, "runner_runtime.py"):
        _fail("runtime-module-outside-promotion")


class RuntimeControlState:
    """Credential-free state projected through the authenticated STREAM peer."""

    def __init__(self, *, context: dict[str, object], boot_id: str, nonce: str,
                 source: dict[str, object], dispatcher: ProcessIdentity, scenario: str,
                 outer_deadline_ns: int,
                 cancel_handler: Callable[[dict[str, object]], None] | None = None,
                 live_probe: Callable[[], tuple[bool, dict[str, object] | None]] | None = None,
                 status_probe: Callable[[], dict[str, object]] | None = None):
        runner_policy.validate_context(context)
        if (type(boot_id) is not str
                or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", boot_id) is None
                or type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
                or type(source) is not dict or set(source) != {"commit", "closure_sha256"}
                or type(source["commit"]) is not str or re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is None
                or type(source["closure_sha256"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", source["closure_sha256"]) is None
                or scenario not in {"normal", "workflow-cancel"}
                or type(outer_deadline_ns) is not int):
            _fail("control-state-binding")
        self.context = copy.deepcopy(context)
        self.boot_id = boot_id
        self.nonce = nonce
        self.source = copy.deepcopy(source)
        self.dispatcher = dispatcher
        self.scenario = scenario
        self.outer_deadline_ns = outer_deadline_ns
        self.cancel_handler = cancel_handler
        self.live_probe = live_probe
        self.status_probe = status_probe
        self.lock = threading.RLock()
        self.child_identity: dict[str, object] | None = None
        self.admitted_identity: dict[str, object] | None = None
        self.readiness: dict[str, object] | None = None
        self.terminal: dict[str, object] | None = None
        self.cancel_notice: dict[str, object] | None = None
        self.readiness_publication = "PENDING"
        self.terminal_publication = "PENDING"
        self.publisher_exit: int | None = None
        self.snapshot_sha256: str | None = None
        self.updated_ns = time.monotonic_ns()
        self.phase = "WAITING"

    def set_ready(self, snapshot: dict[str, object], child: dict[str, object]) -> None:
        with self.lock:
            self.readiness = copy.deepcopy(snapshot)
            self.child_identity = copy.deepcopy(child)
            self.phase = "READY"
            self.updated_ns = time.monotonic_ns()

    def set_terminal(self, snapshot: dict[str, object], digest: str) -> None:
        with self.lock:
            self.terminal = copy.deepcopy(snapshot)
            self.snapshot_sha256 = digest
            self.phase = "TERMINAL"
            self.updated_ns = time.monotonic_ns()

    def set_publication(self, kind: str, state: str, exit_code: int | None,
                        digest: str | None = None) -> None:
        if kind not in {"readiness", "terminal"} or state not in {"PENDING", "LOCAL_PUBLISHED", "FAILED", "UNKNOWN"}:
            _fail("control-publication-invalid")
        with self.lock:
            if kind == "readiness":
                self.readiness_publication = state
            else:
                self.terminal_publication = state
            self.publisher_exit = exit_code
            if digest is not None:
                self.snapshot_sha256 = digest
            self.updated_ns = time.monotonic_ns()

    def request_cancel(self, notice_ns: int) -> dict[str, object]:
        with self.lock:
            if self.cancel_notice is not None:
                return copy.deepcopy(self.cancel_notice)
            received = time.monotonic_ns()
            if (type(notice_ns) is not int or notice_ns < 1 or notice_ns > received
                    or notice_ns > self.outer_deadline_ns):
                _fail("control-cancel-time-invalid")
            if self.phase in {"CLEANUP", "TERMINAL"} or self.terminal is not None:
                _fail("control-cancel-after-cleanup")
            if self.live_probe is None:
                _fail("cancel-child-observation-unavailable")
            child_live, child_observation = self.live_probe()
            if type(child_live) is not bool:
                _fail("cancel-child-observation-invalid")
            record: dict[str, object] = {
                "notice_ns": str(notice_ns), "received_ns": received,
                "live_at_notice": bool(child_live), "child": child_observation,
            }
            if self.cancel_handler is not None:
                self.cancel_handler(record)
            self.cancel_notice = record
            self.phase = "CANCEL_REQUESTED"
            self.updated_ns = received
            return copy.deepcopy(record)

    def status(self) -> dict[str, object]:
        with self.lock:
            if self.status_probe is None:
                _fail("control-status-observation-unavailable")
            refreshed = self.status_probe()
            if type(refreshed) is not dict or type(refreshed.get("running")) is not bool:
                _fail("control-status-observation-invalid")
            running = refreshed["running"]
            if refreshed.get("readiness_publication") in {"PENDING", "LOCAL_PUBLISHED", "FAILED", "UNKNOWN"}:
                self.readiness_publication = refreshed["readiness_publication"]
            if refreshed.get("terminal_publication") in {"PENDING", "LOCAL_PUBLISHED", "FAILED", "UNKNOWN"}:
                self.terminal_publication = refreshed["terminal_publication"]
            if type(refreshed.get("publisher_exit")) is int or refreshed.get("publisher_exit") is None:
                self.publisher_exit = refreshed.get("publisher_exit")
            ready = self.readiness is not None
            terminal = self.terminal is not None
            if terminal:
                state = "TERMINAL"
            elif self.phase == "CLEANUP":
                state = "CLEANUP"
            elif self.cancel_notice is not None:
                state = "CANCEL_REQUESTED" if running or ready else "CLEANUP"
            elif ready:
                state = "READY" if running else "CLEANUP"
            else:
                state = "WAITING"
            return {
                "schema": 1, "run": self.context["run"], "attempt": self.context["attempt"],
                "state": state, "ready": ready, "running": running,
                "cancel_ack": self.cancel_notice is not None,
                "cancel_notice_ns": None if self.cancel_notice is None else self.cancel_notice["notice_ns"],
                "cancel_received_ns": None if self.cancel_notice is None else str(self.cancel_notice["received_ns"]),
                "live_at_notice": None if self.cancel_notice is None else self.cancel_notice["live_at_notice"],
                "terminal": terminal,
                "readiness_publication": self.readiness_publication,
                "terminal_publication": self.terminal_publication,
                "publisher_exit": self.publisher_exit, "snapshot_sha256": self.snapshot_sha256,
                "updated_ns": str(self.updated_ns), "boot_id": self.boot_id,
                "nonce": self.nonce, "source": copy.deepcopy(self.source),
            }


class ControlServer:
    """Root-owned, bounded AF_UNIX STREAM endpoint authenticated by SO_PEERCRED."""

    def __init__(self, path: str | os.PathLike[str], state: RuntimeControlState):
        self.path = os.fspath(path)
        if not isinstance(state, RuntimeControlState) or len(os.fsencode(self.path)) >= 104:
            _fail("control-endpoint-invalid")
        self.state = state
        self.listener: socket.socket | None = None
        self.identity: tuple[int, int, int, int, int] | None = None
        self.closed = False

    def start(self) -> "ControlServer":
        parent = os.path.dirname(self.path)
        parent_info = _secure_dir(parent, owner=os.geteuid())
        if stat.S_IMODE(parent_info.st_mode) & 0o022:
            _fail("control-parent-writable")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        bound_identity: tuple[int, int] | None = None
        try:
            listener.bind(self.path)
            created = os.stat(self.path, follow_symlinks=False)
            if not stat.S_ISSOCK(created.st_mode):
                _fail("control-socket-type")
            bound_identity = (created.st_dev, created.st_ino)
            os.chown(self.path, os.geteuid(), self.state.dispatcher.gid)
            os.chmod(self.path, 0o660)
            listener.listen(8)
            listener.settimeout(0.2)
            info = os.stat(self.path, follow_symlinks=False)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_gid != self.state.dispatcher.gid or stat.S_IMODE(info.st_mode) != 0o660):
                _fail("control-socket-owner-mode")
            self.identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            self.listener = listener
            return self
        except BaseException:
            listener.close()
            if bound_identity is not None:
                try:
                    current = os.stat(self.path, follow_symlinks=False)
                    if (stat.S_ISSOCK(current.st_mode)
                            and (current.st_dev, current.st_ino) == bound_identity):
                        os.unlink(self.path)
                except OSError:
                    pass
            raise

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        listener = self.listener
        self.listener = None
        if listener is not None:
            listener.close()
        if self.identity is not None:
            try:
                current = os.stat(self.path, follow_symlinks=False)
            except FileNotFoundError:
                return
            identity = (current.st_dev, current.st_ino, current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode))
            if identity == self.identity and stat.S_ISSOCK(current.st_mode):
                os.unlink(self.path)
                parent_fd = os.open(os.path.dirname(self.path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)

    def serve_forever(self) -> None:
        while not self.closed:
            listener = self.listener
            if listener is None:
                return
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.closed:
                    return
                time.sleep(0.05)
                continue
            with connection:
                connection.settimeout(0.5)
                self._serve_client(connection)

    def _serve_client(self, connection: socket.socket) -> None:
        try:
            raw_peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if len(raw_peer) != 12:
                _fail("control-peer-unavailable")
            pid, uid, gid = __import__("struct").unpack("=3i", raw_peer)
            expected = self.state.dispatcher
            if (pid != expected.pid or uid != expected.uid or gid != expected.gid):
                _fail("control-peer-refused")
            require_same_process(expected)
            request = bytearray()
            while len(request) <= _MAX_CTRL_REQUEST:
                piece = connection.recv(min(1024, _MAX_CTRL_REQUEST + 1 - len(request)))
                if not piece:
                    break
                request.extend(piece)
                if b"\n" in request:
                    break
            if len(request) > _MAX_CTRL_REQUEST or request.count(b"\n") != 1 or not request.endswith(b"\n"):
                _fail("control-request-size")
            value = _strict_json(bytes(request[:-1]), _MAX_CTRL_REQUEST)
            if type(value) is not dict:
                _fail("control-request-invalid")
            operation = value.get("op")
            if operation == "STATUS" and set(value) == {"op"}:
                response = self.state.status()
            elif operation == "CANCEL" and set(value) == {"op", "notice_ns"}:
                if self.state.scenario != "workflow-cancel":
                    _fail("control-cancel-not-admitted")
                text = value["notice_ns"]
                if type(text) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", text) is None:
                    _fail("control-cancel-time-invalid")
                notice = int(text)
                now = time.monotonic_ns()
                if notice < 1 or notice > now or notice > self.state.outer_deadline_ns:
                    _fail("control-cancel-time-invalid")
                self.state.request_cancel(notice)
                response = self.state.status()
            else:
                _fail("control-request-invalid")
            reply = _canonical(response, _MAX_CTRL_REPLY) + b"\n"
        except Exception:
            reply = b'{"error":"control peer refused"}\n'
        try:
            connection.sendall(reply)
        except OSError:
            return


class _SystemdControl:
    """Bounded actual manager observations and fixed operations."""

    def __init__(self, deadline_ns: int):
        self.deadline_ns = deadline_ns

    def show(self, unit: str) -> dict[str, str]:
        return _show_unit(unit, min(self.deadline_ns, time.monotonic_ns() + 2 * _NS))

    def start(self, unit: str, *, asynchronous: bool = False) -> None:
        args = ["--no-block", "start", unit] if asynchronous else ["start", unit]
        _systemctl(args, min(self.deadline_ns, time.monotonic_ns() + 3 * _NS))

    def stop(self, unit: str) -> None:
        _systemctl(["stop", unit], min(self.deadline_ns, time.monotonic_ns() + 5 * _NS))


def _validate_root_entry(operation: object, run: object, attempt: object) -> runner_policy.RunNames:
    operations = {"receipt-start", "reap", "recover", "publish-readiness", "publish-terminal"}
    if type(operation) is not str or operation not in operations:
        _fail("operation-not-allowed")
    names = runner_policy.RunNames(run, attempt)
    if os.geteuid() != 0:
        _fail("root-required")
    return names


def _receipt_start(names: runner_policy.RunNames) -> int:
    handoff = parse_handoff(_read_handoff_stdin())
    context_names = runner_policy.validate_context(handoff.context)
    if context_names != names:
        _fail("run-argument-mismatch")
    now = time.monotonic_ns()
    if handoff.outer_deadline_ns - now < 540 * _NS or handoff.outer_deadline_ns - now > 600 * _NS:
        _fail("outer-deadline-window")
    _require_platform(handoff.outer_deadline_ns)
    _trust_dispatcher(handoff.dispatcher)
    source = validate_source_manifest(names)
    metadata_deadline = min(handoff.outer_deadline_ns, time.monotonic_ns() + 30 * _NS)
    _verify_public_github(handoff.context, source, metadata_deadline)
    _check_bootstrap_caller(names, handoff, handoff.outer_deadline_ns, source["source_directory"])
    _check_name_collisions(names, handoff.outer_deadline_ns)
    try:
        pwd.getpwuid(handoff.dispatcher.uid)
    except KeyError:
        _fail("dispatcher-account-unavailable")
    parent_fd = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    store = None
    try:
        store = runner_prepare.AuthorityStore.create(parent_fd, handoff.context, {
            "commit": source["commit"], "closure_sha256": source["closure_sha256"],
        })
        nonce = store.nonce
        initial = _make_initial_state(names, handoff, source, nonce)
        _validate_state(initial, names)
        store.save_runtime_state(initial, initial=True)
        store.write_credentials(handoff.runtime)
        control_directory = _create_control_directory(names)
        publisher_directory = _create_publisher_directory(names)
        _update_state(store, names, lambda state: {
            **state, "control_directory": control_directory,
            "publisher_directory": publisher_directory,
        })
        # The OnFailure recovery and one-shot recovery probe have distinct
        # fixed units, effects, and cgroups.
        for role in ("recovery", "recovery-probe"):
            store.intent(role, {"unit": _unit_name(names, role)})
            _ensure_slice_definition(store, names, role, _slice_content(names, role, nonce))
            content = _unit_content(names, role, nonce, names.source, handoff.dispatcher)
            definition = _write_unit(_unit_name(names, role), content)
            _record_definition(store, names, role, {
                "unit": _unit_name(names, role), "sha256": definition["sha256"],
                "device": definition["device"], "inode": definition["inode"],
            })
        _systemctl(["daemon-reload"], handoff.outer_deadline_ns)
        reaper_effect = store.intent("reaper", {"unit": _unit_name(names, "reaper")})
        _ensure_slice_definition(store, names, "reaper", _slice_content(names, "reaper", nonce))
        reaper_content = _unit_content(names, "reaper", nonce, names.source, handoff.dispatcher)
        reaper_definition = _write_unit(_unit_name(names, "reaper"), reaper_content)
        _record_definition(store, names, "reaper", {
            "unit": _unit_name(names, "reaper"), "sha256": reaper_definition["sha256"],
            "device": reaper_definition["device"], "inode": reaper_definition["inode"],
        })
        _systemctl(["daemon-reload"], handoff.outer_deadline_ns)
        _systemctl(["--no-block", "start", _unit_name(names, "reaper")], handoff.outer_deadline_ns)
        observation = _wait_unit_active(names, "reaper", min(handoff.outer_deadline_ns, time.monotonic_ns() + 8 * _NS),
                                        definition={
                                            "unit": _unit_name(names, "reaper"),
                                            "sha256": reaper_definition["sha256"],
                                            "device": reaper_definition["device"],
                                            "inode": reaper_definition["inode"],
                                        })
        store.commit(reaper_effect, {"unit": _unit_name(names, "reaper"),
                                     "invocation_id": observation["invocation_id"]})
        _record_unit(store, names, observation, replace_existing=True)
        # The reaper does not return until a live child has crossed the one-shot
        # root GO pipe and a root-owned readiness snapshot is durable.
        readiness_deadline = min(handoff.outer_deadline_ns, time.monotonic_ns() + 45 * _NS)
        while time.monotonic_ns() < readiness_deadline:
            snapshot = store.read_snapshot("readiness") if _snapshot_present(store, "readiness") else None
            if snapshot is not None:
                if snapshot.get("state") != "READY" or snapshot.get("scenario") != handoff.scenario:
                    _fail("readiness-snapshot-invalid")
                return 0
            reaper_now = _show_unit(_unit_name(names, "reaper"), min(readiness_deadline, time.monotonic_ns() + 2 * _NS))
            if reaper_now["ActiveState"] not in {"active", "activating"}:
                _fail("reaper-exited-before-readiness")
            time.sleep(0.1)
        _fail("readiness-deadline")
    except BaseException:
        if store is not None:
            try:
                _systemctl(["--no-block", "start", _unit_name(names, "recovery")],
                           min(handoff.outer_deadline_ns, time.monotonic_ns() + 2 * _NS))
            except Exception:
                pass
        raise
    finally:
        if store is not None:
            store.close()
        os.close(parent_fd)


def _snapshot_present(store: Any, kind: str) -> bool:
    try:
        store.read_snapshot(kind)
    except Exception:
        return False
    return True


def _self_service_observation(names: runner_policy.RunNames, role: str,
                              deadline_ns: int) -> dict[str, object]:
    state = _load_state_from_names(names)
    definition = state["definitions"].get(role)
    if type(definition) is not dict:
        _fail("self-unit-definition-missing")
    observation = _observe_unit(names, role, deadline_ns, expected_definition=definition, active=True)
    if observation["main_pid"] != os.getpid():
        _fail("self-unit-main-pid-mismatch")
    return observation


def _state_deadlines(state: dict[str, Any]) -> runner_policy.Deadlines:
    value = state["deadlines"]
    if set(value) != {"work_ns", "cleanup_ns", "publish_ns", "outer_ns"}:
        _fail("deadlines-unavailable")
    return runner_policy.Deadlines(
        work_ns=value["work_ns"], cleanup_ns=value["cleanup_ns"],
        publish_ns=value["publish_ns"], outer_ns=value["outer_ns"],
    )


def _child_command_identity(process: ProcessIdentity, dispatcher: ProcessIdentity,
                            pipe_reader: int) -> dict[str, object]:
    if (process.uid != dispatcher.uid or process.gid != dispatcher.gid
            or process.exe_uid != 0 or process.exe_mode & 0o022
            or process.exe_inode != os.stat(_secure_root_binary(_PYTHON), follow_symlinks=False).st_ino):
        _fail("harmless-child-identity")
    fd0 = os.stat(f"/proc/{process.pid}/fd/0", follow_symlinks=True)
    info = Path(f"/proc/{process.pid}/fdinfo/0").read_text(encoding="ascii")
    flags_line = next((line for line in info.splitlines() if line.startswith("flags:")), None)
    if flags_line is None:
        _fail("harmless-child-stdin-unavailable")
    flags = int(flags_line.split(":", 1)[1].strip(), 8)
    reader = os.fstat(pipe_reader)
    if (not stat.S_ISFIFO(fd0.st_mode) or (fd0.st_dev, fd0.st_ino) != (reader.st_dev, reader.st_ino)
            or flags & os.O_ACCMODE != os.O_RDONLY):
        _fail("harmless-child-pipe-identity")
    try:
        cmdline = Path(f"/proc/{process.pid}/cmdline").read_bytes()
    except OSError:
        _fail("harmless-child-command-unavailable")
    expected = [
        _secure_root_binary(_PYTHON), "-I", "-S", "-c", _HARMLESS_CODE,
    ]
    fields = cmdline.rstrip(b"\0").split(b"\0")
    if [item.decode("utf-8", "strict") for item in fields] != expected:
        _fail("harmless-child-command-mismatch")
    try:
        environment = Path(f"/proc/{process.pid}/environ").read_bytes()
    except OSError:
        _fail("harmless-child-environment-unavailable")
    if any(secret.encode("ascii") in environment for secret in (
            "ACTIONS_RUNTIME_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")):
        _fail("harmless-child-secret-inheritance")
    return {
        "fd0_device": reader.st_dev, "fd0_inode": reader.st_ino,
        "fd0_access": "read-only", "argv_sha256": hashlib.sha256(cmdline).hexdigest(),
        "environment_sha256": hashlib.sha256(environment).hexdigest(),
    }


def _record_control_cancel(store: Any, names: runner_policy.RunNames,
                           pipe: Any, record: dict[str, object]) -> None:
    # GO and CANCEL serialize on the RuntimeControlState lock; AdmissionPipe
    # separately serializes closure against its sole root writer.
    pipe.close()
    def transform(state: dict[str, Any]) -> dict[str, Any]:
        if state["cancel_notice"] is None:
            state["cancel_notice"] = copy.deepcopy(record)
            state["timestamps"]["cancel_received_ns"] = record["received_ns"]
            if state["phase"] != "CLEANUP_TERMINAL":
                state["phase"] = "CLEANING"
        elif state["cancel_notice"] != record:
            _fail("cancel-notice-replay")
        return state
    _update_state(store, names, transform)


def _live_child_probe(
    names: runner_policy.RunNames,
    store: Any,
    deadline_ns: int,
    *,
    strict: bool = False,
    pipe_reader_fd: int | None = None,
    dispatcher: ProcessIdentity | None = None,
    control_state: RuntimeControlState | None = None,
) -> tuple[bool, dict[str, object] | None]:
    try:
        state = _load_state(store, names)
        child = state["child"]
        if child is not None and type(child) is not dict:
            _fail("child-state-invalid")
        identity = None if child is None else _identity_from_record(child["process"])
        if identity is None and control_state is not None and control_state.admitted_identity is not None:
            identity = _identity_from_record(control_state.admitted_identity)
        expected_unit = state["units"].get("harmless")
        effect = next((row for row in store.effects() if row["role"] == "harmless"), None)
        if effect is not None and type(effect["observed"]) not in {dict, type(None)}:
            _fail("child-effect-observation-invalid")
        unit = _unit_name(names, "harmless")
        props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
        if props["LoadState"] == "not-found":
            absence = _unit_absence(unit, props)
            observed_effect = None if effect is None else effect["observed"]
            if observed_effect is not None:
                absent_effect = (
                    type(observed_effect) is dict and observed_effect.get("unit") == unit
                    and observed_effect.get("invocation_id") is None
                    and observed_effect.get("absence") == absence
                )
                if not absent_effect:
                    if (type(observed_effect) is not dict or type(expected_unit) is not dict
                            or observed_effect.get("unit") != unit
                            or observed_effect.get("invocation_id") != expected_unit.get("invocation_id")):
                        _fail("child-absence-owner-mismatch")
                    cg = expected_unit.get("cgroup")
                    if type(cg) is not dict or type(cg.get("control_group")) is not str:
                        _fail("child-absence-cgroup-unavailable")
                    try:
                        fresh_cg = _cgroup_snapshot(
                            cg["control_group"], runner_policy.BUDGETS["harmless"], require_populated=False,
                        )
                    except RuntimeFailure as error:
                        if error.code != "cgroup-removed":
                            raise
                        fresh_cg = None
                    if fresh_cg is not None and (
                            fresh_cg["device"] != cg.get("device") or fresh_cg["inode"] != cg.get("inode")
                            or fresh_cg["populated"] is not False or fresh_cg["pids"]):
                        _fail("child-absence-cgroup-not-empty")
                    if not all(_pid_birth_gone(row) for row in cg.get("pids", [])):
                        _fail("child-absence-process-live")
            if identity is not None and not _pid_birth_gone({"pid": identity.pid, "birth": identity.birth}):
                _fail("child-absence-process-live")
            return False, None
        definition = state["definitions"].get("harmless")
        if type(definition) is not dict:
            _fail("child-definition-unavailable")
        if props["LoadState"] != "loaded" or props["FragmentPath"] != _unit_file_name(unit):
            _fail("child-unit-identity-unavailable")
        _read_unit_definition(unit, definition)
        if props["DropInPaths"]:
            _fail("child-unit-dropin-present")
        if props["ActiveState"] not in {"active", "inactive", "failed"}:
            _fail("child-unit-transition-unobserved")
        active = props["ActiveState"] == "active"
        observation = _observe_unit(
            names, "harmless", min(deadline_ns, time.monotonic_ns() + 2 * _NS),
            expected_definition=definition, active=active,
        )
        observed_effect = None if effect is None else effect["observed"]
        actual_effect = (
            type(observed_effect) is dict and observed_effect.get("unit") == unit
            and type(observed_effect.get("invocation_id")) is str
            and "absence" not in observed_effect
        )
        if actual_effect:
            if observed_effect["invocation_id"] != observation["invocation_id"]:
                _fail("child-effect-generation-mismatch")
        elif effect is None or observed_effect is not None:
            _fail("child-effect-observation-mismatch")
        if expected_unit is not None and (
                type(expected_unit) is not dict
                or observation["invocation_id"] != expected_unit["invocation_id"]
                or observation["cgroup"]["device"] != expected_unit["cgroup"]["device"]
                or observation["cgroup"]["inode"] != expected_unit["cgroup"]["inode"]):
            _fail("child-generation-changed")
        if active:
            current = require_same_process(identity) if identity is not None else _identity_from_record(observation["process"])
            if (not actual_effect and (control_state is None or control_state.admitted_identity is None)):
                if pipe_reader_fd is None or dispatcher is None:
                    _fail("uncommitted-child-admission-unobserved")
                _child_command_identity(current, dispatcher, pipe_reader_fd)
            if (observation["main_pid"] != current.pid
                    or not any(row["pid"] == current.pid and row["birth"] == current.birth
                               for row in observation["cgroup"]["pids"])):
                _fail("child-process-cgroup-mismatch")
            return True, {
                "pid": current.pid, "birth": current.birth,
                "invocation_id": observation["invocation_id"],
                "cgroup_device": observation["cgroup"]["device"],
                "cgroup_inode": observation["cgroup"]["inode"],
            }
        cgroup = observation["cgroup"]
        if (observation["main_pid"] != 0 or observation["control_pid"] != 0
                or not (cgroup.get("observed_absent") is True
                        or cgroup.get("populated") is False and not cgroup.get("pids"))):
            _fail("child-inactive-processes-unproved")
        if identity is not None and not _pid_birth_gone({"pid": identity.pid, "birth": identity.birth}):
            _fail("child-inactive-process-live")
        return False, None
    except Exception:
        if strict:
            raise
        return False, None


def _root_status_probe(
    names: runner_policy.RunNames,
    store: Any,
    deadline_ns: int,
    dispatcher: ProcessIdentity,
    pipe_reader_fd: int | None,
    control_state: RuntimeControlState,
) -> dict[str, object]:
    state = _load_state(store, names)
    running, _child = _live_child_probe(
        names, store, min(deadline_ns, time.monotonic_ns() + 2 * _NS), strict=True,
        pipe_reader_fd=pipe_reader_fd, dispatcher=dispatcher, control_state=control_state,
    )
    effect = next((row for row in store.effects() if row["role"] == "harmless"), None)
    admitted = (
        state["child"] is not None or control_state.admitted_identity is not None
        or effect is not None and type(effect["observed"]) is dict
        and "invocation_id" in effect["observed"]
    )
    return {
        "running": running and admitted,
        "readiness_publication": state["publication"]["readiness"]["state"],
        "terminal_publication": state["publication"]["terminal"]["state"],
        "publisher_exit": state["publication"]["terminal"]["exit_code"],
    }




def _wait_store_role_effect(store: Any, role: str, deadline_ns: int) -> dict[str, object] | None:
    while time.monotonic_ns() < deadline_ns:
        effects = store.effects()
        row = next((item for item in effects if item["role"] == role), None)
        if row is None or row["observed"] is not None:
            return row
        time.sleep(0.05)
    return None


def _reap(names: runner_policy.RunNames) -> int:
    store, parent = _open_store(names)
    pipe = None
    control: ControlServer | None = None
    control_thread: threading.Thread | None = None
    reader_fd: int | None = None
    try:
        state = _load_state(store, names)
        _ensure_operation_source(names, state)
        if os.environ.get("DOTUNNEL_GENERATION") != state["nonce"]:
            _fail("reaper-generation-mismatch")
        outer = int(state["outer_deadline_ns"])
        self_observation = _self_service_observation(names, "reaper", min(outer, time.monotonic_ns() + 5 * _NS))
        existing = _wait_store_role_effect(store, "reaper", min(outer, time.monotonic_ns() + 5 * _NS))
        if existing is None or existing["observed"] is None:
            # receipt-start commits the observed service after its nonblocking
            # start. Reaper does not perform work before that durable transition.
            deadline = min(outer, time.monotonic_ns() + 8 * _NS)
            while existing is not None and existing["observed"] is None and time.monotonic_ns() < deadline:
                time.sleep(0.05)
                existing = _wait_store_role_effect(store, "reaper", deadline)
            if existing is None or existing["observed"] is None:
                _fail("reaper-intent-uncommitted")
        _record_unit(store, names, self_observation, replace_existing=True)
        active_usec = self_observation["manager"]["active_enter_usec"]
        reaper_start_ns = int(active_usec) * 1000
        plan = runner_policy.plan_deadlines(reaper_start_ns, outer)
        _update_state(store, names, lambda value: {
            **value, "timestamps": {**value["timestamps"], "reaper_started_ns": reaper_start_ns},
            "deadlines": {"work_ns": plan.work_ns, "cleanup_ns": plan.cleanup_ns,
                          "publish_ns": plan.publish_ns, "outer_ns": plan.outer_ns},
        })
        recovery_effect = next(
            (row for row in store.effects() if row["role"] == "recovery"), None,
        )
        if recovery_effect is None or recovery_effect["observed"] is not None:
            _fail("recovery-reservation-not-pending")
        reserved_recovery = _reconcile_pending_unit(names, store, "recovery", plan.outer_ns)
        if type(reserved_recovery) is not dict or "never_started" not in reserved_recovery:
            _fail("recovery-reservation-not-idle")
        recovery_obs = _start_recovery_probe(names, store, plan.outer_ns)
        # The one-shot recovery probe records its own invocation separately
        # from the recovery unit reserved for OnFailure.
        probe_effect = next((row for row in store.effects() if row["role"] == "recovery-probe"), None)
        if probe_effect is None:
            _fail("recovery-probe-effect-missing")
        if probe_effect["observed"] is None:
            store.commit(probe_effect["id"], {
                "unit": _unit_name(names, "recovery-probe"),
                "invocation_id": recovery_obs["invocation_id"],
            })
        pipe = runner_prepare.AdmissionPipe(deadline_ns=plan.work_ns)
        reader_fd = pipe.take_reader()
        state = _load_state(store, names)
        dispatcher = _identity_from_record(state["dispatcher"])
        cancel_handler = lambda record: _record_control_cancel(store, names, pipe, record)
        live_probe = lambda: _live_child_probe(
            names, store, plan.cleanup_ns, strict=True, pipe_reader_fd=reader_fd,
            dispatcher=dispatcher, control_state=control_state,
        )
        status_probe = lambda: _root_status_probe(
            names, store, plan.cleanup_ns, dispatcher, reader_fd, control_state,
        )
        control_state = RuntimeControlState(
            context=state["context"], boot_id=state["boot_id"], nonce=state["nonce"],
            source={"commit": state["source"]["commit"],
                    "closure_sha256": state["source"]["closure_sha256"]},
            dispatcher=dispatcher, scenario=state["scenario"], outer_deadline_ns=outer,
            cancel_handler=cancel_handler, live_probe=live_probe, status_probe=status_probe,
        )
        if state["cancel_notice"] is not None:
            control_state.cancel_notice = copy.deepcopy(state["cancel_notice"])
            control_state.phase = "CANCEL_REQUESTED"
        control = ControlServer(os.path.join(names.control, "status.sock"), control_state).start()
        control_thread = threading.Thread(target=control.serve_forever, name="runner-status-stream", daemon=True)
        control_thread.start()
        if not _process_identity_live(dispatcher):
            _set_cause(store, names, "dispatcher-dead")
            return _finish_cleanup(
                names, store, control_state, pipe, reader_fd,
                "dispatcher-dead", plan.cleanup_ns,
            )
        if state["cancel_notice"] is not None:
            return _finish_cleanup(names, store, control_state, pipe, reader_fd,
                                   "workflow-cancel-before-child", plan.cleanup_ns)
        if time.monotonic_ns() >= plan.work_ns:
            _set_cause(store, names, "work-deadline")
            return _finish_cleanup(names, store, control_state, pipe, reader_fd,
                                   "work-deadline", plan.cleanup_ns)
        child_observation = _start_harmless(
            names, store, dispatcher, pipe, reader_fd, control_state, plan.work_ns,
        )
        if child_observation is None:
            return _finish_cleanup(names, store, control_state, pipe, reader_fd,
                                   "workflow-cancel-before-go", plan.cleanup_ns)
        child_identity = _identity_from_record(child_observation["process"])
        reader_fd = None  # the verified read-only fd0 is now the only reader
        readiness = _readiness_snapshot(names, store, child_observation, plan)
        store.write_snapshot("readiness", readiness)
        readiness_digest = hashlib.sha256(_canonical(readiness)).hexdigest()
        _update_state(store, names, lambda value: {
            **value, "readiness_sha256": readiness_digest,
            "timestamps": {**value["timestamps"], "ready_ns": readiness["ready_ns"]},
        })
        control_state.set_ready(readiness, child_identity.to_record())
        if not _process_identity_live(dispatcher):
            _set_cause(store, names, "dispatcher-dead")
            return _finish_cleanup(
                names, store, control_state, pipe, reader_fd,
                "dispatcher-dead", plan.cleanup_ns,
            )
        _start_publication(names, store, "readiness", plan.publish_ns)
        while time.monotonic_ns() < plan.cleanup_ns:
            current = _load_state(store, names)
            if not _process_identity_live(dispatcher):
                _set_cause(store, names, "dispatcher-dead")
                break
            if current["cancel_notice"] is not None:
                break
            try:
                require_same_process(child_identity)
            except ProcessLookupError:
                break
            try:
                child_now = _observe_unit(names, "harmless", min(plan.cleanup_ns, time.monotonic_ns() + 2 * _NS), active=True)
                if child_now["invocation_id"] != child_observation["unit"]["invocation_id"]:
                    _set_cause(store, names, "child-generation-changed")
                    break
            except Exception:
                break
            if time.monotonic_ns() >= plan.work_ns:
                _set_cause(store, names, "work-deadline")
                break
            time.sleep(0.1)
        else:
            _set_cause(store, names, "cleanup-deadline")
        if not _process_identity_live(dispatcher):
            _set_cause(store, names, "dispatcher-dead")
        current = _load_state(store, names)
        if current["cancel_notice"] is None:
            props = _show_unit(_unit_name(names, "harmless"), min(plan.cleanup_ns, time.monotonic_ns() + 2 * _NS))
            if props["ActiveState"] == "failed":
                _set_cause(store, names, "child-failed")
            elif props["ActiveState"] == "inactive" and props["ExecMainStatus"] != "0":
                _set_cause(store, names, "child-failed")
            elif state["scenario"] == "workflow-cancel":
                _set_cause(store, names, "child-completed-before-cancel")
        return _finish_cleanup(names, store, control_state, pipe, reader_fd,
                               "normal-or-cancel", plan.cleanup_ns)
    except BaseException:
        try:
            _set_cause(store, names, "runtime-failure")
        except Exception:
            pass
        try:
            state = _load_state(store, names)
            cleanup_deadline = state["deadlines"].get("cleanup_ns") or min(int(state["outer_deadline_ns"]), time.monotonic_ns() + 30 * _NS)
            if pipe is not None:
                pipe.close()
            return _finish_cleanup(names, store, None, pipe, reader_fd, "runtime-failure", cleanup_deadline)
        except Exception:
            return 2
    finally:
        if reader_fd is not None:
            try:
                os.close(reader_fd)
            except OSError:
                pass
        if pipe is not None:
            pipe.close()
        if control is not None:
            control.close()
        if control_thread is not None:
            control_thread.join(timeout=1)
        store.close()
        os.close(parent)


def _start_recovery_probe(names: runner_policy.RunNames, store: Any,
                          deadline_ns: int) -> dict[str, object]:
    role = "recovery-probe"
    unit = _unit_name(names, role)
    _systemctl(["--no-block", "start", unit], min(deadline_ns, time.monotonic_ns() + 2 * _NS))
    definition = _load_state(store, names)["definitions"].get(role)
    if type(definition) is not dict:
        _fail("recovery-probe-definition-missing")
    observation = _wait_unit_active(
        names, role, min(deadline_ns, time.monotonic_ns() + 2 * _NS),
        definition=definition, allow_inactive=True,
    )
    # The probe persists its actual invocation before it returns; never
    # synthesize an inactive generation from the initial manager response.
    limit = min(deadline_ns, time.monotonic_ns() + 2 * _NS)
    while time.monotonic_ns() < limit:
        state = _load_state(store, names)
        latest = state["units"].get(role)
        if type(latest) is dict and latest["invocation_id"] == observation["invocation_id"]:
            return latest
        time.sleep(0.025)
    _fail("recovery-probe-observation-unavailable")


def _start_harmless(
    names: runner_policy.RunNames,
    store: Any,
    dispatcher: ProcessIdentity,
    pipe: Any,
    reader_fd: int,
    control_state: RuntimeControlState,
    deadline_ns: int,
) -> dict[str, object] | None:
    state = _load_state(store, names)
    role = "harmless"
    unit = _unit_name(names, role)
    pipe_info = os.fstat(reader_fd)
    if not stat.S_ISFIFO(pipe_info.st_mode) or os.get_inheritable(reader_fd):
        _fail("admission-reader-identity")
    effect = store.intent(role, {"unit": unit})
    _ensure_slice_definition(store, names, "work", _slice_content(names, "work", state["nonce"]))
    content = _unit_content(names, role, state["nonce"], names.source, dispatcher, reader_fd=reader_fd)
    definition = _write_unit(unit, content)
    _record_definition(store, names, role, definition)
    _systemctl(["daemon-reload"], deadline_ns)
    _systemctl(["--no-block", "start", unit], deadline_ns)
    unit_def = {
        "unit": unit, "sha256": definition["sha256"],
        "device": definition["device"], "inode": definition["inode"],
    }
    try:
        observation = _wait_unit_active(
            names, role, min(deadline_ns, time.monotonic_ns() + 5 * _NS), definition=unit_def,
        )
    except RuntimeFailure:
        with control_state.lock:
            if control_state.cancel_notice is not None:
                pipe.close()
                return None
        raise
    pid = observation["main_pid"]
    if type(pid) is not int or pid <= 0:
        _fail("harmless-child-pid-unavailable")
    process = require_same_process(observe_process(pid))
    pipe_observation = _child_command_identity(process, dispatcher, reader_fd)
    if observation["control_group"] != f"/{names.work_slice}/{unit}":
        _fail("harmless-child-outside-work-slice")
    pipe_record = {
        "device": pipe_info.st_dev, "inode": pipe_info.st_ino,
        "child_fd0": pipe_observation, "reader_exported": False,
    }
    with control_state.lock:
        if control_state.cancel_notice is not None:
            pipe.close()
            return None
        store.commit(effect, {"unit": unit, "invocation_id": observation["invocation_id"]})
        _record_unit(store, names, observation)
        work_info = _cgroup_snapshot(
            f"/{names.work_slice}", runner_policy.BUDGETS["aggregate"], require_populated=True,
        )
        child_record = {
            "process": process.to_record(), "pipe": pipe_record, "unit": unit,
        }
        _update_state(store, names, lambda value: {
            **value, "child": child_record, "phase": "RUNNING",
            "timestamps": {**value["timestamps"], "ready_ns": time.monotonic_ns()},
        })
        pipe.admit_go(pid, process.birth)
        os.close(reader_fd)
        control_state.admitted_identity = process.to_record()
        control_state.child_identity = process.to_record()
    return {
        "unit": observation, "process": process.to_record(), "pipe": pipe_record,
        "work_cgroup": work_info,
    }


def _readiness_snapshot(names: runner_policy.RunNames, store: Any,
                        child: dict[str, object], deadlines: runner_policy.Deadlines) -> dict[str, object]:
    state = _load_state(store, names)
    process = _identity_from_record(child["process"])
    require_same_process(process)
    unit = child["unit"]
    if type(unit) is not dict:
        _fail("readiness-unit-invalid")
    work = child["work_cgroup"]
    pipe = child["pipe"]
    now = time.monotonic_ns()
    readiness = {
        "schema": 1, "run": names.run, "attempt": names.attempt,
        "source": {"commit": state["source"]["commit"], "closure_sha256": state["source"]["closure_sha256"]},
        "boot_id": state["boot_id"], "scenario": state["scenario"],
        "state": "READY", "scenario_result": "PENDING", "cleanup_state": "PENDING",
        "created_ns": str(now), "ready_ns": now,
        "outer_deadline_ns": state["outer_deadline_ns"],
        "deadlines": {"work_ns": deadlines.work_ns, "cleanup_ns": deadlines.cleanup_ns,
                      "publish_ns": deadlines.publish_ns, "outer_ns": deadlines.outer_ns},
        "dispatcher": _identity_from_record(state["dispatcher"]).public_record(),
        "reaper": _public_unit(state["units"]["reaper"]),
        "recovery": _public_unit(state["units"]["recovery"]),
        "child": {
            "process": process.public_record(), "unit": _public_unit(unit),
            "stdin_pipe": {"device": pipe["device"], "inode": pipe["inode"],
                           "access": "read-only", "writer_count": 1},
            "work_cgroup": _public_cgroup(work),
        },
        "container_record_state": "NOT_CREATED",
        "external_workflow_conclusion": "NOT_VERIFIED",
        "cancel_proof": "NOT_VERIFIED",
    }
    _canonical(readiness)
    return readiness


def _public_unit(value: dict[str, object]) -> dict[str, object]:
    manager = value["manager"]
    cgroup = value["cgroup"]
    process = value["process"]
    return {
        "unit": value["unit"], "role": value["role"],
        "invocation_id": value["invocation_id"], "control_group": value["control_group"],
        "cgroup": _public_cgroup(cgroup), "main_pid": value["main_pid"],
        "main_birth": None if process is None else process["birth"],
        "memory_max": manager["memory_max"], "memory_swap_max": manager["memory_swap_max"],
        "cpu_quota_usec": manager["cpu_quota_usec"], "tasks_max": manager["tasks_max"],
        "runtime_max_usec": manager["runtime_max_usec"], "kill_mode": manager["kill_mode"],
        "timeout_stop_usec": manager["timeout_stop_usec"], "restart": manager["restart"],
        "oom_policy": manager["oom_policy"], "standard_output": manager["standard_output"],
        "standard_error": manager["standard_error"], "log_rate_interval_usec": manager["log_rate_interval_usec"],
        "log_rate_burst": manager["log_rate_burst"], "private_network": manager["private_network"],
    }


def _public_cgroup(value: dict[str, object]) -> dict[str, object]:
    return {key: value.get(key) for key in (
        "device", "inode", "control_group", "present", "memory_max", "memory_swap_max",
        "cpu_max", "tasks_max", "memory_current", "memory_swap_current", "pids_current",
        "memory_oom_group", "memory_events", "populated", "pids",
    )}


def _mark_publication(store: Any, names: runner_policy.RunNames, kind: str,
                      state_name: str, exit_code: int | None,
                      artifact: dict[str, object] | None) -> None:
    def transform(state: dict[str, Any]) -> dict[str, Any]:
        record = state["publication"][kind]
        if record["state"] != "PENDING":
            if record["state"] == state_name and record["exit_code"] == exit_code:
                return state
            _fail("publication-result-replay")
        record.update({
            "state": state_name, "exit_code": exit_code,
            "artifact_id": None if artifact is None else artifact["artifact_id"],
            "digest": None if artifact is None else artifact["digest"],
            "url": None if artifact is None else artifact["url"],
            "updated_ns": time.monotonic_ns(),
        })
        return state
    _update_state(store, names, transform)


def _start_publication(names: runner_policy.RunNames, store: Any, kind: str,
                       deadline_ns: int) -> None:
    role = "publisher-readiness" if kind == "readiness" else "publisher-terminal"
    effect = store.intent(role, {"unit": _unit_name(names, role)})
    state = _load_state(store, names)
    if state["publisher_directory"] is None:
        directory = _create_publisher_directory(names)
        _update_state(store, names, lambda value: {**value, "publisher_directory": directory})
    nonce = state["nonce"]
    dispatcher = _identity_from_record(state["dispatcher"])
    _ensure_slice_definition(
        store, names, "publisher-readiness",
        _slice_content(names, "publisher-readiness", nonce),
    )
    content = _unit_content(names, role, nonce, names.source, dispatcher)
    definition = _write_unit(_unit_name(names, role), content)
    _record_definition(store, names, role, {
        "unit": _unit_name(names, role), "sha256": definition["sha256"],
        "device": definition["device"], "inode": definition["inode"],
    })
    _systemctl(["daemon-reload"], deadline_ns)
    _systemctl(["--no-block", "start", _unit_name(names, role)], deadline_ns)
    # Commit the effect after the manager has an actual InvocationID and cgroup.
    observation = _wait_unit_started_or_finished(names, role, deadline_ns, definition={
        "unit": _unit_name(names, role), "sha256": definition["sha256"],
        "device": definition["device"], "inode": definition["inode"],
    })
    store.commit(effect, {"unit": _unit_name(names, role), "invocation_id": observation["invocation_id"]})
    _record_unit(store, names, observation)


def _wait_unit_started_or_finished(names: runner_policy.RunNames, role: str,
                                   deadline_ns: int,
                                   definition: dict[str, object]) -> dict[str, object]:
    unit = _unit_name(names, role)
    while time.monotonic_ns() < deadline_ns:
        props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
        if props["LoadState"] != "loaded" or props["FragmentPath"] != _unit_file_name(unit):
            _fail("publisher-unit-not-loaded")
        if props["InvocationID"] and re.fullmatch(r"[0-9a-f]{32}", props["InvocationID"]):
            active = props["ActiveState"] == "active"
            try:
                return _observe_unit(names, role, min(deadline_ns, time.monotonic_ns() + 2 * _NS),
                                     expected_definition=definition, active=active)
            except RuntimeFailure:
                # The oneshot can finish between manager show and cgroup read;
                # retry with the same actual invocation until its bounded exit.
                time.sleep(0.02)
        else:
            time.sleep(0.025)
    _fail("publisher-unit-start-timeout")


def _runtime_claims(token: str) -> tuple[str, str]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part or re.fullmatch(r"[A-Za-z0-9_-]+", part) is None for part in parts):
        _fail("runtime-token-claims-invalid")
    segment = parts[1]
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception:
        _fail("runtime-token-claims-invalid")
    claims = _strict_json(decoded, 16 * 1024)
    if type(claims) is not dict:
        _fail("runtime-token-claims-invalid")
    run_id = claims.get("workflow_run_backend_id")
    job_id = claims.get("workflow_job_run_backend_id")
    if (type(run_id) is not str or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", run_id) is None
            or type(job_id) is not str or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", job_id) is None):
        _fail("runtime-backend-identity-unavailable")
    return run_id, job_id


def _make_ca(directory: str, deadline_ns: int) -> tuple[str, str]:
    ca_key = os.path.join(directory, "publisher-ca.key")
    ca_cert = os.path.join(directory, "publisher-ca.pem")
    if os.path.lexists(ca_key) or os.path.lexists(ca_cert):
        _fail("publisher-ca-collision")
    _bounded_command([
        _OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", ca_key, "-out", ca_cert, "-days", "1", "-sha256",
        "-subj", "/CN=dotunnel-receipt-local-ca", "-addext",
        "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ], deadline_ns, allowed={_OPENSSL})
    for path, mode in ((ca_key, 0o600), (ca_cert, 0o400)):
        try:
            os.chmod(path, mode, follow_symlinks=False)
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            _fail("publisher-ca-creation-failed")
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
            _fail("publisher-ca-owner-mode")
    return ca_key, ca_cert


def _valid_dns_host(host: str) -> bool:
    if type(host) is not str or not host or len(host) > 253 or not host.isascii() or host.endswith("."):
        return False
    labels = host.lower().split(".")
    return all(1 <= len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)


def _leaf_context_factory(directory: str, ca_key: str, ca_cert: str,
                          deadline_ns: int) -> Callable[[str], ssl.SSLContext]:
    contexts: dict[str, ssl.SSLContext] = {}
    lock = threading.Lock()

    def context_for_host(host: str) -> ssl.SSLContext:
        if not _valid_dns_host(host):
            _fail("publisher-host-invalid")
        with lock:
            if host in contexts:
                return contexts[host]
            stem = "leaf-" + hashlib.sha256(host.encode("ascii")).hexdigest()[:16]
            key = os.path.join(directory, stem + ".key")
            csr = os.path.join(directory, stem + ".csr")
            cert = os.path.join(directory, stem + ".pem")
            serial = os.path.join(directory, "publisher-ca.srl")
            if any(os.path.lexists(path) for path in (key, csr, cert)):
                _fail("publisher-leaf-collision")
            _bounded_command([
                _OPENSSL, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", csr, "-subj", "/CN=" + host,
                "-addext", "subjectAltName=DNS:" + host,
            ], deadline_ns, allowed={_OPENSSL})
            sign_args = [
                _OPENSSL, "x509", "-req", "-in", csr, "-CA", ca_cert,
                "-CAkey", ca_key, "-out", cert, "-days", "1", "-sha256",
                "-copy_extensions", "copy",
            ]
            sign_args.extend(["-CAserial", serial] if os.path.exists(serial) else ["-CAcreateserial"])
            _bounded_command(sign_args, deadline_ns, allowed={_OPENSSL})
            for path, mode in ((key, 0o600), (csr, 0o400), (cert, 0o400)):
                try:
                    os.chmod(path, mode, follow_symlinks=False)
                    info = os.stat(path, follow_symlinks=False)
                except OSError:
                    _fail("publisher-leaf-creation-failed")
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
                    _fail("publisher-leaf-owner-mode")
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.minimum_version = ssl.TLSVersion.TLSv1_2
            server.load_cert_chain(cert, key)
            contexts[host] = server
            return server
    return context_for_host


def _publisher_directory(names: runner_policy.RunNames, state: dict[str, Any]) -> str:
    if state["publisher_directory"] is None:
        _fail("publisher-directory-record-missing")
    path = names.root + "-publisher"
    info = _secure_dir(path, owner=0, exact_mode=0o700)
    recorded = state["publisher_directory"]
    if info.st_dev != recorded["device"] or info.st_ino != recorded["inode"]:
        _fail("publisher-directory-replaced")
    return path


def _secure_node_from_state(state: dict[str, Any], deadline_ns: int) -> str:
    dispatcher = _identity_from_record(state["dispatcher"])
    try:
        path = str(Path(dispatcher.exe_path).resolve(strict=True))
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        _fail("publisher-node-unavailable")
    if ((info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
            != (dispatcher.exe_device, dispatcher.exe_inode, dispatcher.exe_uid, dispatcher.exe_mode)):
        _fail("publisher-node-generation-changed")
    _secure_root_binary(path)
    result = _bounded_command([path, "--version"], min(deadline_ns, time.monotonic_ns() + 2 * _NS),
                              allowed={path}, output_limit=128)
    if result[0] != 0 or re.fullmatch(rb"v24\.[0-9]+\.[0-9]+\n?", result[1]) is None:
        _fail("publisher-node-version")
    return path


def _publisher_child(names: runner_policy.RunNames, store: Any,
                     kind: str, deadline_ns: int, ca_key: str,
                     ca_cert: str, scratch: str) -> tuple[int, dict[str, object] | None]:
    state = _load_state(store, names)
    runtime = store.read_credentials()
    run_backend_id, job_backend_id = _runtime_claims(runtime["ACTIONS_RUNTIME_TOKEN"])
    snapshot = store.read_snapshot(kind)
    snapshot_path = os.path.join(names.root, kind + ".json")
    snapshot_info = os.stat(snapshot_path, follow_symlinks=False)
    root_fd = os.open(names.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw, recorded = _secure_record_at(root_fd, kind + ".json", maximum=_MAX_RECORD, mode=0o600)
    finally:
        os.close(root_fd)
    if (snapshot_info.st_dev, snapshot_info.st_ino) != (recorded.st_dev, recorded.st_ino):
        _fail("publisher-snapshot-identity")
    name = f"runner-{kind}-{names.run}-{names.attempt}"
    policy = runner_artifact.ArtifactGuardPolicy(
        runtime["ACTIONS_RESULTS_URL"], runtime["ACTIONS_RUNTIME_TOKEN"],
        run_backend_id, job_backend_id, name,
    )
    guard_instance = None
    host_fd = -1
    try:
        host_fd = os.open("/proc/1/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        if os.get_inheritable(host_fd) or os.readlink("/proc/self/ns/net") == os.readlink(f"/proc/self/fd/{host_fd}"):
            _fail("publisher-host-network-namespace")
        context_for_host = _leaf_context_factory(scratch, ca_key, ca_cert, deadline_ns)
        guard_instance = runner_artifact.BoundedTLSGuard(
            policy, deadline_ns=deadline_ns, host_network_fd=host_fd,
            context_for_host=context_for_host,
        )
        guard_instance.start()
        address = guard_instance.address
        node = _secure_node_from_state(state, deadline_ns)
        output_name = kind + "-output"
        output_path = os.path.join(scratch, output_name)
        output_fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.fchmod(output_fd, 0o600)
        output_info = os.fstat(output_fd)
        os.fsync(output_fd)
        os.close(output_fd)
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "junited31/dotunnel",
            "GITHUB_RUN_ID": names.run, "GITHUB_RUN_ATTEMPT": names.attempt,
            "GITHUB_OUTPUT": output_path,
            "ACTIONS_RUNTIME_TOKEN": runtime["ACTIONS_RUNTIME_TOKEN"],
            "ACTIONS_RESULTS_URL": runtime["ACTIONS_RESULTS_URL"],
            "ACTIONS_RUNTIME_URL": runtime["ACTIONS_RUNTIME_URL"],
            "NODE_EXTRA_CA_CERTS": ca_cert,
            "HTTPS_PROXY": f"http://{address[0]}:{address[1]}",
            "https_proxy": f"http://{address[0]}:{address[1]}",
            "HTTP_PROXY": f"http://{address[0]}:{address[1]}",
            "http_proxy": f"http://{address[0]}:{address[1]}",
            "INPUT_NAME": name, "INPUT_PATH": snapshot_path,
            "INPUT_IF-NO-FILES-FOUND": "error", "INPUT_RETENTION-DAYS": "7",
            "INPUT_COMPRESSION-LEVEL": "0", "INPUT_OVERWRITE": "false",
            "INPUT_INCLUDE-HIDDEN-FILES": "false",
        }
        if any(key in environment for key in ("GITHUB_TOKEN", "GH_TOKEN", "NODE_OPTIONS", "NODE_PATH")):
            _fail("publisher-environment-invalid")
        action_script = os.path.join(names.source, "upload-index.js")
        source_dir = os.open(names.source, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            action_bytes, action_info = _secure_record_at(source_dir, "upload-index.js", maximum=_MAX_SOURCE_BYTES, mode=0o400)
        finally:
            os.close(source_dir)
        if hashlib.sha256(action_bytes).hexdigest() != state["source"]["files"]["upload-index.js"]:
            _fail("publisher-action-source-changed")
        _secure_root_binary(_NODE_SET_PRIV)
        argv = [
            _NODE_SET_PRIV, "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", "--", node, action_script,
        ]
        try:
            child = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=environment, close_fds=True, start_new_session=True,
            )
        except OSError:
            _fail("publisher-child-start")
        child_birth: int | None = None
        child_identity: ProcessIdentity | None = None
        while child.poll() is None:
            remain = deadline_ns - time.monotonic_ns()
            if remain <= 0:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=1)
                _fail("publisher-child-timeout")
            try:
                observed = observe_process(child.pid)
                if observed.exe_device == os.stat(node, follow_symlinks=False).st_dev and observed.exe_inode == os.stat(node, follow_symlinks=False).st_ino:
                    child_identity = observed
                    child_birth = observed.birth
                    _verify_publisher_child(observed, runtime["ACTIONS_RUNTIME_TOKEN"], output_info)
            except ProcessLookupError:
                pass
            time.sleep(min(0.05, remain / _NS))
        exit_code = child.wait(timeout=1)
        if exit_code != 0:
            return exit_code, None
        if child_identity is None or child_birth is None:
            _fail("publisher-child-identity-unobserved")
        require_same_process(child_identity) if child.poll() is None else None
        try:
            output_fd = os.open(output_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError:
            _fail("publisher-output-unavailable")
        try:
            output_stat = os.fstat(output_fd)
            named_stat = os.stat(output_path, follow_symlinks=False)
            if ((output_stat.st_dev, output_stat.st_ino, output_stat.st_uid, output_stat.st_gid,
                 stat.S_IMODE(output_stat.st_mode), output_stat.st_nlink)
                    != (output_info.st_dev, output_info.st_ino, 0, 0, 0o600, 1)
                    or (named_stat.st_dev, named_stat.st_ino) != (output_info.st_dev, output_info.st_ino)):
                _fail("publisher-output-identity")
            raw_output = _read_fd(output_fd, 4 * 1024)
        finally:
            os.close(output_fd)
        result = runner_artifact.parse_publisher_output(raw_output)
        if (not policy.finalized or policy.uploaded_size <= 0
                or policy.uploaded_size > 128 * 1024
                or policy.uploaded_digest != result["digest"]):
            _fail("publisher-finalization-unobserved")
        return exit_code, result
    finally:
        if guard_instance is not None:
            guard_instance.close()
        if host_fd >= 0:
            os.close(host_fd)


def _verify_publisher_child(identity: ProcessIdentity, runtime_token: str,
                            output_info: os.stat_result) -> None:
    if (identity.uid != 0 or identity.gid != 0
            or identity.cap_eff.strip("0") or identity.cap_prm.strip("0")
            or identity.cap_bnd.strip("0") or identity.cap_amb.strip("0")
            or identity.no_new_privs != 1):
        _fail("publisher-capability-boundary")
    if any(runtime_token.encode("ascii") in row[-1].encode("utf-8", "surrogatepass") for row in identity.held_fds):
        _fail("publisher-secret-in-fd-name")
    has_output_fd = False
    for row in identity.held_fds:
        fd, device, inode, _uid, _gid, _mode, target = row
        if target == "" or fd < 0:
            _fail("publisher-fd-identity")
        try:
            held = os.stat(f"/proc/{identity.pid}/fd/{fd}", follow_symlinks=True)
        except OSError:
            continue
        if (held.st_dev, held.st_ino) == (output_info.st_dev, output_info.st_ino):
            has_output_fd = True
    if not has_output_fd:
        _fail("publisher-output-fd-not-held")


def _publish(names: runner_policy.RunNames, kind: str) -> int:
    store, parent = _open_store(names)
    try:
        state = _load_state(store, names)
        _ensure_operation_source(names, state)
        role = "publisher-readiness" if kind == "readiness" else "publisher-terminal"
        if os.environ.get("DOTUNNEL_GENERATION") != state["nonce"]:
            _fail("publisher-generation-mismatch")
        unit = _self_service_observation(names, role, min(int(state["outer_deadline_ns"]), time.monotonic_ns() + 3 * _NS))
        if unit["manager"]["private_network"] != "yes":
            _fail("publisher-network-isolation-missing")
        snapshot = store.read_snapshot(kind)
        expected_digest = state["readiness_sha256"] if kind == "readiness" else state["terminal_sha256"]
        if (type(snapshot) is not dict or expected_digest is None
                or hashlib.sha256(_canonical(snapshot)).hexdigest() != expected_digest):
            _fail("publisher-snapshot-digest-mismatch")
        if kind == "terminal" and snapshot != state["prepared_terminal"]:
            _fail("terminal-publish-before-freeze")
        if kind == "readiness" and snapshot.get("state") != "READY":
            _fail("readiness-publish-before-ready")
        deadline = min(int(state["outer_deadline_ns"]), time.monotonic_ns() + 30 * _NS)
        scratch = _publisher_directory(names, state)
        ca_key, ca_cert = _make_ca(scratch, deadline)
        exit_code, artifact = _publisher_child(names, store, kind, deadline, ca_key, ca_cert, scratch)
        if exit_code == 0 and artifact is not None:
            _mark_publication(store, names, kind, "LOCAL_PUBLISHED", exit_code, artifact)
            return 0
        _mark_publication(store, names, kind, "FAILED", exit_code, None)
        return 1
    except BaseException:
        try:
            current = store.read_runtime_state()
            if current is not None and current["publication"][kind]["state"] == "PENDING":
                _mark_publication(store, names, kind, "FAILED", 1, None)
        except Exception:
            pass
        return 1
    finally:
        store.close()
        os.close(parent)


def _remove_publisher_scratch(names: runner_policy.RunNames, state: dict[str, Any]) -> None:
    if state["publisher_directory"] is None:
        return
    path = names.root + "-publisher"
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        record = state["publisher_directory"]
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != record["device"] or info.st_ino != record["inode"]:
            _fail("publisher-directory-replaced")
        allowed = {
            "publisher-ca.key", "publisher-ca.pem", "publisher-ca.srl",
            "readiness-output", "terminal-output",
        }
        for name in os.listdir(directory):
            if name not in allowed and not re.fullmatch(r"leaf-[0-9a-f]{16}\.(?:key|csr|pem)", name):
                _fail("publisher-scratch-unknown-file")
            child = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(child.st_mode) or child.st_uid != 0 or child.st_nlink != 1:
                _fail("publisher-scratch-identity")
            os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)
    parent_fd = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.rmdir(names.prefix + "-publisher", dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _systemd_live_unit(names: runner_policy.RunNames, role: str,
                       state: dict[str, Any], deadline_ns: int) -> tuple[dict[str, str], dict[str, object] | None]:
    unit = _unit_name(names, role)
    props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
    if props["LoadState"] == "not-found":
        _unit_absence(unit, props)
        return props, None
    definition = state["definitions"].get(role)
    if type(definition) is not dict:
        _fail("cleanup-definition-missing")
    _read_unit_definition(unit, definition)
    if props["FragmentPath"] != _unit_file_name(unit) or props["DropInPaths"]:
        _fail("cleanup-unit-definition-mismatch")
    invocation = props["InvocationID"]
    expected = state["units"].get(role)
    if expected is not None and expected["invocation_id"] is not None and invocation != expected["invocation_id"]:
        _fail("cleanup-invocation-changed")
    manager = _manager_values(props)
    control_group = manager["control_group"]
    cgroup = None
    if control_group:
        try:
            cgroup = _cgroup_snapshot(control_group, runner_policy.BUDGETS[
                "aggregate" if role == "work" else "harmless" if role == "harmless"
                else "publisher" if role.startswith("publisher") else role
            ], require_populated=None)
        except RuntimeFailure as error:
            if error.code != "cgroup-removed":
                raise
    return props, cgroup


def _unit_pid_births(cgroup: dict[str, object] | None) -> list[dict[str, int]]:
    return [] if cgroup is None else copy.deepcopy(cgroup["pids"])


def _pid_birth_gone(value: dict[str, int]) -> bool:
    try:
        _ppid, birth = _pid_stat(value["pid"])
    except ProcessLookupError:
        return True
    return birth != value["birth"]


def _stop_owned_unit(names: runner_policy.RunNames, role: str,
                     state: dict[str, Any], deadline_ns: int,
                     *, skip: bool = False) -> dict[str, object]:
    props, before_cgroup = _systemd_live_unit(names, role, state, deadline_ns)
    unit = _unit_name(names, role)
    expected = state["units"].get(role)
    expected_cgroup = expected.get("cgroup") if type(expected) is dict else None
    old_pids = [] if type(expected_cgroup) is not dict else expected_cgroup.get("pids", [])
    if props["LoadState"] == "not-found":
        absence = _unit_absence(unit, props)
        for row in old_pids:
            if not _pid_birth_gone(row):
                _fail("cleanup-unloaded-process-live")
        slice_name = names.work_slice if role == "harmless" else _slice_name(names, role)
        cgroup_path = f"/{slice_name}/{unit}"
        if type(expected_cgroup) is dict:
            if expected_cgroup.get("control_group") != cgroup_path:
                _fail("cleanup-unloaded-cgroup-path")
            cgroup_path = expected_cgroup["control_group"]
        try:
            fresh_cgroup = _cgroup_snapshot(
                cgroup_path,
                runner_policy.BUDGETS["harmless" if role == "harmless"
                                    else "publisher" if role.startswith("publisher")
                                    else role],
                require_populated=False,
            )
        except RuntimeFailure as error:
            if error.code != "cgroup-removed":
                raise
            fresh_cgroup = None
        if fresh_cgroup is not None and (
                type(expected_cgroup) is dict
                and (fresh_cgroup["device"] != expected_cgroup.get("device")
                     or fresh_cgroup["inode"] != expected_cgroup.get("inode"))
                or fresh_cgroup["populated"] is not False or fresh_cgroup["pids"]):
            _fail("cleanup-unloaded-cgroup-not-empty")
        return {
            **absence, "invocation_id": None, "cgroup": None, "pids_gone": True,
        }
    if type(expected) is not dict or props["InvocationID"] != expected["invocation_id"]:
        if props["ActiveState"] in {"active", "activating", "deactivating"}:
            _fail("cleanup-active-unit-owner-mismatch")
        if expected is not None:
            _fail("cleanup-unit-generation-mismatch")
    current_pids = _unit_pid_births(before_cgroup)
    pids_before = current_pids + [row for row in old_pids if row not in current_pids]
    if type(expected_cgroup) is dict:
        if before_cgroup is not None and (
                before_cgroup["control_group"] != expected_cgroup.get("control_group")
                or before_cgroup["device"] != expected_cgroup.get("device")
                or before_cgroup["inode"] != expected_cgroup.get("inode")):
            _fail("cleanup-cgroup-generation-mismatch")
        if (before_cgroup is None and props["ActiveState"] in {"active", "activating", "deactivating"}
                and any(not _pid_birth_gone(row) for row in old_pids)):
            _fail("cleanup-active-cgroup-unavailable")
    if props["ActiveState"] in {"active", "activating", "deactivating"} and not skip:
        _systemctl(["stop", unit], min(deadline_ns, time.monotonic_ns() + 5 * _NS))
    elif skip:
        return {"unit": unit, "load_state": props["LoadState"],
                "active_state": props["ActiveState"],
                "main_pid": _parse_unsigned(props["MainPID"], "cleanup-main-pid"),
                "control_pid": _parse_unsigned(props["ControlPID"], "cleanup-control-pid"),
                "cgroup": before_cgroup, "pids_gone": False}
    budget = ("aggregate" if role == "work" else "harmless" if role == "harmless"
              else "publisher" if role.startswith("publisher") else role)
    while time.monotonic_ns() < deadline_ns:
        fresh = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
        if fresh["LoadState"] == "not-found":
            absence = _unit_absence(unit, fresh)
            main_pid = control_pid = 0
            active_state = "inactive"
            cgroup = None
            cgroup_present = False
        else:
            if (fresh["LoadState"] != "loaded" or fresh["FragmentPath"] != _unit_file_name(unit)
                    or fresh["DropInPaths"]):
                _fail("cleanup-unit-disappeared")
            if fresh["InvocationID"] != props["InvocationID"]:
                _fail("cleanup-invocation-reused")
            main_pid = _parse_unsigned(fresh["MainPID"], "cleanup-main-pid")
            control_pid = _parse_unsigned(fresh["ControlPID"], "cleanup-control-pid")
            active_state = fresh["ActiveState"]
            try:
                cgroup = _cgroup_snapshot(
                    fresh["ControlGroup"], runner_policy.BUDGETS[budget], require_populated=False,
                )
                cgroup_present = True
            except RuntimeFailure as error:
                if error.code != "cgroup-removed":
                    raise
                cgroup = None
                cgroup_present = False
        pids_gone = all(_pid_birth_gone(row) for row in pids_before)
        cgroup_empty = cgroup is None or cgroup["populated"] is False and not cgroup["pids"]
        if (active_state in {"inactive", "failed"} and main_pid == 0 and control_pid == 0
                and pids_gone and cgroup_empty):
            return {
                "unit": unit, "load_state": fresh["LoadState"],
                "active_state": active_state, "main_pid": main_pid,
                "control_pid": control_pid,
                "invocation_id": None if fresh["LoadState"] == "not-found" else fresh["InvocationID"],
                "cgroup": cgroup if cgroup_present else {"present": False, "observed_absent": True},
                "pids_gone": pids_gone,
            }
        time.sleep(0.05)
    _fail("cleanup-unit-not-quiescent")


def _work_slice_observation(names: runner_policy.RunNames, deadline_ns: int,
                            *, must_be_empty: bool) -> dict[str, object]:
    props = _show_unit(names.work_slice, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
    state = _load_state_from_names(names)
    child = state["units"].get("harmless")
    if props["LoadState"] == "not-found":
        _unit_absence(names.work_slice, props)
        if type(child) is dict and not all(
                _pid_birth_gone(row) for row in child["cgroup"].get("pids", [])):
            _fail("work-slice-process-live")
        try:
            cgroup = _cgroup_snapshot(
                "/" + names.work_slice, runner_policy.BUDGETS["aggregate"],
                require_populated=False,
            )
        except RuntimeFailure as error:
            if error.code != "cgroup-removed":
                raise
            cgroup = None
        if cgroup is not None and must_be_empty and (cgroup["populated"] or cgroup["pids"]):
            _fail("work-slice-populated")
        return {
            "unit": names.work_slice, "present": False, "observed_absent": True,
            "populated": False if cgroup is None else cgroup["populated"],
            "cgroup": cgroup,
        }
    definition = state["definitions"].get("work-slice")
    if (props["Id"] != names.work_slice or props["FragmentPath"] != _unit_file_name(names.work_slice)
            or props["DropInPaths"] or type(definition) is not dict):
        _fail("work-slice-identity")
    _read_unit_definition(names.work_slice, definition)
    try:
        cgroup = _cgroup_snapshot(
            "/" + names.work_slice, runner_policy.BUDGETS["aggregate"],
            require_populated=False if must_be_empty else True,
        )
    except RuntimeFailure as error:
        if (error.code != "cgroup-removed" or not must_be_empty
                or props["ActiveState"] not in {"inactive", "failed"}
                or _parse_unsigned(props["MainPID"], "work-slice-main-pid") != 0
                or _parse_unsigned(props["ControlPID"], "work-slice-control-pid") != 0):
            raise
        if type(child) is dict and not all(_pid_birth_gone(row) for row in child["cgroup"].get("pids", [])):
            _fail("work-slice-process-live")
        return {
            "unit": names.work_slice, "present": True, "observed_absent": True,
            "populated": False, "cgroup": {"present": False, "observed_absent": True},
        }
    if must_be_empty and (cgroup["populated"] or cgroup["pids"]):
        _fail("work-slice-populated")
    return {
        "unit": names.work_slice, "present": True, "observed_absent": False,
        "populated": cgroup["populated"], "cgroup": cgroup,
    }


def _close_admission(pipe: Any, reader_fd: int | None) -> None:
    if pipe is not None:
        pipe.close()
    if reader_fd is not None:
        try:
            os.close(reader_fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def _prove_unloaded_effect_quiescent(
    names: runner_policy.RunNames,
    state: dict[str, Any],
    effect: dict[str, Any],
    current_absence: dict[str, object],
    deadline_ns: int,
) -> bool:
    observed = effect["observed"]
    if observed is None:
        return True
    if (type(observed) is not dict or observed.get("unit") != current_absence["unit"]):
        return False
    if (observed.get("invocation_id") is None
            and observed.get("absence") == current_absence):
        return True
    expected = state["units"].get(effect["role"])
    if (type(expected) is not dict
            or observed.get("invocation_id") != expected.get("invocation_id")):
        return False
    cgroup = expected.get("cgroup")
    if type(cgroup) is not dict or type(cgroup.get("control_group")) is not str:
        return False
    if not all(_pid_birth_gone(row) for row in cgroup.get("pids", [])):
        return False
    try:
        fresh = _cgroup_snapshot(
            cgroup["control_group"],
            runner_policy.BUDGETS["harmless" if effect["role"] == "harmless"
                                else "publisher" if effect["role"].startswith("publisher")
                                else effect["role"]],
            require_populated=False,
        )
    except RuntimeFailure as error:
        return error.code == "cgroup-removed"
    return (
        fresh["device"] == cgroup.get("device") and fresh["inode"] == cgroup.get("inode")
        and fresh["populated"] is False and not fresh["pids"]
        and time.monotonic_ns() < deadline_ns
    )


def _emergency_fence(
    names: runner_policy.RunNames,
    store: Any,
    state: dict[str, Any],
    effects: tuple[dict[str, Any], ...],
    deadline_ns: int,
    pipe: Any,
    reader_fd: int | None,
) -> dict[str, object]:
    observations: dict[str, object] = {"units": {}, "quiescent": False}
    try:
        _close_admission(pipe, reader_fd)
        admission_closed = True
    except Exception:
        admission_closed = False
    try:
        state = _validate_state(state, names)
        allowed = {"recovery", "recovery-probe", "reaper", "harmless", "publisher-readiness", "publisher-terminal"}
        quiet = admission_closed
        units: dict[str, object] = {}
        for effect in effects:
            role = effect.get("role")
            if role not in allowed or effect.get("desired") != {"unit": _unit_name(names, role)}:
                quiet = False
                continue
            try:
                observation = _reconcile_pending_unit(names, store, role, deadline_ns)
                if observation is None:
                    props = _show_unit(
                        _unit_name(names, role), min(deadline_ns, time.monotonic_ns() + 2 * _NS),
                    )
                    absence = _unit_absence(_unit_name(names, role), props)
                    if not _prove_unloaded_effect_quiescent(names, state, effect, absence, deadline_ns):
                        quiet = False
                        units[role] = {
                            "unit": absence["unit"], "observed_absence": True, "pids_gone": False,
                        }
                    else:
                        units[role] = {**absence, "pids_gone": True}
                    continue
                recorded = effect.get("observed")
                if "never_started" in observation:
                    if ((recorded is not None and recorded != observation)
                            or (recorded is None and role in state["units"])):
                        quiet = False
                        units[role] = {
                            "unit": observation["unit"], "pids_gone": False,
                            "observation_unknown": True,
                        }
                    else:
                        units[role] = {
                            "unit": observation["unit"], "never_started": True, "pids_gone": True,
                        }
                    continue
                if (type(recorded) is dict and (
                        recorded.get("invocation_id") is None
                        or recorded.get("unit") != observation["unit"]
                        or recorded.get("invocation_id") != observation["invocation_id"])):
                    quiet = False
                    continue
                expected = state["units"].get(role)
                if expected is not None and (
                        type(expected) is not dict
                        or expected.get("invocation_id") != observation["invocation_id"]
                        or expected.get("control_group") != observation["control_group"]
                        or expected.get("cgroup", {}).get("device") != observation["cgroup"].get("device")
                        or expected.get("cgroup", {}).get("inode") != observation["cgroup"].get("inode")):
                    quiet = False
                    continue
                state["units"][role] = observation
                if observation["main_pid"] == os.getpid():
                    quiet = False
                    units[role] = {"unit": observation["unit"], "self_service": True, "active": True}
                    continue
                result = _stop_owned_unit(names, role, state, deadline_ns)
                units[role] = result
                if result.get("pids_gone") is not True:
                    quiet = False
            except Exception:
                quiet = False
                units[role] = {
                    "unit": _unit_name(names, role), "pids_gone": False,
                    "observation_unknown": True,
                }
        try:
            work = _work_slice_observation(names, deadline_ns, must_be_empty=True)
            observations["work_slice"] = work
            quiet = quiet and work.get("populated") is False
        except Exception:
            quiet = False
        publisher_slice = _slice_name(names, "publisher-readiness")
        if "publisher-slice" in state["definitions"]:
            try:
                props = _show_unit(publisher_slice, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
                if props["LoadState"] == "not-found":
                    _unit_absence(publisher_slice, props)
                    observations["publisher_slice"] = {
                        "unit": publisher_slice, "present": False, "observed_absent": True,
                    }
                else:
                    definition = state["definitions"]["publisher-slice"]
                    if (props["FragmentPath"] != _unit_file_name(publisher_slice)
                            or props["DropInPaths"]):
                        _fail("publisher-slice-identity")
                    _read_unit_definition(publisher_slice, definition)
                    cg = _cgroup_snapshot("/" + publisher_slice, runner_policy.BUDGETS["publisher"],
                                          require_populated=False)
                    observations["publisher_slice"] = cg
                    quiet = quiet and cg["populated"] is False and not cg["pids"]
            except Exception:
                quiet = False
        observations["units"] = units
        observations["quiescent"] = quiet
        return observations
    except Exception:
        return observations


def _reconcile_cleanup_effects(names: runner_policy.RunNames, store: Any,
                               deadline_ns: int) -> None:
    allowed = {
        "recovery", "recovery-probe", "reaper", "harmless",
        "publisher-readiness", "publisher-terminal",
    }
    for effect in store.effects():
        role = effect["role"]
        unit = _unit_name(names, role) if role in allowed else None
        if unit is None or effect["desired"] != {"unit": unit}:
            _fail("cleanup-effect-role-invalid")
        observed = effect["observed"]
        if observed is None:
            observation = _reconcile_pending_unit(names, store, role, deadline_ns)
            if observation is None:
                absence = _unit_absence(
                    unit, _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS)),
                )
                store.commit_absence(effect["id"], absence)
                continue
            if "never_started" in observation:
                store.commit(effect["id"], observation)
            else:
                store.commit(effect["id"], {
                    "unit": unit, "invocation_id": observation["invocation_id"],
                })
                _record_unit(store, names, observation, replace_existing=True)
            continue
        if (type(observed) is not dict or observed.get("unit") != unit
                or set(observed) not in ({"unit", "invocation_id"},
                                         {"unit", "invocation_id", "absence"},
                                         {"unit", "invocation_id", "never_started"})):
            _fail("cleanup-effect-observation-invalid")
        if "never_started" in observed:
            fresh = _reconcile_pending_unit(names, store, role, deadline_ns)
            if fresh != observed:
                _fail("cleanup-effect-never-started-changed")
            continue
        if observed["invocation_id"] is None:
            if set(observed) != {"unit", "invocation_id", "absence"}:
                _fail("cleanup-effect-absence-invalid")
            props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
            if props["LoadState"] != "not-found" or _unit_absence(unit, props) != observed["absence"]:
                _fail("cleanup-effect-absence-changed")
            continue
        if (set(observed) != {"unit", "invocation_id"}
                or type(observed["invocation_id"]) is not str
                or re.fullmatch(r"[0-9a-f]{32}", observed["invocation_id"]) is None):
            _fail("cleanup-effect-invocation-invalid")
        observation = _reconcile_pending_unit(names, store, role, deadline_ns)
        if observation is None:
            continue
        if observation["invocation_id"] != observed["invocation_id"]:
            _fail("cleanup-effect-generation-changed")
        _record_unit(store, names, observation, replace_existing=True)


def _freeze_terminal_snapshot(
    names: runner_policy.RunNames,
    store: Any,
    state: dict[str, Any],
    scenario_result: str,
    cleanup_state: str,
    cause: str | None,
    observations: dict[str, object],
    work_populated: bool,
    reason: str,
) -> tuple[dict[str, object], str]:
    try:
        snapshot = store.read_snapshot("terminal")
    except ValueError as error:
        if str(error) != "authority-record-not-committed":
            raise
        snapshot = None
    if snapshot is None:
        if state["prepared_terminal"] is not None or state["terminal_sha256"] is not None:
            _fail("terminal-snapshot-state-missing")
        snapshot = _terminal_snapshot(
            names, store, state, scenario_result, cleanup_state, cause,
            observations, work_populated, reason,
        )
        store.write_snapshot("terminal", snapshot)
    expected_fields = {
        "schema", "run", "attempt", "source", "boot_id", "scenario",
        "scenario_result", "cleanup_state", "original_cause", "cleanup_reason",
        "created_ns", "terminal_ns", "timestamps", "dispatcher", "readiness_sha256",
        "readiness", "cancel", "cleanup_observations", "work_populated",
        "container_record_state", "publication_state", "external_cancel_acceptance",
        "external_workflow_conclusion", "cancel_proof",
    }
    digest = hashlib.sha256(_canonical(snapshot)).hexdigest()
    cancel = state["cancel_notice"]
    expected_cancel = None if cancel is None else {
        "notice_ns": cancel["notice_ns"], "received_ns": cancel["received_ns"],
        "live_at_notice": cancel["live_at_notice"], "child": cancel["child"],
    }
    if (type(snapshot) is not dict or set(snapshot) != expected_fields
            or type(snapshot["schema"]) is not int or snapshot["schema"] != 1
            or snapshot["run"] != names.run or snapshot["attempt"] != names.attempt
            or snapshot["source"] != {
                "commit": state["source"]["commit"],
                "closure_sha256": state["source"]["closure_sha256"],
            }
            or snapshot["boot_id"] != state["boot_id"] or snapshot["scenario"] != state["scenario"]
            or snapshot["scenario_result"] not in {"PASS", "FAIL", "NOT_VERIFIED"}
            or snapshot["cleanup_state"] not in {"COMPLETE", "UNKNOWN"}
            or snapshot["cancel"] != expected_cancel
            or snapshot["dispatcher"] != _identity_from_record(state["dispatcher"]).public_record()
            or snapshot["external_cancel_acceptance"] != "NOT_VERIFIED"
            or snapshot["external_workflow_conclusion"] != "NOT_VERIFIED"
            or snapshot["cancel_proof"] != "NOT_VERIFIED"
            or state["prepared_terminal"] is not None and state["prepared_terminal"] != snapshot
            or state["terminal_sha256"] is not None and state["terminal_sha256"] != digest):
        _fail("terminal-snapshot-binding")
    if state["prepared_terminal"] is None or state["terminal_sha256"] is None:
        _update_state(store, names, lambda value: {
            **value, "prepared_terminal": snapshot, "terminal_sha256": digest,
            "timestamps": {**value["timestamps"], "cleanup_finished_ns": time.monotonic_ns(),
                           "terminal_ns": snapshot["terminal_ns"]},
        })
    return snapshot, digest
_CONTROL_STATUS_FIELDS = frozenset({
    "schema", "run", "attempt", "state", "ready", "running", "cancel_ack",
    "cancel_notice_ns", "cancel_received_ns", "live_at_notice", "terminal",
    "readiness_publication", "terminal_publication", "publisher_exit",
    "snapshot_sha256", "updated_ns", "boot_id", "nonce", "source",
})


def _terminal_status_projection(names: runner_policy.RunNames,
                                state: dict[str, Any],
                                snapshot: dict[str, object]) -> dict[str, object]:
    if type(snapshot) is not dict:
        _fail("terminal-status-snapshot-invalid")
    digest = hashlib.sha256(_canonical(snapshot)).hexdigest()
    if (state["prepared_terminal"] != snapshot or state["terminal_sha256"] != digest
            or snapshot.get("run") != names.run or snapshot.get("attempt") != names.attempt
            or snapshot.get("boot_id") != state["boot_id"]
            or snapshot.get("source") != {
                "commit": state["source"]["commit"],
                "closure_sha256": state["source"]["closure_sha256"],
            }):
        _fail("terminal-status-snapshot-binding")
    cancel = state["cancel_notice"]
    if cancel is not None:
        notice = cancel["notice_ns"]
        received = cancel["received_ns"]
        if (type(notice) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", notice) is None
                or type(received) is not int or received < int(notice)
                or type(cancel["live_at_notice"]) is not bool):
            _fail("terminal-status-cancel-order")
    else:
        notice = received = None
    publication = state["publication"]
    terminal_ns = snapshot.get("terminal_ns")
    if type(terminal_ns) is not int or terminal_ns <= 0:
        _fail("terminal-status-time")
    status: dict[str, object] = {
        "schema": 1, "run": names.run, "attempt": names.attempt,
        "state": "TERMINAL", "ready": state["readiness_sha256"] is not None,
        "running": False, "cancel_ack": cancel is not None,
        "cancel_notice_ns": notice,
        "cancel_received_ns": None if received is None else str(received),
        "live_at_notice": None if cancel is None else cancel["live_at_notice"],
        "terminal": True,
        "readiness_publication": publication["readiness"]["state"],
        "terminal_publication": publication["terminal"]["state"],
        "publisher_exit": publication["terminal"]["exit_code"],
        "snapshot_sha256": digest, "updated_ns": str(terminal_ns),
        "boot_id": state["boot_id"], "nonce": state["nonce"],
        "source": {
            "commit": state["source"]["commit"],
            "closure_sha256": state["source"]["closure_sha256"],
        },
    }
    if set(status) != _CONTROL_STATUS_FIELDS:
        _fail("terminal-status-projection-schema")
    return status


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode), info.st_nlink,
    )

def _directory_anchor(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
    )


def _open_control_directory(names: runner_policy.RunNames,
                            state: dict[str, Any]) -> tuple[int, int, tuple[int, int, int, int, int, int]]:
    expected = state["control_directory"]
    basename = names.prefix + "-control"
    if (type(expected) is not dict
            or set(expected) != {"device", "inode", "uid", "mode"}
            or type(expected["device"]) is not int or type(expected["inode"]) is not int
            or expected["uid"] != 0 or expected["mode"] != 0o711
            or names.control != os.path.join(_RUN_DIR, basename)):
        _fail("control-directory-record")
    if os.geteuid() != 0:
        _fail("terminal-status-root-required")
    parent_fd = -1
    directory_fd = -1
    try:
        _secure_dir(_RUN_DIR, owner=0)
        parent_fd = os.open(_RUN_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        parent_info = os.fstat(parent_fd)
        named_parent = os.stat(_RUN_DIR, follow_symlinks=False)
        if (_directory_anchor(parent_info) != _directory_anchor(named_parent)
                or parent_info.st_uid != 0):
            _fail("control-parent-generation")
        directory_fd = os.open(
            basename, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        info = os.fstat(directory_fd)
        named = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
        identity = _directory_identity(info)
        if (identity != _directory_identity(named) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o711 or info.st_nlink < 2
                or (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
                != (expected["device"], expected["inode"], expected["uid"], expected["mode"])):
            _fail("control-directory-generation")
        return parent_fd, directory_fd, identity
    except Exception:
        if directory_fd >= 0:
            os.close(directory_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        raise


def _assert_control_directory(names: runner_policy.RunNames,
                              parent_fd: int, directory_fd: int,
                              expected: tuple[int, int, int, int, int, int]) -> None:
    basename = names.prefix + "-control"
    held_parent = os.fstat(parent_fd)
    named_parent = os.stat(_RUN_DIR, follow_symlinks=False)
    held = os.fstat(directory_fd)
    named = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
    if (_directory_anchor(held_parent) != _directory_anchor(named_parent)
            or held_parent.st_uid != 0
            or _directory_identity(held) != expected
            or _directory_identity(named) != expected):
        _fail("control-directory-replaced")


def _read_terminal_status_at(names: runner_policy.RunNames,
                             parent_fd: int, directory_fd: int,
                             expected_directory: tuple[int, int, int, int, int, int],
                             *, name: str = "terminal-status.json",
                             mode: int = 0o444) -> bytes:
    _assert_control_directory(names, parent_fd, directory_fd, expected_directory)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory_fd)
    except OSError:
        _fail("terminal-status-record-unavailable")
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > 64 * 1024):
            _fail("terminal-status-record-identity")
        raw = _read_fd(fd, 64 * 1024)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        stable = lambda info: (
            info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )
        if (len(raw) != before.st_size or stable(before) != stable(after)
                or stable(before) != stable(named)):
            _fail("terminal-status-record-changed")
        _assert_control_directory(names, parent_fd, directory_fd, expected_directory)
        return raw
    finally:
        os.close(fd)


def _write_terminal_status_record(names: runner_policy.RunNames,
                                  store: Any, deadline_ns: int) -> dict[str, object]:
    if store.terminal_receipt() is None:
        _fail("terminal-status-before-compact-receipt")
    state = _load_state(store, names)
    _ensure_operation_source(names, state)
    snapshot = store.read_snapshot("terminal")
    status = _terminal_status_projection(names, state, snapshot)
    wrapper: dict[str, object] = {
        "schema": 1, "context": copy.deepcopy(state["context"]),
        "source": {
            "commit": state["source"]["commit"],
            "closure_sha256": state["source"]["closure_sha256"],
        },
        "boot_id": state["boot_id"], "nonce": state["nonce"], "status": status,
    }
    raw = _canonical(wrapper, 64 * 1024)
    parent_fd, directory_fd, directory_identity = _open_control_directory(names, state)
    try:
        _assert_control_directory(names, parent_fd, directory_fd, directory_identity)
        try:
            os.stat("terminal-status.json", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            _fail("terminal-status-record-collision")
        else:
            if _read_terminal_status_at(names, parent_fd, directory_fd, directory_identity) != raw:
                _fail("terminal-status-record-collision")
            return wrapper
        work = _work_slice_observation(names, deadline_ns, must_be_empty=True)
        publisher_slice = _publisher_slice_observation(names, state, deadline_ns)
        if (work.get("populated") is not False or publisher_slice.get("populated") is not False
                or not _publishers_quiescent(names, state, deadline_ns)):
            _fail("terminal-status-before-publication-quiescence")
        try:
            fd = os.open(
                "terminal-status.next",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600, dir_fd=directory_fd,
            )
        except FileExistsError:
            try:
                os.stat("terminal-status.json", dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                _fail("terminal-status-temporary-collision")
            if _read_terminal_status_at(names, parent_fd, directory_fd, directory_identity) != raw:
                _fail("terminal-status-record-collision")
            return wrapper
        except OSError:
            _fail("terminal-status-temporary-create")
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or before.st_size != 0):
                _fail("terminal-status-temporary-identity")
            written = 0
            while written < len(raw):
                try:
                    count = os.write(fd, raw[written:])
                except InterruptedError:
                    continue
                if count <= 0:
                    _fail("terminal-status-temporary-write")
                written += count
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            if _read_fd(fd, 64 * 1024) != raw:
                _fail("terminal-status-temporary-readback")
            complete = os.fstat(fd)
            if (complete.st_size != len(raw) or complete.st_uid != 0 or complete.st_gid != 0
                    or stat.S_IMODE(complete.st_mode) != 0o600 or complete.st_nlink != 1):
                _fail("terminal-status-temporary-readback")
            os.fchmod(fd, 0o444)
            os.fsync(fd)
            finalized = os.fstat(fd)
            named = os.stat("terminal-status.next", dir_fd=directory_fd, follow_symlinks=False)
            stable = lambda info: (
                info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size,
            )
            if (stat.S_IMODE(finalized.st_mode) != 0o444 or finalized.st_uid != 0
                    or finalized.st_gid != 0 or finalized.st_nlink != 1
                    or finalized.st_size != len(raw) or stable(finalized) != stable(named)):
                _fail("terminal-status-temporary-finalization")
        finally:
            os.close(fd)
        os.fsync(directory_fd)
        _assert_control_directory(names, parent_fd, directory_fd, directory_identity)
        try:
            _rename_terminal_noreplace(directory_fd)
        except FileExistsError:
            if _read_terminal_status_at(names, parent_fd, directory_fd, directory_identity) == raw:
                return wrapper
            _fail("terminal-status-record-collision")
        except OSError:
            _fail("terminal-status-atomic-rename")
        os.fsync(directory_fd)
        _assert_control_directory(names, parent_fd, directory_fd, directory_identity)
        if _read_terminal_status_at(names, parent_fd, directory_fd, directory_identity) != raw:
            _fail("terminal-status-record-verification")
        return wrapper
    finally:
        os.close(directory_fd)
        os.close(parent_fd)

def _rename_terminal_noreplace(directory_fd: int) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        _fail("terminal-status-atomic-rename-unavailable")
    renameat2.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd, b"terminal-status.next",
        directory_fd, b"terminal-status.json", 1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(
            error_number, os.strerror(error_number), "terminal-status.json",
        )
    raise OSError(
        error_number, os.strerror(error_number), "terminal-status.json",
    )


def _cleanup_receipt(names: runner_policy.RunNames, store: Any,
                     reason: str, cleanup_deadline_ns: int,
                     *, control_state: RuntimeControlState | None = None,
                     pipe: Any = None, reader_fd: int | None = None,
                     claimed: bool = False) -> int:
    state: dict[str, Any] | None = None
    effects: tuple[dict[str, Any], ...] = ()
    observations: dict[str, object] = {}

    def sync_control_terminal(current: dict[str, Any]) -> None:
        if control_state is None:
            return
        terminal_snapshot = store.read_snapshot("terminal")
        digest = hashlib.sha256(_canonical(terminal_snapshot)).hexdigest()
        if (current["prepared_terminal"] != terminal_snapshot
                or current["terminal_sha256"] != digest):
            _fail("control-terminal-snapshot-mismatch")
        control_state.set_publication(
            "readiness", current["publication"]["readiness"]["state"],
            current["publication"]["readiness"]["exit_code"],
            current["publication"]["readiness"]["digest"],
        )
        control_state.set_publication(
            "terminal", current["publication"]["terminal"]["state"],
            current["publication"]["terminal"]["exit_code"], digest,
        )
        control_state.set_terminal(terminal_snapshot, digest)

    try:
        state = _load_state(store, names)
        effects = store.effects()
    except BaseException:
        try:
            _close_admission(pipe, reader_fd)
        except BaseException:
            pass
        return 2
    if control_state is not None:
        with control_state.lock:
            if control_state.terminal is None:
                control_state.phase = "CLEANUP"
                control_state.updated_ns = time.monotonic_ns()
    try:
        _close_admission(pipe, reader_fd)
        if store.terminal_receipt() is not None:
            try:
                _write_terminal_status_record(names, store, cleanup_deadline_ns)
                sync_control_terminal(_load_state(store, names))
                return 0
            except BaseException:
                return 2
        if not claimed:
            if not store.begin_cleanup():
                _wait_cleanup_terminal(store, cleanup_deadline_ns)
                try:
                    if store.terminal_receipt() is None:
                        return 2
                    _write_terminal_status_record(names, store, cleanup_deadline_ns)
                    sync_control_terminal(_load_state(store, names))
                    return 0
                except BaseException:
                    return 2
        _update_state(store, names, lambda value: {
            **value, "phase": "CLEANING",
            "timestamps": {
                **value["timestamps"],
                "cleanup_started_ns": value["timestamps"]["cleanup_started_ns"] or time.monotonic_ns(),
            },
        })
        state = _load_state(store, names)
        effects = store.effects()
        _reconcile_cleanup_effects(names, store, cleanup_deadline_ns)
        state = _load_state(store, names)
        effects = store.effects()
        effect_roles = {row["role"]: row for row in effects}
        readiness_effect = effect_roles.get("publisher-readiness")
        if (readiness_effect is not None
                and state["publication"]["readiness"]["state"] == "PENDING"
                and type(readiness_effect["observed"]) is dict
                and readiness_effect["observed"].get("invocation_id") is not None):
            publish_deadline = min(
                cleanup_deadline_ns,
                state["deadlines"].get("publish_ns") or cleanup_deadline_ns,
            )
            _wait_publisher_quiescent(names, store, "readiness", publish_deadline)
            state = _load_state(store, names)
            effects = store.effects()

        # Reconcile and stop only generations owned by a durable effect row.
        for role in (
            "publisher-readiness", "publisher-terminal", "harmless",
            "recovery-probe", "recovery", "reaper",
        ):
            if role not in state["definitions"]:
                continue
            effect = next((row for row in effects if row["role"] == role), None)
            if effect is None:
                continue
            if (type(effect["observed"]) is dict
                    and "never_started" in effect["observed"]):
                fresh = _reconcile_pending_unit(names, store, role, cleanup_deadline_ns)
                if fresh != effect["observed"]:
                    _fail("cleanup-never-started-generation-changed")
                observations[role] = {
                    "unit": _unit_name(names, role), "never_started": True, "pids_gone": True,
                }
                continue
            unit_state = state["units"].get(role)
            is_current_actor = (
                type(unit_state) is dict and unit_state.get("main_pid") == os.getpid()
            )
            observations[role] = _stop_owned_unit(
                names, role, state, cleanup_deadline_ns, skip=is_current_actor,
            )
            state = _load_state(store, names)
            effects = store.effects()

        observations["work_slice"] = _work_slice_observation(
            names, cleanup_deadline_ns, must_be_empty=True,
        )
        state = _load_state(store, names)
        observations["publisher_slice"] = _publisher_slice_observation(
            names, state, cleanup_deadline_ns,
        )
        publishers_empty = _publishers_quiescent(names, state, cleanup_deadline_ns)
        physically_quiescent = (
            observations["work_slice"].get("populated") is False
            and observations["publisher_slice"].get("populated") is False
            and publishers_empty
        )
        if not physically_quiescent:
            fence = _emergency_fence(
                names, store, state, effects, cleanup_deadline_ns, pipe, reader_fd,
            )
            observations["emergency_fence"] = {
                "quiescent": fence.get("quiescent") is True,
            }
            observations["work_slice"] = _work_slice_observation(
                names, cleanup_deadline_ns, must_be_empty=True,
            )
            state = _load_state(store, names)
            observations["publisher_slice"] = _publisher_slice_observation(
                names, state, cleanup_deadline_ns,
            )
            publishers_empty = _publishers_quiescent(names, state, cleanup_deadline_ns)
            physically_quiescent = (
                fence.get("quiescent") is True
                and observations["work_slice"].get("populated") is False
                and observations["publisher_slice"].get("populated") is False
                and publishers_empty
            )
            if not physically_quiescent:
                return 2

        state = _load_state(store, names)
        effects = store.effects()
        child_effect = next((row for row in effects if row["role"] == "harmless"), None)
        child_status: dict[str, str] | None = None
        if (child_effect is not None and type(child_effect["observed"]) is dict
                and child_effect["observed"].get("invocation_id") is not None):
            child_status = _show_unit(
                _unit_name(names, "harmless"),
                min(cleanup_deadline_ns, time.monotonic_ns() + 2 * _NS),
            )
            if (child_status["LoadState"] != "loaded"
                    or child_status["InvocationID"] != child_effect["observed"]["invocation_id"]
                    or child_status["ActiveState"] not in {"inactive", "failed"}
                    or child_status["MainPID"] != "0" or child_status["ControlPID"] != "0"):
                _fail("harmless-child-terminal-observation")

        readiness_snapshot = None
        readiness_valid = False
        if state["readiness_sha256"] is not None:
            readiness_snapshot = store.read_snapshot("readiness")
            readiness_valid = (
                type(readiness_snapshot) is dict
                and hashlib.sha256(_canonical(readiness_snapshot)).hexdigest()
                == state["readiness_sha256"]
                and readiness_snapshot.get("run") == names.run
                and readiness_snapshot.get("attempt") == names.attempt
                and readiness_snapshot.get("boot_id") == state["boot_id"]
                and readiness_snapshot.get("source") == {
                    "commit": state["source"]["commit"],
                    "closure_sha256": state["source"]["closure_sha256"],
                }
            )
            if not readiness_valid:
                _fail("readiness-snapshot-binding")
        cause = state["original_cause"]
        readiness_published = state["publication"]["readiness"]["state"] == "LOCAL_PUBLISHED"
        normal_ok = (
            state["scenario"] == "normal"
            and child_status is not None
            and child_status["ActiveState"] == "inactive"
            and child_status["ExecMainStatus"] == "0"
            and state["child"] is not None
            and readiness_valid and readiness_published and cause is None
        )
        cancel = state["cancel_notice"]
        cancel_ok = (
            state["scenario"] == "workflow-cancel"
            and type(cancel) is dict
            and cancel["live_at_notice"] is True
            and state["child"] is not None
            and readiness_valid and readiness_published and cause is None
        )
        if cause is None and not normal_ok and not cancel_ok:
            cause = "harmless-child-not-complete"
            _set_cause(store, names, cause)
            state = _load_state(store, names)
        scenario_result = "PASS" if normal_ok else "NOT_VERIFIED" if cancel_ok else "FAIL"
        sanitized_observations: dict[str, object] = {
            "work_slice": {
                "populated": observations["work_slice"].get("populated") is True,
                "observed_absent": observations["work_slice"].get("observed_absent") is True,
            },
            "publisher_slice": {
                "populated": observations["publisher_slice"].get("populated") is True,
                "observed_absent": observations["publisher_slice"].get("observed_absent") is True,
            },
            "publisher_units_quiescent": publishers_empty,
        }
        if "emergency_fence" in observations:
            sanitized_observations["emergency_fence"] = observations["emergency_fence"]
        terminal, terminal_sha = _freeze_terminal_snapshot(
            names, store, state, scenario_result, "COMPLETE", cause,
            sanitized_observations, False, reason,
        )
        state = _load_state(store, names)
        effects = store.effects()
        terminal_effect = next(
            (row for row in effects if row["role"] == "publisher-terminal"), None,
        )
        if terminal_effect is None:
            if state["publication"]["terminal"]["state"] != "PENDING":
                _fail("terminal-publisher-effect-missing")
            _start_publication(
                names, store, "terminal",
                min(cleanup_deadline_ns, int(state["outer_deadline_ns"])),
            )
            pub_state = _wait_publisher_quiescent(names, store, "terminal", cleanup_deadline_ns)
            if pub_state["state"] not in {"LOCAL_PUBLISHED", "FAILED", "UNKNOWN"}:
                _fail("terminal-publication-result-invalid")
        else:
            if state["publication"]["terminal"]["state"] == "PENDING":
                _mark_publication(store, names, "terminal", "UNKNOWN", None, None)
        state = _load_state(store, names)
        effects = store.effects()
        terminal_effect = next(
            (row for row in effects if row["role"] == "publisher-terminal"), None,
        )
        if terminal_effect is not None:
            unit_state = state["units"].get("publisher-terminal")
            is_current_actor = (
                type(unit_state) is dict and unit_state.get("main_pid") == os.getpid()
            )
            observations["publisher-terminal"] = _stop_owned_unit(
                names, "publisher-terminal", state, cleanup_deadline_ns,
                skip=is_current_actor,
            )
        state = _load_state(store, names)
        observations["work_slice"] = _work_slice_observation(
            names, cleanup_deadline_ns, must_be_empty=True,
        )
        observations["publisher_slice"] = _publisher_slice_observation(
            names, state, cleanup_deadline_ns,
        )
        publishers_empty = _publishers_quiescent(names, state, cleanup_deadline_ns)
        if (observations["work_slice"].get("populated") is not False
                or observations["publisher_slice"].get("populated") is not False
                or not publishers_empty):
            _fail("terminal-publication-not-quiescent")
        store.remove_credentials()
        _remove_publisher_scratch(names, state)
        readiness_state = state["publication"]["readiness"]["state"]
        terminal_state = state["publication"]["terminal"]["state"]
        if (readiness_state != "LOCAL_PUBLISHED" or terminal_state != "LOCAL_PUBLISHED"):
            cause = _set_cause(store, names, cause or "publication-failed")
            state = _load_state(store, names)
        final_result = (
            "PASS" if scenario_result == "PASS" and cause is None
            and readiness_state == "LOCAL_PUBLISHED" and terminal_state == "LOCAL_PUBLISHED"
            else "NOT_VERIFIED" if scenario_result == "NOT_VERIFIED" and cause is None
            and readiness_state == "LOCAL_PUBLISHED" and terminal_state == "LOCAL_PUBLISHED"
            else "FAIL"
        )
        _update_state(store, names, lambda value: {
            **value, "phase": "CLEANUP_TERMINAL",
            "timestamps": {
                **value["timestamps"],
                "cleanup_finished_ns": value["timestamps"]["cleanup_finished_ns"] or time.monotonic_ns(),
                "terminal_ns": terminal["terminal_ns"],
            },
        })
        store.finish_cleanup({
            "scenario_result": final_result, "cleanup_state": "COMPLETE",
            "original_cause": cause, "work_populated": False,
            "container_record_state": "NOT_CREATED",
        })
        _write_terminal_status_record(names, store, cleanup_deadline_ns)
        sync_control_terminal(_load_state(store, names))
        return 0
    except BaseException:
        if state is not None:
            try:
                _emergency_fence(
                    names, store, state, effects, cleanup_deadline_ns, pipe, reader_fd,
                )
            except BaseException:
                pass
        return 2
def _finish_cleanup(names: runner_policy.RunNames, store: Any,
                    control_state: RuntimeControlState | None, pipe: Any,
                    reader_fd: int | None, reason: str, cleanup_deadline_ns: int) -> int:
    return _cleanup_receipt(names, store, reason, cleanup_deadline_ns,
                            control_state=control_state, pipe=pipe, reader_fd=reader_fd)


def _terminal_snapshot(names: runner_policy.RunNames, store: Any,
                       state: dict[str, Any], scenario_result: str,
                       cleanup_state: str, cause: str | None,
                       observations: dict[str, object], work_populated: bool,
                       reason: str) -> dict[str, object]:
    cancel = state["cancel_notice"]
    readiness = store.read_snapshot("readiness") if state["readiness_sha256"] is not None else None
    return {
        "schema": 1, "run": names.run, "attempt": names.attempt,
        "source": {"commit": state["source"]["commit"], "closure_sha256": state["source"]["closure_sha256"]},
        "boot_id": state["boot_id"], "scenario": state["scenario"],
        "scenario_result": scenario_result, "cleanup_state": cleanup_state,
        "original_cause": cause, "cleanup_reason": reason,
        "created_ns": str(time.monotonic_ns()), "terminal_ns": time.monotonic_ns(),
        "timestamps": copy.deepcopy(state["timestamps"]),
        "dispatcher": _identity_from_record(state["dispatcher"]).public_record(),
        "readiness_sha256": state["readiness_sha256"],
        "readiness": None if readiness is None else {
            "state": readiness["state"], "ready_ns": readiness["ready_ns"],
            "child": readiness["child"],
        },
        "cancel": None if cancel is None else {
            "notice_ns": cancel["notice_ns"], "received_ns": cancel["received_ns"],
            "live_at_notice": cancel["live_at_notice"], "child": cancel["child"],
        },
        "cleanup_observations": observations,
        "work_populated": work_populated,
        "container_record_state": "NOT_CREATED",
        "publication_state": "PENDING",
        "external_cancel_acceptance": "NOT_VERIFIED",
        "external_workflow_conclusion": "NOT_VERIFIED",
        "cancel_proof": "NOT_VERIFIED",
    }


def _wait_cleanup_terminal(store: Any, deadline_ns: int) -> None:
    while time.monotonic_ns() < deadline_ns:
        try:
            if store.terminal_receipt() is not None:
                return
        except Exception:
            return
        time.sleep(0.05)


def _wait_publisher_quiescent(names: runner_policy.RunNames, store: Any,
                              kind: str, deadline_ns: int) -> dict[str, object]:
    role = "publisher-readiness" if kind == "readiness" else "publisher-terminal"
    unit = _unit_name(names, role)
    while time.monotonic_ns() < deadline_ns:
        props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
        if props["LoadState"] == "loaded" and props["ActiveState"] in {"inactive", "failed"}:
            current = _load_state(store, names)
            result = current["publication"][kind]
            if result["state"] in {"LOCAL_PUBLISHED", "FAILED"}:
                return result
        time.sleep(0.05)
    _set_cause(store, names, "publisher-deadline")
    _systemctl(["--no-block", "stop", unit], min(deadline_ns, time.monotonic_ns() + _NS))
    _mark_publication(store, names, kind, "UNKNOWN", None, None)
    return _load_state(store, names)["publication"][kind]


def _publishers_quiescent(names: runner_policy.RunNames,
                          state: dict[str, Any], deadline_ns: int) -> bool:
    for role in ("publisher-readiness", "publisher-terminal"):
        unit = _unit_name(names, role)
        definition = state["definitions"].get(role)
        props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
        if definition is None:
            if props["LoadState"] != "not-found":
                return False
            _unit_absence(unit, props)
            cgroup_path = f"/{_slice_name(names, role)}/{unit}"
            try:
                actual_cgroup = _cgroup_snapshot(
                    cgroup_path, runner_policy.BUDGETS["publisher"], require_populated=False,
                )
            except RuntimeFailure as error:
                if error.code != "cgroup-removed":
                    raise
                continue
            if actual_cgroup["populated"] or actual_cgroup["pids"]:
                return False
            continue
        if type(definition) is not dict:
            return False
        if (props["LoadState"] != "loaded" or props["Id"] != unit
                or props["FragmentPath"] != _unit_file_name(unit) or props["DropInPaths"]
                or props["ActiveState"] not in {"inactive", "failed"}
                or _parse_unsigned(props["MainPID"], "publisher-main-pid") != 0
                or _parse_unsigned(props["ControlPID"], "publisher-control-pid") != 0):
            return False
        expected = state["units"].get(role)
        expected_cgroup = expected.get("cgroup") if type(expected) is dict else None
        if type(expected) is dict and (
                props["InvocationID"] != expected.get("invocation_id")
                or props["ControlGroup"] != expected.get("control_group")):
            return False
        if props["ControlGroup"] != f"/{_slice_name(names, role)}/{unit}":
            return False
        try:
            actual_cgroup = _cgroup_snapshot(
                props["ControlGroup"], runner_policy.BUDGETS["publisher"],
                require_populated=False,
            )
        except RuntimeFailure as error:
            if error.code != "cgroup-removed":
                raise
            if type(expected_cgroup) is dict and not all(
                    _pid_birth_gone(row) for row in expected_cgroup.get("pids", [])):
                return False
            continue
        if type(expected_cgroup) is dict and (
                actual_cgroup["device"] != expected_cgroup.get("device")
                or actual_cgroup["inode"] != expected_cgroup.get("inode")):
            return False
        if (actual_cgroup["populated"] is not False or actual_cgroup["pids"]
                or type(expected_cgroup) is dict
                and not all(_pid_birth_gone(row) for row in expected_cgroup.get("pids", []))):
            return False
    return True


def _publisher_slice_observation(names: runner_policy.RunNames,
                                 state: dict[str, Any], deadline_ns: int) -> dict[str, object]:
    role = "publisher-slice"
    unit = _slice_name(names, "publisher-readiness")
    definition = state["definitions"].get(role)
    props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
    if definition is None:
        if props["LoadState"] != "not-found":
            _fail("publisher-slice-untracked")
        _unit_absence(unit, props)
        try:
            cgroup = _cgroup_snapshot(
                "/" + unit, runner_policy.BUDGETS["publisher"], require_populated=False,
            )
        except RuntimeFailure as error:
            if error.code != "cgroup-removed":
                raise
            return {"unit": unit, "present": False, "observed_absent": True, "populated": False}
        if cgroup["populated"] or cgroup["pids"]:
            _fail("publisher-slice-untracked-process")
        return {
            "unit": unit, "present": False, "observed_absent": True,
            "populated": False, "cgroup": cgroup,
        }
    if type(definition) is not dict:
        _fail("publisher-slice-definition")
    if props["LoadState"] == "not-found":
        _unit_absence(unit, props)
        try:
            cgroup = _cgroup_snapshot("/" + unit, runner_policy.BUDGETS["publisher"],
                                      require_populated=False)
        except RuntimeFailure as error:
            if error.code != "cgroup-removed":
                raise
            return {"unit": unit, "present": False, "observed_absent": True, "populated": False}
        if cgroup["populated"] or cgroup["pids"]:
            _fail("publisher-slice-still-populated")
        return {
            "unit": unit, "present": False, "observed_absent": True,
            "populated": False, "cgroup": cgroup,
        }
    if (props["Id"] != unit or props["FragmentPath"] != _unit_file_name(unit)
            or props["DropInPaths"] or props["ControlGroup"] != "/" + unit):
        _fail("publisher-slice-identity")
    _read_unit_definition(unit, definition)
    try:
        cgroup = _cgroup_snapshot("/" + unit, runner_policy.BUDGETS["publisher"],
                                  require_populated=False)
    except RuntimeFailure as error:
        if (error.code != "cgroup-removed"
                or props["ActiveState"] not in {"inactive", "failed"}
                or _parse_unsigned(props["MainPID"], "publisher-slice-main-pid") != 0
                or _parse_unsigned(props["ControlPID"], "publisher-slice-control-pid") != 0):
            raise
        return {
            "unit": unit, "present": True, "observed_absent": True,
            "populated": False, "cgroup": {"present": False, "observed_absent": True},
        }
    return {
        "unit": unit, "present": True, "observed_absent": False,
        "populated": cgroup["populated"], "cgroup": cgroup,
    }

def _require_previous_recovery_actor_gone(
    state: dict[str, Any],
    effect_observation: dict[str, Any],
    current_unit: str,
    current_invocation: str,
) -> None:
    if (type(effect_observation) is not dict
            or set(effect_observation) != {"unit", "invocation_id"}
            or effect_observation["unit"] != current_unit
            or type(effect_observation["invocation_id"]) is not str
            or re.fullmatch(r"[0-9a-f]{32}", effect_observation["invocation_id"]) is None
            or type(current_invocation) is not str
            or re.fullmatch(r"[0-9a-f]{32}", current_invocation) is None
            or effect_observation["invocation_id"] == current_invocation):
        _fail("recovery-previous-actor-effect-invalid")
    old_unit = state["units"].get("recovery")
    if (type(old_unit) is not dict
            or old_unit.get("unit") != current_unit
            or old_unit.get("invocation_id") != effect_observation["invocation_id"]
            or type(old_unit.get("process")) is not dict
            or type(old_unit.get("cgroup")) is not dict
            or type(old_unit["cgroup"].get("pids")) is not list):
        _fail("recovery-previous-actor-unrecorded")
    old_process = _identity_from_record(old_unit["process"])
    old_pids = old_unit["cgroup"]["pids"]
    if (not _pid_birth_gone({"pid": old_process.pid, "birth": old_process.birth})
            or not all(_pid_birth_gone(row) for row in old_pids)):
        _fail("recovery-previous-actor-live")



def _recover(names: runner_policy.RunNames) -> int:
    store, parent = _open_store(names)
    state: dict[str, Any] | None = None
    effects: tuple[dict[str, Any], ...] = ()
    cleanup_deadline = time.monotonic_ns() + 30 * _NS
    try:
        state = _load_state(store, names)
        cleanup_deadline = min(
            int(state["outer_deadline_ns"]), time.monotonic_ns() + 30 * _NS,
        )
        effects = store.effects()
        _ensure_operation_source(names, state)
        if os.environ.get("DOTUNNEL_GENERATION") != state["nonce"]:
            _fail("recovery-generation-mismatch")
        actor_role = None
        actor_observation = None
        for role in ("recovery-probe", "recovery"):
            props = _show_unit(
                _unit_name(names, role), min(cleanup_deadline, time.monotonic_ns() + 2 * _NS),
            )
            if (props["LoadState"] == "loaded"
                    and _parse_unsigned(props["MainPID"], "recovery-main-pid") == os.getpid()
                    and props["ActiveState"] in {"active", "activating", "deactivating"}):
                actor_role = role
                actor_observation = _self_service_observation(
                    names, role, min(cleanup_deadline, time.monotonic_ns() + 5 * _NS),
                )
                break
        if actor_role is None or actor_observation is None:
            _fail("recovery-actor-not-authenticated")
        actor_effect = next((row for row in effects if row["role"] == actor_role), None)
        if (actor_effect is None
                or actor_effect["desired"] != {"unit": _unit_name(names, actor_role)}):
            _fail("recovery-actor-effect-missing")
        observed = actor_effect["observed"]
        terminal_receipt = store.terminal_receipt()
        if terminal_receipt is not None:
            # A later authenticated recovery activation may only verify or
            # publish the immutable local terminal record; never replay upload.
            _write_terminal_status_record(names, store, cleanup_deadline)
            return 0
        recovery_generation_replaced = False
        if type(observed) is dict and (
                observed.get("invocation_id") is None
                or observed.get("unit") != actor_observation["unit"]
                or observed.get("invocation_id") != actor_observation["invocation_id"]):
            if actor_role != "recovery":
                _fail("recovery-actor-generation-mismatch")
            _require_previous_recovery_actor_gone(
                state, observed, actor_observation["unit"], actor_observation["invocation_id"],
            )
            recovery_generation_replaced = True
        if actor_role == "recovery-probe":
            # This fixed one-shot service only proves that the reaper's
            # independent recovery path can run; it never claims cleanup.
            _record_unit(store, names, actor_observation, replace_existing=True)
            return 0

        reaper_row = next((row for row in effects if row["role"] == "reaper"), None)
        reaper_props = _show_unit(
            _unit_name(names, "reaper"),
            min(cleanup_deadline, time.monotonic_ns() + 2 * _NS),
        )
        if reaper_row is None:
            if reaper_props["LoadState"] != "not-found":
                _fail("reaper-effect-missing")
            _unit_absence(_unit_name(names, "reaper"), reaper_props)
            cgroup_path = f"/{_slice_name(names, 'reaper')}/{_unit_name(names, 'reaper')}"
            try:
                cgroup = _cgroup_snapshot(
                    cgroup_path, runner_policy.BUDGETS["reaper"], require_populated=False,
                )
            except RuntimeFailure as error:
                if error.code != "cgroup-removed":
                    raise
                cgroup = None
            unit_state = state["units"].get("reaper")
            old_cgroup = unit_state.get("cgroup") if type(unit_state) is dict else None
            old_process = unit_state.get("process") if type(unit_state) is dict else None
            old_pids = old_cgroup.get("pids", []) if type(old_cgroup) is dict else []
            if (cgroup is not None and (cgroup["populated"] or cgroup["pids"])
                    or not all(_pid_birth_gone(row) for row in old_pids)
                    or type(old_process) is dict and not _pid_birth_gone({
                        "pid": old_process["pid"], "birth": old_process["birth"],
                    })):
                _fail("reaper-untracked-work-live")
        else:
            if reaper_row["desired"] != {"unit": _unit_name(names, "reaper")}:
                _fail("reaper-effect-binding")
            _wait_reaper_stopped(names, state, reaper_row, cleanup_deadline)
        if recovery_generation_replaced:
            return _fence_replaced_recovery_actor(
                names, store, state, effects, actor_observation, cleanup_deadline,
            )
        try:
            claimed = store.begin_cleanup()
        except BaseException:
            _emergency_fence(
                names, store, state, effects, cleanup_deadline, None, None,
            )
            return 2
        if not claimed:
            _wait_cleanup_terminal(store, cleanup_deadline)
            if store.terminal_receipt() is None:
                return 2
            _write_terminal_status_record(names, store, cleanup_deadline)
            return 0
        return _cleanup_receipt(
            names, store, "independent-recovery", cleanup_deadline, claimed=True,
        )
    except BaseException:
        if state is not None:
            try:
                _emergency_fence(
                    names, store, state, effects, cleanup_deadline, None, None,
                )
            except BaseException:
                pass
        return 2
    finally:
        store.close()
        os.close(parent)


def _never_started_observation(
    names: runner_policy.RunNames,
    state: dict[str, Any],
    role: str,
    properties: dict[str, str],
) -> dict[str, object]:
    unit = _unit_name(names, role)
    definition = state["definitions"].get(role)
    if type(definition) is not dict or properties["Id"] != unit:
        _fail("never-started-definition-missing")
    expected_slice = names.work_slice if role == "harmless" else _slice_name(names, role)
    manager = _check_unit_budget(properties, role, expected_slice, active=False)
    if (manager["load_state"] != "loaded" or manager["active_state"] != "inactive"
            or manager["sub_state"] != "dead" or manager["invocation_id"] != ""
            or manager["main_pid"] != 0 or manager["control_pid"] != 0
            or manager["control_group"] != ""):
        _fail("never-started-manager-state")
    _read_unit_definition(unit, definition)
    fragment = manager["fragment_path"]
    info = os.stat(fragment, follow_symlinks=False)
    if (info.st_dev != definition["device"] or info.st_ino != definition["inode"]
            or properties["WorkingDirectory"] != "/" or properties["NoNewPrivileges"] != "yes"):
        _fail("never-started-definition-identity")
    required_environment = {
        f"DOTUNNEL_GENERATION={state['nonce']}",
        f"DOTUNNEL_RUN={names.run}",
        f"DOTUNNEL_ATTEMPT={names.attempt}",
        "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
    }
    if not required_environment <= set(properties["Environment"].split()):
        _fail("never-started-generation-mismatch")
    control_group = f"/{expected_slice}/{unit}"
    budget = runner_policy.BUDGETS["harmless" if role == "harmless" else (
        "publisher" if role.startswith("publisher") else role
    )]
    try:
        _cgroup_snapshot(control_group, budget, require_populated=False)
    except RuntimeFailure as error:
        if error.code != "cgroup-removed":
            raise
    else:
        _fail("never-started-cgroup-present")
    idle = {
        "load_state": "loaded", "active_state": "inactive", "sub_state": "dead",
        "main_pid": 0, "control_pid": 0, "fragment_path": fragment,
        "definition_sha256": definition["sha256"], "device": info.st_dev,
        "inode": info.st_ino, "nonce": state["nonce"], "control_group": "",
        "cgroup_absent": True,
    }
    return {"unit": unit, "invocation_id": None, "never_started": idle}


def _reconcile_pending_unit(names: runner_policy.RunNames, store: Any,
                            role: str, deadline_ns: int) -> dict[str, object] | None:
    state = _load_state(store, names)
    definition = state["definitions"].get(role)
    unit = _unit_name(names, role)
    props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
    if props["LoadState"] == "not-found":
        _unit_absence(unit, props)
        return None
    if type(definition) is not dict:
        _fail("reconcile-definition-missing")
    try:
        if props["InvocationID"] == "":
            return _never_started_observation(names, state, role, props)
        return _observe_unit(names, role, deadline_ns, expected_definition=definition, active=False)
    except RuntimeFailure:
        _fail("reconcile-resource-ambiguous")
def _verify_reaper_stop_control(names: runner_policy.RunNames,
                                process_id: int, control_group: str,
                                cgroup: dict[str, object]) -> ProcessIdentity:
    executable = _secure_root_binary(_SYSTEMCTL)
    executable_info = os.stat(executable, follow_symlinks=False)
    identity = require_same_process(observe_process(process_id))
    if (identity.uid != 0 or identity.gid != 0 or identity.exe_uid != 0
            or identity.exe_mode & 0o022 or identity.no_new_privs != 1
            or (identity.exe_device, identity.exe_inode) != (executable_info.st_dev, executable_info.st_ino)
            or identity.cgroup != control_group):
        _fail("reaper-stop-control-identity")
    _check_no_process_secrets(process_id)
    _raw, argv = _process_argv(process_id)
    if argv != [_SYSTEMCTL, "--no-block", "start", _unit_name(names, "recovery")]:
        _fail("reaper-stop-control-command")
    if not any(row["pid"] == process_id and row["birth"] == identity.birth
               for row in cgroup["pids"]):
        _fail("reaper-stop-control-cgroup")
    return identity


def _wait_reaper_stopped(names: runner_policy.RunNames, state: dict[str, Any],
                         effect: dict[str, Any], deadline_ns: int) -> dict[str, object]:
    unit = _unit_name(names, "reaper")
    definition = state["definitions"].get("reaper")
    expected_unit = state["units"].get("reaper")
    if type(definition) is not dict:
        _fail("reaper-stop-definition-missing")
    expected_cgroup = expected_unit.get("cgroup") if type(expected_unit) is dict else None
    expected_process = expected_unit.get("process") if type(expected_unit) is dict else None
    recorded = effect["observed"]
    expected_invocation = None
    if type(recorded) is dict:
        if (recorded.get("unit") != unit or type(recorded.get("invocation_id")) is not str
                or re.fullmatch(r"[0-9a-f]{32}", recorded["invocation_id"]) is None):
            _fail("reaper-stop-effect-invalid")
        expected_invocation = recorded["invocation_id"]
    observed_invocation: str | None = None
    cgroup_path = f"/{_slice_name(names, 'reaper')}/{unit}"
    while time.monotonic_ns() < deadline_ns:
        props = _show_unit(unit, min(deadline_ns, time.monotonic_ns() + 2 * _NS))
        if props["LoadState"] == "not-found":
            _unit_absence(unit, props)
            try:
                cgroup = _cgroup_snapshot(
                    cgroup_path, runner_policy.BUDGETS["reaper"], require_populated=False,
                )
            except RuntimeFailure as error:
                if error.code != "cgroup-removed":
                    raise
                cgroup = None
            if cgroup is not None and (cgroup["populated"] or cgroup["pids"]):
                _fail("reaper-stop-unloaded-cgroup-live")
            old_pids = [] if type(expected_cgroup) is not dict else expected_cgroup.get("pids", [])
            if (not all(_pid_birth_gone(row) for row in old_pids)
                    or type(expected_process) is dict and not _pid_birth_gone({
                        "pid": expected_process["pid"], "birth": expected_process["birth"],
                    })):
                _fail("reaper-stop-unloaded-process-live")
            return {
                "unit": unit, "load_state": "not-found",
                "cgroup": cgroup if cgroup is not None else {"present": False, "observed_absent": True},
            }
        if (props["LoadState"] != "loaded" or props["Id"] != unit
                or props["FragmentPath"] != _unit_file_name(unit) or props["DropInPaths"]):
            _fail("reaper-stop-unit-identity")
        _read_unit_definition(unit, definition)
        manager = _check_unit_budget(
            props, "reaper", _slice_name(names, "reaper"), active=False,
        )
        invocation = manager["invocation_id"]
        if (type(invocation) is not str or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
                or expected_invocation is not None and invocation != expected_invocation
                or observed_invocation is not None and invocation != observed_invocation):
            _fail("reaper-stop-invocation-mismatch")
        observed_invocation = invocation
        if (manager["control_group"] != cgroup_path
                or props["WorkingDirectory"] != "/"
                or props["NoNewPrivileges"] != "yes"):
            _fail("reaper-stop-process-boundary")
        required_environment = {
            f"DOTUNNEL_GENERATION={state['nonce']}",
            f"DOTUNNEL_RUN={names.run}",
            f"DOTUNNEL_ATTEMPT={names.attempt}",
            "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
        }
        if not required_environment <= set(props["Environment"].split()):
            _fail("reaper-stop-environment")
        try:
            cgroup = _cgroup_snapshot(
                cgroup_path, runner_policy.BUDGETS["reaper"], require_populated=False,
            )
        except RuntimeFailure as error:
            if (error.code != "cgroup-removed"
                    or manager["active_state"] not in {"inactive", "failed"}
                    or manager["main_pid"] != 0 or manager["control_pid"] != 0):
                raise
            cgroup = None
        if (type(expected_cgroup) is dict and cgroup is not None
                and (cgroup["device"] != expected_cgroup.get("device")
                     or cgroup["inode"] != expected_cgroup.get("inode"))):
            _fail("reaper-stop-cgroup-generation")
        main_pid = manager["main_pid"]
        control_pid = manager["control_pid"]
        if main_pid:
            if type(expected_process) is not dict:
                _fail("reaper-stop-main-owner-missing")
            process = require_same_process(_identity_from_record(expected_process))
            if (process.pid != main_pid or process.cgroup != cgroup_path
                    or cgroup is None
                    or not any(row["pid"] == main_pid and row["birth"] == process.birth
                               for row in cgroup["pids"])):
                _fail("reaper-stop-main-owner-mismatch")
        if control_pid:
            if cgroup is None:
                _fail("reaper-stop-control-cgroup-missing")
            _verify_reaper_stop_control(names, control_pid, cgroup_path, cgroup)
        stopped = (
            manager["active_state"] in {"inactive", "failed"}
            and main_pid == 0 and control_pid == 0
            and (cgroup is None or cgroup["populated"] is False and not cgroup["pids"])
        )
        if stopped:
            old_pids = [] if type(expected_cgroup) is not dict else expected_cgroup.get("pids", [])
            if (not all(_pid_birth_gone(row) for row in old_pids)
                    or type(expected_process) is dict and not _pid_birth_gone({
                        "pid": expected_process["pid"], "birth": expected_process["birth"],
                    })):
                _fail("reaper-stop-process-birth-live")
            return {"unit": unit, "manager": manager, "cgroup": cgroup}
        time.sleep(0.05)
    _fail("reaper-stop-handoff-timeout")
def _fence_replaced_recovery_actor(
    names: runner_policy.RunNames,
    store: Any,
    state: dict[str, Any],
    effects: tuple[dict[str, Any], ...],
    actor_observation: dict[str, object],
    deadline_ns: int,
) -> int:
    try:
        claimed = store.begin_cleanup()
    except BaseException:
        _emergency_fence(names, store, state, effects, deadline_ns, None, None)
        return 2
    if not claimed:
        _wait_cleanup_terminal(store, deadline_ns)
        if store.terminal_receipt() is not None:
            _write_terminal_status_record(names, store, deadline_ns)
            return 0
        return 2

    current = _self_service_observation(
        names, "recovery", min(deadline_ns, time.monotonic_ns() + 5 * _NS),
    )
    if (current["main_pid"] != os.getpid()
            or current["invocation_id"] != actor_observation["invocation_id"]):
        _fail("recovery-replacement-actor-changed")
    fence = _emergency_fence(names, store, state, effects, deadline_ns, None, None)
    fenced_units = fence.get("units")
    if type(fenced_units) is not dict:
        return 2
    for effect in effects:
        if effect.get("role") == "recovery":
            continue
        result = fenced_units.get(effect.get("role"))
        if type(result) is not dict or result.get("pids_gone") is not True:
            return 2

    state = _load_state(store, names)
    work = _work_slice_observation(names, deadline_ns, must_be_empty=True)
    publisher_slice = _publisher_slice_observation(names, state, deadline_ns)
    publishers_empty = _publishers_quiescent(names, state, deadline_ns)
    if (work.get("populated") is not False
            or publisher_slice.get("populated") is not False
            or not publishers_empty):
        return 2
    current_effects = store.effects()
    if (current_effects != effects
            or any(effect["observed"] is None for effect in current_effects)):
        return 2
    if store.terminal_receipt() is not None:
        _write_terminal_status_record(names, store, deadline_ns)
        return 0
    if state["prepared_terminal"] is not None or state["terminal_sha256"] is not None:
        return 2
    try:
        existing_snapshot = store.read_snapshot("terminal")
    except ValueError as error:
        if str(error) != "authority-record-not-committed":
            return 2
        existing_snapshot = None
    except Exception:
        return 2
    if existing_snapshot is not None:
        return 2

    def record_failure(value: dict[str, Any]) -> dict[str, Any]:
        if value["original_cause"] is None:
            value["original_cause"] = "recovery-generation-replaced"
        for kind in ("readiness", "terminal"):
            publication = value["publication"][kind]
            if publication["state"] == "PENDING":
                publication.update({
                    "state": "UNKNOWN", "exit_code": None,
                    "artifact_id": None, "digest": None, "url": None,
                    "updated_ns": time.monotonic_ns(),
                })
        return value

    state = _update_state(store, names, record_failure)
    observations = {
        "work_slice": {
            "populated": False,
            "observed_absent": work.get("observed_absent") is True,
        },
        "publisher_slice": {
            "populated": False,
            "observed_absent": publisher_slice.get("observed_absent") is True,
        },
        "publisher_units_quiescent": True,
        "emergency_fence": {
            "owned_effects_fenced": True,
            "recovery_generation_replaced": True,
        },
    }
    _freeze_terminal_snapshot(
        names, store, state, "FAIL", "UNKNOWN", state["original_cause"],
        observations, False, "recovery-generation-replaced",
    )
    state = _load_state(store, names)
    store.finish_cleanup({
        "scenario_result": "FAIL", "cleanup_state": "UNKNOWN",
        "original_cause": state["original_cause"], "work_populated": False,
        "container_record_state": "NOT_CREATED",
    })
    _write_terminal_status_record(names, store, deadline_ns)
    return 2




def _root_operation(operation: str, names: runner_policy.RunNames) -> int:
    if operation == "receipt-start":
        return _receipt_start(names)
    if operation == "reap":
        return _reap(names)
    if operation == "recover":
        return _recover(names)
    if operation == "publish-readiness":
        return _publish(names, "readiness")
    if operation == "publish-terminal":
        return _publish(names, "terminal")
    _fail("operation-not-allowed")


def main(operation: str, run: str, attempt: str) -> int:
    """Run one fixed root lifecycle operation; diagnostics stay generic."""
    try:
        names = _validate_root_entry(operation, run, attempt)
        if operation == "receipt-start":
            return _root_operation(operation, names)
        # Root-owned units must execute only the promoted sibling loader path.
        state = _load_state_from_names(names)
        _ensure_operation_source(names, state)
        return _root_operation(operation, names)
    except RuntimeFailure:
        try:
            os.write(2, b"runner receipt operation refused\n")
        except OSError:
            pass
        return 2
    except BaseException:
        try:
            os.write(2, b"runner receipt operation failed\n")
        except OSError:
            pass
        return 2
