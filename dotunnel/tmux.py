"""Fixed-socket tmux transport for recorded agent panes.

Only dotunnel-created panes with a revalidated managed record, or explicitly
registered read-only panes, enter inventory. Pane names and process discovery
are never used as authority.
"""
from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import stat
import time
import uuid
from typing import Any, Callable

from .supervision_config import Connection, Profile, Project, SupervisionError

_PANE_ID = re.compile(r"%[0-9]+\Z")
_SESSION_ID = re.compile(r"\$[0-9]+\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_MAX_OUTPUT = 4 * 1024 * 1024
_MAX_PROC_FILE = 1024 * 1024
_MAX_PROMPT_BYTES = 8 * 1024
_MAX_READ_LINES = 200
_MAX_KEYS = 8
_IDENTITY_FIELDS = (
    "native_id",
    "boot_id",
    "server_pid",
    "server_start",
    "pane_pid",
    "pane_start",
)
_MANAGED_IDENTITY_FIELDS = (*_IDENTITY_FIELDS, "nonce")
_PANE_FORMAT = "#{pane_id}\t#{pane_pid}\t#{pane_dead}"
_KEY_NAMES = {
    "enter": "Enter",
    "esc": "Escape",
    "up": "Up",
    "down": "Down",
    "left": "Left",
    "right": "Right",
    "tab": "Tab",
    "y": "y",
    "n": "n",
    **{str(number): str(number) for number in range(1, 10)},
}


def _error(code: str, reason: str | None = None) -> SupervisionError:
    return SupervisionError(code, reason=reason)


def _raise(code: str, reason: str | None = None) -> None:
    raise _error(code, reason)


def _positive_integer(value: object) -> bool:
    return type(value) is int and 0 < value <= 2**31 - 1


def _start_time(value: object) -> bool:
    return type(value) is int and value >= 0


def _identity(value: object, *, managed: bool) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    fields = _MANAGED_IDENTITY_FIELDS if managed else _IDENTITY_FIELDS
    if any(field not in value for field in fields):
        return None
    native_id = value.get("native_id")
    boot_id = value.get("boot_id")
    if not isinstance(native_id, str) or not _PANE_ID.fullmatch(native_id):
        return None
    if not isinstance(boot_id, str) or not _BOOT_ID.fullmatch(boot_id.lower()):
        return None
    if not _positive_integer(value.get("server_pid")) or not _start_time(value.get("server_start")):
        return None
    if not _positive_integer(value.get("pane_pid")) or not _start_time(value.get("pane_start")):
        return None
    result = {
        "native_id": native_id,
        "boot_id": boot_id.lower(),
        "server_pid": value["server_pid"],
        "server_start": value["server_start"],
        "pane_pid": value["pane_pid"],
        "pane_start": value["pane_start"],
    }
    if managed:
        nonce = value.get("nonce")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            return None
        result["nonce"] = nonce
    return result


def _identity_key(identity: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(identity.get(field) for field in _MANAGED_IDENTITY_FIELDS)


def _boot_id() -> str | None:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError):
        return None
    return value if _BOOT_ID.fullmatch(value) else None


def _proc_stat(pid: int) -> tuple[str, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = raw.rfind(")")
        if close < 0:
            return None
        fields = raw[close + 2 :].split()
        if len(fields) <= 19:
            return None
        return fields[0], int(fields[19])
    except (OSError, UnicodeError, ValueError):
        return None


def _proc_cmdline(pid: int) -> list[str] | None:
    try:
        with Path(f"/proc/{pid}/cmdline").open("rb") as stream:
            raw = stream.read(_MAX_PROC_FILE + 1)
    except OSError:
        return None
    if not raw or len(raw) > _MAX_PROC_FILE:
        return None
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    try:
        return [part.decode("utf-8", "surrogateescape") for part in parts]
    except UnicodeError:
        return None


def _proc_has_nonce(pid: int, nonce: str) -> bool:
    try:
        with Path(f"/proc/{pid}/environ").open("rb") as stream:
            raw = stream.read(_MAX_PROC_FILE + 1)
    except OSError:
        return False
    if len(raw) > _MAX_PROC_FILE:
        return False
    matches = [value for value in raw.split(b"\0") if value.startswith(b"DOTUNNEL_MCP_NONCE=")]
    return matches == [b"DOTUNNEL_MCP_NONCE=" + nonce.encode("ascii")]


def _proc_executable(pid: int) -> Path | None:
    try:
        return Path(f"/proc/{pid}/exe").resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None


def _proc_cwd(pid: int) -> Path | None:
    try:
        cwd = Path(f"/proc/{pid}/cwd").resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    return cwd if cwd.is_absolute() else None


def _runtime_command(executable: Path, args: Sequence[str], *, trusted_path: str) -> tuple[list[str], Path]:
    """Resolve direct binaries and ordinary shebang/env launchers exactly."""
    if not executable.is_absolute():
        _raise("invalid_request", "profile_executable_not_absolute")
    if not isinstance(args, Sequence) or isinstance(args, (str, bytes)) or any(
        not isinstance(arg, str) or "\0" in arg for arg in args
    ):
        _raise("invalid_request", "invalid_profile_arguments")
    try:
        canonical = executable.resolve(strict=True)
        info = executable.stat()
    except (OSError, ValueError, RuntimeError):
        _raise("backend_unavailable", "profile_executable_unavailable")
    if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
        _raise("unsupported_operation", "profile_executable_not_runnable")
    try:
        with executable.open("rb") as stream:
            first_line = stream.readline(4097)
    except OSError:
        _raise("backend_unavailable", "profile_executable_unavailable")
    direct = [str(executable), *args]
    if not first_line.startswith(b"#!"):
        return direct, canonical
    if len(first_line) > 4096:
        _raise("unsupported_operation", "profile_shebang_too_long")
    try:
        interpreter_line = os.fsdecode(first_line[2:].strip())
        words = interpreter_line.split(None, 1)
        interpreter = words[0] if words else ""
        optional = words[1] if len(words) > 1 else ""
    except (UnicodeError, ValueError):
        _raise("unsupported_operation", "invalid_profile_shebang")
    if not interpreter or not Path(interpreter).is_absolute():
        _raise("unsupported_operation", "invalid_profile_shebang")

    if Path(interpreter).name == "env":
        try:
            options = shlex.split(optional)
        except ValueError:
            _raise("unsupported_operation", "invalid_profile_shebang")
        if options and options[0] == "-S":
            command = options[1:]
        else:
            command = options
        if not command or command[0].startswith("-"):
            _raise("unsupported_operation", "unsupported_env_shebang")
        resolved = shutil.which(command[0], path=trusted_path)
        if resolved is None:
            _raise("backend_unavailable", "profile_interpreter_unavailable")
        try:
            runtime_executable = Path(resolved).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            _raise("backend_unavailable", "profile_interpreter_unavailable")
        runtime_argv = [command[0], *command[1:], str(executable), *args]
        return runtime_argv, runtime_executable

    runtime_argv = [interpreter]
    if optional:
        runtime_argv.append(optional)
    runtime_argv.extend((str(executable), *args))
    try:
        runtime_executable = Path(interpreter).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _raise("backend_unavailable", "profile_interpreter_unavailable")
    return runtime_argv, runtime_executable


def _verified_process_cwd(
    pid: int,
    start: int,
    *,
    argv: Sequence[str] | None = None,
    executable: Path | None = None,
    nonce: str | None = None,
) -> Path | None:
    before = _proc_stat(pid)
    if before is None or before[0] in ("Z", "X", "x") or before[1] != start:
        return None
    if argv is not None and _proc_cmdline(pid) != list(argv):
        return None
    if executable is not None and _proc_executable(pid) != executable:
        return None
    if nonce is not None and not _proc_has_nonce(pid, nonce):
        return None
    cwd = _proc_cwd(pid)
    if cwd is None:
        return None
    after = _proc_stat(pid)
    if after is None or after[1] != start or after[0] in ("Z", "X", "x"):
        return None
    return cwd


def _project_map(projects: Sequence[Project]) -> dict[str, Project]:
    return {project.id: project for project in projects if isinstance(project.id, str)}


def _pane_pid_rows(stdout: bytes) -> dict[str, tuple[int, bool] | None] | None:
    try:
        text = stdout.decode("utf-8", "strict")
    except UnicodeError:
        return None
    rows: dict[str, tuple[int, bool] | None] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        native_id, pid_value, dead_value = fields
        if (
            not _PANE_ID.fullmatch(native_id)
            or not pid_value.isascii()
            or not pid_value.isdecimal()
            or len(pid_value) > 10
            or dead_value not in ("0", "1")
        ):
            continue
        pid = int(pid_value)
        if not _positive_integer(pid):
            continue
        if native_id in rows:
            rows[native_id] = None
        else:
            rows[native_id] = (pid, dead_value == "1")
    return rows


def _single_pane(stdout: bytes) -> tuple[str, int, bool] | None:
    rows = _pane_pid_rows(stdout)
    if rows is None or len(rows) != 1:
        return None
    native_id, value = next(iter(rows.items()))
    if value is None:
        return None
    return native_id, value[0], value[1]


@dataclass(frozen=True)
class _Managed:
    project: str
    profile: str
    name: str
    argv: tuple[str, ...]
    executable: Path

class TmuxBackend:
    """Manage only recorded panes on one fixed tmux socket."""

    def __init__(self, connection: Connection, runner: Callable[..., Any]):
        self.connection = connection
        self._runner = runner
        self._trusted_path = getattr(runner, "trusted_path", None)
        if not isinstance(self._trusted_path, str) or not self._trusted_path:
            _raise("backend_unavailable", "trusted_path_unavailable")
        self._managed: dict[tuple[Any, ...], _Managed] = {}
        self._readonly_projects: dict[str, Project] = {}
        executable = connection.executable
        socket = connection.socket
        if not isinstance(executable, Path) or not executable.is_absolute() or not isinstance(socket, Path) or not socket.is_absolute():
            _raise("backend_unavailable", "invalid_tmux_connection")

    async def _execute(
        self,
        args: Sequence[str],
        *,
        deadline: float,
        input: bytes | None = None,
        allow_failure: bool = False,
        no_start: bool = True,
    ) -> tuple[int, bytes, bytes]:
        argv = [str(self.connection.executable)]
        if no_start:
            argv.append("-N")
        else:
            argv.extend(("-f", "/dev/null"))
        argv.extend(("-S", str(self.connection.socket)))
        argv.extend(args)
        try:
            result = await self._runner(argv, cwd=Path("/"), deadline=deadline, input=input)
        except asyncio.CancelledError:
            raise
        except SupervisionError:
            raise
        except Exception:
            _raise("backend_unavailable", "tmux_cli_failed")
        if not isinstance(result, tuple) or len(result) != 3:
            _raise("backend_unavailable", "invalid_tmux_runner_result")
        code, stdout, stderr = result
        if type(code) is not int or not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            _raise("backend_unavailable", "invalid_tmux_runner_result")
        if len(stdout) + len(stderr) > _MAX_OUTPUT:
            _raise("backend_unavailable", "tmux_output_limit")
        if code != 0 and not allow_failure:
            _raise("backend_unavailable", "tmux_command_failed")
        return code, stdout, stderr

    async def _server(self, *, deadline: float) -> tuple[str, int, int] | None:
        code, stdout, stderr = await self._execute(
            ("display-message", "-p", "-F", "#{pid}"),
            deadline=deadline,
            allow_failure=True,
        )
        if code != 0:
            message = stderr.decode("utf-8", "replace").strip().lower()
            if message.startswith("no server running on "):
                return None
            _raise("backend_unavailable", "tmux_command_failed")
        try:
            value = stdout.decode("ascii", "strict").strip()
            pid = int(value)
        except (UnicodeError, ValueError):
            _raise("backend_unavailable", "tmux_server_identity_unavailable")
        if not _positive_integer(pid):
            _raise("backend_unavailable", "tmux_server_identity_unavailable")
        boot_id = _boot_id()
        process = _proc_stat(pid)
        if boot_id is None or process is None or process[0] in ("Z", "X", "x"):
            _raise("backend_unavailable", "tmux_server_identity_unavailable")
        return boot_id, pid, process[1]

    @staticmethod
    def _server_matches(identity: Mapping[str, Any], server: tuple[str, int, int]) -> bool:
        return (
            identity.get("boot_id"),
            identity.get("server_pid"),
            identity.get("server_start"),
        ) == server

    async def _panes(self, *, deadline: float, session_id: str | None = None) -> dict[str, tuple[int, bool] | None]:
        args: list[str] = ["list-panes"]
        if session_id is None:
            args.append("-a")
        else:
            args.extend(("-s", "-t", session_id))
        args.extend(("-F", _PANE_FORMAT))
        _, stdout, _ = await self._execute(args, deadline=deadline)
        rows = _pane_pid_rows(stdout)
        if rows is None:
            _raise("backend_unavailable", "invalid_tmux_pane_inventory")
        return rows

    async def _pane(self, native_id: str, *, deadline: float) -> tuple[str, int, bool]:
        if not _PANE_ID.fullmatch(native_id):
            _raise("stale_target", "invalid_native_pane_id")
        code, stdout, _ = await self._execute(
            (
                "display-message",
                "-p",
                "-t",
                native_id,
                "-F",
                _PANE_FORMAT,
            ),
            deadline=deadline,
            allow_failure=True,
        )
        if code != 0:
            _raise("stale_target", "pane_missing")
        pane = _single_pane(stdout)
        if pane is None:
            _raise("stale_target", "pane_identity_unavailable")
        return pane

    def _managed_from_record(
        self,
        record: Mapping[str, Any],
        projects: Mapping[str, Project],
    ) -> tuple[Project, dict[str, Any], _Managed] | None:
        if record.get("state") != "active":
            return None
        binding = record.get("binding")
        native = record.get("native")
        if not isinstance(binding, Mapping) or not isinstance(native, Mapping):
            return None
        if binding.get("connection") != self.connection.id:
            return None
        project_id = binding.get("project")
        profile_id = binding.get("profile")
        project = projects.get(project_id) if isinstance(project_id, str) else None
        if project is None or self.connection.id not in project.connections or profile_id not in project.profiles:
            return None
        raw_identity = native.get("identity")
        identity = _identity(raw_identity, managed=True)
        if identity is None or native.get("native_id") != identity["native_id"]:
            return None
        nonce = identity["nonce"]
        if record.get("nonce", native.get("nonce")) != nonce or native.get("nonce") != nonce:
            return None
        if native.get("project") not in (None, project.id) or native.get("profile") not in (None, profile_id):
            return None
        argv = native.get("command_argv")
        executable_value = native.get("command_executable")
        name = native.get("name", record.get("name", identity["native_id"]))
        if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(arg, str) for arg in argv):
            return None
        if not isinstance(executable_value, str) or not isinstance(name, str) or not name or len(name) > 128:
            return None
        try:
            executable = Path(executable_value)
        except (TypeError, ValueError):
            return None
        if not executable.is_absolute():
            return None
        managed = _Managed(project.id, profile_id, name, tuple(argv), executable)
        return project, identity, managed

    def _readonly_from_setting(
        self,
        target: Mapping[str, Any],
        projects: Mapping[str, Project],
    ) -> tuple[Project, dict[str, Any]] | None:
        project_id = target.get("project")
        project = projects.get(project_id) if isinstance(project_id, str) else None
        native_id = target.get("native_id")
        raw_identity = target.get("identity")
        if project is None or self.connection.id not in project.connections:
            return None
        if not isinstance(native_id, str) or not _PANE_ID.fullmatch(native_id) or not isinstance(raw_identity, Mapping):
            return None
        identity = _identity({**raw_identity, "native_id": native_id}, managed=False)
        if identity is None:
            return None
        # read_targets are operator-authored, read-only generation pins. They
        # intentionally have no dotunnel launch nonce.
        return project, identity

    def _row(
        self,
        project: Project,
        identity: dict[str, Any],
        *,
        name: str,
        readonly: bool,
        profile: str | None,
        managed: bool,
        cwd: Path,
    ) -> dict[str, Any]:
        return {
            "native_id": identity["native_id"],
            "project": project.id,
            "name": name,
            "identity": dict(identity),
            "process_state": "running",
            "agent_state": "unknown",
            "state_source": "unavailable",
            "readonly": readonly,
            "cwd": str(cwd),
            "original_repo": None,
            "profile": profile,
            "connection": self.connection.id,
            "managed": managed,
            "nonce": identity.get("nonce"),
        }

    def _remember(self, identity: Mapping[str, Any], managed: _Managed) -> None:
        key = _identity_key(identity)
        self._managed.pop(key, None)
        self._managed[key] = managed
        while len(self._managed) > 1000:
            del self._managed[next(iter(self._managed))]

    async def start(
        self,
        project: Project,
        profile: Profile,
        name: str,
        worktree_branch: str | None,
        attempt: dict[str, Any],
        *,
        deadline: float,
    ) -> dict[str, Any]:
        if not isinstance(project.path, Path) or not project.path.is_absolute():
            _raise("invalid_request", "project_path_not_absolute")
        if worktree_branch is not None:
            _raise("unsupported_operation", "tmux_worktree_branch_unsupported")
        if self.connection.id not in project.connections or profile.id not in project.profiles:
            _raise("unsupported_operation", "profile_project_binding_mismatch")
        if "tmux" not in profile.backends:
            _raise("unsupported_operation", "tmux_profile_unavailable")
        if not isinstance(name, str) or not name or len(name) > 128:
            _raise("invalid_request", "invalid_agent_name")
        if not isinstance(attempt, Mapping):
            _raise("invalid_request", "invalid_start_attempt")
        nonce = attempt.get("nonce")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            _raise("invalid_request", "invalid_start_nonce")
        command_argv, command_executable = self._validate_profile(profile)
        home = pwd.getpwuid(os.getuid()).pw_dir
        session_name = "dotunnel-" + uuid.uuid4().hex
        # tmux reparses one command word through a shell, even after "--".
        # An empty-args profile needs a fixed exec launcher to preserve argv.
        create_args = (
            "new-session",
            "-d",
            "-P",
            "-F",
            "#{session_id}",
            "-s",
            session_name,
            "-c",
            str(project.path),
            "-e",
            "DOTUNNEL_MCP_NONCE=" + nonce,
            "-e",
            "HOME=" + home,
            "-e",
            "PATH=" + self._trusted_path,
            "-e",
            "LANG=C.UTF-8",
            "--",
            *(("/usr/bin/env", "--") if not profile.args else ()),
            str(profile.executable),
            *profile.args,
        )
        try:
            code, stdout, _ = await self._execute(
                create_args,
                deadline=deadline,
                allow_failure=True,
                no_start=False,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _raise("delivery_unknown", "tmux_start_effect_unknown")
        if code != 0:
            _raise("delivery_unknown", "tmux_start_effect_unknown")
        try:
            session_lines = stdout.decode("ascii", "strict").strip().splitlines()
            if len(session_lines) != 1 or not _SESSION_ID.fullmatch(session_lines[0]):
                _raise("delivery_unknown", "tmux_start_identity_unavailable")
            session_id = session_lines[0]
            server = await self._server(deadline=deadline)
            if server is None:
                _raise("delivery_unknown", "tmux_start_identity_unavailable")
            panes = await self._panes(deadline=deadline, session_id=session_id)
            if len(panes) != 1:
                _raise("delivery_unknown", "tmux_start_identity_unavailable")
            native_id, pane_value = next(iter(panes.items()))
            if pane_value is None:
                _raise("delivery_unknown", "tmux_start_identity_unavailable")
            pane_pid, dead = pane_value
            process = _proc_stat(pane_pid)
            if dead or process is None or process[0] in ("Z", "X", "x"):
                _raise("delivery_unknown", "tmux_start_process_unavailable")
            identity = {
                "native_id": native_id,
                "boot_id": server[0],
                "server_pid": server[1],
                "server_start": server[2],
                "pane_pid": pane_pid,
                "pane_start": process[1],
                "nonce": nonce,
            }
            managed = _Managed(
                project.id,
                profile.id,
                name,
                tuple(command_argv),
                command_executable,
            )
            pane = (native_id, pane_pid, dead)
            process_cwd = self._verified_cwd(identity, pane, server=server, managed=managed)
            if process_cwd is None:
                _raise("delivery_unknown", "tmux_start_process_identity_unavailable")
        except asyncio.CancelledError:
            raise
        except Exception:
            _raise("delivery_unknown", "tmux_start_identity_unavailable")

        row = self._row(
            project,
            identity,
            name=name,
            readonly=False,
            profile=profile.id,
            managed=True,
            cwd=process_cwd,
        )
        row["command_argv"] = command_argv
        row["command_executable"] = str(command_executable)
        self._remember(identity, managed)
        return row

    def _verified_cwd(
        self,
        identity: Mapping[str, Any],
        pane: tuple[str, int, bool],
        *,
        server: tuple[str, int, int],
        managed: _Managed | None,
    ) -> Path | None:
        if not self._server_matches(identity, server):
            return None
        native_id, pid, dead = pane
        if native_id != identity.get("native_id") or pid != identity.get("pane_pid") or dead:
            return None
        return _verified_process_cwd(
            pid,
            identity["pane_start"],
            argv=managed.argv if managed is not None else None,
            executable=managed.executable if managed is not None else None,
            nonce=identity.get("nonce") if managed is not None else None,
        )

    async def inventory(
        self,
        projects: Sequence[Project],
        records: Sequence[dict[str, Any]],
        *,
        deadline: float,
    ) -> list[dict[str, Any]]:
        project_by_id = _project_map(projects)
        managed_candidates = [
            candidate
            for record in records
            if isinstance(record, Mapping)
            for candidate in [self._managed_from_record(record, project_by_id)]
            if candidate is not None
        ]
        readonly_candidates = [
            candidate
            for target in self.connection.read_targets
            if isinstance(target, Mapping)
            for candidate in [self._readonly_from_setting(target, project_by_id)]
            if candidate is not None
        ]
        if not managed_candidates and not readonly_candidates:
            return []
        for project, _ in readonly_candidates:
            self._readonly_projects[project.id] = project

        server = await self._server(deadline=deadline)
        if server is None:
            return []
        panes = await self._panes(deadline=deadline)
        rows: dict[tuple[str, str], dict[str, Any]] = {}
        for project, identity, managed in managed_candidates:
            if not self._server_matches(identity, server):
                continue
            pane = panes.get(identity["native_id"])
            if pane is None:
                continue
            process_cwd = self._verified_cwd(
                identity,
                (identity["native_id"], *pane),
                server=server,
                managed=managed,
            )
            if process_cwd is None:
                continue
            self._remember(identity, managed)
            rows[(project.id, identity["native_id"])] = self._row(
                project,
                identity,
                name=managed.name,
                readonly=False,
                profile=managed.profile,
                managed=True,
                cwd=process_cwd,
            )

        for project, identity in readonly_candidates:
            if not self._server_matches(identity, server):
                continue
            pane = panes.get(identity["native_id"])
            if pane is None:
                continue
            process_cwd = self._verified_cwd(
                identity,
                (identity["native_id"], *pane),
                server=server,
                managed=None,
            )
            if process_cwd is None:
                continue
            key = (project.id, identity["native_id"])
            if key in rows:
                continue
            rows[key] = self._row(
                project,
                identity,
                name=identity["native_id"],
                readonly=True,
                profile=None,
                managed=False,
                cwd=process_cwd,
            )
        return sorted(rows.values(), key=lambda row: (row["project"], row["name"], row["native_id"]))

    def _target_identity(self, target: Mapping[str, Any], *, managed: bool) -> dict[str, Any]:
        identity = _identity(target.get("identity"), managed=managed)
        if identity is None or target.get("native_id") != identity["native_id"]:
            _raise("stale_target", "unverified_identity")
        if target.get("connection") not in (None, self.connection.id):
            _raise("stale_target", "wrong_connection")
        return identity

    async def _verify_managed_target(
        self,
        target: Mapping[str, Any],
        *,
        deadline: float,
        profile: Profile | None = None,
    ) -> tuple[dict[str, Any], _Managed, Path]:
        if target.get("readonly") is not False or target.get("managed") is not True:
            _raise("unsupported_operation", "managed_pane_required")
        identity = self._target_identity(target, managed=True)
        if target.get("nonce") != identity["nonce"]:
            _raise("stale_target", "nonce_mismatch")
        managed = self._managed.get(_identity_key(identity))
        if managed is None:
            _raise("stale_target", "managed_record_missing")
        if target.get("project") != managed.project or target.get("profile") != managed.profile:
            _raise("stale_target", "binding_mismatch")
        if profile is not None:
            if profile.id != managed.profile:
                _raise("stale_target", "profile_mismatch")
            argv, executable = _runtime_command(
                profile.executable, profile.args, trusted_path=self._trusted_path
            )
            if tuple(argv) != managed.argv or executable != managed.executable:
                _raise("stale_target", "profile_command_mismatch")
        server = await self._server(deadline=deadline)
        if server is None:
            _raise("stale_target", "tmux_server_missing")
        if not self._server_matches(identity, server):
            _raise("stale_target", "server_generation_changed")
        pane = await self._pane(identity["native_id"], deadline=deadline)
        process_cwd = self._verified_cwd(identity, pane, server=server, managed=managed)
        if process_cwd is None:
            _raise("stale_target", "pane_generation_changed")
        if target.get("cwd") != str(process_cwd):
            _raise("stale_target", "pane_cwd_changed")
        return identity, managed, process_cwd


    async def _verify_readonly_target(
        self,
        target: Mapping[str, Any],
        *,
        deadline: float,
    ) -> tuple[dict[str, Any], Project, Path]:
        actual = self._target_identity(target, managed=False)
        project_id = target.get("project")
        project = self._readonly_projects.get(project_id) if isinstance(project_id, str) else None
        if project is None:
            _raise("stale_target", "readonly_project_missing")
        matched = False
        for registration in self.connection.read_targets:
            if not isinstance(registration, Mapping) or registration.get("project") != project_id:
                continue
            native_id = registration.get("native_id")
            raw = registration.get("identity")
            if not isinstance(raw, Mapping):
                continue
            registered = _identity({**raw, "native_id": native_id}, managed=False)
            if registered == actual:
                matched = True
                break
        if not matched or self.connection.id not in project.connections:
            _raise("stale_target", "readonly_registration_mismatch")
        server = await self._server(deadline=deadline)
        if server is None:
            _raise("stale_target", "tmux_server_missing")
        if not self._server_matches(actual, server):
            _raise("stale_target", "server_generation_changed")
        pane = await self._pane(actual["native_id"], deadline=deadline)
        process_cwd = self._verified_cwd(actual, pane, server=server, managed=None)
        if process_cwd is None:
            _raise("stale_target", "pane_generation_changed")
        if target.get("cwd") != str(process_cwd):
            _raise("stale_target", "pane_cwd_changed")
        return actual, project, process_cwd

    async def read(self, target: dict[str, Any], lines: int, *, deadline: float) -> dict[str, Any]:
        if type(lines) is not int or not 1 <= lines <= _MAX_READ_LINES:
            _raise("invalid_request", "invalid_read_lines")
        if not isinstance(target, Mapping):
            _raise("stale_target", "invalid_target")
        if target.get("readonly") is True:
            identity, _, cwd = await self._verify_readonly_target(target, deadline=deadline)
        else:
            identity, _, cwd = await self._verify_managed_target(target, deadline=deadline)
        _, stdout, _ = await self._execute(
            ("capture-pane", "-p", "-t", identity["native_id"]),
            deadline=deadline,
        )
        captured_lines = stdout.splitlines(keepends=True)
        text = b"".join(captured_lines[-lines:]).decode("utf-8", "replace")
        return {
            **dict(target),
            "identity": identity,
            "cwd": str(cwd),
            "process_state": "running",
            "agent_state": "unknown",
            "state_source": "unavailable",
            "text": text,
        }

    def _prompt_bytes(self, text: object) -> bytes:
        if not isinstance(text, str) or not text:
            _raise("invalid_request", "invalid_prompt_text")
        try:
            data = text.encode("utf-8", "strict")
        except UnicodeError:
            _raise("invalid_request", "invalid_prompt_text")
        if len(data) > _MAX_PROMPT_BYTES or any(
            (ord(char) < 0x20 and char not in "\n\t") or 0x7F <= ord(char) <= 0x9F
            for char in text
        ):
            _raise("invalid_request", "invalid_prompt_text")
        return data

    def _validate_profile(self, profile: Profile) -> tuple[list[str], Path]:
        if (
            "tmux" not in profile.backends
            or profile.input_mode != "bracketed-paste"
        ):
            _raise("unsupported_operation", "tmux_profile_input_unsupported")
        return _runtime_command(
            profile.executable, profile.args, trusted_path=self._trusted_path
        )

    async def _delete_buffer(self, name: str, *, deadline: float) -> bool:
        cleanup_deadline = max(deadline, time.monotonic() + 1.0)
        code, _, _ = await self._execute(
            ("delete-buffer", "-b", name),
            deadline=cleanup_deadline,
            allow_failure=True,
        )
        return code == 0

    async def _cleanup_buffer(self, name: str, *, deadline: float) -> bool:
        task = asyncio.create_task(self._delete_buffer(name, deadline=deadline))
        expires = time.monotonic() + 1.0
        interrupted = False
        while not task.done():
            remaining = expires - time.monotonic()
            if remaining <= 0:
                task.cancel()
                break
            try:
                await asyncio.wait_for(asyncio.shield(task), remaining)
            except asyncio.CancelledError:
                interrupted = True
            except asyncio.TimeoutError:
                task.cancel()
                break
            except Exception:
                break
        if interrupted:
            raise asyncio.CancelledError
        if task.cancelled():
            return False
        try:
            return task.result()
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def prompt(
        self,
        target: dict[str, Any],
        text: str,
        profile: Profile,
        *,
        deadline: float,
    ) -> dict[str, Any]:
        data = self._prompt_bytes(text)
        expected_argv, expected_executable = self._validate_profile(profile)
        if not isinstance(target, Mapping):
            _raise("stale_target", "invalid_target")
        identity, managed, _ = await self._verify_managed_target(
            target, deadline=deadline, profile=profile
        )
        verified_target = dict(target)
        verified_target["identity"] = dict(identity)
        if tuple(expected_argv) != managed.argv or expected_executable != managed.executable:
            _raise("stale_target", "profile_command_mismatch")

        buffer_name = "dotunnel-" + uuid.uuid4().hex
        buffer_touched = False
        paste_started = False
        delivery: str | None = None
        cleanup_ok = True
        try:
            # Revalidate the recorded pane immediately before staging; after
            # loading, it is checked again immediately before the paste.
            buffer_touched = True
            code, _, _ = await self._execute(
                ("load-buffer", "-b", buffer_name, "-"),
                deadline=deadline,
                input=data,
                allow_failure=True,
            )
            if code != 0:
                delivery = "unknown"
            else:
                await self._verify_managed_target(verified_target, deadline=deadline, profile=profile)
                paste_started = True
                try:
                    code, _, _ = await self._execute(
                        (
                            "paste-buffer",
                            "-p",
                            "-r",
                            "-b",
                            buffer_name,
                            "-t",
                            identity["native_id"],
                        ),
                        deadline=deadline,
                        allow_failure=True,
                    )
                    delivery = "confirmed" if code == 0 else "unknown"
                except asyncio.CancelledError:
                    raise
                except Exception:
                    delivery = "unknown"
        finally:
            if buffer_touched:
                cleanup_ok = await self._cleanup_buffer(buffer_name, deadline=deadline)
        if delivery is None:
            delivery = "unknown" if paste_started else "refused"
        if not cleanup_ok:
            delivery = "unknown"
        return {"delivery": delivery}

    async def answer(
        self,
        target: dict[str, Any],
        keys: list[str],
        *,
        deadline: float,
    ) -> dict[str, Any]:
        if (
            not isinstance(keys, list)
            or not 1 <= len(keys) <= _MAX_KEYS
            or any(not isinstance(key, str) or key not in _KEY_NAMES for key in keys)
        ):
            _raise("invalid_request", "invalid_answer_keys")
        if not isinstance(target, Mapping):
            _raise("stale_target", "invalid_target")
        dispatched = False
        try:
            # Map only fixed allowlisted keys immediately before dispatch.
            identity, _, _ = await self._verify_managed_target(target, deadline=deadline)
            dispatched = True
            code, _, _ = await self._execute(
                ("send-keys", "-t", identity["native_id"], *(_KEY_NAMES[key] for key in keys)),
                deadline=deadline,
                allow_failure=True,
            )
            return {"delivery": "confirmed" if code == 0 else "unknown"}
        except asyncio.CancelledError:
            raise
        except Exception:
            if dispatched:
                return {"delivery": "unknown"}
            raise
