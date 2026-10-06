"""Interactive opt-in registration of installed native CLI wrapper jobs."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import termios
import tty
import select
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import cli_jobs, config as config_helpers, integrations
from .integrations import CLI_LABELS, SUPPORTED_CLIS, TASK_NAMES


_BWRAP = integrations.BWRAP_PATH
_SETUP_CONFIG = "config.json"
_PROFILE = "profile.yaml"
_KEY_REFERENCE = "runtime-api-key"
_JOB_DIRECTORY = "cli-jobs"
_REQUEST_DIRECTORY = "dotunnel-requests"
_TASK_TIMEOUT = 240
_CONFIG_LIMIT = 64 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PRIVATE_READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_PRIVATE_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_TASK_DESCRIPTIONS = {
    backend: f"Run the configured {CLI_LABELS[backend]} isolated CLI job from its local request file."
    for backend in SUPPORTED_CLIS
}
_RUNTIME_FIELDS = {
    "codex": (
        ("executable", "native executable"),
        ("companion", "codex-code-mode-host companion executable"),
        ("auth", "private auth.json reference"),
    ),
    "claude": (
        ("executable", "native executable"),
        ("oauth_token", "private OAuth token file reference"),
    ),
    "omp": (
        ("executable", "Bun executable"),
        ("cli", "OMP CLI module file"),
        ("modules", "OMP installed module directory"),
        ("config", "private OMP config file reference"),
        ("auth", "private OMP auth database reference"),
    ),
}


@dataclass(frozen=True)
class _Snapshot:
    device: int
    inode: int
    links: int
    owner: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    digest: str


@dataclass
class _State:
    directory: Path
    parent_fd: int
    directory_fd: int
    root: Path
    document: dict[str, Any]
    snapshot: _Snapshot

    def close(self) -> None:
        os.close(self.directory_fd)
        os.close(self.parent_fd)


@dataclass(frozen=True)
class _Prepared:
    backend: str
    value: dict[str, Any]
    request_text: str
    needs_write: bool


@dataclass
class _CreatedEntry:
    parent_fd: int
    name: str
    device: int
    inode: int
    is_directory: bool


def _safe_json(raw: bytes) -> Any:
    def reject_constant(_value: str) -> Any:
        raise ValueError

    return json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=config_helpers._object,
        parse_constant=reject_constant,
    )


def _snapshot(info: os.stat_result, raw: bytes) -> _Snapshot:
    return _Snapshot(
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        hashlib.sha256(raw).hexdigest(),
    )


def _read_fd(fd: int, *, limit: int = _CONFIG_LIMIT) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > limit
    ):
        raise ValueError("Setup configuration must be a private regular file")
    chunks = bytearray()
    offset = 0
    while len(chunks) <= limit:
        block = os.pread(fd, min(8192, limit + 1 - len(chunks)), offset)
        if not block:
            break
        chunks.extend(block)
        offset += len(block)
    after = os.fstat(fd)
    if (
        len(chunks) > limit
        or len(chunks) != after.st_size
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or after.st_nlink != 1
        or after.st_uid != os.getuid()
        or stat.S_IMODE(after.st_mode) != 0o600
    ):
        raise ValueError("Setup configuration changed while being read")
    return bytes(chunks), after


def _open_state_directory(directory: Path) -> tuple[Path, int, int]:
    if not isinstance(directory, Path):
        directory = Path(directory)
    if ".." in directory.parts:
        raise ValueError("Choose a setup directory without parent traversal")
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    directory = Path(os.path.normpath(os.fspath(directory)))
    if directory.name in {"", ".", "/"}:
        raise ValueError("Setup directory is invalid")
    try:
        from .setup import _trusted_parent

        parent_fd = _trusted_parent(directory.parent)
        try:
            directory_fd = os.open(directory.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
    except (OSError, TypeError, ValueError):
        raise ValueError("Setup directory is unavailable or unsafe") from None
    info = os.fstat(directory_fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(directory_fd)
        os.close(parent_fd)
        raise ValueError("Setup directory must be a private operator-owned 0700 directory")
    return directory, parent_fd, directory_fd


def _read_registry(directory: Path) -> _State:
    directory, parent_fd, directory_fd = _open_state_directory(directory)
    try:
        for name in (_PROFILE, _KEY_REFERENCE):
            try:
                fd = os.open(name, _PRIVATE_READ_FLAGS, dir_fd=directory_fd)
            except OSError:
                raise ValueError("Existing setup key/profile references are unavailable or unsafe") from None
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise ValueError("Existing setup key/profile references are unavailable or unsafe")
            finally:
                os.close(fd)
        try:
            config_fd = os.open(_SETUP_CONFIG, _PRIVATE_READ_FLAGS, dir_fd=directory_fd)
        except OSError:
            raise ValueError("Existing setup registry is unavailable or unsafe") from None
        try:
            raw, info = _read_fd(config_fd)
        finally:
            os.close(config_fd)
        try:
            document = _safe_json(raw)
            if not isinstance(document, dict):
                raise ValueError
        except (UnicodeError, ValueError, TypeError, RecursionError):
            raise ValueError("Existing setup registry is invalid or unsafe") from None
        config_path = directory / _SETUP_CONFIG
        try:
            loaded = config_helpers.load_config(config_path)
        except (OSError, TypeError, ValueError):
            raise ValueError("Existing setup registry is invalid or unsafe") from None
        if loaded.root != Path(document.get("root", "")):
            raise ValueError("Existing setup registry changed while being inspected")
        try:
            current_fd = os.open(_SETUP_CONFIG, _PRIVATE_READ_FLAGS, dir_fd=directory_fd)
            try:
                current_raw, current_info = _read_fd(current_fd)
            finally:
                os.close(current_fd)
        except OSError:
            raise ValueError("Existing setup registry changed while being inspected") from None
        if _snapshot(info, raw) != _snapshot(current_info, current_raw):
            raise ValueError("Existing setup registry changed while being inspected")
        return _State(
            directory=directory,
            parent_fd=parent_fd,
            directory_fd=directory_fd,
            root=loaded.root,
            document=document,
            snapshot=_snapshot(info, raw),
        )
    except BaseException:
        os.close(directory_fd)
        os.close(parent_fd)
        raise


def _state_path_matches(state: _State) -> bool:
    try:
        current = os.stat(state.directory.name, dir_fd=state.parent_fd, follow_symlinks=False)
        opened = os.fstat(state.directory_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == opened.st_dev
        and current.st_ino == opened.st_ino
        and current.st_uid == os.getuid()
        and stat.S_IMODE(current.st_mode) == 0o700
    )


def _owned_tasks(document: dict[str, Any], directory: Path) -> dict[str, dict[str, Any]]:
    by_name = {name: backend for backend, name in TASK_NAMES.items()}
    owned: dict[str, dict[str, Any]] = {}
    for task in document["tasks"]:
        if not isinstance(task, dict):
            continue
        backend = by_name.get(task.get("name"))
        if backend is None:
            continue
        config_path = directory / _JOB_DIRECTORY / f"{backend}.json"
        valid = integrations.is_managed_task(task, backend, config_path)
        if not valid:
            raise ValueError("A reserved native CLI task name is already in use")
        owned[backend] = task
    return owned


def _terminal_key(fd: int) -> bytes | None:
    try:
        ready, _, _ = select.select([fd], [], [], 0.12)
        if not ready:
            return None
        value = os.read(fd, 1)
        if not value:
            raise ValueError("Terminal input reached EOF; no selection was accepted")
        return value
    except OSError:
        raise ValueError("Terminal input failed; no selection was accepted") from None


def _write_selector(installed: list[str], selected: set[str], focus: int) -> None:
    stream = sys.stdout
    stream.write("\x1b[2J\x1b[H")
    stream.write("Select installed native CLI integrations (Up/Down, Space toggle, Enter accept, Esc cancel):\r\n")
    for index, backend in enumerate(installed):
        marker = "x" if backend in selected else " "
        focus_marker = ">" if index == focus else " "
        stream.write(f"{focus_marker} [{marker}] {CLI_LABELS[backend]}\r\n")
    stream.flush()


def select_clis(
    installed: Mapping[str, Path],
    initially_selected: set[str] | frozenset[str] = frozenset(),
) -> set[str] | None:
    """Raw-terminal checkbox selector; None means explicit cancellation."""
    names = [backend for backend in SUPPORTED_CLIS if backend in installed]
    if not names:
        return set()
    if not set(initially_selected) <= set(names):
        raise ValueError("Initial CLI selection is invalid")
    try:
        fd = sys.stdin.fileno()
        if not os.isatty(fd):
            raise ValueError("CLI selection requires an interactive terminal")
        original = termios.tcgetattr(fd)
    except (OSError, AttributeError, ValueError, termios.error):
        raise ValueError("CLI selection requires an interactive terminal") from None
    selected = set(initially_selected)
    focus = 0
    try:
        tty.setraw(fd, termios.TCSADRAIN)
        _write_selector(names, selected, focus)
        while True:
            key = _terminal_key(fd)
            if key is None:
                continue
            if key in (b"\x03",):
                return None
            if key in (b"\r", b"\n"):
                return set(selected)
            if key == b" ":
                backend = names[focus]
                if backend in selected:
                    selected.remove(backend)
                else:
                    selected.add(backend)
                _write_selector(names, selected, focus)
                continue
            if key == b"\x1b":
                prefix = _terminal_key(fd)
                if prefix == b"[":
                    direction = _terminal_key(fd)
                    if direction == b"A":
                        focus = max(0, focus - 1)
                    elif direction == b"B":
                        focus = min(len(names) - 1, focus + 1)
                    _write_selector(names, selected, focus)
                    continue
                if prefix is None:
                    return None
                return None
    except (OSError, termios.error):
        raise ValueError("Terminal input failed; no selection was accepted") from None
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, original)
        except (OSError, termios.error):
            raise ValueError("Terminal settings could not be restored") from None


def _available(installed: Mapping[str, Path]) -> dict[str, Path]:
    if not isinstance(installed, Mapping):
        raise ValueError("Installed CLI discovery result is invalid")
    result: dict[str, Path] = {}
    for backend, path in installed.items():
        if backend not in SUPPORTED_CLIS or not isinstance(path, Path):
            raise ValueError("Installed CLI discovery result is invalid")
        result[backend] = path
    return result


def _prompt(prompt_fn: Callable[[str], str] | None, text: str) -> str:
    function = input if prompt_fn is None else prompt_fn
    value = function(text)
    if not isinstance(value, str):
        raise ValueError("A text value is required; nothing was changed")
    return value.strip()


def _absolute_input(value: str, label: str) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or "\x00" in value:
            raise ValueError
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError
        return Path(os.path.normpath(os.fspath(path)))
    except (TypeError, ValueError, UnicodeError):
        raise ValueError(f"Enter an absolute, non-traversing {label} path") from None


def _list_input(value: str, *, allow_empty: bool) -> list[str]:
    if not value.strip() and allow_empty:
        return []
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        raise ValueError("Enter comma-separated relative paths")
    values: list[str] = []
    for part in parts:
        try:
            components = cli_jobs._relative_path(part)
            value = "/".join(components)
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("Use safe, allowed relative source-file paths") from None
        if value in values:
            raise ValueError("Source-file paths must be unique")
        values.append(value)
    return values


def _prompt_job(
    state: _State,
    backend: str,
    prompt_fn: Callable[[str], str] | None,
) -> tuple[dict[str, Any], str]:
    runtime: dict[str, str] = {}
    for key, label in _RUNTIME_FIELDS[backend]:
        runtime[key] = str(_absolute_input(
            _prompt(prompt_fn, f"{CLI_LABELS[backend]} {label} (absolute path)"),
            "runtime reference",
        ))
    alias = _prompt(prompt_fn, "Target alias (letters, digits, underscore, hyphen)")
    if not cli_jobs._IDENTIFIER.fullmatch(alias):
        raise ValueError("Target alias must be 1-64 letters, digits, underscores, or hyphens")
    source_root = _absolute_input(_prompt(prompt_fn, "Source root directory (absolute path)"), "source root")
    source_files = _list_input(_prompt(prompt_fn, "Allowed relative files (comma-separated)"), allow_empty=False)
    editable = _list_input(
        _prompt(prompt_fn, "Editable subset (comma-separated; blank means review-only)"),
        allow_empty=True,
    )
    value: dict[str, Any] = {
        "backend": backend,
        "workspace": str(state.root),
        "request": f"{_REQUEST_DIRECTORY}/{backend}.json",
        "runtime": runtime,
        "targets": {
            alias: {
                "root": str(source_root),
                "files": source_files,
                "editable": editable,
            }
        },
    }
    request = {
        "target": alias,
        "mode": "review",
        "instruction": "Review the selected files for correctness and report concrete findings with file and line references. Do not modify anything.",
    }
    request_text = json.dumps(request, indent=2) + "\n"
    config_path = state.directory / _JOB_DIRECTORY / f"{backend}.json"
    integrations._validate_job_data(
        config_path,
        backend,
        state.root,
        value,
        request_text,
        bwrap_path=_BWRAP,
    )
    return value, request_text


def _directory_at(parent_fd: int, name: str, *, create: bool, created: list[_CreatedEntry]) -> int:
    made = False
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            made = True
        except FileExistsError:
            pass
    try:
        fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError:
        raise ValueError("Integration directory is unavailable or unsafe") from None
    try:
        info = os.fstat(fd)
        if made:
            created.append(_CreatedEntry(os.dup(parent_fd), name, info.st_dev, info.st_ino, True))
            os.fchmod(fd, 0o700)
            info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Integration directory must be private and operator-owned")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _workspace_fd(workspace: Path) -> int:
    try:
        from .setup import _trusted_parent

        parent_fd = _trusted_parent(workspace.parent)
        try:
            fd = os.open(workspace.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    except (OSError, TypeError, ValueError):
        raise ValueError("MCP workspace is unavailable or unsafe") from None
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ValueError("MCP workspace must be a private operator-owned directory")
    return fd


def _entry_exists(parent_fd: int | None, name: str) -> bool:
    if parent_fd is None:
        return False
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        raise ValueError("Integration file path is unavailable or unsafe") from None


def _existing_artifacts(state: _State, backend: str) -> tuple[bool, int | None, int | None]:
    job_directory_fd: int | None = None
    workspace_fd: int | None = None
    request_directory_fd: int | None = None
    try:
        if _entry_exists(state.directory_fd, _JOB_DIRECTORY):
            job_directory_fd = _directory_at(state.directory_fd, _JOB_DIRECTORY, create=False, created=[])
        workspace_fd = _workspace_fd(state.root)
        if _entry_exists(workspace_fd, _REQUEST_DIRECTORY):
            request_directory_fd = _directory_at(workspace_fd, _REQUEST_DIRECTORY, create=False, created=[])
        config_exists = _entry_exists(job_directory_fd, f"{backend}.json")
        request_exists = _entry_exists(request_directory_fd, f"{backend}.json")
        if config_exists != request_exists:
            raise ValueError("Incomplete prior integration files; no task was registered")
        return config_exists, job_directory_fd, request_directory_fd
    except BaseException:
        if job_directory_fd is not None:
            os.close(job_directory_fd)
        if request_directory_fd is not None:
            os.close(request_directory_fd)
        raise
    finally:
        if workspace_fd is not None:
            os.close(workspace_fd)


def _write_file(parent_fd: int, name: str, content: bytes, created: list[_CreatedEntry]) -> None:
    try:
        fd = os.open(name, _PRIVATE_CREATE_FLAGS, 0o600, dir_fd=parent_fd)
    except OSError:
        raise ValueError("An integration file already exists or cannot be created; nothing was overwritten") from None
    try:
        info = os.fstat(fd)
        created.append(_CreatedEntry(os.dup(parent_fd), name, info.st_dev, info.st_ino, False))
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("New integration file has unsafe metadata")
        os.fchmod(fd, 0o600)
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(fd)
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_uid != os.getuid()
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_size != len(content)
        ):
            raise ValueError("New integration file changed while being written")
    except OSError:
        raise ValueError("Integration file could not be written safely") from None
    finally:
        os.close(fd)


def _cleanup_created(created: list[_CreatedEntry]) -> None:
    for entry in reversed(created):
        try:
            info = os.stat(entry.name, dir_fd=entry.parent_fd, follow_symlinks=False)
            if info.st_dev == entry.device and info.st_ino == entry.inode:
                if entry.is_directory:
                    os.rmdir(entry.name, dir_fd=entry.parent_fd)
                else:
                    os.unlink(entry.name, dir_fd=entry.parent_fd)
        except OSError:
            pass
        finally:
            os.close(entry.parent_fd)
    created.clear()


def _close_created(created: list[_CreatedEntry]) -> None:
    for entry in created:
        os.close(entry.parent_fd)
    created.clear()


def _create_artifacts(state: _State, prepared: list[_Prepared]) -> list[_CreatedEntry]:
    pending = [item for item in prepared if item.needs_write]
    if not pending:
        return []
    created: list[_CreatedEntry] = []
    job_directory_fd: int | None = None
    workspace_fd: int | None = None
    request_directory_fd: int | None = None
    try:
        job_directory_fd = _directory_at(state.directory_fd, _JOB_DIRECTORY, create=True, created=created)
        workspace_fd = _workspace_fd(state.root)
        request_directory_fd = _directory_at(workspace_fd, _REQUEST_DIRECTORY, create=True, created=created)
        for item in pending:
            config_text = json.dumps(item.value, indent=2) + "\n"
            if len(config_text.encode("utf-8")) > _CONFIG_LIMIT:
                raise ValueError("Integration configuration exceeds the supported size")
            _write_file(job_directory_fd, f"{item.backend}.json", config_text.encode("utf-8"), created)
            _write_file(request_directory_fd, f"{item.backend}.json", item.request_text.encode("utf-8"), created)
    except BaseException:
        _cleanup_created(created)
        raise
    finally:
        if request_directory_fd is not None:
            os.close(request_directory_fd)
        if workspace_fd is not None:
            os.close(workspace_fd)
        if job_directory_fd is not None:
            os.close(job_directory_fd)
    return created


def _operator_command(workspace: Path) -> Path:
    candidate = shutil.which("dotunnel")
    if candidate is None:
        raise ValueError("Install the dotunnel command before registering native CLI integrations")
    try:
        command = integrations._inspect_launcher(candidate)
        if command is None or command.name != "dotunnel":
            raise ValueError
        info = integrations._checked_path(command, "executable")
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("The installed dotunnel command is unavailable or unsafe") from None
    if command.is_relative_to(workspace):
        raise ValueError("The dotunnel command must be outside the writable MCP workspace")
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError("The installed dotunnel command is unavailable or unsafe")
    return command


def _task(backend: str, command: Path, config_path: Path, workspace: Path) -> dict[str, Any]:
    argv = [str(command), "cli-job", "--config", str(config_path)]
    try:
        from .tasks import TaskSpec

        TaskSpec(
            name=TASK_NAMES[backend],
            description=_TASK_DESCRIPTIONS[backend],
            argv=tuple(argv),
            cwd=workspace,
            timeout_seconds=_TASK_TIMEOUT,
        )
    except (TypeError, ValueError):
        raise ValueError("Native CLI task definition is invalid") from None
    return {
        "name": TASK_NAMES[backend],
        "description": _TASK_DESCRIPTIONS[backend],
        "argv": argv,
        "cwd": ".",
        "timeout_seconds": _TASK_TIMEOUT,
    }


def _snapshot_at(directory_fd: int) -> tuple[bytes, _Snapshot]:
    try:
        fd = os.open(_SETUP_CONFIG, _PRIVATE_READ_FLAGS, dir_fd=directory_fd)
    except OSError:
        raise ValueError("Setup registry changed or became unsafe") from None
    try:
        raw, info = _read_fd(fd)
    finally:
        os.close(fd)
    return raw, _snapshot(info, raw)


def _assert_registry_snapshot(state: _State, expected: _Snapshot) -> None:
    _raw, current = _snapshot_at(state.directory_fd)
    if current != expected or not _state_path_matches(state):
        raise ValueError("Setup registry changed; rerun setup to review current integrations")


def _write_registry(state: _State, document: dict[str, Any], expected: _Snapshot) -> None:
    raw = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    if len(raw) > _CONFIG_LIMIT:
        raise ValueError("Setup registry exceeds the supported size")
    try:
        current_fd = os.open(_SETUP_CONFIG, _PRIVATE_READ_FLAGS, dir_fd=state.directory_fd)
    except OSError:
        raise ValueError("Setup registry changed or became unsafe") from None
    temporary = f".config.json.{uuid.uuid4().hex}.tmp"
    temporary_created = False
    renamed = False
    try:
        fcntl.flock(current_fd, fcntl.LOCK_EX)
        old_raw, old_snapshot = _snapshot_at(state.directory_fd)
        if old_snapshot != expected:
            raise ValueError("Setup registry changed; rerun setup to review current integrations")
        if not _state_path_matches(state):
            raise ValueError("Setup directory changed; no registry update was published")
        try:
            temp_fd = os.open(temporary, _PRIVATE_CREATE_FLAGS, 0o600, dir_fd=state.directory_fd)
        except OSError:
            raise ValueError("A private registry update file could not be created") from None
        temporary_created = True
        try:
            os.fchmod(temp_fd, 0o600)
            view = memoryview(raw)
            offset = 0
            while offset < len(view):
                written = os.write(temp_fd, view[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(temp_fd)
        except OSError:
            raise ValueError("The private registry update could not be written safely") from None
        finally:
            os.close(temp_fd)
        try:
            config_helpers.load_config(state.directory / temporary)
        except (OSError, TypeError, ValueError):
            raise ValueError("The selected task registry is invalid; no update was published") from None
        confirm_raw, confirm_snapshot = _snapshot_at(state.directory_fd)
        if confirm_snapshot != expected or confirm_raw != old_raw:
            raise ValueError("Setup registry changed; rerun setup to review current integrations")
        if not _state_path_matches(state):
            raise ValueError("Setup directory changed; no registry update was published")
        os.rename(
            temporary,
            _SETUP_CONFIG,
            src_dir_fd=state.directory_fd,
            dst_dir_fd=state.directory_fd,
        )
        renamed = True
        try:
            os.fsync(state.directory_fd)
        except OSError:
            pass
    except (OSError, UnicodeError):
        raise ValueError("Setup registry could not be updated safely") from None
    finally:
        if temporary_created and not renamed:
            try:
                os.unlink(temporary, dir_fd=state.directory_fd)
            except OSError:
                pass
        os.close(current_fd)



def _same_selection(current: list[dict[str, Any]], updated: list[dict[str, Any]]) -> bool:
    return current == updated



def configure_integrations(
    directory: Path,
    installed: Mapping[str, Path],
    selected: set[str] | frozenset[str],
    *,
    prompt_fn: Callable[[str], str] | None = None,
    _expected_snapshot: _Snapshot | None = None,
) -> bool:
    """Validate all selected wrappers, then publish one atomic task-registry update."""
    available = _available(installed)
    try:
        selected_set = set(selected)
    except TypeError:
        raise ValueError("Native CLI selection is invalid") from None
    if not selected_set <= set(available):
        raise ValueError("Only installed Codex, Claude Code, and OMP integrations can be selected")
    state = _read_registry(directory)
    created: list[_CreatedEntry] = []
    published_bytes: bytes | None = None
    published = False
    try:
        if _expected_snapshot is not None and state.snapshot != _expected_snapshot:
            raise ValueError("Setup registry changed while selection was open; rerun setup")
        active = _owned_tasks(state.document, state.directory)
        prepared: list[_Prepared] = []
        for backend in SUPPORTED_CLIS:
            if backend not in selected_set:
                continue
            config_path = state.directory / _JOB_DIRECTORY / f"{backend}.json"
            exists, job_directory_fd, request_directory_fd = _existing_artifacts(state, backend)
            if job_directory_fd is not None:
                os.close(job_directory_fd)
            if request_directory_fd is not None:
                os.close(request_directory_fd)
            if exists:
                integrations._load_managed_job(
                    config_path,
                    backend,
                    state.root,
                    bwrap_path=_BWRAP,
                )
                prepared.append(_Prepared(backend, {}, "", False))
            else:
                value, request_text = _prompt_job(state, backend, prompt_fn)
                prepared.append(_Prepared(backend, value, request_text, True))

        updated_tasks: list[dict[str, Any]] = []
        for task_value in state.document["tasks"]:
            backend = next((name for name, task_name in TASK_NAMES.items() if task_value.get("name") == task_name), None)
            if backend is None:
                updated_tasks.append(task_value)
            elif backend not in available or backend in selected_set:
                updated_tasks.append(task_value)
        added = [item.backend for item in prepared if item.backend not in active]
        command = _operator_command(state.root) if added else None
        for backend in added:
            item = next(value for value in prepared if value.backend == backend)
            config_path = state.directory / _JOB_DIRECTORY / f"{backend}.json"
            assert command is not None
            updated_tasks.append(_task(backend, command, config_path, state.root))
        if len(updated_tasks) > 50:
            raise ValueError("Task registry limit would be exceeded")
        names = [task.get("name") for task in updated_tasks]
        if len(names) != len(set(names)):
            raise ValueError("Task registry contains a reserved-name collision")

        updated_document = dict(state.document)
        updated_document["tasks"] = updated_tasks
        registry_changed = not _same_selection(state.document["tasks"], updated_tasks)
        if registry_changed:
            published_bytes = (json.dumps(updated_document, indent=2) + "\n").encode("utf-8")
        if registry_changed or any(item.needs_write for item in prepared):
            _assert_registry_snapshot(state, state.snapshot)
        if any(item.needs_write for item in prepared):
            created = _create_artifacts(state, prepared)
            for item in prepared:
                if item.needs_write:
                    integrations._load_managed_job(
                        state.directory / _JOB_DIRECTORY / f"{item.backend}.json",
                        item.backend,
                        state.root,
                        bwrap_path=_BWRAP,
                    )
        if registry_changed:
            _write_registry(state, updated_document, state.snapshot)
            published = True
        elif created:
            _assert_registry_snapshot(state, state.snapshot)
        if selected_set:
            print("Selected native CLI wrappers are registered as fixed optional tasks; requests start in review mode.")
            print("Auth references were checked by path metadata only. Authentication is not proven; no model request was run.")
        elif registry_changed:
            print("Deselected installed native CLIs; only setup-owned task entries were removed.")
        else:
            print("No native CLI integration tasks changed.")
        _close_created(created)
        return True
    except BaseException:
        if not published and published_bytes is not None:
            try:
                current_raw, _current_snapshot = _snapshot_at(state.directory_fd)
                published = current_raw == published_bytes and _state_path_matches(state)
            except (OSError, UnicodeError, ValueError):
                pass
        if not published:
            _cleanup_created(created)
        else:
            _close_created(created)
        raise
    finally:
        state.close()


def configure_directory(
    directory: Path,
    installed: Mapping[str, Path],
    *,
    selector_fn: Callable[[Mapping[str, Path], set[str]], set[str] | None] | None = None,
    prompt_fn: Callable[[str], str] | None = None,
    bubblewrap_fn: Callable[[], str] | None = None,
) -> bool:
    available = _available(installed)
    check = (lambda: integrations.bubblewrap_status(_BWRAP)) if bubblewrap_fn is None else bubblewrap_fn
    state = _read_registry(directory)
    try:
        status = check()
        integrations.print_bubblewrap_status(status)
        if not available:
            print("No installed Codex, Claude Code, or OMP CLI was found on PATH; optional integrations were skipped.")
            print("Install any native CLI separately, then rerun `dotunnel setup` to select its wrapper integration.")
            return True
        while status != "ready":
            answer = _prompt(
                prompt_fn,
                "Install Bubblewrap in another terminal, then press Enter to check again, or type s to skip CLI integrations: ",
            ).lower()
            if answer in ("s", "skip"):
                print("Optional CLI integrations skipped; setup configuration was not changed.")
                print(f"After installing Bubblewrap, run `dotunnel setup --directory {state.directory}` to enable them.")
                return True
            status = check()
            integrations.print_bubblewrap_status(status)
        active = _owned_tasks(state.document, state.directory)
        initial = set(active) & set(available)
        choose = select_clis if selector_fn is None else selector_fn
        selected = choose(available, initial)
        if selected is None:
            print("Native CLI selection cancelled; setup configuration was not changed.")
            return False
        return configure_integrations(
            state.directory,
            available,
            selected,
            prompt_fn=prompt_fn,
            _expected_snapshot=state.snapshot,
        )
    finally:
        state.close()


class _OnboardingParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid setup arguments; use --help. Secrets belong only in hidden terminal prompts, never argv.\n")


def _arguments(argv: list[str] | None) -> tuple[list[str], argparse.Namespace]:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = _OnboardingParser(
        prog="dotunnel setup",
        description="Configure the private MCP setup and optional installed native CLI wrappers",
    )
    parser.add_argument("--directory", type=Path, default=Path.cwd() / ".dotunnel-setup")
    parser.add_argument(
        "--tunnel-client",
        type=Path,
        default=Path(client) if (client := shutil.which("tunnel-client")) else None,
    )
    return values, parser.parse_args(values)


def _configure_new_setup(profile: Path) -> None:
    installed = integrations.discover_clis()
    if not configure_directory(profile.parent, installed):
        raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    try:
        values, args = _arguments(argv)
        directory = args.directory
        if ".." in directory.parts:
            raise ValueError("Choose a setup directory without parent traversal")
        if not directory.is_absolute():
            directory = Path.cwd() / directory
        directory = Path(os.path.normpath(os.fspath(directory)))
        if sys.platform != "linux" or os.getuid() == 0:
            raise ValueError("Run setup on Linux as a non-root operator")
        if os.path.lexists(directory):
            installed = integrations.discover_clis()
            return 0 if configure_directory(directory, installed) else 130
        client = args.tunnel_client
        if client is None or not client.is_absolute():
            raise ValueError("Install the official Tunnel client on PATH or pass an absolute --tunnel-client path")
        verified_client = integrations._inspect_launcher(str(client))
        if verified_client is None:
            raise ValueError("Tunnel client executable or its parent directory is unsafe")
        values += ["--tunnel-client", str(verified_client)]
        from . import setup

        return setup.main(values, configuration_callback=_configure_new_setup)
    except ValueError as error:
        print(f"Setup failed: {error}. No integration selection was published.", file=sys.stderr)
        return 2
    except (OSError, EOFError):
        print("Setup failed because local input or private files were unavailable. No credential value was displayed.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nSetup cancelled or interrupted; any completed registry update remains intact.", file=sys.stderr)
        return 130
