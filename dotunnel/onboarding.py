"""Interactive opt-in registration of installed native CLI wrapper jobs."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import termios
import tty
import select
import uuid
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from . import cli_jobs, config as config_helpers, integrations
from .integrations import CLI_LABELS, SUPPORTED_CLIS, TASK_NAMES
import subprocess


_BWRAP = integrations.BWRAP_PATH
_SETUP_CONFIG = "config.json"
_PROFILE = "profile.yaml"
_KEY_REFERENCE = "runtime-api-key"
_JOB_DIRECTORY = "cli-jobs"
_REQUEST_DIRECTORY = "dotunnel-requests"
_TASK_TIMEOUT = 240
_CONFIG_LIMIT = 64 * 1024
_PROC_ROOT = Path("/proc")
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

@dataclass(frozen=True)
class _SupervisionStateSnapshot:
    path: Path
    root: tuple[int, int]
    key_file: tuple[int, ...]
    epoch_file: tuple[int, ...]
    epoch: str
    key_digest: bytes


@dataclass
class _State:
    directory: Path
    parent_fd: int
    directory_fd: int
    root: Path
    document: dict[str, Any]
    snapshot: _Snapshot
    references: dict[str, tuple[int, int, int, int, int]]
    legacy: bool = False

    def close(self) -> None:
        os.close(self.directory_fd)
        os.close(self.parent_fd)


@dataclass(frozen=True)
class _Prepared:
    backend: str
    value: dict[str, Any]
    request_text: str
    config_path: Path
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



def _migrate_legacy_document(document: dict[str, Any]) -> dict[str, Any]:
    allowed_fields = {"root", "tasks", "file_access", "supervision"}
    if set(document) - allowed_fields or not {"root", "tasks"} <= set(document):
        raise ValueError("Existing setup registry is invalid or unsafe")
    converted = copy.deepcopy(document)
    legacy = "file_access" not in converted
    if legacy:
        converted["file_access"] = {
            "read": [{"path": ".", "kind": "tree"}],
            "write": [{"path": ".", "kind": "tree"}],
        }
    supervision = converted.get("supervision")
    if supervision is not None:
        if not isinstance(supervision, dict) or set(supervision) - {
            "state_dir", "connections", "projects", "profiles", "default_connection", "protected_paths",
        }:
            raise ValueError("Existing setup supervision is invalid or unsafe")
        connections = supervision.get("connections")
        profiles = supervision.get("profiles")
        projects = supervision.get("projects")
        if not isinstance(connections, list) or not isinstance(profiles, list) or not isinstance(projects, list):
            raise ValueError("Existing setup supervision is invalid or unsafe")
        by_connection = {item.get("id"): item for item in connections if isinstance(item, dict)}
        by_profile = {item.get("id"): item for item in profiles if isinstance(item, dict)}
        for project in projects:
            if not isinstance(project, dict):
                raise ValueError("Existing setup supervision is invalid or unsafe")
            if "allowed_actions" in project and "profile_actions" in project:
                continue
            legacy = True
            project_id = project.get("id")
            protected = project.get("protected", False)
            if not isinstance(protected, bool):
                raise ValueError("Existing setup supervision is invalid or unsafe")
            project_connections = project.get("connections", [])
            project_profiles = project.get("profiles", [])
            if not isinstance(project_connections, list) or not isinstance(project_profiles, list):
                raise ValueError("Existing setup supervision is invalid or unsafe")
            has_allowed_actions = "allowed_actions" in project
            explicit_ceiling = project.get("allowed_actions")
            ceiling = set(explicit_ceiling) if isinstance(explicit_ceiling, list) else {"read"}
            if not has_allowed_actions:
                ceiling = {"read"}
            per_profile: dict[str, list[str]] = {}
            mutations = {"start", "prompt", "answer"}
            for profile_id in project_profiles:
                profile = by_profile.get(profile_id, {})
                profile_backends = profile.get("backends", ["herdr", "tmux"])
                permitted = not protected and any(
                    isinstance(by_connection.get(connection_id), dict)
                    and by_connection[connection_id].get("backend") in profile_backends
                    and not (
                        by_connection[connection_id].get("backend") == "tmux"
                        and any(
                            isinstance(target, dict) and target.get("project") == project_id
                            for target in by_connection[connection_id].get("read_targets", [])
                        )
                    )
                    for connection_id in project_connections
                )
                actions = sorted(
                    mutations if has_allowed_actions is False else mutations & ceiling
                ) if permitted else []
                per_profile[str(profile_id)] = actions
                if not has_allowed_actions:
                    ceiling.update(actions)
            project["allowed_actions"] = sorted(ceiling)
            if "profile_actions" not in project:
                project["profile_actions"] = per_profile
        converted["supervision"] = supervision
    if not legacy:
        raise ValueError("Existing setup registry is invalid or unsafe")
    return converted


def _read_registry(directory: Path) -> _State:
    directory, parent_fd, directory_fd = _open_state_directory(directory)
    try:
        references: dict[str, tuple[int, int, int, int, int]] = {}
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
                references[name] = (
                    info.st_dev,
                    info.st_ino,
                    info.st_nlink,
                    info.st_uid,
                    stat.S_IMODE(info.st_mode),
                )
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
        legacy = False
        try:
            config_helpers.load_config(config_path)
        except (OSError, TypeError, ValueError):
            try:
                document = _migrate_legacy_document(document)
                loaded = config_helpers._parse_document(document, config_path)
                legacy = True
            except (OSError, TypeError, ValueError, KeyError):
                raise ValueError("Existing setup registry is invalid or unsafe") from None
        else:
            try:
                loaded = config_helpers._parse_document(document, config_path)
            except (OSError, TypeError, ValueError, KeyError):
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
            references=references,
            legacy=legacy,
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
        argv = task.get("argv")
        config_path = (
            Path(argv[3])
            if isinstance(argv, list) and len(argv) == 4 and isinstance(argv[3], str)
            else Path("/")
        )
        relative = (
            config_path.relative_to(directory)
            if config_path.is_absolute() and config_path.is_relative_to(directory)
            else Path("/")
        )
        legacy_path = relative == Path(_JOB_DIRECTORY) / f"{backend}.json"
        generated_path = (
            len(relative.parts) == 3
            and relative.parts[0] == "native-cli"
            and relative.parts[2] == f"{backend}.json"
            and relative.parts[1]
            and all(character.isalnum() or character in "_-" for character in relative.parts[1])
        )
        valid = (legacy_path or generated_path) and integrations.is_managed_task(
            task, backend, config_path
        )
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
    directory: Path,
    workspace: Path,
    backend: str,
    prompt_fn: Callable[[str], str] | None,
    generation: str,
    *,
    workspace_ready: bool,
) -> _Prepared:
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
    source_files = _list_input(
        _prompt(prompt_fn, "Allowed relative files (comma-separated)"),
        allow_empty=False,
    )
    editable = _list_input(
        _prompt(prompt_fn, "Editable subset (comma-separated; blank means review-only)"),
        allow_empty=True,
    )
    request_path = f"{_REQUEST_DIRECTORY}/{generation}/{backend}.json"
    config_path = directory / "native-cli" / generation / f"{backend}.json"
    value: dict[str, Any] = {
        "backend": backend,
        "workspace": str(workspace),
        "request": request_path,
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
    integrations._validate_job_data(
        config_path,
        backend,
        workspace,
        value,
        request_text,
        bwrap_path=_BWRAP,
        workspace_ready=workspace_ready,
    )
    return _Prepared(backend, value, request_text, config_path, True)


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


def _create_artifacts(
    directory: Path,
    workspace: Path,
    prepared: list[_Prepared],
) -> list[_CreatedEntry]:
    pending = [item for item in prepared if item.needs_write]
    if not pending:
        return []
    generation = pending[0].config_path.parent.name
    for item in pending:
        if (
            item.config_path != directory / "native-cli" / generation / f"{item.backend}.json"
            or item.value.get("request") != f"{_REQUEST_DIRECTORY}/{generation}/{item.backend}.json"
        ):
            raise ValueError("One setup publication must use a single immutable CLI job generation")
    created: list[_CreatedEntry] = []
    setup_fd: int | None = None
    native_fd: int | None = None
    generation_fd: int | None = None
    workspace_fd: int | None = None
    request_fd: int | None = None
    request_generation_fd: int | None = None
    try:
        from .setup import _trusted_parent

        setup_parent_fd = _trusted_parent(directory.parent)
        try:
            setup_fd = os.open(directory.name, _DIRECTORY_FLAGS, dir_fd=setup_parent_fd)
        finally:
            os.close(setup_parent_fd)
        native_fd = _directory_at(setup_fd, "native-cli", create=True, created=created)
        generation_fd = _directory_at(native_fd, generation, create=True, created=created)
        workspace_fd = _workspace_fd(workspace)
        request_fd = _directory_at(
            workspace_fd, _REQUEST_DIRECTORY, create=True, created=created,
        )
        request_generation_fd = _directory_at(
            request_fd, generation, create=True, created=created,
        )
        for item in pending:
            config_text = json.dumps(item.value, indent=2) + "\n"
            config_bytes = config_text.encode("utf-8")
            if len(config_bytes) > _CONFIG_LIMIT:
                raise ValueError("Integration configuration exceeds the supported size")
            _write_file(generation_fd, f"{item.backend}.json", config_bytes, created)
            _write_file(
                request_generation_fd,
                f"{item.backend}.json",
                item.request_text.encode("utf-8"),
                created,
            )
        for item in pending:
            integrations._load_managed_job(
                item.config_path,
                item.backend,
                workspace,
                bwrap_path=_BWRAP,
            )
    except BaseException:
        _cleanup_created(created)
        raise
    finally:
        for fd in (
            request_generation_fd,
            request_fd,
            workspace_fd,
            generation_fd,
            native_fd,
            setup_fd,
        ):
            if fd is not None:
                os.close(fd)
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
def _workspace_is_job_eligible(workspace: Path) -> bool:
    try:
        info = os.stat(workspace, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _job_overview(task: dict[str, Any], backend: str) -> dict[str, Any]:
    argv = task.get("argv")
    if not isinstance(argv, list) or len(argv) != 4 or not isinstance(argv[3], str):
        raise ValueError("A setup-owned fixed job has an invalid private config reference")
    try:
        config_path, value = cli_jobs._load_private_config(argv[3])
        parsed = cli_jobs._parse_config_shape(value)
        if parsed.backend != backend or len(parsed.targets) != 1:
            raise ValueError
        target = next(iter(parsed.targets.values()))
    except (cli_jobs._InvalidConfig, OSError, TypeError, ValueError):
        raise ValueError("A setup-owned fixed job is unavailable or unsafe") from None
    return {
        "backend": backend,
        "root": str(target.root),
        "files": list(target.files),
        "editable": list(target.editable),
        "config": str(config_path),
        "request": str(parsed.workspace / parsed.request),
        "request_relative": parsed.request,
        "workspace": parsed.workspace,
    }


def _new_task_document(
    document: dict[str, Any],
    workspace: Path,
    overviews: dict[str, dict[str, Any]],
    prepared: list[_Prepared],
    replaced: set[str],
    removals: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    updated: list[dict[str, Any]] = []
    removed: list[dict[str, str]] = []
    for task in document["tasks"]:
        backend = next(
            (name for name, task_name in TASK_NAMES.items() if task.get("name") == task_name),
            None,
        )
        if backend is None:
            updated.append(task)
            continue
        if backend in removals:
            removed.append({"backend": backend, "workspace": "not inspected"})
        elif backend in replaced:
            removed.append({
                "backend": backend,
                "workspace": str(overviews[backend]["workspace"]),
            })
        else:
            updated.append(task)
    added = {item.backend for item in prepared if item.needs_write}
    command = _operator_command(workspace) if added else None
    for backend in SUPPORTED_CLIS:
        if backend not in added:
            continue
        item = next(value for value in prepared if value.backend == backend)
        assert command is not None
        updated.append(_task(backend, command, item.config_path, workspace))
    if len(updated) > 50:
        raise ValueError("Task registry limit would be exceeded")
    names = [task.get("name") for task in updated]
    if len(names) != len(set(names)):
        raise ValueError("Task registry contains a reserved-name collision")
    return updated, removed


def _request_rules(
    draft: Any,
    request_relatives: tuple[str, ...],
    prompt_fn: Callable[[str], str] | None,
) -> dict[str, list[dict[str, str]]] | None:
    from . import permission_setup
    from .file_access import FileAccess

    before = FileAccess.parse(draft.file_access)
    if not request_relatives:
        return draft.file_access
    after = permission_setup.add_request_grants(draft.file_access, request_relatives)
    after_policy = FileAccess.parse(after)
    request_parts = {tuple(request.split("/")) for request in request_relatives}
    additions = {
        action: [
            rule
            for rule in getattr(after_policy, action)
            if rule.kind == "file"
            and rule.parts in request_parts
            and rule not in getattr(before, action)
        ]
        for action in ("read", "write")
    }
    if not any(additions.values()):
        return draft.file_access
    print("Fixed jobs require separately reviewed exact request-control-file access:")
    for action in ("read", "write"):
        for rule in additions[action]:
            print(f"  MCP {action}: exact file {draft.workspace / '/'.join(rule.parts)}")
    if not permission_setup.confirm(
        prompt_fn,
        "Add these explicit exact request-file read/write rules? [y/N]: ",
        default=False,
    ):
        return None
    return after



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
    for name, reference in state.references.items():
        try:
            fd = os.open(name, _PRIVATE_READ_FLAGS, dir_fd=state.directory_fd)
        except OSError:
            raise ValueError("Setup key/profile references changed; nothing was published") from None
        try:
            info = os.fstat(fd)
            current_reference = (
                info.st_dev,
                info.st_ino,
                info.st_nlink,
                info.st_uid,
                stat.S_IMODE(info.st_mode),
            )
            if current_reference != reference or not stat.S_ISREG(info.st_mode):
                raise ValueError("Setup key/profile references changed; nothing was published")
        finally:
            os.close(fd)


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
        os.fsync(state.directory_fd)
    except (OSError, UnicodeError):
        if renamed:
            from .setup import ConfigPublicationUnconfirmed

            raise ConfigPublicationUnconfirmed(
                "the configuration rename succeeded, but directory durability could not be confirmed"
            ) from None
        raise ValueError("Setup registry could not be updated safely") from None
    finally:
        if temporary_created and not renamed:
            try:
                os.unlink(temporary, dir_fd=state.directory_fd)
            except OSError:
                pass
        os.close(current_fd)



def _offer_bubblewrap_install(
    status: str,
    check: Callable[[], str],
    prompt_fn: Callable[[str], str] | None,
    sudo_fn: Callable[[], bool],
    install_fn: Callable[[list[str]], bool],
    argv: list[str] | None,
) -> str:
    """Offer a best-effort sudo install attempt; otherwise print guidance."""
    if argv and sudo_fn():
        command = shlex.join(argv)
        while True:
            answer = _prompt(prompt_fn, f"Sudo appears available for this account. Install Bubblewrap now with `{command}`? [Y/n] ").lower()
            if answer in ("", "y", "yes"):
                if install_fn(argv):
                    status = check()
                    integrations.print_bubblewrap_status(status)
                    if status != "missing":
                        return status
                print("Bubblewrap installation did not complete; nothing else was changed.")
                break
            if answer in ("n", "no"):
                break
            print("Enter Y or n.")
    integrations.print_bubblewrap_guidance(argv)
    return status


def _choose_fixed_jobs(
    available: Mapping[str, Path],
    initially_selected: set[str],
    directory: Path,
    *,
    chooser: Callable[[Mapping[str, Path], set[str]], set[str] | None] | None = None,
    prompt_fn: Callable[[str], str] | None = None,
    check: Callable[[], str] | None = None,
    sudo_fn: Callable[[], bool] | None = None,
    install_fn: Callable[[list[str]], bool] | None = None,
    install_argv_fn: Callable[[], list[str] | None] | None = None,
    on_skip: Callable[[], None] | None = None,
) -> set[str] | None:
    available = _available(available)
    status_check = (
        (lambda: integrations.bubblewrap_status(_BWRAP))
        if check is None else check
    )
    status = status_check()
    integrations.print_bubblewrap_status(status)
    if status == "missing":
        status = _offer_bubblewrap_install(
            status,
            status_check,
            prompt_fn,
            integrations.sudo_available if sudo_fn is None else sudo_fn,
            integrations.install_bubblewrap if install_fn is None else install_fn,
            (integrations.bubblewrap_install_argv if install_argv_fn is None else install_argv_fn)(),
        )
    if not available:
        print("No installed Codex, Claude Code, or OMP CLI was found on PATH; optional integrations were skipped.")
        print("Install any native CLI separately, then rerun `dotunnel setup` to select its wrapper integration.")
        return set()
    while status != "ready":
        answer = _prompt(
            prompt_fn,
            "Install Bubblewrap in another terminal, then press Enter to check again, or type s to skip CLI integrations: ",
        ).casefold()
        if answer in ("s", "skip"):
            if on_skip is not None:
                on_skip()
            print("Optional CLI integrations skipped; no setup changes have been saved.")
            print(f"After installing Bubblewrap, run `dotunnel setup --directory {directory}` to enable them.")
            return set()
        status = status_check()
        integrations.print_bubblewrap_status(status)
    choose = select_clis if chooser is None else chooser
    selected = choose(available, set(initially_selected))
    if selected is None:
        print("Native CLI selection cancelled; no setup changes were made.")
        return None
    try:
        result = set(selected)
    except TypeError:
        raise ValueError("Native CLI selection is invalid") from None
    if not result <= set(available):
        raise ValueError("Only installed Codex, Claude Code, and OMP integrations can be selected")
    return result


def _private_directory_handles(directory: Path) -> tuple[int, int, int, int]:
    from .setup import _trusted_parent

    parent_fd = _trusted_parent(directory.parent)
    try:
        directory_fd = os.open(directory.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    info = os.fstat(directory_fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(directory_fd)
        os.close(parent_fd)
        raise ValueError("Private setup directory changed or is unsafe")
    return parent_fd, directory_fd, info.st_dev, info.st_ino


def _private_directory_matches(directory: Path, handles: tuple[int, int, int, int]) -> bool:
    parent_fd, directory_fd, device, inode = handles
    try:
        opened = os.fstat(directory_fd)
        visible = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        opened.st_dev == device
        and opened.st_ino == inode
        and visible.st_dev == device
        and visible.st_ino == inode
        and stat.S_ISDIR(visible.st_mode)
        and visible.st_uid == os.getuid()
        and stat.S_IMODE(visible.st_mode) == 0o700
    )


def _private_reference_snapshot(directory: Path) -> dict[str, tuple[int, int, int, int, int]]:
    from .setup import _trusted_parent

    parent_fd = _trusted_parent(directory.parent)
    try:
        setup_fd = os.open(directory.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        references: dict[str, tuple[int, int, int, int, int]] = {}
        for name in (_PROFILE, _KEY_REFERENCE):
            try:
                fd = os.open(name, _PRIVATE_READ_FLAGS, dir_fd=setup_fd)
            except OSError:
                raise ValueError("New private key/profile references are unavailable or unsafe") from None
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise ValueError("New private key/profile references are unavailable or unsafe")
                references[name] = (
                    info.st_dev,
                    info.st_ino,
                    info.st_nlink,
                    info.st_uid,
                    stat.S_IMODE(info.st_mode),
                )
            finally:
                os.close(fd)
        return references
    finally:
        os.close(setup_fd)


def _private_references_match(
    directory: Path,
    expected: dict[str, tuple[int, int, int, int, int]],
) -> bool:
    try:
        return _private_reference_snapshot(directory) == expected
    except (OSError, TypeError, ValueError):
        return False


def _initial_config_matches(directory_fd: int, document: dict[str, Any]) -> bool:
    try:
        fd = os.open(_SETUP_CONFIG, _PRIVATE_READ_FLAGS, dir_fd=directory_fd)
        try:
            raw, _info = _read_fd(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return False
    return raw == (json.dumps(document, indent=2) + "\n").encode("utf-8")


def _supervision_file_identity(authority: Any, name: str) -> tuple[int, ...]:
    fd = os.open(name, _PRIVATE_READ_FLAGS, dir_fd=authority._dir_fd)
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("Existing live supervision state is unsafe")
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _supervision_state_snapshot(path: Path) -> _SupervisionStateSnapshot:
    from .supervision_state import SupervisionState

    authority = None
    try:
        authority = SupervisionState(path)

        def root_identity() -> tuple[int, int]:
            opened = os.fstat(authority._dir_fd)
            visible = os.stat(authority.path, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(visible.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
            ):
                raise ValueError("Existing live supervision state changed")
            return opened.st_dev, opened.st_ino

        root_before = root_identity()
        key_before = _supervision_file_identity(authority, "key")
        epoch_before = _supervision_file_identity(authority, "epoch.json")
        epoch = authority.epoch
        key_digest = hashlib.sha256(authority.key).digest()
        key_after = _supervision_file_identity(authority, "key")
        epoch_after = _supervision_file_identity(authority, "epoch.json")
        root_after = root_identity()
        if (
            root_before != root_after
            or key_before != key_after
            or epoch_before != epoch_after
        ):
            raise ValueError("Existing live supervision state changed")
        return _SupervisionStateSnapshot(
            authority.path,
            root_after,
            key_after,
            epoch_after,
            epoch,
            key_digest,
        )
    except (OSError, TypeError, ValueError):
        raise ValueError(
            "Existing live supervision state is missing, invalid, or changed; "
            "setup will not save or reinitialize it"
        ) from None
    finally:
        if authority is not None:
            authority.close()


def _assert_supervision_state_unchanged(
    expected: _SupervisionStateSnapshot | None,
) -> None:
    if expected is not None and _supervision_state_snapshot(expected.path) != expected:
        raise ValueError(
            "Existing live supervision state changed; configuration was not published"
        )


def _initialize_supervision_state(
    path: Path,
    directory: Path,
) -> tuple[tuple[int, int], list[_CreatedEntry]]:
    created: list[_CreatedEntry] = []
    setup_parent_fd = -1
    setup_fd = -1
    supervision_fd = -1
    authority = None
    identity: tuple[int, int] | None = None
    try:
        from .setup import _trusted_parent
        from .supervision_state import SupervisionState

        setup_parent_fd = _trusted_parent(directory.parent)
        setup_fd = os.open(directory.name, _DIRECTORY_FLAGS, dir_fd=setup_parent_fd)
        setup_info = os.fstat(setup_fd)
        if setup_info.st_uid != os.getuid() or stat.S_IMODE(setup_info.st_mode) != 0o700:
            raise ValueError("Private setup directory changed or is unsafe")
        supervision_fd = _directory_at(setup_fd, "supervision", create=True, created=created)
        if os.path.lexists(path):
            raise ValueError("New supervision state path already exists; no state was reinitialized")
        authority = SupervisionState.initialize(path)
        state_info = os.fstat(authority._dir_fd)
        visible = os.stat(path.name, dir_fd=supervision_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(visible.st_mode)
            or (state_info.st_dev, state_info.st_ino) != (visible.st_dev, visible.st_ino)
            or visible.st_uid != os.getuid()
            or stat.S_IMODE(visible.st_mode) != 0o700
        ):
            raise ValueError("New supervision state changed during initialization")
        identity = (state_info.st_dev, state_info.st_ino)
        authority.close()
        authority = None
        return identity, created
    except BaseException:
        if authority is not None:
            authority.close()
            authority = None
        if identity is not None:
            _remove_new_supervision_state(path, identity)
        _cleanup_created(created)
        raise
    finally:
        if authority is not None:
            authority.close()
        for fd in (supervision_fd, setup_fd, setup_parent_fd):
            if fd >= 0:
                os.close(fd)


def _remove_new_supervision_state(path: Path, identity: tuple[int, int]) -> bool:
    from .setup import _trusted_parent
    from .supervision_state import _CATEGORIES

    parent_fd = root_fd = -1
    try:
        parent_fd = _trusted_parent(path.parent)
        root_fd = os.open(path.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        root_info = os.fstat(root_fd)
        visible = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (root_info.st_dev, root_info.st_ino) != identity
            or (visible.st_dev, visible.st_ino) != identity
            or visible.st_uid != os.getuid()
            or stat.S_IMODE(visible.st_mode) != 0o700
        ):
            return False
        files = ("key", "epoch.json", "lock")
        if set(os.listdir(root_fd)) != set(files) | set(_CATEGORIES):
            return False
        file_ids: dict[str, tuple[int, int]] = {}
        for name in files:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                return False
            file_ids[name] = (info.st_dev, info.st_ino)
        directory_ids: dict[str, tuple[int, int]] = {}
        for name in _CATEGORIES:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                return False
            child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root_fd)
            try:
                child_info = os.fstat(child_fd)
                if (
                    (child_info.st_dev, child_info.st_ino) != (info.st_dev, info.st_ino)
                    or os.listdir(child_fd)
                ):
                    return False
            finally:
                os.close(child_fd)
            directory_ids[name] = (info.st_dev, info.st_ino)
        for name, expected in file_ids.items():
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != expected:
                return False
            os.unlink(name, dir_fd=root_fd)
        for name, expected in directory_ids.items():
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != expected:
                return False
            os.rmdir(name, dir_fd=root_fd)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            return False
        os.rmdir(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _read_proc_file(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = bytearray()
        while len(value) <= limit:
            chunk = os.read(fd, min(4096, limit + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
        if len(value) > limit:
            raise ValueError("Process metadata exceeds the supported bound")
        return bytes(value)
    finally:
        os.close(fd)


def _process_starttime(raw: bytes) -> bytes:
    closing = raw.rfind(b")")
    if closing < 0:
        raise ValueError("Malformed process state")
    fields = raw[closing + 1:].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        raise ValueError("Malformed process state")
    return fields[19]


def _local_client_state(client: Path, profile: Path, *, proc_root: Path | None = None) -> str:
    """Classify the matching local client using bounded, secret-free proc metadata."""
    proc_root = _PROC_ROOT if proc_root is None else proc_root
    try:
        executable = client.resolve(strict=True)
        profile_path = profile.resolve(strict=True)
        entries = list(proc_root.iterdir())
        if len(entries) > 32768:
            return "unknown"
    except (OSError, RuntimeError, ValueError):
        return "unknown"
    found = False
    states = {b"R", b"S", b"D", b"Z", b"T", b"t", b"X", b"x", b"K", b"W", b"P", b"I"}

    def dead_leader(entry: Path, first: bytes | None = None) -> bool:
        first = _read_proc_file(entry / "stat", 8192) if first is None else first
        start = _process_starttime(first)
        fields = first[first.rfind(b")") + 1:].split()
        if not fields or fields[0] not in states:
            raise ValueError("Malformed process state")
        if fields[0] not in (b"Z", b"X"):
            return False
        count = 0
        for thread in (entry / "task").iterdir():
            count += 1
            if count > 32768 or thread.name != entry.name:
                raise ValueError("Zombie still has live tasks")
        second = _read_proc_file(entry / "stat", 8192)
        fields = second[second.rfind(b")") + 1:].split()
        return count == 1 and _process_starttime(second) == start and bool(fields) and fields[0] in (b"Z", b"X")

    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdigit():
            continue
        try:
            status = _read_proc_file(entry / "status", 8192).decode("ascii", "strict")
            line = next((line[4:] for line in status.splitlines() if line.startswith("Uid:")), None)
            if line is None:
                return "unknown"
            uids = line.split()
            if len(uids) != 4 or any(not value.isascii() or not value.isdigit() for value in uids):
                return "unknown"
            if os.getuid() not in {int(value) for value in uids}:
                continue
            try:
                raw_executable = os.readlink(entry / "exe")
            except (FileNotFoundError, ProcessLookupError):
                try:
                    entry.lstat()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if dead_leader(entry):
                    continue
                return "unknown"
            if not os.path.isabs(raw_executable):
                return "unknown"
            if raw_executable.endswith(" (deleted)"):
                if Path(raw_executable[:-10]).resolve(strict=False) == executable:
                    return "unknown"
                continue
            if Path(raw_executable).resolve(strict=False) != executable:
                continue
            first = _read_proc_file(entry / "stat", 8192)
            first_start = _process_starttime(first)
            if dead_leader(entry, first):
                continue
            command = _read_proc_file(entry / "cmdline", 8192)
            second = _read_proc_file(entry / "stat", 8192)
            second_fields = second[second.rfind(b")") + 1:].split()
            if (_process_starttime(second) != first_start or not second_fields or second_fields[0] not in states
                    or second_fields[0] in (b"Z", b"X") or not command.endswith(b"\0")):
                return "unknown"
            argv = command[:-1].split(b"\0")
            if argv != [os.fsencode(executable), b"run", b"--profile-file", os.fsencode(profile_path)]:
                return "unknown"
            found = True
        except (FileNotFoundError, ProcessLookupError):
            try:
                entry.lstat()
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError:
                return "unknown"
            return "unknown"
        except (OSError, UnicodeError, RuntimeError, ValueError):
            return "unknown"
    return "active" if found else "stopped"


def _require_stopped_client(client: Path, profile: Path, *, state: str | None = None) -> None:
    result = _local_client_state(client, profile) if state is None else state
    if result != "stopped":
        raise ValueError("The existing Tunnel client is active or its local ownership/state is unknown; stop the corresponding owned client before reconfiguration")


def _confirm_no_other_client(prompt_fn: Callable[[str], str] | None) -> bool:
    from .permission_setup import confirm
    print("A local process check cannot prove that no other local or remote client owns this Tunnel.")
    return confirm(prompt_fn, "I explicitly confirm no other local or remote client is active for this Tunnel [y/N]: ", default=False)


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

def _client_path(value: Path | None) -> Path:
    if value is None or not value.is_absolute():
        raise ValueError("Install the official Tunnel client on PATH or pass an absolute --tunnel-client path")
    try:
        client = integrations._inspect_launcher(str(value))
    except (OSError, RuntimeError, TypeError, ValueError):
        client = None
    if client is None:
        raise ValueError("Tunnel client executable or its parent directory is unsafe")
    return client


def _require_interactive_terminal() -> None:
    try:
        interactive = sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, OSError, ValueError):
        interactive = False
    if not interactive:
        raise ValueError("Setup onboarding requires an interactive terminal")


def main(argv: list[str] | None = None) -> int:
    from . import permission_setup, setup

    state: _State | None = None
    supervision_snapshot: _SupervisionStateSnapshot | None = None
    staged: list[_CreatedEntry] = []
    workspace_entry: _CreatedEntry | None = None
    private_handles: tuple[int, int, int, int] | None = None
    new_references: dict[str, tuple[int, int, int, int, int]] | None = None
    private_artifacts_started = False
    new_state_path: Path | None = None
    new_state_identity: tuple[int, int] | None = None
    state_staging: list[_CreatedEntry] = []
    published = False
    directory = Path.cwd() / ".dotunnel-setup"
    try:
        _values, args = _arguments(argv)
        directory = args.directory
        if ".." in directory.parts:
            raise ValueError("Choose a setup directory without parent traversal")
        if not directory.is_absolute():
            directory = Path.cwd() / directory
        directory = Path(os.path.normpath(os.fspath(directory)))
        if sys.platform != "linux" or os.getuid() == 0:
            raise ValueError("Run setup on Linux as a non-root operator")
        _require_interactive_terminal()
        client = _client_path(args.tunnel_client)

        existing_setup = os.path.lexists(directory)
        if existing_setup:
            state = _read_registry(directory)
            directory = state.directory
            document = copy.deepcopy(state.document)
            active = _owned_tasks(document, directory)
            if document.get("supervision") is not None:
                supervision_snapshot = _supervision_state_snapshot(
                    Path(document["supervision"]["state_dir"])
                )
            _require_stopped_client(client, directory / _PROFILE)
            if not _confirm_no_other_client(None):
                print("No external-client attestation; existing setup was not changed.")
                return 130
            legacy = state.legacy
            current_root = state.root
            current_file_access = document.get("file_access")
            current_supervision = document.get("supervision")
        else:
            from .setup import _destination

            _destination(directory)
            document = {"tasks": []}
            active = {}
            legacy = False
            current_root = None
            current_file_access = None
            current_supervision = None

        generation = uuid.uuid4().hex
        draft = permission_setup.collect_draft(
            None,
            directory=directory,
            current_root=current_root,
            current_file_access=current_file_access,
            current_supervision=current_supervision,
            existing_setup=existing_setup,
            legacy=legacy,
            selected_jobs=set(),
            generation=generation,
        )
        directory = draft.directory
        if not existing_setup:
            from .setup import _destination

            _destination(directory)

        available = integrations.discover_clis()
        if not draft.create_workspace and not _workspace_is_job_eligible(draft.workspace):
            print(
                "This existing project is not an operator-owned 0700 workspace. "
                "Fixed native CLI jobs are unavailable; no chmod will be attempted."
            )
            available = {}
        selection_skipped = False

        def mark_selection_skipped() -> None:
            nonlocal selection_skipped
            selection_skipped = True

        selected = _choose_fixed_jobs(
            available,
            initial,
            directory,
            on_skip=mark_selection_skipped,
        )
        if selected is None:
            return 130

        removals: set[str] = set()
        for backend in SUPPORTED_CLIS:
            if backend not in active or backend in selected:
                continue
            if backend in available and not selection_skipped:
                removals.add(backend)
            elif permission_setup.confirm(
                None,
                f"Remove the existing setup-owned {CLI_LABELS[backend]} task registration? [y/N]: ",
                default=False,
            ):
                removals.add(backend)
        overviews = {
            backend: _job_overview(task, backend)
            for backend, task in active.items()
            if backend not in removals
        }
        replaced = {
            backend for backend in selected
            if backend in overviews and overviews[backend]["workspace"] != draft.workspace
        }
        prepared: list[_Prepared] = []
        for backend in SUPPORTED_CLIS:
            if backend not in selected or backend in active and backend not in replaced:
                continue
            prepared.append(_prompt_job(
                draft.directory,
                draft.workspace,
                backend,
                None,
                generation,
                workspace_ready=not draft.create_workspace,
            ))

        updated_tasks, removed_jobs = _new_task_document(
            document,
            draft.workspace,
            overviews,
            prepared,
            replaced,
            removals,
        )
        updated_document = copy.deepcopy(document)
        updated_document["root"] = str(draft.workspace)
        updated_document["file_access"] = draft.file_access
        updated_document["tasks"] = updated_tasks
        if draft.supervision is None:
            updated_document.pop("supervision", None)
        else:
            updated_document["supervision"] = draft.supervision

        job_details: list[dict[str, Any]] = []
        retained_backends = {
            backend for backend, task in active.items()
            if any(value.get("name") == task.get("name") for value in updated_tasks)
        }
        for backend in SUPPORTED_CLIS:
            if backend in retained_backends and backend not in replaced:
                detail = dict(overviews[backend])
                integrations._load_managed_job(
                    Path(detail["config"]),
                    backend,
                    Path(detail["workspace"]),
                    bwrap_path=_BWRAP,
                )
                job_details.append(detail)
        for item in prepared:
            parsed = cli_jobs._parse_config_shape(item.value)
            target = next(iter(parsed.targets.values()))
            job_details.append({
                "backend": item.backend,
                "root": str(target.root),
                "files": list(target.files),
                "editable": list(target.editable),
                "config": str(item.config_path),
                "request": str(draft.workspace / parsed.request),
            })
        request_relatives = tuple(dict.fromkeys(
            [
                str(detail["request_relative"])
                for backend, detail in overviews.items()
                if backend in retained_backends and detail["workspace"] == draft.workspace
            ]
            + [
                cli_jobs._parse_config_shape(item.value).request
                for item in prepared
            ]
        ))
        access = _request_rules(draft, request_relatives, None)
        if access is None:
            print("Exact request-control-file grants were declined; nothing was saved.")
            return 130
        draft = replace(
            draft,
            jobs=frozenset(selected),
            file_access=access,
            requests=request_relatives,
        )
        updated_document["file_access"] = draft.file_access

        permission_setup.validate_draft_document(
            draft,
            updated_document,
            directory / _SETUP_CONFIG,
        )
        reserved_names = set(TASK_NAMES.values())
        general_tasks = [task for task in updated_tasks if task.get("name") not in reserved_names]
        key_reference = directory / _KEY_REFERENCE
        print(f"  Future private config: {directory / _SETUP_CONFIG} (atomic publication last)")
        print(
            f"  Private profile: {directory / _PROFILE} "
            f"({'existing reference preserved' if existing_setup else 'created only after confirmation'})"
        )
        permission_setup.print_summary(
            draft,
            tasks=general_tasks,
            job_details=job_details,
            removed_jobs=removed_jobs,
            key_reference=key_reference,
        )
        if state is None:
            setup._destination(directory)
        else:
            _assert_registry_snapshot(state, state.snapshot)
        _assert_supervision_state_unchanged(supervision_snapshot)
        if draft.create_workspace:
            if os.path.lexists(draft.workspace):
                raise ValueError("New workspace path appeared during setup review; nothing was changed")
            if draft.workspace.parent != directory:
                workspace_parent_fd = setup._trusted_parent(draft.workspace.parent)
                os.close(workspace_parent_fd)
        else:
            workspace_fd = config_helpers._open_absolute(
                draft.workspace,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            os.close(workspace_fd)
        if not permission_setup.confirm(
            None,
            "I approve this exact permission setup and authorize saving these changes? [y/N]: ",
            default=False,
        ):
            print("Permission setup not approved; no key input or filesystem changes were made.")
            return 130

        old_supervision = document.get("supervision")
        if draft.supervision is not None and old_supervision is None:
            new_state_path = Path(draft.supervision["state_dir"])
            if not permission_setup.confirm(
                None,
                f"Initialize new empty supervision state at {new_state_path} now? [y/N]: ",
                default=False,
            ):
                print(
                    "New supervision state was not initialized; no credential input "
                    "or configuration was saved."
                )
                return 130

        tunnel_id: str | None = None
        key: str | None = None
        if not existing_setup:
            tunnel_id = input("Tunnel ID (tunnel_ followed by 32 lowercase hex digits): ").strip()
            setup._validate(tunnel_id, "validation-only")
            key = setup.read_key()
            setup._validate(tunnel_id, key)

        if state is not None:
            _assert_registry_snapshot(state, state.snapshot)

        if existing_setup:
            if draft.create_workspace:
                from .setup import _create_workspace

                parent_fd, workspace_fd, device, inode = _create_workspace(draft.workspace)
                workspace_entry = _CreatedEntry(
                    os.dup(parent_fd),
                    draft.workspace.name,
                    device,
                    inode,
                    True,
                )
                os.close(workspace_fd)
                os.close(parent_fd)
            profile = directory / _PROFILE
        else:
            assert tunnel_id is not None and key is not None
            private_artifacts_started = True
            profile, owned_workspace = setup.prepare_private_artifacts(
                directory,
                tunnel_id,
                key,
                workspace=draft.workspace,
                create_workspace=draft.create_workspace,
            )
            if owned_workspace is not None:
                parent_fd, workspace_fd, device, inode = owned_workspace
                workspace_entry = _CreatedEntry(
                    os.dup(parent_fd),
                    draft.workspace.name,
                    device,
                    inode,
                    True,
                )
                os.close(workspace_fd)
                os.close(parent_fd)

        private_handles = _private_directory_handles(directory)
        if not existing_setup:
            new_references = _private_reference_snapshot(directory)

        if prepared:
            staged = _create_artifacts(directory, draft.workspace, prepared)
        for item in prepared:
            integrations._load_managed_job(
                item.config_path,
                item.backend,
                draft.workspace,
                bwrap_path=_BWRAP,
            )
        config_helpers._parse_document(updated_document, directory / _SETUP_CONFIG)

        if new_state_path is not None:
            new_state_identity, state_staging = _initialize_supervision_state(
                new_state_path,
                directory,
            )
        if state is not None:
            _assert_registry_snapshot(state, state.snapshot)
            _assert_supervision_state_unchanged(supervision_snapshot)
            expected_registry = (json.dumps(updated_document, indent=2) + "\n").encode("utf-8")
            try:
                _write_registry(state, updated_document, state.snapshot)
            except setup.ConfigPublicationUnconfirmed:
                published = True
                raise
            except BaseException:
                try:
                    current_raw, _current = _snapshot_at(state.directory_fd)
                    published = current_raw == expected_registry and _state_path_matches(state)
                except (OSError, UnicodeError, ValueError):
                    pass
                raise
            published = True
        else:
            if (
                private_handles is None
                or new_references is None
                or not _private_directory_matches(directory, private_handles)
                or not _private_references_match(directory, new_references)
            ):
                raise ValueError(
                    "Private setup directory or key/profile references changed; "
                    "configuration was not published"
                )
            try:
                setup.publish_initial_config(
                    directory,
                    updated_document,
                    expected_directory=(private_handles[2], private_handles[3]),
                )
            except setup.ConfigPublicationUnconfirmed:
                published = True
                raise
            except BaseException as error:
                published = (
                    _private_directory_matches(directory, private_handles)
                    and new_references is not None
                    and _private_references_match(directory, new_references)
                    and _initial_config_matches(private_handles[1], updated_document)
                )
                if published and isinstance(error, (OSError, ValueError)):
                    raise setup.ConfigPublicationUnconfirmed(
                        "the configuration is published, but directory durability could not be confirmed"
                    ) from None
                raise
            published = True

        if state_staging:
            _close_created(state_staging)
        _close_created(staged)
        if workspace_entry is not None:
            os.close(workspace_entry.parent_fd)
            workspace_entry = None
        if private_handles is not None:
            os.close(private_handles[0])
            os.close(private_handles[1])
            private_handles = None

        print("Setup configuration saved. Saved permissions are applied only when a new MCP process starts.")
        print("No native model/CLI was run; only the trusted Tunnel client's doctor may run after publication.")
        try:
            setup._doctor(client, profile)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            print(
                "Setup was saved, but the trusted Tunnel client doctor failed; nothing was rolled back.",
                file=sys.stderr,
            )
            return 2

        try:
            _require_stopped_client(client, profile)
        except ValueError as error:
            print(f"Setup was saved; connection start refused: {error}.", file=sys.stderr)
            return 2
        if not _confirm_no_other_client(None):
            print("Setup was saved; no connection was started without explicit external-client attestation.")
            return 0
        if not permission_setup.confirm(
            None,
            "Start the configured Tunnel client in this foreground terminal now? [y/N]: ",
            default=False,
        ):
            print("Setup was saved; the Tunnel client remains stopped.")
            manual_argv = [str(client), "run", "--profile-file", str(profile)]
            print(f"To start later in the foreground: {shlex.join(manual_argv)}")
            setup._registration(tunnel_id)
            return 0
        try:
            return setup._foreground(client, profile, tunnel_id)
        except (OSError, EOFError, ValueError, subprocess.TimeoutExpired):
            print(
                "Setup was saved; foreground startup/readiness did not complete. A Tunnel connection may have started; "
                "the saved configuration and credentials remain intact.",
                file=sys.stderr,
            )
            return 2
    except setup.ConfigPublicationUnconfirmed as error:
        published = True
        print(
            f"Setup configuration publication is unconfirmed; private references were preserved for reconciliation ({error}). "
            "No Tunnel connection was started.",
            file=sys.stderr,
        )
        return 2
    except (ValueError, OSError, EOFError, subprocess.TimeoutExpired) as error:
        if published:
            print(
                "Setup was saved; post-publication input or confirmation did not complete, so no connection was started. "
                "The saved configuration and credentials remain intact.",
                file=sys.stderr,
            )
        elif private_artifacts_started:
            print(
                f"Setup configuration was not published; private preparation was attempted for {directory / _KEY_REFERENCE} "
                f"and {directory / _PROFILE}. Private files may remain there. Inspect those references and choose a new directory "
                "for private setup retry; the key value is not displayed.",
                file=sys.stderr,
            )
        elif isinstance(error, ValueError):
            print(f"Setup failed: {error}.", file=sys.stderr)
        else:
            print(
                "Setup failed because local input or private files were unavailable; "
                "no credential value was displayed.",
                file=sys.stderr,
            )
        return 2
    except KeyboardInterrupt:
        if not published and private_artifacts_started:
            print(
                f"\nSetup was interrupted before publication; private preparation was attempted for "
                f"{directory / _KEY_REFERENCE} and {directory / _PROFILE}. Private files may remain there. "
                "Inspect those references and choose a new directory for private setup retry; the key value is not displayed.",
                file=sys.stderr,
            )
        else:
            print(
                "\nSetup cancelled or interrupted; published configuration and credentials remain intact.",
                file=sys.stderr,
            )
        return 130
    finally:
        if private_handles is not None:
            os.close(private_handles[0])
            os.close(private_handles[1])
        if published and staged:
            _close_created(staged)
        elif not published and staged:
            _cleanup_created(staged)
        if workspace_entry is not None:
            if published:
                os.close(workspace_entry.parent_fd)
            else:
                _cleanup_created([workspace_entry])
        if not published and new_state_identity is not None and new_state_path is not None:
            _remove_new_supervision_state(new_state_path, new_state_identity)
        if published and state_staging:
            _close_created(state_staging)
        elif not published and state_staging:
            _cleanup_created(state_staging)
        if state is not None:
            state.close()
