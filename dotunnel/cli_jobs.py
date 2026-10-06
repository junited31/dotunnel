"""Operator-only isolated native CLI jobs with immutable source snapshots."""

from __future__ import annotations

import argparse
import ctypes
import difflib
import errno
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config as config_helpers
from .files import WorkspaceFiles, _validate_components


_CONFIG_LIMIT = 64 * 1024
_FILE_LIMIT = 64 * 1024
_PATH_LIMIT = 256
_INSTRUCTION_LIMIT = 8192
_DIFF_CHUNK_LIMIT = 48 * 1024
_REPORT_LIMIT = 64 * 1024
_STDOUT_LIMIT = 8 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
_FILE_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | os.O_CLOEXEC
    | os.O_NOCTTY
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_PROTECTED_SOURCE_NAMES = {
    "agent.db",
    "auth.json",
    "client.json",
    "config.local",
    "config.local.json",
    "profile.json",
}
_ENV_KEEP = {"HOME", "PATH", "LANG", "LC_ALL", "USER", "LOGNAME", "SHELL", "TERM"}


class _InvalidRequest(Exception):
    pass


class _InvalidConfig(Exception):
    pass


class _CandidateInvalid(Exception):
    pass


class _SourceConflict(Exception):
    pass


_NATIVE_ERROR_CODES = frozenset(
    {
        "SANDBOX_UNAVAILABLE",
        "NATIVE_UNAVAILABLE",
        "TIMEOUT",
        "OUTPUT_LIMIT",
        "NATIVE_FAILURE",
        "INVALID_NATIVE_STREAM",
    }
)


class _NativeFailure(Exception):
    def __init__(self, diagnostics: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.diagnostics = diagnostics or {}


def _native_failure_diagnostics(result: object, details: frozenset[str]) -> dict[str, Any]:
    """Keep only fixed codes and numeric bounds from a failed native result."""
    if not isinstance(result, dict):
        return {}
    diagnostics: dict[str, Any] = {}
    code = result.get("error_code")
    if isinstance(code, str) and code in _NATIVE_ERROR_CODES:
        diagnostics["native_error_code"] = code
    detail = result.get("detail")
    if isinstance(detail, str) and detail in details:
        diagnostics["native_detail"] = detail
    exit_code = result.get("cli_exit_code")
    if type(exit_code) is int and -255 <= exit_code <= 255:
        diagnostics["native_exit_code"] = exit_code
    elapsed = result.get("elapsed_seconds")
    if type(elapsed) is float and math.isfinite(elapsed) and 0 <= elapsed <= 86400:
        diagnostics["native_elapsed_seconds"] = round(elapsed, 3)
    return diagnostics


class _ArtifactFailure(Exception):
    pass


@dataclass(frozen=True)
class _Target:
    root: Path
    files: tuple[str, ...]
    editable: frozenset[str]


@dataclass(frozen=True)
class _JobConfig:
    backend: str
    workspace: Path
    request: str
    runtime: dict[str, str]
    targets: dict[str, _Target]


@dataclass
class _PinnedSource:
    fd: int
    device: int
    inode: int
    content: bytes
    sha256: str


def _reject_constant(_value: str) -> Any:
    raise ValueError("Non-finite JSON numbers are not allowed")


def _decode_json(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=config_helpers._object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("Invalid UTF-8 JSON") from None


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid absolute path")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ValueError("Invalid absolute path") from None
    if len(encoded) > 4096:
        raise ValueError("Invalid absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Invalid absolute path")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("Invalid absolute path")
    return path


def _relative_path(value: object, limit: int = _PATH_LIMIT) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid relative path")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ValueError("Invalid relative path") from None
    if len(encoded) > limit or any(unicodedata.category(ch) == "Cc" for ch in value):
        raise ValueError("Invalid relative path")
    try:
        components = _validate_components(value, allow_root=False)
        if any(component.casefold() in _PROTECTED_SOURCE_NAMES for component in components):
            raise ValueError("Protected source path")
        return components
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Invalid relative path") from None


def _load_private_config(path_value: str) -> tuple[Path, dict[str, Any]]:
    try:
        path = _absolute_path(path_value)
        fd = config_helpers._open_absolute(path, os.O_RDONLY | os.O_NONBLOCK)
    except (OSError, TypeError, ValueError, UnicodeError):
        raise _InvalidConfig from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
        ):
            raise _InvalidConfig
        chunks = bytearray()
        while len(chunks) <= _CONFIG_LIMIT:
            block = os.read(fd, min(8192, _CONFIG_LIMIT + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > _CONFIG_LIMIT:
            raise _InvalidConfig
        try:
            value = _decode_json(bytes(chunks))
        except ValueError:
            raise _InvalidConfig from None
    except _InvalidConfig:
        raise
    except OSError:
        raise _InvalidConfig from None
    finally:
        os.close(fd)
    try:
        config_helpers._keys(value, {"backend", "workspace", "request", "runtime", "targets"})
    except (TypeError, ValueError):
        raise _InvalidConfig from None
    return path, value


def _parse_config_shape(value: dict[str, Any]) -> _JobConfig:
    backend = value["backend"]
    if backend not in ("omp", "claude", "codex"):
        raise _InvalidConfig
    runtime_keys = {
        "omp": {"executable", "cli", "modules", "config", "auth"},
        "claude": {"executable", "oauth_token"},
        "codex": {"executable", "companion", "auth"},
    }[backend]
    try:
        runtime = config_helpers._keys(value["runtime"], runtime_keys)
    except (TypeError, ValueError):
        raise _InvalidConfig from None

    try:
        workspace = _absolute_path(value["workspace"])
        request = value["request"]
        _relative_path(request, limit=4096)
    except (TypeError, ValueError, UnicodeError):
        raise _InvalidConfig from None
    if workspace == Path("/") or workspace == Path.home():
        raise _InvalidConfig

    raw_targets = value["targets"]
    if not isinstance(raw_targets, dict) or not 1 <= len(raw_targets) <= 16:
        raise _InvalidConfig
    targets: dict[str, _Target] = {}
    for name, raw_target in raw_targets.items():
        if not isinstance(name, str) or _IDENTIFIER.fullmatch(name) is None:
            raise _InvalidConfig
        try:
            target = config_helpers._keys(raw_target, {"root", "files", "editable"})
            root = _absolute_path(target["root"])
            raw_files = target["files"]
            raw_editable = target["editable"]
            if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= 32:
                raise ValueError
            if not isinstance(raw_editable, list):
                raise ValueError
            files = tuple("/".join(_relative_path(item)) for item in raw_files)
            editable_values = tuple("/".join(_relative_path(item)) for item in raw_editable)
            if len(set(files)) != len(files) or len(set(editable_values)) != len(editable_values):
                raise ValueError
            if not set(editable_values) <= set(files):
                raise ValueError
        except (TypeError, ValueError, UnicodeError):
            raise _InvalidConfig from None
        targets[name] = _Target(root=root, files=files, editable=frozenset(editable_values))

    return _JobConfig(
        backend=backend,
        workspace=workspace,
        request=request,
        runtime=runtime,
        targets=targets,
    )


def _validate_target_roots(targets: dict[str, _Target]) -> None:
    for target in targets.values():
        try:
            source_root = WorkspaceFiles(target.root)
            source_root.close()
        except (OSError, TypeError, ValueError):
            raise _InvalidConfig from None


def _parse_request(text: str, targets: dict[str, _Target]) -> tuple[str, str, str]:
    try:
        raw = _decode_json(text.encode("utf-8", "strict"))
        value = config_helpers._keys(raw, {"target", "mode", "instruction"})
        target = value["target"]
        mode = value["mode"]
        instruction = value["instruction"]
        if not isinstance(target, str) or target not in targets:
            raise ValueError
        if mode not in ("review", "edit"):
            raise ValueError
        if not isinstance(instruction, str) or not instruction or "\x00" in instruction:
            raise ValueError
        instruction_bytes = instruction.encode("utf-8", "strict")
        if len(instruction_bytes) > _INSTRUCTION_LIMIT:
            raise ValueError
    except (TypeError, ValueError, UnicodeError):
        raise _InvalidRequest from None
    return target, mode, instruction


def _validate_runtime_paths(
    config: _JobConfig,
    config_path: Path,
) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for key, value in config.runtime.items():
            path = _absolute_path(value)
            if path.is_relative_to(config.workspace) or path == config_path:
                raise ValueError
            if key == "modules":
                if config_path.is_relative_to(path):
                    raise ValueError
            elif key in {"executable", "cli", "companion"}:
                if config_path.is_relative_to(path.parent):
                    raise ValueError
            result[key] = os.fspath(path)
    except (TypeError, ValueError, UnicodeError):
        raise _InvalidConfig from None
    return result


def _read_fd(fd: int, limit: int = _FILE_LIMIT) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("Invalid regular file")
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
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or len(chunks) != after.st_size
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
    ):
        raise ValueError("File changed while reading")
    return bytes(chunks), after


def _pin_source_file(files: WorkspaceFiles, path: str) -> int:
    components = _relative_path(path)
    parent_fd, name = files._open_parent(components)
    try:
        return WorkspaceFiles._open_regular_at(parent_fd, name, _FILE_READ_FLAGS)
    finally:
        os.close(parent_fd)


def _mkdir_chain_at(root_fd: int, components: tuple[str, ...]) -> int:
    current_fd = os.dup(root_fd)
    try:
        for component in components:
            try:
                os.mkdir(component, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            child_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                os.close(child_fd)
                raise OSError("Not a directory")
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("Short write")
        offset += written


def _write_candidate_file(root_fd: int, path: str, content: bytes) -> None:
    components = _relative_path(path)
    parent_fd = _mkdir_chain_at(root_fd, components[:-1])
    try:
        fd = os.open(components[-1], _FILE_CREATE_FLAGS, 0o600, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("Invalid candidate file")
            os.fchmod(fd, 0o600)
            _write_all(fd, content)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _snapshot_sources(
    target: _Target,
    snapshot: Path,
) -> tuple[WorkspaceFiles, dict[str, _PinnedSource]]:
    try:
        source_files = WorkspaceFiles(target.root)
    except (OSError, ValueError, TypeError):
        raise _InvalidConfig from None
    try:
        candidate_files = WorkspaceFiles(snapshot)
    except (OSError, ValueError, TypeError):
        source_files.close()
        raise _InvalidConfig from None
    sources: dict[str, _PinnedSource] = {}
    snapshot_fd = -1
    try:
        snapshot_fd = os.dup(candidate_files._root_fd)
        for path in target.files:
            fd = _pin_source_file(source_files, path)
            try:
                content, info = _read_fd(fd)
                content.decode("utf-8", "strict")
                read_result = source_files.read_file(path)
                read_content = read_result["content"].encode("utf-8", "strict")
                digest = hashlib.sha256(content).hexdigest()
                if read_content != content or read_result["sha256"] != digest:
                    raise ValueError("Source changed during snapshot")
                _write_candidate_file(snapshot_fd, path, content)
                sources[path] = _PinnedSource(
                    fd=fd,
                    device=info.st_dev,
                    inode=info.st_ino,
                    content=content,
                    sha256=digest,
                )
                fd = -1
            finally:
                if fd >= 0:
                    os.close(fd)
    except (OSError, TypeError, ValueError, UnicodeError):
        for source in sources.values():
            os.close(source.fd)
        source_files.close()
        raise _InvalidConfig from None
    finally:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        candidate_files.close()
    return source_files, sources


def _candidate_read_file(parent_fd: int, name: str) -> bytes:
    fd = WorkspaceFiles._open_regular_at(parent_fd, name, _FILE_READ_FLAGS)
    try:
        try:
            content, _info = _read_fd(fd)
            content.decode("utf-8", "strict")
        except (UnicodeError, ValueError):
            raise _CandidateInvalid from None
        return content
    finally:
        os.close(fd)


def _scan_candidate(snapshot: Path, expected_paths: set[str]) -> dict[str, bytes]:
    expected_directories: set[str] = set()
    for path in expected_paths:
        components = path.split("/")
        for index in range(1, len(components)):
            expected_directories.add("/".join(components[:index]))

    try:
        candidate_root = WorkspaceFiles(snapshot)
    except (OSError, TypeError, ValueError):
        raise _CandidateInvalid from None
    found: dict[str, bytes] = {}

    def visit(directory_fd: int, prefix: tuple[str, ...]) -> None:
        try:
            with os.scandir(directory_fd) as iterator:
                entries = []
                entry_limit = len(expected_paths) + len(expected_directories)
                for entry in iterator:
                    if len(entries) >= entry_limit:
                        raise _CandidateInvalid
                    entries.append(entry)
        except OSError:
            raise _CandidateInvalid from None
        for entry in entries:
            name = entry.name
            try:
                path = "/".join((*prefix, name))
                _relative_path(path)
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except (OSError, TypeError, ValueError, UnicodeError):
                raise _CandidateInvalid from None
            if stat.S_ISDIR(info.st_mode):
                if path not in expected_directories:
                    raise _CandidateInvalid
                try:
                    child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                except OSError:
                    raise _CandidateInvalid from None
                try:
                    child_info = os.fstat(child_fd)
                    if (
                        not stat.S_ISDIR(child_info.st_mode)
                        or child_info.st_dev != info.st_dev
                        or child_info.st_ino != info.st_ino
                    ):
                        raise _CandidateInvalid
                    visit(child_fd, (*prefix, name))
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                if path not in expected_paths or path in found or info.st_nlink != 1:
                    raise _CandidateInvalid
                content = _candidate_read_file(directory_fd, name)
                found[path] = content
            else:
                raise _CandidateInvalid

    try:
        visit(candidate_root._root_fd, ())
    finally:
        candidate_root.close()
    if found.keys() != expected_paths:
        raise _CandidateInvalid
    return found


def _verify_sources_unchanged(
    source_files: WorkspaceFiles,
    sources: dict[str, _PinnedSource],
    configured_root: Path,
) -> None:
    try:
        current_root = config_helpers._open_absolute(configured_root, _DIRECTORY_FLAGS)
        try:
            pinned_info = os.fstat(source_files._root_fd)
            current_info = os.fstat(current_root)
            if (pinned_info.st_dev, pinned_info.st_ino) != (current_info.st_dev, current_info.st_ino):
                raise ValueError
        finally:
            os.close(current_root)
    except (OSError, ValueError):
        raise _SourceConflict from None
    for path, source in sources.items():
        try:
            pinned_content, info = _read_fd(source.fd)
            if info.st_dev != source.device or info.st_ino != source.inode:
                raise ValueError
            current = source_files.read_file(path)
            current_bytes = current["content"].encode("utf-8", "strict")
            current_fd = _pin_source_file(source_files, path)
            try:
                current_info = os.fstat(current_fd)
                if current_info.st_dev != source.device or current_info.st_ino != source.inode:
                    raise ValueError
            finally:
                os.close(current_fd)
            if (
                hashlib.sha256(pinned_content).hexdigest() != source.sha256
                or hashlib.sha256(current_bytes).hexdigest() != source.sha256
                or current["sha256"] != source.sha256
            ):
                raise ValueError
        except (OSError, TypeError, ValueError, UnicodeError):
            raise _SourceConflict from None


def _lf_lines(content: bytes) -> list[str]:
    lines: list[str] = []
    start = 0
    while True:
        newline = content.find(b"\n", start)
        if newline < 0:
            if start < len(content):
                lines.append(content[start:].decode("utf-8", "strict"))
            break
        lines.append(content[start : newline + 1].decode("utf-8", "strict"))
        start = newline + 1
    return lines


def _file_diff(path: str, before: bytes, after: bytes) -> str:
    changes = difflib.unified_diff(
        _lf_lines(before),
        _lf_lines(after),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="\n",
    )
    output: list[str] = []
    for index, line in enumerate(changes):
        if index < 2 or line.startswith("@@ "):
            output.append(line if line.endswith("\n") else line + "\n")
        elif line and line[0] in " +-":
            if line.endswith("\n"):
                output.append(line)
            else:
                output.append(line + "\n\\ No newline at end of file\n")
        else:
            output.append(line if line.endswith("\n") else line + "\n")
    return "".join(output)


def _chunk_diff(diff: str) -> list[bytes]:
    chunks: list[bytes] = []
    current = bytearray()
    for character in diff:
        encoded = character.encode("utf-8", "strict")
        if current and len(current) + len(encoded) > _DIFF_CHUNK_LIMIT:
            chunks.append(bytes(current))
            current.clear()
        current.extend(encoded)
    if current:
        chunks.append(bytes(current))
    return chunks


def _open_or_create_directories(
    root_fd: int,
    components: tuple[str, ...],
    created: list[int],
) -> int:
    current_fd = os.dup(root_fd)
    try:
        for index, component in enumerate(components):
            try:
                os.mkdir(component, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            else:
                created.append(index)
            child_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                os.close(child_fd)
                raise OSError("Not a directory")
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        try:
            child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError:
            return
        try:
            with os.scandir(child_fd) as iterator:
                names = [entry.name for entry in iterator]
            for child_name in names:
                _remove_tree_at(child_fd, child_name)
        finally:
            os.close(child_fd)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            return
    else:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            return


def _remove_created_directories(
    workspace_files: WorkspaceFiles,
    components: tuple[str, ...],
    created: list[int],
) -> None:
    for index in reversed(created):
        try:
            parent_fd = workspace_files._open_directory(components[:index])
            try:
                os.rmdir(components[index], dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        except (OSError, ValueError):
            pass


def _write_artifact_file(directory_fd: int, name: str, content: bytes) -> None:
    fd = os.open(name, _FILE_CREATE_FLAGS, 0o600, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("Invalid artifact file")
        os.fchmod(fd, 0o600)
        _write_all(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise OSError(errno.ENOSYS, "Atomic no-replace rename is unavailable") from None
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _publish_artifacts(
    workspace_files: WorkspaceFiles,
    backend: str,
    job_id: str,
    report: dict[str, Any],
    diff: str,
) -> tuple[str, str]:
    relative_root = f"cli-results/{backend}/{job_id}"
    chunks = _chunk_diff(diff)
    chunk_metadata = []
    for index, content in enumerate(chunks, start=1):
        path = f"{relative_root}/diff-{index:04d}.txt"
        chunk_metadata.append(
            {"path": path, "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}
        )
    report["diff_chunks"] = chunk_metadata
    report["diff_sha256"] = hashlib.sha256(diff.encode("utf-8", "strict")).hexdigest()
    try:
        report_bytes = json.dumps(
            report,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise _ArtifactFailure from None
    if len(report_bytes) > _REPORT_LIMIT:
        raise _ArtifactFailure
    report_path = f"{relative_root}/report.json"
    report_digest = hashlib.sha256(report_bytes).hexdigest()

    base_fd = -1
    stage_fd = -1
    stage_name = f".stage-{job_id}"
    stage_created = False
    published = False
    created_directories: list[int] = []
    try:
        base_fd = _open_or_create_directories(
            workspace_files._root_fd,
            ("cli-results", backend),
            created_directories,
        )
        os.mkdir(stage_name, 0o700, dir_fd=base_fd)
        stage_created = True
        stage_fd = os.open(stage_name, _DIRECTORY_FLAGS, dir_fd=base_fd)
        if stat.S_IMODE(os.fstat(stage_fd).st_mode) & 0o077:
            raise OSError("Artifact staging directory is not private")
        for index, content in enumerate(chunks, start=1):
            _write_artifact_file(stage_fd, f"diff-{index:04d}.txt", content)
        _write_artifact_file(stage_fd, "report.json", report_bytes)
        os.fsync(stage_fd)
        _rename_noreplace(base_fd, stage_name, job_id)
        stage_created = False
        published = True
        os.fsync(base_fd)
        return report_path, report_digest
    except (OSError, ValueError):
        if base_fd >= 0:
            if published:
                _remove_tree_at(base_fd, job_id)
            elif stage_created:
                _remove_tree_at(base_fd, stage_name)
        _remove_created_directories(
            workspace_files,
            ("cli-results", backend),
            created_directories,
        )
        raise _ArtifactFailure from None
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if base_fd >= 0:
            os.close(base_fd)


def _candidate_result(
    workspace_files: WorkspaceFiles,
    config: _JobConfig,
    target_name: str,
    target: _Target,
    mode: str,
    native_result: dict[str, Any],
    snapshot: Path,
    source_files: WorkspaceFiles,
    sources: dict[str, _PinnedSource],
) -> dict[str, Any]:
    candidate = _scan_candidate(snapshot, set(target.files))
    editable = target.editable if mode == "edit" else frozenset()
    changed = {
        path
        for path in target.files
        if candidate[path] != sources[path].content
    }
    if not changed <= editable:
        raise _CandidateInvalid

    files_report = []
    diff_parts = []
    for path in sorted(target.files):
        before = sources[path].content
        after = candidate[path]
        files_report.append(
            {
                "path": path,
                "before_sha256": sources[path].sha256,
                "after_sha256": hashlib.sha256(after).hexdigest(),
                "changed": path in changed,
            }
        )
        if path in changed:
            diff_parts.append(_file_diff(path, before, after))
    protected_paths = set(target.files) - editable
    if mode == "review":
        protected_paths = set(target.files)
    report = {
        "schema_version": 1,
        "status": "candidate_ready" if mode == "edit" else "reviewed",
        "backend": config.backend,
        "job_id": "",
        "target": target_name,
        "mode": mode,
        "verification": "not_run",
        "changed_file_count": len(changed),
        "files": files_report,
        "protected_source_hashes": {
            path: sources[path].sha256 for path in sorted(protected_paths)
        },
        "native_exit_code": native_result["cli_exit_code"],
        "native_elapsed_seconds": native_result["elapsed_seconds"],
        "native_summary": native_result["summary"],
    }
    _verify_sources_unchanged(source_files, sources, target.root)
    # Use one identifier for the report and every artifact path.
    job_id = str(uuid.uuid4())
    report["job_id"] = job_id
    diff = "".join(diff_parts)
    report_path, report_sha256 = _publish_artifacts(
        workspace_files,
        config.backend,
        job_id,
        report,
        diff,
    )
    return {
        "status": report["status"],
        "backend": config.backend,
        "job_id": job_id,
        "changed_file_count": len(changed),
        "report_path": report_path,
        "report_sha256": report_sha256,
        "cli_exit_code": native_result["cli_exit_code"],
        "elapsed_seconds": native_result["elapsed_seconds"],
        "verification": "not_run",
    }


def _run_validated_job(
    job_config: _JobConfig,
    target_name: str,
    mode: str,
    instruction: str,
    runtime: dict[str, str],
    workspace_files: WorkspaceFiles,
) -> dict[str, Any]:
    target = job_config.targets[target_name]
    try:
        temporary = tempfile.TemporaryDirectory(prefix="dotunnel-cli-job-")
    except OSError:
        raise _CandidateInvalid from None
    with temporary:
        temporary_path = Path(temporary.name)
        snapshot = temporary_path / "workspace"
        try:
            snapshot.mkdir(mode=0o700)
            temp_info = os.stat(temporary_path, follow_symlinks=False)
            snapshot_info = os.stat(snapshot, follow_symlinks=False)
            if (
                not stat.S_ISDIR(temp_info.st_mode)
                or not stat.S_ISDIR(snapshot_info.st_mode)
                or stat.S_IMODE(temp_info.st_mode) != 0o700
                or stat.S_IMODE(snapshot_info.st_mode) != 0o700
                or temporary_path.is_relative_to(job_config.workspace)
                or snapshot.is_relative_to(job_config.workspace)
                or temporary_path.is_relative_to(target.root)
            ):
                raise _InvalidConfig
        except (OSError, ValueError):
            raise _InvalidConfig from None

        source_files, sources = _snapshot_sources(target, snapshot)
        try:
            try:
                from . import cli_backend
            except ImportError:
                raise _NativeFailure from None
            try:
                native_result = cli_backend.run_native(
                    job_config.backend,
                    runtime,
                    snapshot,
                    tuple(sorted(target.editable)),
                    mode,
                    instruction,
                )
            except ValueError:
                _verify_sources_unchanged(source_files, sources, target.root)
                raise _InvalidConfig from None
            except Exception:
                _verify_sources_unchanged(source_files, sources, target.root)
                raise _NativeFailure from None
            _verify_sources_unchanged(source_files, sources, target.root)
            if not isinstance(native_result, dict):
                raise _NativeFailure
            if native_result.get("status") != "completed":
                raise _NativeFailure(
                    _native_failure_diagnostics(native_result, cli_backend._NATIVE_FAILURE_DETAILS)
                )
            exit_code = native_result.get("cli_exit_code")
            elapsed = native_result.get("elapsed_seconds")
            summary = native_result.get("summary")
            if (
                isinstance(exit_code, bool)
                or (exit_code is not None and not isinstance(exit_code, int))
                or not isinstance(elapsed, float)
                or not math.isfinite(elapsed)
                or elapsed < 0
                or not isinstance(summary, str)
            ):
                raise _NativeFailure
            try:
                if len(summary.encode("utf-8", "strict")) > 2048:
                    raise _NativeFailure
            except UnicodeError:
                raise _NativeFailure from None
            normalized_result = {
                "status": "completed",
                "cli_exit_code": exit_code,
                "elapsed_seconds": elapsed,
                "summary": summary,
            }
            try:
                return _candidate_result(
                    workspace_files,
                    job_config,
                    target_name,
                    target,
                    mode,
                    normalized_result,
                    snapshot,
                    source_files,
                    sources,
                )
            except _SourceConflict:
                raise
            except _CandidateInvalid:
                raise
            except _ArtifactFailure:
                raise
            except (OSError, ValueError, UnicodeError):
                raise _CandidateInvalid from None
        finally:
            for source in sources.values():
                try:
                    os.close(source.fd)
                except OSError:
                    pass
            source_files.close()


def _scrub_environment() -> None:
    for key in tuple(os.environ):
        if key not in _ENV_KEEP:
            del os.environ[key]
    # TaskRunner deliberately supplies a synthetic HOME. Admission protects the
    # real account home; the native child receives a separate tmpfs HOME.
    import pwd

    os.environ["HOME"] = pwd.getpwuid(os.getuid()).pw_dir


def _emit(value: dict[str, Any]) -> None:
    text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(text.encode("utf-8", "strict")) > _STDOUT_LIMIT:
        text = '{"status":"failed","error_code":"OUTPUT_TOO_LARGE"}'
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _InvalidRequest


def main(argv: list[str]) -> int:
    parser = _ArgumentParser(
        prog="dotunnel cli-job",
        description="Run an isolated OMP, Claude, or Codex review/edit job",
        allow_abbrev=False,
    )
    parser.add_argument("--config", required=True, help="Absolute private job configuration JSON")
    try:
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise _InvalidRequest
        args = parser.parse_args(argv)
    except SystemExit as result:
        return int(result.code or 0)
    except _InvalidRequest:
        _emit({"status": "rejected", "error_code": "INVALID_REQUEST"})
        return 2

    if sys.platform != "linux" or os.getuid() == 0 or os.geteuid() == 0:
        _emit({"status": "rejected", "error_code": "UNSUPPORTED_ENVIRONMENT"})
        return 2
    try:
        _scrub_environment()
    except (KeyError, OSError):
        _emit({"status": "rejected", "error_code": "UNSUPPORTED_ENVIRONMENT"})
        return 2

    try:
        config_path, raw_config = _load_private_config(args.config)
        job_config = _parse_config_shape(raw_config)
        if config_path == job_config.workspace or config_path.is_relative_to(job_config.workspace):
            raise _InvalidConfig
        code_root = Path(__file__).absolute().parent
        if config_path.is_relative_to(code_root) or code_root.is_relative_to(job_config.workspace):
            raise _InvalidConfig
        try:
            workspace_files = WorkspaceFiles(job_config.workspace)
        except (OSError, TypeError, ValueError):
            raise _InvalidConfig from None
        try:
            try:
                request_text = workspace_files.read_file(job_config.request)["content"]
            except (OSError, TypeError, ValueError, UnicodeError):
                raise _InvalidRequest from None
            target_name, mode, instruction = _parse_request(request_text, job_config.targets)
            _validate_target_roots(job_config.targets)
            runtime = _validate_runtime_paths(job_config, config_path)
            with open(os.devnull, "w", encoding="utf-8") as sink:
                from contextlib import redirect_stderr, redirect_stdout

                with redirect_stdout(sink), redirect_stderr(sink):
                    result = _run_validated_job(
                        job_config,
                        target_name,
                        mode,
                        instruction,
                        runtime,
                        workspace_files,
                    )
        finally:
            workspace_files.close()
    except _InvalidRequest:
        _emit({"status": "rejected", "error_code": "INVALID_REQUEST"})
        return 2
    except _InvalidConfig:
        _emit({"status": "rejected", "error_code": "INVALID_CONFIG"})
        return 2
    except _NativeFailure as failure:
        _emit({"status": "failed", "error_code": "NATIVE_FAILED", **failure.diagnostics})
        return 1
    except _CandidateInvalid:
        _emit({"status": "failed", "error_code": "CANDIDATE_INVALID"})
        return 1
    except _SourceConflict:
        _emit({"status": "failed", "error_code": "SOURCE_CONFLICT"})
        return 1
    except _ArtifactFailure:
        _emit({"status": "failed", "error_code": "ARTIFACT_FAILURE"})
        return 1
    except Exception:
        _emit({"status": "failed", "error_code": "JOB_FAILED"})
        return 1

    _emit(result)
    return 0
